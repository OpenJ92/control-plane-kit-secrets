from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import re
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .audit import AuditUnavailable, SqliteAuditStore, audit_record
from .auth import (
    ProviderAuthenticationError,
    ProviderAuthorizer,
    ProviderCredential,
    SecretUseDenied,
)
from .models import (
    DelegationKeyGenerationConflict,
    SecretAlreadyExists,
    SecretIntentMismatch,
    SecretMetadata,
    SecretMetadataInvalid,
    SecretMissing,
    SecretResolutionConflict,
    SecretRevoked,
    SecretTampered,
    SecretVersionRevocationConflict,
)
from .store import (
    EncryptedSecretStore,
    GATEWAY_DELEGATION_PURPOSE,
    GATEWAY_SIGNING_INTENT,
)


MAX_SECRET_BYTES = 64 * 1024
MAX_CORRELATION_CHARS = 128
MAX_SECRET_REFERENCE_CHARS = 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_REFERENCE_PROVIDER = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_REFERENCE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
ALLOWED_SECRET_USE_INTENTS = frozenset(
    {
        "application.control-token",
        "cloudflare.api-token",
        "cloudflare.tunnel-token",
        "docker.local-socket-access-marker",
        "docker.remote-tls.ca-certificate",
        "docker.remote-tls.client-certificate",
        "docker.remote-tls.client-key",
        "gateway.probe-signing-key",
        "oci.pull-credential",
        "postgres.password",
    }
)


class SecretWriteRequest(BaseModel):
    value_base64: str = Field(min_length=1)
    intent: str
    labels: dict[str, str] = Field(default_factory=dict)
    caller_subject: str | None = Field(default=None, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=MAX_CORRELATION_CHARS)


class SecretRotateRequest(BaseModel):
    value_base64: str = Field(min_length=1)
    intent: str
    labels: dict[str, str] = Field(default_factory=dict)
    caller_subject: str | None = Field(default=None, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=MAX_CORRELATION_CHARS)


class SecretResolveRequest(BaseModel):
    intent: str
    caller_subject: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=MAX_CORRELATION_CHARS)
    version_id: str | None = None


class SecretRevokeRequest(BaseModel):
    caller_subject: str | None = Field(default=None, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=MAX_CORRELATION_CHARS)


class SecretVersionRevokeRequest(BaseModel):
    version_number: int = Field(ge=1)
    caller_subject: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=MAX_CORRELATION_CHARS)


class DelegationKeyGenerateRequest(BaseModel):
    secret_reference: str = Field(
        min_length=1,
        max_length=MAX_SECRET_REFERENCE_CHARS,
    )
    purpose: str = Field(min_length=1, max_length=64)
    issuer: str = Field(min_length=1, max_length=200)
    caller_subject: str = Field(min_length=1, max_length=200)
    correlation_id: str = Field(min_length=1, max_length=MAX_CORRELATION_CHARS)


def create_app(
    *,
    store: EncryptedSecretStore,
    audit_store: SqliteAuditStore,
    credentials: tuple[ProviderCredential, ...],
    provider_id: str = "local-dev-provider",
) -> FastAPI:
    authorizer = ProviderAuthorizer(credentials)
    app = FastAPI(title="control-plane-kit-secrets")

    def credential(authorization: str | None = Header(default=None)) -> ProviderCredential:
        try:
            return authorizer.authenticate(authorization)
        except ProviderAuthenticationError as exc:
            raise _error(401, "denied", "unauthenticated") from exc

    @app.get("/health/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    def ready() -> dict[str, str]:
        return {"status": "ready"}

    @app.post("/v1/workspaces/{workspace_id}/secrets/{secret_id}")
    def write_secret(
        workspace_id: str,
        secret_id: str,
        request: SecretWriteRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        caller_subject = request.caller_subject or client.subject
        correlation_id = request.correlation_id or "not-provided"
        try:
            _validate_intent(request.intent)
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="malformed",
                code="unsupported-intent",
            )
            raise exc
        try:
            _require(
                authorizer,
                client,
                action="secret.write",
                workspace_id=workspace_id,
                intent=request.intent,
            )
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="denied",
                code="insufficient-scope",
            )
            raise exc
        try:
            labels = _canonical_intent_labels(request.labels, request.intent)
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="malformed",
                code="intent-label-conflict",
            )
            raise exc
        value = _decode_secret_value(request.value_base64)
        try:
            metadata = store.create_secret(
                workspace_id=workspace_id,
                secret_id=secret_id,
                value=value,
                labels=labels,
            )
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=metadata.version_id,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="stored",
                code="secret-stored",
            )
            return {"outcome": "stored", "metadata": _metadata_response(metadata)}
        except SecretMetadataInvalid as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="malformed",
                code="invalid-metadata",
            )
            raise _error(400, "malformed", "invalid-metadata") from exc
        except SecretAlreadyExists as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="already-exists",
                code="secret-already-exists",
            )
            raise _error(409, "already-exists", "secret-already-exists") from exc

    @app.post(
        "/v1/workspaces/{workspace_id}/delegation-keys/{secret_id}/generate"
    )
    def generate_delegation_key(
        workspace_id: str,
        secret_id: str,
        request: DelegationKeyGenerateRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        if (
            request.purpose != GATEWAY_DELEGATION_PURPOSE
            or not _IDENTIFIER.fullmatch(request.issuer)
            or not _IDENTIFIER.fullmatch(request.caller_subject)
            or not _valid_secret_reference(request.secret_reference)
        ):
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=GATEWAY_SIGNING_INTENT,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="malformed",
                code="invalid-delegation-key-generation",
            )
            raise _error(400, "malformed", "invalid-delegation-key-generation")
        try:
            _require(
                authorizer,
                client,
                action="secret.generate-delegation-key",
                workspace_id=workspace_id,
                intent=GATEWAY_SIGNING_INTENT,
            )
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=GATEWAY_SIGNING_INTENT,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="denied",
                code="insufficient-scope",
            )
            raise exc
        try:
            generated = store.generate_delegation_key(
                workspace_id=workspace_id,
                secret_id=secret_id,
                secret_reference=request.secret_reference,
                purpose=request.purpose,
                issuer=request.issuer,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                provider_id=provider_id,
                audit_store=audit_store,
            )
            return {
                "outcome": "generated",
                "secret_reference": generated.secret_reference,
                "metadata": _metadata_response(generated.metadata),
                "purpose": generated.purpose,
                "issuer": generated.issuer,
                "correlation_id": generated.correlation_id,
                "key_id": generated.key_id,
                "algorithm": generated.algorithm,
                "public_key_pem": generated.public_key_pem,
                "fingerprint_sha256": sha256(
                    generated.public_key_pem.encode("ascii")
                ).hexdigest(),
                "replayed": generated.replayed,
            }
        except DelegationKeyGenerationConflict as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=GATEWAY_SIGNING_INTENT,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="conflict",
                code="generation-correlation-conflict",
            )
            raise _error(
                409,
                "conflict",
                "generation-correlation-conflict",
            ) from exc
        except SecretAlreadyExists as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=GATEWAY_SIGNING_INTENT,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="already-exists",
                code="secret-already-exists",
            )
            raise _error(409, "already-exists", "secret-already-exists") from exc
        except SecretRevoked as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=GATEWAY_SIGNING_INTENT,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="revoked",
                code="secret-revoked",
            )
            raise _error(409, "revoked", "secret-revoked") from exc
        except SecretTampered as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=GATEWAY_SIGNING_INTENT,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="unavailable",
                code="integrity-failure",
            )
            raise _error(503, "unavailable", "integrity-failure") from exc
        except AuditUnavailable as exc:
            raise _error(503, "unavailable", "audit-unavailable") from exc

    @app.post("/v1/workspaces/{workspace_id}/secrets/{secret_id}/rotate")
    def rotate_secret(
        workspace_id: str,
        secret_id: str,
        request: SecretRotateRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        caller_subject = request.caller_subject or client.subject
        correlation_id = request.correlation_id or "not-provided"
        try:
            _validate_intent(request.intent)
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="malformed",
                code="unsupported-intent",
            )
            raise exc
        try:
            _require(
                authorizer,
                client,
                action="secret.rotate",
                workspace_id=workspace_id,
                intent=request.intent,
            )
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="denied",
                code="insufficient-scope",
            )
            raise exc
        try:
            labels = _canonical_intent_labels(request.labels, request.intent)
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="malformed",
                code="intent-label-conflict",
            )
            raise exc
        value = _decode_secret_value(request.value_base64)
        try:
            metadata = store.rotate_secret(
                workspace_id=workspace_id,
                secret_id=secret_id,
                value=value,
                labels=labels,
                expected_intent=request.intent,
            )
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=metadata.version_id,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="rotated",
                code="secret-rotated",
            )
            return {"outcome": "rotated", "metadata": _metadata_response(metadata)}
        except SecretMissing as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="missing",
                code="secret-missing",
            )
            raise _error(404, "missing", "secret-missing") from exc
        except SecretMetadataInvalid as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="malformed",
                code="invalid-metadata",
            )
            raise _error(400, "malformed", "invalid-metadata") from exc
        except SecretAlreadyExists as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="already-exists",
                code="secret-version-conflict",
            )
            raise _error(409, "already-exists", "secret-version-conflict") from exc
        except SecretIntentMismatch as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=request.intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="already-exists",
                code="secret-intent-conflict",
            )
            raise _error(409, "already-exists", "secret-intent-conflict") from exc

    @app.post("/v1/workspaces/{workspace_id}/secrets/{secret_id}/resolve")
    def resolve_secret(
        workspace_id: str,
        secret_id: str,
        request: SecretResolveRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        try:
            client = authorizer.authenticate(authorization)
        except ProviderAuthenticationError as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject="unauthenticated",
                correlation_id=request.correlation_id,
                outcome="denied",
                code="unauthenticated",
            )
            raise _error(401, "denied", "unauthenticated") from exc
        try:
            _validate_intent(request.intent)
        except HTTPException as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="malformed",
                code="unsupported-intent",
            )
            raise exc
        try:
            _require(
                authorizer,
                client,
                action="secret.resolve",
                workspace_id=workspace_id,
                intent=request.intent,
            )
        except HTTPException as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="denied",
                code="insufficient-scope",
            )
            raise exc
        try:
            resolved = store.resolve_secret_for_use(
                workspace_id=workspace_id,
                secret_id=secret_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                version_id=request.version_id,
            )
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=resolved.metadata.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="resolved",
                code="secret-resolved",
            )
            return {
                "outcome": "resolved",
                "metadata": _metadata_response(resolved.metadata),
                "value_base64": base64.b64encode(resolved.value).decode("ascii"),
            }
        except SecretMissing as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="missing",
                code="secret-missing",
            )
            raise _error(404, "missing", "secret-missing") from exc
        except SecretRevoked as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="revoked",
                code="secret-revoked",
            )
            raise _error(409, "revoked", "secret-revoked") from exc
        except SecretResolutionConflict as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="already-exists",
                code="resolution-correlation-conflict",
            )
            raise _error(
                409,
                "already-exists",
                "resolution-correlation-conflict",
            ) from exc
        except SecretIntentMismatch as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="denied",
                code="secret-intent-mismatch",
            )
            raise _error(403, "denied", "secret-intent-mismatch") from exc
        except SecretTampered as exc:
            _append_resolve_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
                intent=request.intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="unavailable",
                code="integrity-failure",
            )
            raise _error(503, "unavailable", "integrity-failure") from exc

    @app.post(
        "/v1/workspaces/{workspace_id}/secrets/{secret_id}/"
        "versions/{version_id}/revoke"
    )
    def revoke_secret_version(
        workspace_id: str,
        secret_id: str,
        version_id: str,
        request: SecretVersionRevokeRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require(authorizer, client, action="secret.revoke", workspace_id=workspace_id)
        try:
            revoked = store.revoke_secret_version(
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=version_id,
                version_number=request.version_number,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                provider_id=provider_id,
                audit_store=audit_store,
            )
            return {
                "outcome": "revoked",
                "metadata": _metadata_response(revoked),
            }
        except SecretVersionRevocationConflict as exc:
            raise _error(409, "conflict", "version-revocation-conflict") from exc
        except SecretRevoked as exc:
            raise _error(409, "conflict", "secret-revoked") from exc
        except SecretMissing as exc:
            raise _error(404, "missing", "secret-missing") from exc
        except SecretTampered as exc:
            raise _error(503, "unavailable", "integrity-failure") from exc
        except AuditUnavailable as exc:
            raise _error(503, "unavailable", "audit-unavailable") from exc

    @app.post("/v1/workspaces/{workspace_id}/secrets/{secret_id}/revoke")
    def revoke_secret(
        workspace_id: str,
        secret_id: str,
        request: SecretRevokeRequest | None = None,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require(authorizer, client, action="secret.revoke", workspace_id=workspace_id)
        caller_subject = (
            client.subject
            if request is None or request.caller_subject is None
            else request.caller_subject
        )
        correlation_id = (
            "not-provided"
            if request is None or request.correlation_id is None
            else request.correlation_id
        )
        try:
            revoked = store.revoke_secret(workspace_id=workspace_id, secret_id=secret_id)
            for metadata in revoked:
                _append_audit(
                    audit_store,
                    provider_id=provider_id,
                    workspace_id=workspace_id,
                    secret_id=secret_id,
                    version_id=metadata.version_id,
                    intent=_durable_metadata_intent(metadata),
                    caller_subject=caller_subject,
                    correlation_id=correlation_id,
                    outcome="revoked",
                    code="secret-revoked",
                )
            return {
                "outcome": "revoked",
                "metadata": [_metadata_response(metadata) for metadata in revoked],
            }
        except SecretMissing as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=None,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="missing",
                code="secret-missing",
            )
            raise _error(404, "missing", "secret-missing") from exc
        except SecretTampered as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=None,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome="unavailable",
                code="integrity-failure",
            )
            raise _error(503, "unavailable", "integrity-failure") from exc

    @app.get("/v1/workspaces/{workspace_id}/secrets/{secret_id}/metadata")
    def read_metadata(
        workspace_id: str,
        secret_id: str,
        version_id: str | None = None,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require(authorizer, client, action="secret.metadata", workspace_id=workspace_id)
        try:
            metadata = store.metadata(
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=version_id,
            )
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=metadata.version_id,
                intent=None,
                caller_subject=client.subject,
                correlation_id="not-provided",
                outcome="metadata",
                code="metadata-read",
            )
            return {"outcome": "metadata", "metadata": _metadata_response(metadata)}
        except SecretMissing as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=version_id,
                intent=None,
                caller_subject=client.subject,
                correlation_id="not-provided",
                outcome="missing",
                code="secret-missing",
            )
            raise _error(404, "missing", "secret-missing") from exc

    return app


def _metadata_response(metadata: SecretMetadata) -> dict[str, Any]:
    return {
        "workspace_id": metadata.workspace_id,
        "secret_id": metadata.secret_id,
        "version_id": metadata.version_id,
        "version_number": metadata.version_number,
        "status": metadata.status.value,
        "algorithm": metadata.algorithm,
        "key_fingerprint": metadata.key_fingerprint,
        "key_version": metadata.key_version,
        "labels": dict(metadata.labels),
        "created_at": metadata.created_at,
        "revoked_at": metadata.revoked_at,
    }


def _decode_secret_value(encoded: str) -> bytes:
    try:
        value = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise _error(400, "malformed", "invalid-secret-material") from exc
    if len(value) > MAX_SECRET_BYTES:
        raise _error(400, "malformed", "secret-material-too-large")
    return value


def _validate_intent(intent: str) -> None:
    if intent not in ALLOWED_SECRET_USE_INTENTS:
        raise _error(400, "malformed", "unsupported-intent")


def _canonical_intent_labels(
    labels: dict[str, str],
    intent: str,
) -> dict[str, str]:
    supplied = labels.get("intent")
    if supplied is not None and supplied != intent:
        raise _error(400, "malformed", "intent-label-conflict")
    return {**labels, "intent": intent}


def _durable_metadata_intent(metadata: SecretMetadata) -> str | None:
    intent = metadata.labels.get("intent")
    if intent in ALLOWED_SECRET_USE_INTENTS:
        return intent
    return None


def _valid_secret_reference(value: str) -> bool:
    parsed = urlsplit(value)
    path = tuple(part for part in parsed.path.split("/") if part)
    return bool(
        parsed.scheme == "secret"
        and _REFERENCE_PROVIDER.fullmatch(parsed.netloc)
        and not parsed.query
        and not parsed.fragment
        and path
        and parsed.path == "/" + "/".join(path)
        and all(
            part not in {".", ".."} and _REFERENCE_SEGMENT.fullmatch(part)
            for part in path
        )
    )


def _require(
    authorizer: ProviderAuthorizer,
    client: ProviderCredential,
    *,
    action: str,
    workspace_id: str,
    intent: str | None = None,
) -> None:
    try:
        authorizer.require(
            client,
            action=action,
            workspace_id=workspace_id,
            intent=intent,
        )
    except SecretUseDenied as exc:
        raise _error(403, "denied", "insufficient-scope") from exc


def _append_resolve_audit(
    audit_store: SqliteAuditStore,
    *,
    provider_id: str,
    workspace_id: str,
    secret_id: str,
    version_id: str | None,
    intent: str | None,
    caller_subject: str,
    correlation_id: str,
    outcome: str,
    code: str,
) -> None:
    _append_audit(
        audit_store,
        provider_id=provider_id,
        workspace_id=workspace_id,
        secret_id=secret_id,
        version_id=version_id,
        intent=intent,
        caller_subject=caller_subject,
        correlation_id=correlation_id,
        outcome=outcome,
        code=code,
    )


def _append_audit(
    audit_store: SqliteAuditStore,
    *,
    provider_id: str,
    workspace_id: str,
    secret_id: str,
    version_id: str | None,
    intent: str | None,
    caller_subject: str,
    correlation_id: str,
    outcome: str,
    code: str,
) -> None:
    try:
        audit_store.append(
            audit_record(
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=version_id,
                intent=intent,
                caller_subject=caller_subject,
                correlation_id=correlation_id,
                outcome=outcome,
                code=code,
            )
        )
    except AuditUnavailable as exc:
        raise _error(503, "unavailable", "audit-unavailable") from exc


def _error(status_code: int, outcome: str, code: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"outcome": outcome, "code": code},
    )
