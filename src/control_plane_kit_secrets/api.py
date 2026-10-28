from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import re
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from control_plane_kit_server_sdk.fastapi import install_cpk_wrapper

from .audit import AuditUnavailable, SqliteAuditStore, audit_record
from .auth import (
    ProviderAuthenticationError,
    ProviderAuthorizer,
    ProviderCredential,
)
from ._delegation_signing import delegation_signing_intent_for
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
from .provider_policy import (
    ALLOWED_SECRET_USE_INTENTS,
    PolicyCommandResult,
    PolicyCoordinate,
    PolicyGrantPage,
    PolicyGrantRead,
    ProviderGrantRecord,
    ProviderPolicyConflict,
    ProviderPolicyDenied,
    ProviderPolicyInvalid,
    ProviderPolicyMissing,
    ProviderPolicyStore,
    ProviderPolicyUnavailable,
)
from .store import EncryptedSecretStore
from .control import (
    ReceiverNodeControlConfiguration,
    require_secrets_control_configuration,
)


MAX_SECRET_BYTES = 64 * 1024
MAX_CORRELATION_CHARS = 128
MAX_SECRET_REFERENCE_CHARS = 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_REFERENCE_PROVIDER = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_REFERENCE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
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


class PolicyGrantRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=512)
    workspace_id: str = Field(min_length=1, max_length=512)
    action: str = Field(min_length=1, max_length=512)
    intent: str | None = Field(default=None, max_length=512)
    expected_revision: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=MAX_CORRELATION_CHARS)


class PolicyRevokeRequest(PolicyGrantRequest):
    pass


ProviderInitialization = tuple[
    EncryptedSecretStore,
    SqliteAuditStore,
    tuple[ProviderCredential, ...],
    ProviderPolicyStore,
]
ProviderInitializer = Callable[[], ProviderInitialization]


def create_app(
    *,
    control: ReceiverNodeControlConfiguration,
    initialize_provider: ProviderInitializer,
    provider_id: str = "local-dev-provider",
    clock: Callable[[], int] = lambda: int(time.time()),
) -> FastAPI:
    control = require_secrets_control_configuration(control)
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
                policy_store,
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
        try:
            generation_intent = delegation_signing_intent_for(request.purpose)
        except SecretMetadataInvalid as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=None,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="malformed",
                code="invalid-delegation-key-generation",
            )
            raise _error(
                400,
                "malformed",
                "invalid-delegation-key-generation",
            ) from exc
        if (
            not _IDENTIFIER.fullmatch(request.issuer)
            or not _IDENTIFIER.fullmatch(request.caller_subject)
            or not _valid_secret_reference(request.secret_reference)
        ):
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=generation_intent,
                caller_subject=request.caller_subject,
                correlation_id=request.correlation_id,
                outcome="malformed",
                code="invalid-delegation-key-generation",
            )
            raise _error(400, "malformed", "invalid-delegation-key-generation")
        try:
            _require(
                policy_store,
                client,
                action="secret.generate-delegation-key",
                workspace_id=workspace_id,
                intent=generation_intent,
            )
        except HTTPException as exc:
            _append_audit(
                audit_store,
                provider_id=provider_id,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=None,
                intent=generation_intent,
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
                intent=generation_intent,
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
                intent=generation_intent,
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
                intent=generation_intent,
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
                intent=generation_intent,
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
                intent=generation_intent,
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
                policy_store,
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
                policy_store,
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
        _require(policy_store, client, action="secret.revoke", workspace_id=workspace_id)
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
        _require(policy_store, client, action="secret.revoke", workspace_id=workspace_id)
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
        _require(policy_store, client, action="secret.metadata", workspace_id=workspace_id)
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

    @app.post("/v1/provider-policy/grants")
    def grant_policy(
        request: PolicyGrantRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        coordinate = _policy_coordinate(request)
        _require_policy_admin(
            policy_store, client, event_kind="grant",
            correlation_id=request.correlation_id, coordinate=coordinate,
        )
        try:
            return _policy_command_response(policy_store.grant(
                actor=client.subject,
                correlation_id=request.correlation_id,
                expected_revision=request.expected_revision,
                coordinate=coordinate,
            ))
        except ProviderPolicyInvalid as exc:
            _record_policy_invalid(
                policy_store, client, "grant", request.correlation_id,
                exc.code, coordinate=coordinate,
            )
            raise _error(400, "malformed", exc.code) from exc
        except ProviderPolicyConflict as exc:
            raise _error(409, "conflict", exc.code) from exc
        except ProviderPolicyUnavailable as exc:
            raise _error(503, "unavailable", "provider-policy-unavailable") from exc

    @app.post("/v1/provider-policy/grants/{grant_id}/revoke")
    def revoke_policy(
        grant_id: str,
        request: PolicyRevokeRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        coordinate = _policy_coordinate(request)
        _require_policy_admin(
            policy_store, client, event_kind="revoke",
            correlation_id=request.correlation_id, coordinate=coordinate,
            grant_id=grant_id,
        )
        try:
            return _policy_command_response(policy_store.revoke(
                actor=client.subject,
                correlation_id=request.correlation_id,
                expected_revision=request.expected_revision,
                grant_id=grant_id,
                coordinate=coordinate,
            ))
        except ProviderPolicyInvalid as exc:
            _record_policy_invalid(
                policy_store, client, "revoke", request.correlation_id,
                exc.code, coordinate=coordinate, grant_id=grant_id,
            )
            raise _error(400, "malformed", exc.code) from exc
        except ProviderPolicyConflict as exc:
            raise _error(409, "conflict", exc.code) from exc
        except ProviderPolicyUnavailable as exc:
            raise _error(503, "unavailable", "provider-policy-unavailable") from exc

    @app.get("/v1/provider-policy/grants/{grant_id}")
    def read_policy_grant(
        grant_id: str,
        correlation_id: str = Header(alias="X-Correlation-ID", max_length=MAX_CORRELATION_CHARS),
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require_policy_admin(
            policy_store, client, event_kind="grant-read",
            correlation_id=correlation_id, grant_id=grant_id,
        )
        try:
            return _policy_grant_read_response(policy_store.read_grant(
                actor=client.subject,
                audit_correlation_id=correlation_id,
                grant_id=grant_id,
            ))
        except ProviderPolicyMissing as exc:
            raise _error(404, "missing", exc.code) from exc
        except ProviderPolicyInvalid as exc:
            raise _error(400, "malformed", exc.code) from exc
        except ProviderPolicyUnavailable as exc:
            raise _error(503, "unavailable", "provider-policy-unavailable") from exc

    @app.get("/v1/provider-policy/grants")
    def list_policy_grants(
        correlation_id: str = Header(alias="X-Correlation-ID", max_length=MAX_CORRELATION_CHARS),
        subject: str | None = None,
        workspace_id: str | None = None,
        action: str | None = None,
        intent_mode: str = "any",
        intent: str | None = None,
        limit: int = 100,
        after_grant_id: str | None = None,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require_policy_admin(
            policy_store, client, event_kind="grant-list",
            correlation_id=correlation_id,
        )
        try:
            return _policy_page_response(policy_store.list_current(
                actor=client.subject,
                audit_correlation_id=correlation_id,
                subject=subject,
                workspace_id=workspace_id,
                action=action,
                intent_mode=intent_mode,
                intent=intent,
                limit=limit,
                after_grant_id=after_grant_id,
            ))
        except ProviderPolicyInvalid as exc:
            _record_policy_invalid(
                policy_store, client, "grant-list", correlation_id, exc.code,
            )
            raise _error(400, "malformed", exc.code) from exc
        except ProviderPolicyUnavailable as exc:
            raise _error(503, "unavailable", "provider-policy-unavailable") from exc

    @app.get("/v1/provider-policy/commands/{command_correlation_id}")
    def read_policy_command(
        command_correlation_id: str,
        correlation_id: str = Header(alias="X-Correlation-ID", max_length=MAX_CORRELATION_CHARS),
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require_policy_admin(
            policy_store, client, event_kind="command-read",
            correlation_id=correlation_id,
        )
        try:
            return _policy_command_response(policy_store.read_command(
                actor=client.subject,
                audit_correlation_id=correlation_id,
                command_correlation_id=command_correlation_id,
            ))
        except ProviderPolicyMissing as exc:
            raise _error(404, "missing", exc.code) from exc
        except ProviderPolicyInvalid as exc:
            raise _error(400, "malformed", exc.code) from exc
        except ProviderPolicyUnavailable as exc:
            raise _error(503, "unavailable", "provider-policy-unavailable") from exc

    install_cpk_wrapper(app, configuration=control, clock=clock)
    # Complete host admission precedes the single protected/durable effect.
    # All handler closures are bound before this app can be returned or served.
    store, audit_store, credentials, policy_store = initialize_provider()
    authorizer = ProviderAuthorizer(credentials)
    return app


def _policy_coordinate(request: PolicyGrantRequest) -> PolicyCoordinate:
    return PolicyCoordinate(
        subject=request.subject,
        workspace_id=request.workspace_id,
        action=request.action,
        intent=request.intent,
    )


def _require_policy_admin(
    policy_store: ProviderPolicyStore,
    client: ProviderCredential,
    *,
    event_kind: str,
    correlation_id: str,
    coordinate: PolicyCoordinate | None = None,
    grant_id: str | None = None,
) -> None:
    if "secrets.policy-admin" in client.capabilities:
        return
    try:
        policy_store.record_denial(
            event_kind=event_kind,
            actor=client.subject,
            correlation_id=correlation_id,
            code="policy-admin-required",
            coordinate=coordinate,
            grant_id=grant_id,
        )
    except ProviderPolicyInvalid:
        try:
            policy_store.record_denial(
                event_kind=event_kind,
                actor=client.subject,
                correlation_id=correlation_id,
                code="policy-admin-required",
            )
        except (ProviderPolicyInvalid, ProviderPolicyUnavailable) as exc:
            raise _error(503, "unavailable", "provider-policy-unavailable") from exc
    except ProviderPolicyUnavailable as exc:
        raise _error(503, "unavailable", "provider-policy-unavailable") from exc
    raise _error(403, "denied", "policy-admin-required")


def _record_policy_invalid(
    policy_store: ProviderPolicyStore,
    client: ProviderCredential,
    event_kind: str,
    correlation_id: str,
    code: str,
    *,
    coordinate: PolicyCoordinate | None = None,
    grant_id: str | None = None,
) -> None:
    try:
        policy_store.record_denial(
            event_kind=event_kind,
            actor=client.subject,
            correlation_id=correlation_id,
            code=code,
            outcome="malformed",
            coordinate=coordinate,
            grant_id=grant_id,
        )
    except ProviderPolicyInvalid:
        try:
            policy_store.record_denial(
                event_kind=event_kind,
                actor=client.subject,
                correlation_id=correlation_id,
                code=code,
                outcome="malformed",
            )
        except ProviderPolicyInvalid:
            return
        except ProviderPolicyUnavailable as exc:
            raise _error(503, "unavailable", "provider-policy-unavailable") from exc
    except ProviderPolicyUnavailable as exc:
        raise _error(503, "unavailable", "provider-policy-unavailable") from exc


def _policy_command_response(result: PolicyCommandResult) -> dict[str, Any]:
    return {
        "provider_id": result.provider_id,
        "correlation_id": result.correlation_id,
        "operation": result.operation,
        "subject": result.coordinate.subject,
        "workspace_id": result.coordinate.workspace_id,
        "action": result.coordinate.action,
        "intent": result.coordinate.intent,
        "expected_revision": result.expected_revision,
        "outcome": result.outcome,
        "code": result.code,
        "grant_id": result.grant_id,
        "resulting_revision": result.resulting_revision,
        "actor": result.actor,
        "occurred_at": result.occurred_at,
    }


def _policy_grant_response(grant: ProviderGrantRecord) -> dict[str, Any]:
    return {
        "grant_id": grant.grant_id,
        "provider_id": grant.provider_id,
        "subject": grant.coordinate.subject,
        "workspace_id": grant.coordinate.workspace_id,
        "action": grant.coordinate.action,
        "intent": grant.coordinate.intent,
        "origin": grant.origin,
        "granted_by": grant.granted_by,
        "grant_correlation_id": grant.grant_correlation_id,
        "granted_at": grant.granted_at,
        "revoked_by": grant.revoked_by,
        "revoke_correlation_id": grant.revoke_correlation_id,
        "revoked_at": grant.revoked_at,
    }


def _policy_grant_read_response(result: PolicyGrantRead) -> dict[str, Any]:
    return {"revision": result.revision, "grant": _policy_grant_response(result.grant)}


def _policy_page_response(page: PolicyGrantPage) -> dict[str, Any]:
    return {
        "revision": page.revision,
        "grants": [_policy_grant_response(grant) for grant in page.grants],
        "next_after": page.next_after,
    }


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
    policy_store: ProviderPolicyStore,
    client: ProviderCredential,
    *,
    action: str,
    workspace_id: str,
    intent: str | None = None,
) -> None:
    try:
        policy_store.require_active(PolicyCoordinate(
            subject=client.subject,
            action=action,
            workspace_id=workspace_id,
            intent=intent,
        ))
    except ProviderPolicyDenied as exc:
        raise _error(403, "denied", "insufficient-scope") from exc
    except ProviderPolicyInvalid as exc:
        raise _error(400, "malformed", exc.code) from exc
    except ProviderPolicyUnavailable as exc:
        raise _error(503, "unavailable", "provider-policy-unavailable") from exc


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
