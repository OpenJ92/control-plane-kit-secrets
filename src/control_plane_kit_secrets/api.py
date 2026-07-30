from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .auth import (
    ProviderAuthenticationError,
    ProviderAuthorizer,
    ProviderCredential,
    SecretUseDenied,
)
from .models import (
    SecretAlreadyExists,
    SecretMetadata,
    SecretMetadataInvalid,
    SecretMissing,
    SecretRevoked,
    SecretTampered,
)
from .store import EncryptedSecretStore


MAX_SECRET_BYTES = 64 * 1024
MAX_CORRELATION_CHARS = 128
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
    labels: dict[str, str] = Field(default_factory=dict)


class SecretRotateRequest(BaseModel):
    value_base64: str = Field(min_length=1)
    labels: dict[str, str] = Field(default_factory=dict)


class SecretResolveRequest(BaseModel):
    intent: str
    caller_subject: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=MAX_CORRELATION_CHARS)
    version_id: str | None = None


def create_app(
    *,
    store: EncryptedSecretStore,
    credentials: tuple[ProviderCredential, ...],
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
        _require(authorizer, client, action="secret.write", workspace_id=workspace_id)
        value = _decode_secret_value(request.value_base64)
        try:
            return {
                "outcome": "stored",
                "metadata": _metadata_response(
                    store.create_secret(
                        workspace_id=workspace_id,
                        secret_id=secret_id,
                        value=value,
                        labels=request.labels,
                    )
                ),
            }
        except SecretMetadataInvalid as exc:
            raise _error(400, "malformed", "invalid-metadata") from exc
        except SecretAlreadyExists as exc:
            raise _error(409, "already-exists", "secret-already-exists") from exc

    @app.post("/v1/workspaces/{workspace_id}/secrets/{secret_id}/rotate")
    def rotate_secret(
        workspace_id: str,
        secret_id: str,
        request: SecretRotateRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require(authorizer, client, action="secret.rotate", workspace_id=workspace_id)
        value = _decode_secret_value(request.value_base64)
        try:
            metadata = store.rotate_secret(
                workspace_id=workspace_id,
                secret_id=secret_id,
                value=value,
                labels=request.labels,
            )
            return {"outcome": "rotated", "metadata": _metadata_response(metadata)}
        except SecretMissing as exc:
            raise _error(404, "missing", "secret-missing") from exc
        except SecretMetadataInvalid as exc:
            raise _error(400, "malformed", "invalid-metadata") from exc
        except SecretAlreadyExists as exc:
            raise _error(409, "already-exists", "secret-version-conflict") from exc

    @app.post("/v1/workspaces/{workspace_id}/secrets/{secret_id}/resolve")
    def resolve_secret(
        workspace_id: str,
        secret_id: str,
        request: SecretResolveRequest,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _validate_intent(request.intent)
        _require(
            authorizer,
            client,
            action="secret.resolve",
            workspace_id=workspace_id,
            intent=request.intent,
        )
        try:
            resolved = store.resolve_secret(
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=request.version_id,
            )
            return {
                "outcome": "resolved",
                "metadata": _metadata_response(resolved.metadata),
                "value_base64": base64.b64encode(resolved.value).decode("ascii"),
            }
        except SecretMissing as exc:
            raise _error(404, "missing", "secret-missing") from exc
        except SecretRevoked as exc:
            raise _error(409, "revoked", "secret-revoked") from exc
        except SecretTampered as exc:
            raise _error(503, "unavailable", "integrity-failure") from exc

    @app.post("/v1/workspaces/{workspace_id}/secrets/{secret_id}/revoke")
    def revoke_secret(
        workspace_id: str,
        secret_id: str,
        client: ProviderCredential = Depends(credential),
    ) -> dict[str, Any]:
        _require(authorizer, client, action="secret.revoke", workspace_id=workspace_id)
        try:
            revoked = store.revoke_secret(workspace_id=workspace_id, secret_id=secret_id)
            return {
                "outcome": "revoked",
                "metadata": [_metadata_response(metadata) for metadata in revoked],
            }
        except SecretMissing as exc:
            raise _error(404, "missing", "secret-missing") from exc
        except SecretTampered as exc:
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
            return {"outcome": "metadata", "metadata": _metadata_response(metadata)}
        except SecretMissing as exc:
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


def _error(status_code: int, outcome: str, code: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"outcome": outcome, "code": code},
    )
