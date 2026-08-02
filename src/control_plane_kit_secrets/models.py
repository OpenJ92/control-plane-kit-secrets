from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


class SecretStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class SecretStoreError(Exception):
    """Bounded storage failure without secret-bearing details."""


class SecretMissing(SecretStoreError):
    def __init__(self) -> None:
        super().__init__("secret reference is missing")


class SecretAlreadyExists(SecretStoreError):
    def __init__(self) -> None:
        super().__init__("secret reference already exists")


class SecretResolutionConflict(SecretStoreError):
    def __init__(self) -> None:
        super().__init__("secret resolution correlation conflicts with prior use")


class DelegationKeyGenerationConflict(SecretStoreError):
    def __init__(self) -> None:
        super().__init__(
            "delegation key generation correlation conflicts with prior use"
        )


class SecretIntentMismatch(SecretStoreError):
    def __init__(self) -> None:
        super().__init__("secret intent does not match durable metadata")


class SecretRevoked(SecretStoreError):
    def __init__(self) -> None:
        super().__init__("secret reference is revoked")


class SecretTampered(SecretStoreError):
    def __init__(self) -> None:
        super().__init__("secret record failed integrity verification")


class SecretMetadataInvalid(SecretStoreError):
    def __init__(self) -> None:
        super().__init__("secret metadata is invalid")


@dataclass(frozen=True)
class SecretMetadata:
    workspace_id: str
    secret_id: str
    version_id: str
    version_number: int
    status: SecretStatus
    algorithm: str
    key_fingerprint: str
    key_version: str
    labels: Mapping[str, str]
    created_at: str
    revoked_at: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "labels", MappingProxyType(dict(self.labels)))


@dataclass(frozen=True, repr=False)
class ResolvedSecret:
    metadata: SecretMetadata
    _value: bytes

    @property
    def value(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return (
            "ResolvedSecret("
            f"workspace_id={self.metadata.workspace_id!r}, "
            f"secret_id={self.metadata.secret_id!r}, "
            f"version_id={self.metadata.version_id!r}, "
            "value=<redacted>)"
        )


@dataclass(frozen=True)
class GeneratedDelegationKey:
    """Public generation result; private material remains in encrypted custody."""

    metadata: SecretMetadata
    secret_reference: str
    purpose: str
    issuer: str
    correlation_id: str
    key_id: str
    algorithm: str
    public_key_pem: str
    replayed: bool = False
