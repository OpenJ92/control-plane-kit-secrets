from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecretsBoundary:
    package: str
    owns_encrypted_custody: bool
    owns_provider_local_audit: bool
    owns_operations_uow: bool
    owns_runtime_interpreters: bool
    owns_server_process: bool
    owns_product_descriptors: bool


SECRETS_BOUNDARY = SecretsBoundary(
    package="control-plane-kit-secrets",
    owns_encrypted_custody=True,
    owns_provider_local_audit=True,
    owns_operations_uow=False,
    owns_runtime_interpreters=False,
    owns_server_process=False,
    owns_product_descriptors=False,
)
