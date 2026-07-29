"""Package boundary markers for control-plane-kit-secrets.

#1165 intentionally exposes only lightweight ownership facts. Secret storage,
provider APIs, audit records, and encryption are introduced by later issues.
"""

from __future__ import annotations

from .boundaries import SECRETS_BOUNDARY, SecretsBoundary

PACKAGE_NAME = "control-plane-kit-secrets"

__all__ = [
    "PACKAGE_NAME",
    "SECRETS_BOUNDARY",
    "SecretsBoundary",
]
