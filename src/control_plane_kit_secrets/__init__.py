"""Package boundary markers for control-plane-kit-secrets."""

from __future__ import annotations

from .boundaries import SECRETS_BOUNDARY, SecretsBoundary

PACKAGE_NAME = "control-plane-kit-secrets"

__all__ = [
    "PACKAGE_NAME",
    "SECRETS_BOUNDARY",
    "SecretsBoundary",
]
