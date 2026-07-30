from __future__ import annotations

import base64
import binascii
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .bootstrap_files import (
    ProtectedBootstrapFileError,
    read_protected_bootstrap_file,
)


MASTER_KEY_BYTES = 32
ALGORITHM = "AES-256-GCM"
MAXIMUM_MASTER_KEY_FILE_BYTES = 4096


class SecretCryptoError(Exception):
    """Bounded crypto failure without secret-bearing details."""


@dataclass(frozen=True, repr=False)
class MasterKey:
    _key: bytes
    version: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()[:24]

    def encrypt(self, *, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return AESGCM(self._key).encrypt(nonce, plaintext, aad)

    def decrypt(self, *, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:  # pragma: no cover - library-specific subclasses vary.
            raise SecretCryptoError("secret material could not be decrypted") from exc


def load_master_key_file(path: str | Path, *, version: str = "local") -> MasterKey:
    encoded = Path(path).read_text(encoding="utf-8").strip()
    return _master_key_from_encoded(encoded, version=version)


def _master_key_from_encoded(encoded: str, *, version: str) -> MasterKey:
    try:
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise SecretCryptoError("invalid master key file") from exc
    if len(key) != MASTER_KEY_BYTES:
        raise SecretCryptoError("invalid master key file")
    return MasterKey(_key=key, version=version)


def load_master_key_from_environment(
    environment: Mapping[str, str] | None = None,
    *,
    variable: str = "CPK_SECRETS_MASTER_KEY_FILE",
    version: str = "local",
) -> MasterKey:
    source = os.environ if environment is None else environment
    path = source.get(variable)
    if not path:
        raise SecretCryptoError("master key file is not configured")
    try:
        encoded = read_protected_bootstrap_file(
            path,
            maximum_bytes=MAXIMUM_MASTER_KEY_FILE_BYTES,
        ).decode("utf-8").strip()
    except (ProtectedBootstrapFileError, UnicodeDecodeError) as exc:
        raise SecretCryptoError("invalid master key file") from exc
    return _master_key_from_encoded(encoded, version=version)


def encode_master_key_for_file(key: bytes) -> str:
    if len(key) != MASTER_KEY_BYTES:
        raise SecretCryptoError("invalid master key")
    return base64.urlsafe_b64encode(key).decode("ascii")
