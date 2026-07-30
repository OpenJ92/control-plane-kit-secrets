from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from .auth import ProviderCredential, ProviderGrant


_MAXIMUM_CREDENTIAL_FILE_BYTES = 64 * 1024


class ProviderConfigurationError(Exception):
    def __init__(self) -> None:
        super().__init__("secret provider configuration is invalid")


def load_provider_credentials(
    environment: Mapping[str, str],
) -> tuple[ProviderCredential, ...]:
    credentials_file = environment.get("CPK_SECRETS_CREDENTIALS_FILE")
    development_json = environment.get(
        "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON"
    )
    if bool(credentials_file) == bool(development_json):
        raise ProviderConfigurationError()
    if credentials_file is not None:
        return _credentials_from_file(credentials_file)
    assert development_json is not None
    return _credentials_from_json(development_json)


def _credentials_from_file(path_value: str) -> tuple[ProviderCredential, ...]:
    descriptor: int | None = None
    try:
        path = Path(path_value)
        if not path.is_absolute():
            raise ValueError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= _MAXIMUM_CREDENTIAL_FILE_BYTES
        ):
            raise ValueError
        chunks: list[bytes] = []
        remaining = _MAXIMUM_CREDENTIAL_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise ValueError
        return _credentials_from_json(payload.decode("utf-8"))
    except Exception as exc:
        raise ProviderConfigurationError() from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _credentials_from_json(payload: str) -> tuple[ProviderCredential, ...]:
    try:
        decoded = json.loads(payload, object_pairs_hook=_unique_object)
        if not isinstance(decoded, list):
            raise ValueError
        return tuple(_credential_from_mapping(item) for item in decoded)
    except Exception as exc:
        raise ProviderConfigurationError() from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError
        decoded[key] = value
    return decoded


def _credential_from_mapping(item: Any) -> ProviderCredential:
    if not isinstance(item, dict):
        raise ValueError
    grants = item.get("grants", [])
    if not isinstance(grants, list):
        raise ValueError
    return ProviderCredential(
        subject=str(item["subject"]),
        token=str(item["token"]),
        grants=tuple(_grant_from_mapping(grant) for grant in grants),
    )


def _grant_from_mapping(item: Any) -> ProviderGrant:
    if not isinstance(item, dict):
        raise ValueError
    intents = item.get("intents", ["*"])
    if not isinstance(intents, list):
        raise ValueError
    return ProviderGrant(
        action=str(item["action"]),
        workspace_id=str(item["workspace_id"]),
        intents=tuple(str(intent) for intent in intents),
    )
