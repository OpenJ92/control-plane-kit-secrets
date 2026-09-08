from __future__ import annotations

import json
from typing import Any, Mapping

from .auth import ProviderCredential, ProviderGrant
from .bootstrap_files import (
    ProtectedBootstrapFileError,
    read_protected_bootstrap_file,
)


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
    try:
        payload = read_protected_bootstrap_file(
            path_value,
            maximum_bytes=_MAXIMUM_CREDENTIAL_FILE_BYTES,
        )
        return _credentials_from_json(payload.decode("utf-8"))
    except (ProtectedBootstrapFileError, UnicodeDecodeError):
        raise ProviderConfigurationError() from None


def _credentials_from_json(payload: str) -> tuple[ProviderCredential, ...]:
    try:
        if len(payload.encode("utf-8")) > _MAXIMUM_CREDENTIAL_FILE_BYTES:
            raise ValueError
        decoded = json.loads(payload, object_pairs_hook=_unique_object)
        if not isinstance(decoded, list):
            raise ValueError
        credentials = tuple(_credential_from_mapping(item) for item in decoded)
        if len({credential.token for credential in credentials}) != len(credentials):
            raise ValueError
        return credentials
    except Exception:
        raise ProviderConfigurationError() from None


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
    if item.keys() - {"subject", "token", "grants"}:
        raise ValueError
    grants = item.get("grants", [])
    if not isinstance(grants, list):
        raise ValueError
    token = _text(item["token"])
    if not token.isascii() or token != token.strip():
        raise ValueError
    return ProviderCredential(
        subject=_text(item["subject"]),
        token=token,
        grants=tuple(_grant_from_mapping(grant) for grant in grants),
    )


def _grant_from_mapping(item: Any) -> ProviderGrant:
    if not isinstance(item, dict):
        raise ValueError
    if item.keys() - {"action", "workspace_id", "intents"}:
        raise ValueError
    intents = item.get("intents", ["*"])
    if not isinstance(intents, list):
        raise ValueError
    return ProviderGrant(
        action=_text(item["action"]),
        workspace_id=_text(item["workspace_id"]),
        intents=tuple(_text(intent) for intent in intents),
    )


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError
    return value
