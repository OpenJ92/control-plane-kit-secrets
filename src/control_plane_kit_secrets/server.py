from __future__ import annotations

import json
import os
from typing import Any, Mapping

from .api import create_app
from .audit import SqliteAuditStore
from .auth import ProviderCredential, ProviderGrant
from .crypto import load_master_key_from_environment
from .store import EncryptedSecretStore


class ProviderConfigurationError(Exception):
    def __init__(self) -> None:
        super().__init__("secret provider configuration is invalid")


def app_from_environment(environment: Mapping[str, str] | None = None) -> object:
    source = os.environ if environment is None else environment
    database_path = source.get("CPK_SECRETS_DATABASE_PATH")
    provider_id = source.get("CPK_SECRETS_PROVIDER_ID", "local-dev-provider")
    credentials_json = source.get("CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON")
    if not database_path or not credentials_json:
        raise ProviderConfigurationError()

    master_key = load_master_key_from_environment(source)
    store = EncryptedSecretStore(database_path, master_key=master_key)
    store.initialize()
    audit_store = SqliteAuditStore(database_path)
    audit_store.initialize()
    return create_app(
        store=store,
        audit_store=audit_store,
        credentials=_credentials_from_json(credentials_json),
        provider_id=provider_id,
    )


def _credentials_from_json(payload: str) -> tuple[ProviderCredential, ...]:
    try:
        decoded = json.loads(payload)
        if not isinstance(decoded, list):
            raise ValueError
        return tuple(_credential_from_mapping(item) for item in decoded)
    except Exception as exc:
        raise ProviderConfigurationError() from exc


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


app = app_from_environment()
