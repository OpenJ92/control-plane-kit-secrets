from __future__ import annotations

import os
from typing import Mapping

from .api import create_app
from .audit import SqliteAuditStore
from .bootstrap import ProviderConfigurationError, load_provider_credentials
from .crypto import load_master_key_from_environment
from .store import EncryptedSecretStore


def app_from_environment(environment: Mapping[str, str] | None = None) -> object:
    source = os.environ if environment is None else environment
    database_path = source.get("CPK_SECRETS_DATABASE_PATH")
    provider_id = source.get("CPK_SECRETS_PROVIDER_ID", "local-dev-provider")
    if not database_path:
        raise ProviderConfigurationError()

    master_key = load_master_key_from_environment(source)
    store = EncryptedSecretStore(database_path, master_key=master_key)
    store.initialize()
    audit_store = SqliteAuditStore(database_path)
    audit_store.initialize()
    return create_app(
        store=store,
        audit_store=audit_store,
        credentials=load_provider_credentials(source),
        provider_id=provider_id,
    )


app = app_from_environment()
