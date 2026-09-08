from __future__ import annotations

import os
from typing import Mapping

from .api import create_app
from .bootstrap import ProviderConfigurationError, load_provider_credentials
from .crypto import SecretCryptoError, load_master_key_from_environment
from .custody import admit_provider_custody


def app_from_environment(environment: Mapping[str, str] | None = None) -> object:
    source = os.environ if environment is None else environment
    database_path = source.get("CPK_SECRETS_DATABASE_PATH")
    provider_id = source.get("CPK_SECRETS_PROVIDER_ID", "local-dev-provider")
    if not database_path:
        raise ProviderConfigurationError()

    try:
        master_key = load_master_key_from_environment(source)
        credentials = load_provider_credentials(source)
    except (SecretCryptoError, ProviderConfigurationError):
        raise ProviderConfigurationError() from None
    store, audit_store = admit_provider_custody(
        database_path, master_key=master_key, provider_id=provider_id
    )
    return create_app(
        store=store,
        audit_store=audit_store,
        credentials=credentials,
        provider_id=provider_id,
    )


app = app_from_environment()
