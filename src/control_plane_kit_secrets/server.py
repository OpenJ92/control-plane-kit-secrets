from __future__ import annotations

import os
from typing import Mapping

from .api import create_app
from .bootstrap import ProviderConfigurationError, load_provider_credentials
from .crypto import SecretCryptoError, load_master_key_from_environment
from .custody import admit_provider_custody
from .control import read_secrets_control_configuration


def app_from_environment(environment: Mapping[str, str] | None = None) -> object:
    source = os.environ if environment is None else environment
    database_path = source.get("CPK_SECRETS_DATABASE_PATH")
    provider_id = source.get("CPK_SECRETS_PROVIDER_ID", "local-dev-provider")
    if not database_path:
        raise ProviderConfigurationError()

    control = read_secrets_control_configuration(source)

    def initialize_provider():
        try:
            master_key = load_master_key_from_environment(source)
            credentials = load_provider_credentials(source)
        except (SecretCryptoError, ProviderConfigurationError):
            raise ProviderConfigurationError() from None
        store, audit_store = admit_provider_custody(
            database_path, master_key=master_key, provider_id=provider_id
        )
        return store, audit_store, credentials

    return create_app(
        control=control,
        initialize_provider=initialize_provider,
        provider_id=provider_id,
    )


app = app_from_environment()
