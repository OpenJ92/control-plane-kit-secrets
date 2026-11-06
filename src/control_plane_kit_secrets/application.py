"""Import-safe environment composition; no app or private work at import time."""
from __future__ import annotations

import os
from typing import Callable, Mapping

from .api import create_app
from . import bootstrap, crypto
from .bootstrap import ProviderConfigurationError
from .crypto import SecretCryptoError
from .custody import admit_provider_custody
from .provider_policy import ProviderPolicyStore
from .control import (
    ReceiverNodeControlConfiguration, HttpVerificationSampleReceiverBinding,
    HTTP_VERIFICATION_SAMPLES_CONFIGURATION_ENVIRONMENT,
    read_secrets_control_configuration, require_secrets_control_configuration,
)


def app_from_environment(
    environment: Mapping[str, str] | None = None, *,
    control: ReceiverNodeControlConfiguration | None = None,
    http_verification_binding: HttpVerificationSampleReceiverBinding | None = None,
    clock: Callable[[], int] | None = None,
    http_sample_clock: Callable[[], float] | None = None,
) -> object:
    """Compose one provider; callers may supply one independent public snapshot."""
    source = os.environ if environment is None else environment
    companion = HTTP_VERIFICATION_SAMPLES_CONFIGURATION_ENVIRONMENT
    if environment is not None and (
        (companion in source) != (companion in os.environ)
        or source.get(companion) != os.environ.get(companion)
    ):
        # SDK owns the single companion reader and uses process environment.
        # An explicit mapping must not hide or redirect that delivered opt-in.
        raise ProviderConfigurationError()
    database_path = source.get("CPK_SECRETS_DATABASE_PATH")
    provider_id = source.get("CPK_SECRETS_PROVIDER_ID", "local-dev-provider")
    if not database_path:
        raise ProviderConfigurationError()

    control = (read_secrets_control_configuration(source) if control is None else
               require_secrets_control_configuration(control))

    def initialize_provider():
        try:
            master_key = crypto.load_master_key_from_environment(source)
            credentials = bootstrap.load_provider_credentials(source)
        except (SecretCryptoError, ProviderConfigurationError):
            raise ProviderConfigurationError() from None
        store, audit_store = admit_provider_custody(
            database_path,
            master_key=master_key,
            provider_id=provider_id,
            credentials=credentials,
        )
        return (
            store,
            audit_store,
            credentials,
            ProviderPolicyStore(database_path, provider_id=provider_id),
        )

    options = {} if clock is None else {"clock": clock}
    return create_app(
        control=control,
        initialize_provider=initialize_provider,
        provider_id=provider_id,
        http_verification_binding=http_verification_binding,
        http_sample_clock=http_sample_clock,
        **options,
    )


__all__ = ["app_from_environment"]
