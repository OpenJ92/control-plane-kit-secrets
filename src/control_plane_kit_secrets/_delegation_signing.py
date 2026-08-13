"""Provider-local admission for delegation signing-key families."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from .models import SecretMetadataInvalid


GATEWAY_DELEGATION_PURPOSE = "gateway-probe"
GATEWAY_SIGNING_INTENT = "gateway.probe-signing-key"

_DELEGATION_SIGNING_INTENTS: Mapping[str, str] = MappingProxyType(
    {
        GATEWAY_DELEGATION_PURPOSE: GATEWAY_SIGNING_INTENT,
        "gateway-node-control-transit": (
            "gateway.node-control-transit-signing-key"
        ),
        "workload-node-control": "workload.node-control-signing-key",
    }
)


def delegation_signing_intent_for(purpose: object) -> str:
    """Return the one admitted provider intent for a delegation purpose."""

    if type(purpose) is not str or purpose not in _DELEGATION_SIGNING_INTENTS:
        raise SecretMetadataInvalid()
    return _DELEGATION_SIGNING_INTENTS[purpose]


def require_delegation_signing_family(purpose: object, intent: object) -> str:
    """Require an exact admitted purpose/intent pair and return its intent."""

    admitted_intent = delegation_signing_intent_for(purpose)
    if type(intent) is not str or intent != admitted_intent:
        raise SecretMetadataInvalid()
    return admitted_intent
