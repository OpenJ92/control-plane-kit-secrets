from __future__ import annotations

from dataclasses import dataclass, field
from hmac import compare_digest


class ProviderAuthenticationError(Exception):
    def __init__(self) -> None:
        super().__init__("provider client is not authenticated")


@dataclass(frozen=True)
class ProviderGrant:
    action: str
    workspace_id: str
    intents: tuple[str, ...] = ("*",)

@dataclass(frozen=True, repr=False)
class ProviderCredential:
    subject: str
    token: str = field(repr=False)
    grants: tuple[ProviderGrant, ...] = ()
    capabilities: tuple[str, ...] = ()


class ProviderAuthorizer:
    def __init__(self, credentials: tuple[ProviderCredential, ...]) -> None:
        self._credentials = credentials

    def authenticate(self, authorization: str | None) -> ProviderCredential:
        if not authorization or not authorization.startswith("Bearer "):
            raise ProviderAuthenticationError()
        presented = authorization.removeprefix("Bearer ").strip()
        for credential in self._credentials:
            if compare_digest(credential.token, presented):
                return credential
        raise ProviderAuthenticationError()
