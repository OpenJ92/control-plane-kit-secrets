from __future__ import annotations

from dataclasses import dataclass, field
from hmac import compare_digest


class ProviderAuthenticationError(Exception):
    def __init__(self) -> None:
        super().__init__("provider client is not authenticated")


class SecretUseDenied(Exception):
    def __init__(self) -> None:
        super().__init__("secret use is denied")


@dataclass(frozen=True)
class ProviderGrant:
    action: str
    workspace_id: str
    intents: tuple[str, ...] = ("*",)

    def permits(self, *, action: str, workspace_id: str, intent: str | None) -> bool:
        if self.action != action:
            return False
        if self.workspace_id not in ("*", workspace_id):
            return False
        if intent is None:
            return True
        return "*" in self.intents or intent in self.intents


@dataclass(frozen=True, repr=False)
class ProviderCredential:
    subject: str
    token: str = field(repr=False)
    grants: tuple[ProviderGrant, ...] = ()


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

    def require(
        self,
        credential: ProviderCredential,
        *,
        action: str,
        workspace_id: str,
        intent: str | None = None,
    ) -> None:
        for grant in credential.grants:
            if grant.permits(action=action, workspace_id=workspace_id, intent=intent):
                return
        raise SecretUseDenied()
