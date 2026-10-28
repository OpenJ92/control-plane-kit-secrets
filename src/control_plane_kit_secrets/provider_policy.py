from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable
from uuid import uuid4

from .auth import ProviderCredential


SCHEMA_VERSION = 2
INTENT_KEY_NONE = "<none>"
ALLOWED_SECRET_USE_INTENTS = frozenset(
    {
        "application.control-token",
        "cloudflare.api-token",
        "cloudflare.tunnel-token",
        "docker.local-socket-access-marker",
        "docker.remote-tls.ca-certificate",
        "docker.remote-tls.client-certificate",
        "docker.remote-tls.client-key",
        "gateway.probe-signing-key",
        "gateway.node-control-transit-signing-key",
        "gateway.node-health-read-transit-signing-key",
        "oci.pull-credential",
        "postgres.password",
        "secrets.custody-root-key",
        "secrets.provider-credentials-document",
        "workload.node-control-signing-key",
        "workload.node-health-read-signing-key",
    }
)
_INTENT_ACTIONS = frozenset(
    {"secret.write", "secret.generate-delegation-key", "secret.rotate", "secret.resolve"}
)
_INTENTLESS_ACTIONS = frozenset({"secret.revoke", "secret.metadata"})
_DELEGATION_INTENTS = frozenset(
    intent for intent in ALLOWED_SECRET_USE_INTENTS if "signing-key" in intent
)


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS provider_grants (
        grant_id TEXT PRIMARY KEY,
        provider_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        workspace_id TEXT NOT NULL,
        action TEXT NOT NULL,
        intent TEXT,
        intent_key TEXT NOT NULL,
        origin TEXT NOT NULL CHECK (origin IN ('seed', 'command')),
        granted_by TEXT NOT NULL,
        grant_correlation_id TEXT NOT NULL,
        granted_at TEXT NOT NULL,
        revoked_by TEXT,
        revoke_correlation_id TEXT,
        revoked_at TEXT,
        CHECK (
            (intent IS NULL AND intent_key = '<none>')
            OR (intent IS NOT NULL AND intent_key = intent)
        ),
        CHECK (
            (revoked_by IS NULL AND revoke_correlation_id IS NULL AND revoked_at IS NULL)
            OR (revoked_by IS NOT NULL AND revoke_correlation_id IS NOT NULL AND revoked_at IS NOT NULL)
        )
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_grants_active_tuple
    ON provider_grants (provider_id, subject, workspace_id, action, intent_key)
    WHERE revoked_at IS NULL
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_provider_grants_subject
    ON provider_grants (provider_id, subject, workspace_id, action, intent_key)
    """,
    """
    CREATE TABLE IF NOT EXISTS provider_policy_events (
        event_id TEXT PRIMARY KEY,
        provider_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        workspace_id TEXT NOT NULL,
        action TEXT NOT NULL,
        intent TEXT,
        event_kind TEXT NOT NULL CHECK (event_kind IN ('seed', 'grant', 'revoke')),
        actor TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        code TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        FOREIGN KEY (grant_id) REFERENCES provider_grants (grant_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_provider_policy_events_subject
    ON provider_policy_events (provider_id, subject, occurred_at, event_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS provider_policy_seed (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        provider_id TEXT NOT NULL,
        seed_digest TEXT NOT NULL,
        applied_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL CHECK (schema_version = 2)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS provider_policy_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        provider_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS provider_policy_commands (
        provider_id TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        operation TEXT NOT NULL CHECK (operation IN ('grant', 'revoke')),
        request_digest TEXT NOT NULL,
        subject TEXT NOT NULL,
        workspace_id TEXT NOT NULL,
        action TEXT NOT NULL,
        intent TEXT,
        intent_key TEXT NOT NULL,
        expected_revision INTEGER NOT NULL CHECK (expected_revision >= 0),
        outcome TEXT NOT NULL,
        code TEXT NOT NULL,
        grant_id TEXT,
        resulting_revision INTEGER NOT NULL CHECK (resulting_revision >= 0),
        actor TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        PRIMARY KEY (provider_id, correlation_id),
        CHECK (
            (intent IS NULL AND intent_key = '<none>')
            OR (intent IS NOT NULL AND intent_key = intent)
        )
    )
    """,
)


class ProviderPolicySeedRejected(Exception):
    pass


@dataclass(frozen=True, order=True)
class PolicySeedGrant:
    subject: str
    workspace_id: str
    action: str
    intent: str | None

    def descriptor(self) -> list[str | None]:
        return [self.subject, self.workspace_id, self.action, self.intent]


def initialize_policy_in_transaction(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA_STATEMENTS:
        connection.execute(statement)


def seed_policy_in_transaction(
    connection: sqlite3.Connection,
    *,
    provider_id: str,
    credentials: tuple[ProviderCredential, ...],
) -> None:
    grants = _canonical_seed(credentials)
    applied_at = datetime.now(tz=UTC).isoformat(timespec="microseconds")
    digest = _seed_digest(provider_id, grants)
    for grant in grants:
        grant_id = _grant_id(provider_id, grant)
        connection.execute(
            """
            INSERT INTO provider_grants (
                grant_id, provider_id, subject, workspace_id, action, intent,
                intent_key, origin, granted_by, grant_correlation_id, granted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'seed', 'bootstrap', 'initial-seed', ?)
            """,
            (
                grant_id,
                provider_id,
                grant.subject,
                grant.workspace_id,
                grant.action,
                grant.intent,
                grant.intent if grant.intent is not None else INTENT_KEY_NONE,
                applied_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO provider_policy_events (
                event_id, provider_id, grant_id, subject, workspace_id, action,
                intent, event_kind, actor, correlation_id, outcome, code, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'seed', 'bootstrap', 'initial-seed',
                      'seeded', 'provider-policy-seeded', ?)
            """,
            (
                str(uuid4()), provider_id, grant_id, grant.subject,
                grant.workspace_id, grant.action, grant.intent, applied_at,
            ),
        )
    connection.execute(
        "INSERT INTO provider_policy_seed VALUES (?, ?, ?, ?, ?)",
        (1, provider_id, digest, applied_at, SCHEMA_VERSION),
    )
    connection.execute(
        "INSERT INTO provider_policy_state VALUES (?, ?, ?)",
        (1, provider_id, 1),
    )


def verify_policy_seed(connection: sqlite3.Connection, *, provider_id: str) -> None:
    marker = connection.execute(
        "SELECT singleton, provider_id, seed_digest, applied_at, schema_version "
        "FROM provider_policy_seed"
    ).fetchall()
    state = connection.execute(
        "SELECT singleton, provider_id, revision FROM provider_policy_state"
    ).fetchall()
    if (
        len(marker) != 1
        or marker[0][0] != 1
        or marker[0][1] != provider_id
        or not _digest_text(marker[0][2])
        or not isinstance(marker[0][3], str)
        or not marker[0][3]
        or marker[0][4] != SCHEMA_VERSION
        or len(state) != 1
        or state[0][0] != 1
        or state[0][1] != provider_id
        or type(state[0][2]) is not int
        or state[0][2] < 1
    ):
        raise ProviderPolicySeedRejected()
    rows = connection.execute(
        "SELECT subject, workspace_id, action, intent FROM provider_grants "
        "WHERE provider_id = ? AND origin = 'seed' "
        "ORDER BY subject, workspace_id, action, intent_key",
        (provider_id,),
    ).fetchall()
    try:
        grants = tuple(
            PolicySeedGrant(str(subject), str(workspace), str(action), intent)
            for subject, workspace, action, intent in rows
        )
    except (TypeError, ValueError):
        raise ProviderPolicySeedRejected() from None
    if marker[0][2] != _seed_digest(provider_id, grants):
        raise ProviderPolicySeedRejected()


def _canonical_seed(
    credentials: tuple[ProviderCredential, ...],
) -> tuple[PolicySeedGrant, ...]:
    if not isinstance(credentials, tuple) or not all(
        isinstance(credential, ProviderCredential) for credential in credentials
    ):
        raise ProviderPolicySeedRejected()
    by_subject: dict[str, frozenset[PolicySeedGrant]] = {}
    for credential in credentials:
        _bounded_text(credential.subject)
        exact: set[PolicySeedGrant] = set()
        for grant in credential.grants:
            _bounded_text(grant.action)
            _bounded_text(grant.workspace_id)
            if grant.workspace_id == "*" or grant.action == "*":
                raise ProviderPolicySeedRejected()
            if grant.action in _INTENTLESS_ACTIONS:
                if grant.intents:
                    raise ProviderPolicySeedRejected()
                exact.add(PolicySeedGrant(
                    credential.subject, grant.workspace_id, grant.action, None
                ))
            elif grant.action in _INTENT_ACTIONS:
                if not grant.intents:
                    raise ProviderPolicySeedRejected()
                for intent in grant.intents:
                    _bounded_text(intent)
                    permitted = (
                        _DELEGATION_INTENTS
                        if grant.action == "secret.generate-delegation-key"
                        else ALLOWED_SECRET_USE_INTENTS
                    )
                    if intent == "*" or intent not in permitted:
                        raise ProviderPolicySeedRejected()
                    exact.add(PolicySeedGrant(
                        credential.subject, grant.workspace_id, grant.action, intent
                    ))
            else:
                raise ProviderPolicySeedRejected()
        frozen = frozenset(exact)
        prior = by_subject.setdefault(credential.subject, frozen)
        if prior != frozen:
            raise ProviderPolicySeedRejected()
    return tuple(sorted(grant for grants in by_subject.values() for grant in grants))


def _seed_digest(provider_id: str, grants: Iterable[PolicySeedGrant]) -> str:
    document = json.dumps(
        [
            "cpk-secrets-provider-policy-seed",
            SCHEMA_VERSION,
            provider_id,
            [grant.descriptor() for grant in grants],
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(document).hexdigest()


def _grant_id(provider_id: str, grant: PolicySeedGrant) -> str:
    document = json.dumps(
        ["cpk-secrets-provider-policy-grant", provider_id, grant.descriptor()],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "seed-" + hashlib.sha256(document).hexdigest()


def _bounded_text(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ProviderPolicySeedRejected()


def _digest_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
