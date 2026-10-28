from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Iterator
from uuid import uuid4

from .auth import ProviderCredential

MAX_POLICY_REVISION = (1 << 63) - 1


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
        grant_id TEXT,
        subject TEXT,
        workspace_id TEXT,
        action TEXT,
        intent TEXT,
        event_kind TEXT NOT NULL CHECK (
            event_kind IN (
                'seed', 'grant', 'revoke', 'grant-read', 'grant-list', 'command-read'
            )
        ),
        actor TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        code TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        FOREIGN KEY (grant_id) REFERENCES provider_grants (grant_id),
        CHECK (
            event_kind != 'seed'
            OR (
                grant_id IS NOT NULL
                AND subject IS NOT NULL
                AND workspace_id IS NOT NULL
                AND action IS NOT NULL
            )
        )
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


class ProviderPolicyInvalid(Exception):
    def __init__(self, code: str = "provider-policy-invalid") -> None:
        self.code = code
        super().__init__("provider policy request is invalid")


class ProviderPolicyDenied(Exception):
    def __init__(self) -> None:
        super().__init__("provider policy denies secret use")


class ProviderPolicyMissing(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("provider policy record is missing")


class ProviderPolicyUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("provider policy is unavailable")


class ProviderPolicyConflict(Exception):
    def __init__(
        self,
        code: str,
        result: PolicyCommandResult | None = None,
    ) -> None:
        self.code = code
        self.result = result
        super().__init__("provider policy command conflicts")


@dataclass(frozen=True, order=True)
class PolicyCoordinate:
    subject: str
    workspace_id: str
    action: str
    intent: str | None

    def descriptor(self) -> list[str | None]:
        return [self.subject, self.workspace_id, self.action, self.intent]


@dataclass(frozen=True)
class ProviderGrantRecord:
    grant_id: str
    provider_id: str
    coordinate: PolicyCoordinate
    origin: str
    granted_by: str
    grant_correlation_id: str
    granted_at: str
    revoked_by: str | None
    revoke_correlation_id: str | None
    revoked_at: str | None


@dataclass(frozen=True)
class PolicyCommandResult:
    provider_id: str
    correlation_id: str
    operation: str
    coordinate: PolicyCoordinate
    expected_revision: int
    outcome: str
    code: str
    grant_id: str | None
    resulting_revision: int
    actor: str
    occurred_at: str


@dataclass(frozen=True)
class PolicyGrantRead:
    revision: int
    grant: ProviderGrantRecord


@dataclass(frozen=True)
class PolicyGrantPage:
    revision: int
    grants: tuple[ProviderGrantRecord, ...]
    next_after: str | None


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


class ProviderPolicyStore:
    def __init__(self, database_path: str | Path, *, provider_id: str) -> None:
        _policy_text(provider_id)
        self._database_path = Path(database_path)
        self._provider_id = provider_id

    def current_revision(self) -> int:
        try:
            with self._connection() as connection:
                return self._revision(connection)
        except sqlite3.Error:
            raise ProviderPolicyUnavailable() from None

    def require_active(self, coordinate: PolicyCoordinate) -> None:
        _validate_coordinate(coordinate)
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT grant_id FROM provider_grants WHERE provider_id = ? "
                    "AND subject = ? AND workspace_id = ? AND action = ? "
                    "AND intent_key = ? AND revoked_at IS NULL",
                    (
                        self._provider_id,
                        coordinate.subject,
                        coordinate.workspace_id,
                        coordinate.action,
                        _intent_key(coordinate.intent),
                    ),
                ).fetchone()
        except sqlite3.Error:
            raise ProviderPolicyUnavailable() from None
        if row is None:
            raise ProviderPolicyDenied()

    def grant(
        self,
        *,
        actor: str,
        correlation_id: str,
        expected_revision: int,
        coordinate: PolicyCoordinate,
    ) -> PolicyCommandResult:
        return self._command(
            operation="grant",
            actor=actor,
            correlation_id=correlation_id,
            expected_revision=expected_revision,
            coordinate=coordinate,
            requested_grant_id=None,
        )

    def revoke(
        self,
        *,
        actor: str,
        correlation_id: str,
        expected_revision: int,
        grant_id: str,
        coordinate: PolicyCoordinate,
    ) -> PolicyCommandResult:
        _policy_text(grant_id)
        return self._command(
            operation="revoke",
            actor=actor,
            correlation_id=correlation_id,
            expected_revision=expected_revision,
            coordinate=coordinate,
            requested_grant_id=grant_id,
        )

    def read_grant(
        self, *, actor: str, audit_correlation_id: str, grant_id: str
    ) -> PolicyGrantRead:
        _policy_text(actor)
        _policy_text(audit_correlation_id)
        _policy_text(grant_id)
        missing = False
        result = None
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                revision = self._revision(connection)
                row = connection.execute(
                    "SELECT * FROM provider_grants WHERE provider_id = ? AND grant_id = ?",
                    (self._provider_id, grant_id),
                ).fetchone()
                missing = row is None
                self._event(
                    connection,
                    event_kind="grant-read",
                    actor=actor,
                    correlation_id=audit_correlation_id,
                    outcome="missing" if missing else "read",
                    code="provider-grant-missing" if missing else "provider-grant-read",
                    grant_id=None if missing else grant_id,
                    coordinate=None if missing else _grant_from_row(row).coordinate,
                )
                if not missing:
                    result = PolicyGrantRead(revision, _grant_from_row(row))
        except sqlite3.Error:
            raise ProviderPolicyUnavailable() from None
        if missing:
            raise ProviderPolicyMissing("provider-grant-missing")
        assert result is not None
        return result

    def list_current(
        self,
        *,
        actor: str,
        audit_correlation_id: str,
        subject: str | None = None,
        workspace_id: str | None = None,
        action: str | None = None,
        intent_mode: str = "any",
        intent: str | None = None,
        limit: int = 100,
        after_grant_id: str | None = None,
    ) -> PolicyGrantPage:
        _policy_text(actor)
        _policy_text(audit_correlation_id)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ProviderPolicyInvalid("provider-policy-limit-invalid")
        for value in (subject, workspace_id, action, after_grant_id):
            if value is not None:
                _policy_text(value)
        if intent_mode not in {"any", "none", "exact"}:
            raise ProviderPolicyInvalid("provider-policy-intent-filter-invalid")
        if intent_mode == "exact":
            if intent is None:
                raise ProviderPolicyInvalid("provider-policy-intent-filter-invalid")
            _policy_text(intent)
            if intent not in ALLOWED_SECRET_USE_INTENTS:
                raise ProviderPolicyInvalid("provider-policy-intent-filter-invalid")
        elif intent is not None:
            raise ProviderPolicyInvalid("provider-policy-intent-filter-invalid")

        clauses = ["provider_id = ?", "revoked_at IS NULL"]
        parameters: list[object] = [self._provider_id]
        for column, value in (
            ("subject", subject), ("workspace_id", workspace_id), ("action", action)
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if intent_mode == "none":
            clauses.append("intent IS NULL")
        elif intent_mode == "exact":
            clauses.append("intent = ?")
            parameters.append(intent)
        if after_grant_id is not None:
            clauses.append("grant_id > ?")
            parameters.append(after_grant_id)
        parameters.append(limit + 1)
        result = None
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                revision = self._revision(connection)
                rows = connection.execute(
                    "SELECT * FROM provider_grants WHERE " + " AND ".join(clauses)
                    + " ORDER BY grant_id LIMIT ?",
                    tuple(parameters),
                ).fetchall()
                has_more = len(rows) > limit
                selected = rows[:limit]
                grants = tuple(_grant_from_row(row) for row in selected)
                next_after = grants[-1].grant_id if has_more and grants else None
                self._event(
                    connection,
                    event_kind="grant-list",
                    actor=actor,
                    correlation_id=audit_correlation_id,
                    outcome="read",
                    code="provider-grants-listed",
                )
                result = PolicyGrantPage(revision, grants, next_after)
        except sqlite3.Error:
            raise ProviderPolicyUnavailable() from None
        assert result is not None
        return result

    def read_command(
        self,
        *,
        actor: str,
        audit_correlation_id: str,
        command_correlation_id: str,
    ) -> PolicyCommandResult:
        _policy_text(actor)
        _policy_text(audit_correlation_id)
        _policy_text(command_correlation_id)
        missing = False
        result = None
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM provider_policy_commands "
                    "WHERE provider_id = ? AND correlation_id = ?",
                    (self._provider_id, command_correlation_id),
                ).fetchone()
                missing = row is None
                self._event(
                    connection,
                    event_kind="command-read",
                    actor=actor,
                    correlation_id=audit_correlation_id,
                    outcome="missing" if missing else "read",
                    code=("provider-policy-command-missing" if missing
                          else "provider-policy-command-read"),
                    grant_id=None,
                    coordinate=None if missing else _coordinate_from_row(row),
                )
                if not missing:
                    result = _command_from_row(row)
        except sqlite3.Error:
            raise ProviderPolicyUnavailable() from None
        if missing:
            raise ProviderPolicyMissing("provider-policy-command-missing")
        assert result is not None
        return result

    def record_denial(
        self,
        *,
        event_kind: str,
        actor: str,
        correlation_id: str,
        code: str,
        outcome: str = "denied",
        coordinate: PolicyCoordinate | None = None,
        grant_id: str | None = None,
    ) -> None:
        if event_kind not in {"grant", "revoke", "grant-read", "grant-list", "command-read"}:
            raise ProviderPolicyInvalid()
        _policy_text(actor)
        _policy_text(correlation_id)
        _policy_text(code)
        if coordinate is not None:
            _validate_coordinate(coordinate)
        if grant_id is not None:
            _policy_text(grant_id)
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._event(
                    connection,
                    event_kind=event_kind,
                    actor=actor,
                    correlation_id=correlation_id,
                    outcome=outcome,
                    code=code,
                    grant_id=None,
                    coordinate=coordinate,
                )
        except sqlite3.Error:
            raise ProviderPolicyUnavailable() from None

    def _command(
        self,
        *,
        operation: str,
        actor: str,
        correlation_id: str,
        expected_revision: int,
        coordinate: PolicyCoordinate,
        requested_grant_id: str | None,
    ) -> PolicyCommandResult:
        _policy_text(actor)
        _policy_text(correlation_id)
        _validate_coordinate(coordinate)
        if (
            type(expected_revision) is not int
            or not 0 <= expected_revision <= MAX_POLICY_REVISION
        ):
            raise ProviderPolicyInvalid("provider-policy-revision-invalid")
        digest = _command_digest(
            provider_id=self._provider_id,
            operation=operation,
            coordinate=coordinate,
            requested_grant_id=requested_grant_id,
            expected_revision=expected_revision,
            actor=actor,
        )
        conflict_code = None
        result = None
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM provider_policy_commands "
                    "WHERE provider_id = ? AND correlation_id = ?",
                    (self._provider_id, correlation_id),
                ).fetchone()
                if existing is not None:
                    result = _command_from_row(existing)
                    if existing["request_digest"] == digest:
                        if result.outcome in {"granted", "revoked"}:
                            return result
                        conflict_code = result.code
                    else:
                        self._event(
                            connection,
                            event_kind=operation,
                            actor=actor,
                            correlation_id=correlation_id,
                            outcome="conflict",
                            code="policy-correlation-conflict",
                            coordinate=coordinate,
                        )
                        conflict_code = "policy-correlation-conflict"
                else:
                    revision = self._revision(connection)
                    if expected_revision != revision:
                        result = self._record_command(
                            connection,
                            operation=operation,
                            correlation_id=correlation_id,
                            digest=digest,
                            coordinate=coordinate,
                            expected_revision=expected_revision,
                            outcome="conflict",
                            code="policy-revision-conflict",
                            grant_id=requested_grant_id,
                            resulting_revision=revision,
                            actor=actor,
                        )
                        conflict_code = result.code
                    elif operation == "grant":
                        active = self._active_row(connection, coordinate)
                        if active is not None:
                            result = self._record_command(
                                connection,
                                operation=operation,
                                correlation_id=correlation_id,
                                digest=digest,
                                coordinate=coordinate,
                                expected_revision=expected_revision,
                                outcome="conflict",
                                code="provider-grant-active",
                                grant_id=active["grant_id"],
                                resulting_revision=revision,
                                actor=actor,
                            )
                            conflict_code = result.code
                        else:
                            grant_id = str(uuid4())
                            occurred_at = _now()
                            connection.execute(
                                """
                                INSERT INTO provider_grants (
                                    grant_id, provider_id, subject, workspace_id,
                                    action, intent, intent_key, origin, granted_by,
                                    grant_correlation_id, granted_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'command', ?, ?, ?)
                                """,
                                (
                                    grant_id, self._provider_id, coordinate.subject,
                                    coordinate.workspace_id, coordinate.action,
                                    coordinate.intent, _intent_key(coordinate.intent),
                                    actor, correlation_id, occurred_at,
                                ),
                            )
                            connection.execute(
                                "UPDATE provider_policy_state SET revision = ? "
                                "WHERE singleton = 1 AND provider_id = ?",
                                (revision + 1, self._provider_id),
                            )
                            result = self._record_command(
                                connection,
                                operation=operation,
                                correlation_id=correlation_id,
                                digest=digest,
                                coordinate=coordinate,
                                expected_revision=expected_revision,
                                outcome="granted",
                                code="provider-policy-granted",
                                grant_id=grant_id,
                                resulting_revision=revision + 1,
                                actor=actor,
                                occurred_at=occurred_at,
                            )
                    else:
                        target = connection.execute(
                            "SELECT * FROM provider_grants WHERE provider_id = ? "
                            "AND grant_id = ?",
                            (self._provider_id, requested_grant_id),
                        ).fetchone()
                        if (
                            target is None
                            or _coordinate_from_row(target) != coordinate
                            or target["revoked_at"] is not None
                        ):
                            result = self._record_command(
                                connection,
                                operation=operation,
                                correlation_id=correlation_id,
                                digest=digest,
                                coordinate=coordinate,
                                expected_revision=expected_revision,
                                outcome="conflict",
                                code="provider-grant-revoke-conflict",
                                grant_id=requested_grant_id,
                                resulting_revision=revision,
                                actor=actor,
                            )
                            conflict_code = result.code
                        else:
                            occurred_at = _now()
                            connection.execute(
                                "UPDATE provider_grants SET revoked_by = ?, "
                                "revoke_correlation_id = ?, revoked_at = ? "
                                "WHERE provider_id = ? AND grant_id = ?",
                                (
                                    actor, correlation_id, occurred_at,
                                    self._provider_id, requested_grant_id,
                                ),
                            )
                            connection.execute(
                                "UPDATE provider_policy_state SET revision = ? "
                                "WHERE singleton = 1 AND provider_id = ?",
                                (revision + 1, self._provider_id),
                            )
                            result = self._record_command(
                                connection,
                                operation=operation,
                                correlation_id=correlation_id,
                                digest=digest,
                                coordinate=coordinate,
                                expected_revision=expected_revision,
                                outcome="revoked",
                                code="provider-policy-revoked",
                                grant_id=requested_grant_id,
                                resulting_revision=revision + 1,
                                actor=actor,
                                occurred_at=occurred_at,
                            )
        except sqlite3.Error:
            raise ProviderPolicyUnavailable() from None
        if conflict_code is not None:
            raise ProviderPolicyConflict(conflict_code, result)
        assert result is not None
        return result

    def _record_command(
        self,
        connection: sqlite3.Connection,
        *,
        operation: str,
        correlation_id: str,
        digest: str,
        coordinate: PolicyCoordinate,
        expected_revision: int,
        outcome: str,
        code: str,
        grant_id: str | None,
        resulting_revision: int,
        actor: str,
        occurred_at: str | None = None,
    ) -> PolicyCommandResult:
        timestamp = occurred_at or _now()
        connection.execute(
            """
            INSERT INTO provider_policy_commands (
                provider_id, correlation_id, operation, request_digest, subject,
                workspace_id, action, intent, intent_key, expected_revision,
                outcome, code, grant_id, resulting_revision, actor, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._provider_id, correlation_id, operation, digest,
                coordinate.subject, coordinate.workspace_id, coordinate.action,
                coordinate.intent, _intent_key(coordinate.intent), expected_revision,
                outcome, code, grant_id, resulting_revision, actor, timestamp,
            ),
        )
        self._event(
            connection,
            event_kind=operation,
            actor=actor,
            correlation_id=correlation_id,
            outcome=outcome,
            code=code,
            grant_id=grant_id if outcome in {"granted", "revoked"} else None,
            coordinate=coordinate,
            occurred_at=timestamp,
        )
        return PolicyCommandResult(
            self._provider_id, correlation_id, operation, coordinate,
            expected_revision, outcome, code, grant_id, resulting_revision,
            actor, timestamp,
        )

    def _event(
        self,
        connection: sqlite3.Connection,
        *,
        event_kind: str,
        actor: str,
        correlation_id: str,
        outcome: str,
        code: str,
        grant_id: str | None = None,
        coordinate: PolicyCoordinate | None = None,
        occurred_at: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO provider_policy_events (
                event_id, provider_id, grant_id, subject, workspace_id, action,
                intent, event_kind, actor, correlation_id, outcome, code, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()), self._provider_id, grant_id,
                None if coordinate is None else coordinate.subject,
                None if coordinate is None else coordinate.workspace_id,
                None if coordinate is None else coordinate.action,
                None if coordinate is None else coordinate.intent,
                event_kind, actor, correlation_id, outcome, code,
                occurred_at or _now(),
            ),
        )

    def _revision(self, connection: sqlite3.Connection) -> int:
        rows = connection.execute(
            "SELECT revision FROM provider_policy_state "
            "WHERE singleton = 1 AND provider_id = ?",
            (self._provider_id,),
        ).fetchall()
        if len(rows) != 1 or type(rows[0]["revision"]) is not int:
            raise sqlite3.DatabaseError("provider policy state unavailable")
        return rows[0]["revision"]

    def _active_row(
        self, connection: sqlite3.Connection, coordinate: PolicyCoordinate
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM provider_grants WHERE provider_id = ? AND subject = ? "
            "AND workspace_id = ? AND action = ? AND intent_key = ? "
            "AND revoked_at IS NULL",
            (
                self._provider_id, coordinate.subject, coordinate.workspace_id,
                coordinate.action, _intent_key(coordinate.intent),
            ),
        ).fetchone()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _validate_coordinate(coordinate: PolicyCoordinate) -> None:
    if not isinstance(coordinate, PolicyCoordinate):
        raise ProviderPolicyInvalid()
    for value in (coordinate.subject, coordinate.workspace_id, coordinate.action):
        _policy_text(value)
        if value == "*":
            raise ProviderPolicyInvalid()
    if coordinate.action in _INTENTLESS_ACTIONS:
        if coordinate.intent is not None:
            raise ProviderPolicyInvalid()
    elif coordinate.action in _INTENT_ACTIONS:
        if coordinate.intent is None:
            raise ProviderPolicyInvalid()
        _policy_text(coordinate.intent)
        permitted = (
            _DELEGATION_INTENTS
            if coordinate.action == "secret.generate-delegation-key"
            else ALLOWED_SECRET_USE_INTENTS
        )
        if coordinate.intent == "*" or coordinate.intent not in permitted:
            raise ProviderPolicyInvalid()
    else:
        raise ProviderPolicyInvalid()


def _policy_text(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ProviderPolicyInvalid()


def _intent_key(intent: str | None) -> str:
    return INTENT_KEY_NONE if intent is None else intent


def _now() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds")


def _command_digest(
    *,
    provider_id: str,
    operation: str,
    coordinate: PolicyCoordinate,
    requested_grant_id: str | None,
    expected_revision: int,
    actor: str,
) -> str:
    document = json.dumps(
        [
            "cpk-secrets-provider-policy-command",
            SCHEMA_VERSION,
            provider_id,
            operation,
            coordinate.descriptor(),
            requested_grant_id,
            expected_revision,
            actor,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(document).hexdigest()


def _coordinate_from_row(row: sqlite3.Row) -> PolicyCoordinate:
    return PolicyCoordinate(
        subject=str(row["subject"]),
        workspace_id=str(row["workspace_id"]),
        action=str(row["action"]),
        intent=None if row["intent"] is None else str(row["intent"]),
    )


def _grant_from_row(row: sqlite3.Row) -> ProviderGrantRecord:
    return ProviderGrantRecord(
        grant_id=str(row["grant_id"]),
        provider_id=str(row["provider_id"]),
        coordinate=_coordinate_from_row(row),
        origin=str(row["origin"]),
        granted_by=str(row["granted_by"]),
        grant_correlation_id=str(row["grant_correlation_id"]),
        granted_at=str(row["granted_at"]),
        revoked_by=None if row["revoked_by"] is None else str(row["revoked_by"]),
        revoke_correlation_id=(None if row["revoke_correlation_id"] is None
                               else str(row["revoke_correlation_id"])),
        revoked_at=None if row["revoked_at"] is None else str(row["revoked_at"]),
    )


def _command_from_row(row: sqlite3.Row) -> PolicyCommandResult:
    return PolicyCommandResult(
        provider_id=str(row["provider_id"]),
        correlation_id=str(row["correlation_id"]),
        operation=str(row["operation"]),
        coordinate=_coordinate_from_row(row),
        expected_revision=int(row["expected_revision"]),
        outcome=str(row["outcome"]),
        code=str(row["code"]),
        grant_id=None if row["grant_id"] is None else str(row["grant_id"]),
        resulting_revision=int(row["resulting_revision"]),
        actor=str(row["actor"]),
        occurred_at=str(row["occurred_at"]),
    )


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
        or not value.strip()
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
