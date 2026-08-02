from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4


class AuditUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("secret provider audit is unavailable")


@dataclass(frozen=True)
class AuditRecord:
    event_id: str
    provider_id: str
    workspace_id: str
    secret_id: str
    version_id: str | None
    intent: str | None
    caller_subject: str
    correlation_id: str
    outcome: str
    code: str
    occurred_at: str


class SqliteAuditStore:
    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    event_id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    secret_id TEXT NOT NULL,
                    version_id TEXT,
                    intent TEXT,
                    caller_subject TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    code TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_records_reference
                ON audit_records (workspace_id, secret_id, occurred_at)
                """
            )

    def append(self, record: AuditRecord) -> None:
        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO audit_records (
                        event_id, provider_id, workspace_id, secret_id, version_id,
                        intent, caller_subject, correlation_id, outcome, code,
                        occurred_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.event_id,
                        record.provider_id,
                        record.workspace_id,
                        record.secret_id,
                        record.version_id,
                        record.intent,
                        record.caller_subject,
                        record.correlation_id,
                        record.outcome,
                        record.code,
                        record.occurred_at,
                    ),
                )
        except sqlite3.Error as exc:
            raise AuditUnavailable() from exc

    def append_in_transaction(
        self,
        connection: sqlite3.Connection,
        record: AuditRecord,
    ) -> None:
        """Append through a caller-owned provider transaction."""

        try:
            connection.execute(
                """
                INSERT INTO audit_records (
                    event_id, provider_id, workspace_id, secret_id, version_id,
                    intent, caller_subject, correlation_id, outcome, code,
                    occurred_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.event_id,
                    record.provider_id,
                    record.workspace_id,
                    record.secret_id,
                    record.version_id,
                    record.intent,
                    record.caller_subject,
                    record.correlation_id,
                    record.outcome,
                    record.code,
                    record.occurred_at,
                ),
            )
        except sqlite3.Error as exc:
            raise AuditUnavailable() from exc

    def rows_for_tests(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT event_id, provider_id, workspace_id, secret_id, version_id,
                       intent, caller_subject, correlation_id, outcome, code,
                       occurred_at
                FROM audit_records
                ORDER BY occurred_at, event_id
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def audit_record(
    *,
    provider_id: str,
    workspace_id: str,
    secret_id: str,
    version_id: str | None,
    intent: str | None,
    caller_subject: str,
    correlation_id: str,
    outcome: str,
    code: str,
) -> AuditRecord:
    return AuditRecord(
        event_id=str(uuid4()),
        provider_id=provider_id,
        workspace_id=workspace_id,
        secret_id=secret_id,
        version_id=version_id,
        intent=intent,
        caller_subject=caller_subject,
        correlation_id=correlation_id,
        outcome=outcome,
        code=code,
        occurred_at=datetime.now(tz=UTC).isoformat(timespec="microseconds"),
    )
