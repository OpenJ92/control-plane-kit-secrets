from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator
from uuid import uuid4

from .crypto import ALGORITHM, MasterKey, SecretCryptoError
from .models import (
    ResolvedSecret,
    SecretAlreadyExists,
    SecretMetadata,
    SecretMetadataInvalid,
    SecretMissing,
    SecretResolutionConflict,
    SecretRevoked,
    SecretStatus,
    SecretTampered,
)

NONCE_BYTES = 12
MAX_LABELS = 16
MAX_LABEL_KEY_CHARS = 64
MAX_LABEL_VALUE_CHARS = 256


class EncryptedSecretStore:
    def __init__(self, database_path: str | Path, *, master_key: MasterKey) -> None:
        self._database_path = Path(database_path)
        self._master_key = master_key

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secret_versions (
                    workspace_id TEXT NOT NULL,
                    secret_id TEXT NOT NULL,
                    version_id TEXT NOT NULL,
                    version_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    key_version TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    labels_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT,
                    PRIMARY KEY (workspace_id, secret_id, version_id),
                    UNIQUE (workspace_id, secret_id, version_number)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_secret_versions_latest
                ON secret_versions (workspace_id, secret_id, version_number DESC)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secret_resolution_selections (
                    workspace_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    secret_id TEXT NOT NULL,
                    intent TEXT NOT NULL,
                    caller_subject TEXT NOT NULL,
                    version_id TEXT NOT NULL,
                    selected_at TEXT NOT NULL,
                    PRIMARY KEY (workspace_id, correlation_id),
                    FOREIGN KEY (workspace_id, secret_id, version_id)
                      REFERENCES secret_versions (
                        workspace_id,
                        secret_id,
                        version_id
                      )
                )
                """
            )

    def create_secret(
        self,
        *,
        workspace_id: str,
        secret_id: str,
        value: bytes,
        labels: dict[str, str] | None = None,
    ) -> SecretMetadata:
        return self._insert_version(
            workspace_id=workspace_id,
            secret_id=secret_id,
            value=value,
            labels=labels or {},
            version_number=1,
        )

    def rotate_secret(
        self,
        *,
        workspace_id: str,
        secret_id: str,
        value: bytes,
        labels: dict[str, str] | None = None,
    ) -> SecretMetadata:
        with self._connection() as connection:
            latest = self._latest_row(
                connection, workspace_id=workspace_id, secret_id=secret_id
            )
            if latest is None:
                raise SecretMissing()
            next_number = int(latest["version_number"]) + 1
        return self._insert_version(
            workspace_id=workspace_id,
            secret_id=secret_id,
            value=value,
            labels=labels or {},
            version_number=next_number,
        )

    def revoke_secret(self, *, workspace_id: str, secret_id: str) -> list[SecretMetadata]:
        revoked: list[SecretMetadata] = []
        with self._connection() as connection:
            rows = self._all_rows(
                connection, workspace_id=workspace_id, secret_id=secret_id
            )
            if not rows:
                raise SecretMissing()
            now = _now()
            for row in rows:
                metadata = self._metadata_from_row(row)
                if metadata.status is SecretStatus.REVOKED:
                    revoked.append(metadata)
                    continue
                plaintext = self._decrypt_row(row)
                revoked_metadata = SecretMetadata(
                    workspace_id=metadata.workspace_id,
                    secret_id=metadata.secret_id,
                    version_id=metadata.version_id,
                    version_number=metadata.version_number,
                    status=SecretStatus.REVOKED,
                    algorithm=metadata.algorithm,
                    key_fingerprint=metadata.key_fingerprint,
                    key_version=metadata.key_version,
                    labels=metadata.labels,
                    created_at=metadata.created_at,
                    revoked_at=now,
                )
                nonce = os.urandom(NONCE_BYTES)
                ciphertext = self._master_key.encrypt(
                    nonce=nonce,
                    plaintext=plaintext,
                    aad=self._aad(revoked_metadata),
                )
                connection.execute(
                    """
                    UPDATE secret_versions
                    SET status = ?, nonce = ?, ciphertext = ?, revoked_at = ?
                    WHERE workspace_id = ? AND secret_id = ? AND version_id = ?
                    """,
                    (
                        SecretStatus.REVOKED.value,
                        nonce,
                        ciphertext,
                        now,
                        workspace_id,
                        secret_id,
                        metadata.version_id,
                    ),
                )
                revoked.append(revoked_metadata)
        return revoked

    def metadata(
        self,
        *,
        workspace_id: str,
        secret_id: str,
        version_id: str | None = None,
    ) -> SecretMetadata:
        row = self._select_row(
            workspace_id=workspace_id,
            secret_id=secret_id,
            version_id=version_id,
        )
        if row is None:
            raise SecretMissing()
        return self._metadata_from_row(row)

    def resolve_secret(
        self,
        *,
        workspace_id: str,
        secret_id: str,
        version_id: str | None = None,
    ) -> ResolvedSecret:
        row = self._select_row(
            workspace_id=workspace_id,
            secret_id=secret_id,
            version_id=version_id,
        )
        if row is None:
            raise SecretMissing()
        metadata = self._metadata_from_row(row)
        if metadata.status is SecretStatus.REVOKED:
            raise SecretRevoked()
        return ResolvedSecret(metadata=metadata, _value=self._decrypt_row(row))

    def resolve_secret_for_use(
        self,
        *,
        workspace_id: str,
        secret_id: str,
        intent: str,
        caller_subject: str,
        correlation_id: str,
        version_id: str | None = None,
    ) -> ResolvedSecret:
        """Atomically pin first use and replay the selected provider version."""

        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            selection = connection.execute(
                """
                SELECT secret_id, intent, caller_subject, version_id
                FROM secret_resolution_selections
                WHERE workspace_id = ? AND correlation_id = ?
                """,
                (workspace_id, correlation_id),
            ).fetchone()
            if selection is not None:
                selected_version_id = str(selection["version_id"])
                if (
                    str(selection["secret_id"]) != secret_id
                    or str(selection["intent"]) != intent
                    or str(selection["caller_subject"]) != caller_subject
                    or (
                        version_id is not None
                        and version_id != selected_version_id
                    )
                ):
                    raise SecretResolutionConflict()
            else:
                selected = self._select_row_with_connection(
                    connection,
                    workspace_id=workspace_id,
                    secret_id=secret_id,
                    version_id=version_id,
                )
                if selected is None:
                    raise SecretMissing()
                selected_metadata = self._metadata_from_row(selected)
                if selected_metadata.status is SecretStatus.REVOKED:
                    raise SecretRevoked()
                selected_version_id = selected_metadata.version_id
                connection.execute(
                    """
                    INSERT INTO secret_resolution_selections (
                        workspace_id,
                        correlation_id,
                        secret_id,
                        intent,
                        caller_subject,
                        version_id,
                        selected_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        workspace_id,
                        correlation_id,
                        secret_id,
                        intent,
                        caller_subject,
                        selected_version_id,
                        _now(),
                    ),
                )

            row = self._select_row_with_connection(
                connection,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=selected_version_id,
            )
            if row is None:
                raise SecretMissing()
            metadata = self._metadata_from_row(row)
            if metadata.status is SecretStatus.REVOKED:
                raise SecretRevoked()
            return ResolvedSecret(
                metadata=metadata,
                _value=self._decrypt_row(row),
            )

    def raw_rows_for_tests(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT workspace_id, secret_id, version_id, version_number, status,
                       algorithm, key_fingerprint, key_version, nonce, ciphertext,
                       labels_json, created_at, revoked_at
                FROM secret_versions
                ORDER BY workspace_id, secret_id, version_number
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def _insert_version(
        self,
        *,
        workspace_id: str,
        secret_id: str,
        value: bytes,
        labels: dict[str, str],
        version_number: int,
    ) -> SecretMetadata:
        metadata = SecretMetadata(
            workspace_id=workspace_id,
            secret_id=secret_id,
            version_id=str(uuid4()),
            version_number=version_number,
            status=SecretStatus.ACTIVE,
            algorithm=ALGORITHM,
            key_fingerprint=self._master_key.fingerprint,
            key_version=self._master_key.version,
            labels=_clean_labels(labels),
            created_at=_now(),
            revoked_at=None,
        )
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = self._master_key.encrypt(
            nonce=nonce,
            plaintext=value,
            aad=self._aad(metadata),
        )
        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO secret_versions (
                        workspace_id, secret_id, version_id, version_number, status,
                        algorithm, key_fingerprint, key_version, nonce, ciphertext,
                        labels_json, created_at, revoked_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metadata.workspace_id,
                        metadata.secret_id,
                        metadata.version_id,
                        metadata.version_number,
                        metadata.status.value,
                        metadata.algorithm,
                        metadata.key_fingerprint,
                        metadata.key_version,
                        nonce,
                        ciphertext,
                        json.dumps(dict(metadata.labels), sort_keys=True),
                        metadata.created_at,
                        metadata.revoked_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise SecretAlreadyExists() from exc
        return metadata

    def _select_row(
        self,
        *,
        workspace_id: str,
        secret_id: str,
        version_id: str | None,
    ) -> sqlite3.Row | None:
        with self._connection() as connection:
            return self._select_row_with_connection(
                connection,
                workspace_id=workspace_id,
                secret_id=secret_id,
                version_id=version_id,
            )

    def _select_row_with_connection(
        self,
        connection: sqlite3.Connection,
        *,
        workspace_id: str,
        secret_id: str,
        version_id: str | None,
    ) -> sqlite3.Row | None:
        if version_id is None:
            return self._latest_row(
                connection,
                workspace_id=workspace_id,
                secret_id=secret_id,
            )
        return connection.execute(
            """
            SELECT *
            FROM secret_versions
            WHERE workspace_id = ? AND secret_id = ? AND version_id = ?
            """,
            (workspace_id, secret_id, version_id),
        ).fetchone()

    def _latest_row(
        self, connection: sqlite3.Connection, *, workspace_id: str, secret_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT *
            FROM secret_versions
            WHERE workspace_id = ? AND secret_id = ?
            ORDER BY version_number DESC
            LIMIT 1
            """,
            (workspace_id, secret_id),
        ).fetchone()

    def _all_rows(
        self, connection: sqlite3.Connection, *, workspace_id: str, secret_id: str
    ) -> Iterable[sqlite3.Row]:
        return connection.execute(
            """
            SELECT *
            FROM secret_versions
            WHERE workspace_id = ? AND secret_id = ?
            ORDER BY version_number
            """,
            (workspace_id, secret_id),
        ).fetchall()

    def _decrypt_row(self, row: sqlite3.Row) -> bytes:
        metadata = self._metadata_from_row(row)
        if metadata.algorithm != ALGORITHM:
            raise SecretTampered()
        if metadata.key_fingerprint != self._master_key.fingerprint:
            raise SecretTampered()
        try:
            return self._master_key.decrypt(
                nonce=bytes(row["nonce"]),
                ciphertext=bytes(row["ciphertext"]),
                aad=self._aad(metadata),
            )
        except SecretCryptoError as exc:
            raise SecretTampered() from exc

    def _metadata_from_row(self, row: sqlite3.Row) -> SecretMetadata:
        return SecretMetadata(
            workspace_id=str(row["workspace_id"]),
            secret_id=str(row["secret_id"]),
            version_id=str(row["version_id"]),
            version_number=int(row["version_number"]),
            status=SecretStatus(str(row["status"])),
            algorithm=str(row["algorithm"]),
            key_fingerprint=str(row["key_fingerprint"]),
            key_version=str(row["key_version"]),
            labels=json.loads(str(row["labels_json"])),
            created_at=str(row["created_at"]),
            revoked_at=(
                str(row["revoked_at"]) if row["revoked_at"] is not None else None
            ),
        )

    def _aad(self, metadata: SecretMetadata) -> bytes:
        payload = {
            "workspace_id": metadata.workspace_id,
            "secret_id": metadata.secret_id,
            "version_id": metadata.version_id,
            "version_number": metadata.version_number,
            "status": metadata.status.value,
            "algorithm": metadata.algorithm,
            "key_fingerprint": metadata.key_fingerprint,
            "key_version": metadata.key_version,
            "labels": dict(metadata.labels),
            "created_at": metadata.created_at,
            "revoked_at": metadata.revoked_at,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _connect(self) -> sqlite3.Connection:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _now() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="microseconds")


def _clean_labels(labels: dict[str, str]) -> dict[str, str]:
    if len(labels) > MAX_LABELS:
        raise SecretMetadataInvalid()
    cleaned: dict[str, str] = {}
    for key, value in labels.items():
        label_key = str(key)
        label_value = str(value)
        if (
            not label_key
            or len(label_key) > MAX_LABEL_KEY_CHARS
            or len(label_value) > MAX_LABEL_VALUE_CHARS
        ):
            raise SecretMetadataInvalid()
        cleaned[label_key] = label_value
    return cleaned
