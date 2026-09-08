from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from .audit import SqliteAuditStore, _SCHEMA_STATEMENTS as _AUDIT_SCHEMA
from .crypto import MasterKey, SecretCryptoError
from .store import EncryptedSecretStore, _SCHEMA_STATEMENTS as _STORE_SCHEMA


_SCHEMA_VERSION = 1
_WITNESS = b"cpk-secrets-custody-v1"
_BINDING_SCHEMA = """
CREATE TABLE provider_custody_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    provider_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL
)
"""


class ProviderCustodyRejected(Exception):
    def __init__(self) -> None:
        super().__init__("secret provider custody is incompatible")


class ProviderCustodyUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("secret provider custody is unavailable")


def admit_provider_custody(
    database_path: str | Path, *, master_key: MasterKey, provider_id: str
) -> tuple[EncryptedSecretStore, SqliteAuditStore]:
    """Admit one exact provider/root/schema identity before exposing custody.

    SQLite owns recovery and locking. Rejection preserves logical application
    state; this is not a filesystem snapshot or protection from hostile path
    replacement. There is no retry or adoption of existing unbound schemas.
    """
    connection = None
    try:
        path = Path(database_path)
        if str(path) == ":memory:" or path.is_symlink() or (path.exists() and not path.is_file()):
            raise ProviderCustodyRejected()
        path.parent.mkdir(parents=True, exist_ok=True)
        store = EncryptedSecretStore(path, master_key=master_key)
        audit = SqliteAuditStore(path)
        connection = sqlite3.connect(path, timeout=5.0)
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            observed = _schema(connection)
            if not observed:
                store.initialize_in_transaction(connection)
                audit.initialize_in_transaction(connection)
                connection.execute(_BINDING_SCHEMA)
                nonce = os.urandom(12)
                ciphertext = master_key.encrypt(
                    nonce=nonce, plaintext=_WITNESS, aad=_context(provider_id)
                )
                connection.execute(
                    "INSERT INTO provider_custody_binding VALUES (?, ?, ?, ?, ?)",
                    (1, _SCHEMA_VERSION, provider_id, nonce, ciphertext),
                )
            if _schema(connection) != _expected_schema():
                raise ProviderCustodyRejected()
            _verify_binding(connection, master_key=master_key, provider_id=provider_id)
        return store, audit
    except ProviderCustodyRejected:
        raise ProviderCustodyRejected() from None
    except sqlite3.Error as error:
        code = getattr(error, "sqlite_errorcode", 0) & 0xFF
        if code in (sqlite3.SQLITE_NOTADB, sqlite3.SQLITE_CORRUPT):
            raise ProviderCustodyRejected() from None
        raise ProviderCustodyUnavailable() from None
    except (OSError, SecretCryptoError):
        raise ProviderCustodyUnavailable() from None
    finally:
        if connection is not None:
            connection.close()


def _context(provider_id: str) -> bytes:
    return json.dumps(
        ["cpk-secrets-provider-custody", _SCHEMA_VERSION, provider_id],
        ensure_ascii=True, separators=(",", ":"),
    ).encode("ascii")


def _canonical_sql(sql: str) -> str:
    return " ".join(sql.split()).replace("IF NOT EXISTS ", "")


def _expected_schema() -> tuple[tuple[str, str, str, str], ...]:
    expected = []
    for statement in (*_STORE_SCHEMA, *_AUDIT_SCHEMA, _BINDING_SCHEMA):
        sql = _canonical_sql(statement)
        words = sql.split()
        kind, name = words[1].lower(), words[2]
        owner = name if kind == "table" else words[4]
        expected.append((kind, name, owner, sql))
    return tuple(sorted(expected))


def _schema(connection: sqlite3.Connection) -> tuple[tuple[str, str, str, str], ...]:
    # Compare complete declared definitions: columns, constraints, indexes and
    # foreign keys, including rejection of additional views/triggers/objects.
    # SQLite-generated constraint indexes have no SQL and are covered by their
    # owning table's exact PRIMARY KEY/UNIQUE declarations.
    return tuple(sorted(
        (kind, name, owner, _canonical_sql(sql or ""))
        for kind, name, owner, sql in connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE NOT (type = 'index' AND sql IS NULL AND name GLOB 'sqlite_autoindex_*')"
        )
    ))


def _verify_binding(
    connection: sqlite3.Connection, *, master_key: MasterKey, provider_id: str
) -> None:
    rows = connection.execute(
        "SELECT singleton, schema_version, provider_id, nonce, ciphertext FROM provider_custody_binding"
    ).fetchall()
    if len(rows) != 1:
        raise ProviderCustodyRejected()
    singleton, version, stored_provider, nonce, ciphertext = rows[0]
    if (
        singleton != 1 or version != _SCHEMA_VERSION or stored_provider != provider_id
        or not isinstance(nonce, bytes) or len(nonce) != 12
        or not isinstance(ciphertext, bytes) or len(ciphertext) != len(_WITNESS) + 16
    ):
        raise ProviderCustodyRejected()
    try:
        witness = master_key.decrypt(nonce=nonce, ciphertext=ciphertext, aad=_context(provider_id))
    except SecretCryptoError:
        raise ProviderCustodyRejected() from None
    if witness != _WITNESS:
        raise ProviderCustodyRejected()
