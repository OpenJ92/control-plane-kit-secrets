from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Final

from .audit import SqliteAuditStore, _SCHEMA_STATEMENTS as _AUDIT_SCHEMA
from .auth import ProviderCredential
from .crypto import MasterKey, SecretCryptoError
from .provider_policy import (
    ProviderPolicySeedRejected,
    _SCHEMA_STATEMENTS as _POLICY_SCHEMA,
    initialize_policy_in_transaction,
    seed_policy_in_transaction,
    verify_policy_seed,
)
from .store import EncryptedSecretStore, _SCHEMA_STATEMENTS as _STORE_SCHEMA


_SCHEMA_VERSION = 2
_V1_WITNESS = b"cpk-secrets-custody-v1"
_V2_WITNESS = b"cpk-secrets-custody-v2"
_V1_BINDING_SCHEMA = """
CREATE TABLE provider_custody_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    provider_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL
)
"""
_V2_BINDING_SCHEMA = """
CREATE TABLE provider_custody_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    provider_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL
)
"""
_SEED_OMITTED: Final = object()


class ProviderCustodyRejected(Exception):
    def __init__(self) -> None:
        super().__init__("secret provider custody is incompatible")


class ProviderCustodyUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("secret provider custody is unavailable")


def admit_provider_custody(
    database_path: str | Path,
    *,
    master_key: MasterKey,
    provider_id: str,
    credentials: tuple[ProviderCredential, ...] | object = _SEED_OMITTED,
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
                seed = _require_seed(credentials)
                store.initialize_in_transaction(connection)
                audit.initialize_in_transaction(connection)
                initialize_policy_in_transaction(connection)
                seed_policy_in_transaction(
                    connection, provider_id=provider_id, credentials=seed
                )
                _write_binding(
                    connection, master_key=master_key, provider_id=provider_id
                )
            elif observed == _expected_schema(1):
                seed = _require_seed(credentials)
                _verify_binding(
                    connection,
                    master_key=master_key,
                    provider_id=provider_id,
                    version=1,
                )
                initialize_policy_in_transaction(connection)
                seed_policy_in_transaction(
                    connection, provider_id=provider_id, credentials=seed
                )
                connection.execute("DROP TABLE provider_custody_binding")
                _write_binding(
                    connection, master_key=master_key, provider_id=provider_id
                )
            elif observed != _expected_schema(2):
                raise ProviderCustodyRejected()
            if _schema(connection) != _expected_schema(2):
                raise ProviderCustodyRejected()
            _verify_binding(
                connection,
                master_key=master_key,
                provider_id=provider_id,
                version=2,
            )
            verify_policy_seed(connection, provider_id=provider_id)
        return store, audit
    except ProviderCustodyRejected:
        raise ProviderCustodyRejected() from None
    except sqlite3.Error as error:
        code = getattr(error, "sqlite_errorcode", 0) & 0xFF
        if code in (sqlite3.SQLITE_NOTADB, sqlite3.SQLITE_CORRUPT):
            raise ProviderCustodyRejected() from None
        raise ProviderCustodyUnavailable() from None
    except ProviderPolicySeedRejected:
        raise ProviderCustodyRejected() from None
    except (OSError, SecretCryptoError):
        raise ProviderCustodyUnavailable() from None
    finally:
        if connection is not None:
            connection.close()


def _context(provider_id: str, version: int) -> bytes:
    return json.dumps(
        ["cpk-secrets-provider-custody", version, provider_id],
        ensure_ascii=True, separators=(",", ":"),
    ).encode("ascii")


def _canonical_sql(sql: str) -> str:
    return " ".join(sql.split()).replace("IF NOT EXISTS ", "")


def _expected_schema(version: int) -> tuple[tuple[str, str, str, str], ...]:
    expected = []
    policy = _POLICY_SCHEMA if version == 2 else ()
    binding = _V2_BINDING_SCHEMA if version == 2 else _V1_BINDING_SCHEMA
    for statement in (*_STORE_SCHEMA, *_AUDIT_SCHEMA, *policy, binding):
        sql = _canonical_sql(statement)
        words = sql.split()
        if words[1].upper() == "TABLE":
            kind, name, owner = "table", words[2], words[2]
        elif words[1].upper() == "INDEX":
            kind, name, owner = "index", words[2], words[4]
        elif words[1:3] == ["UNIQUE", "INDEX"]:
            kind, name, owner = "index", words[3], words[5]
        else:
            raise RuntimeError("unsupported custody schema statement")
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
    connection: sqlite3.Connection,
    *,
    master_key: MasterKey,
    provider_id: str,
    version: int,
) -> None:
    rows = connection.execute(
        "SELECT singleton, schema_version, provider_id, nonce, ciphertext FROM provider_custody_binding"
    ).fetchall()
    if len(rows) != 1:
        raise ProviderCustodyRejected()
    singleton, stored_version, stored_provider, nonce, ciphertext = rows[0]
    if (
        singleton != 1 or stored_version != version or stored_provider != provider_id
        or not isinstance(nonce, bytes) or len(nonce) != 12
        or not isinstance(ciphertext, bytes)
    ):
        raise ProviderCustodyRejected()
    witness = _V2_WITNESS if version == 2 else _V1_WITNESS
    if len(ciphertext) != len(witness) + 16:
        raise ProviderCustodyRejected()
    try:
        observed_witness = master_key.decrypt(
            nonce=nonce,
            ciphertext=ciphertext,
            aad=_context(provider_id, version),
        )
    except SecretCryptoError:
        raise ProviderCustodyRejected() from None
    if observed_witness != witness:
        raise ProviderCustodyRejected()


def _require_seed(
    credentials: tuple[ProviderCredential, ...] | object,
) -> tuple[ProviderCredential, ...]:
    if credentials is _SEED_OMITTED or not isinstance(credentials, tuple):
        raise ProviderCustodyRejected()
    return credentials


def _write_binding(
    connection: sqlite3.Connection, *, master_key: MasterKey, provider_id: str
) -> None:
    connection.execute(_V2_BINDING_SCHEMA)
    nonce = os.urandom(12)
    ciphertext = master_key.encrypt(
        nonce=nonce,
        plaintext=_V2_WITNESS,
        aad=_context(provider_id, _SCHEMA_VERSION),
    )
    connection.execute(
        "INSERT INTO provider_custody_binding VALUES (?, ?, ?, ?, ?)",
        (1, _SCHEMA_VERSION, provider_id, nonce, ciphertext),
    )
