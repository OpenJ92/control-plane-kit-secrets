from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from control_plane_kit_secrets.crypto import (
    MasterKey,
    encode_master_key_for_file,
    load_master_key_from_environment,
    load_master_key_file,
)
from control_plane_kit_secrets.models import (
    SecretAlreadyExists,
    SecretMetadataInvalid,
    SecretMissing,
    SecretResolutionConflict,
    SecretRevoked,
    SecretStatus,
    SecretTampered,
)
from control_plane_kit_secrets.store import EncryptedSecretStore


class EncryptedSecretStoreTests(unittest.TestCase):
    def test_master_key_loads_from_explicit_mounted_file_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            expected = _write_key(paths["key"])

            loaded = load_master_key_from_environment(
                {"CPK_SECRETS_MASTER_KEY_FILE": str(paths["key"])},
                version="mounted-file",
            )

            self.assertEqual(loaded.fingerprint, expected.fingerprint)
            self.assertEqual(loaded.version, "mounted-file")

    def test_restart_preserves_resolution_with_same_master_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            key = _write_key(paths["key"])
            store = EncryptedSecretStore(paths["db"], master_key=key)
            store.initialize()

            metadata = store.create_secret(
                workspace_id="workspace-1",
                secret_id="cloudflare-token",
                value=b"secret-value-1166",
                labels={"intent": "cloudflare.api-token"},
            )

            restarted = EncryptedSecretStore(paths["db"], master_key=key)
            restarted.initialize()
            resolved = restarted.resolve_secret(
                workspace_id="workspace-1",
                secret_id="cloudflare-token",
                version_id=metadata.version_id,
            )

            self.assertEqual(resolved.value, b"secret-value-1166")
            self.assertEqual(resolved.metadata.version_id, metadata.version_id)
            self.assertEqual(resolved.metadata.status, SecretStatus.ACTIVE)
            self.assertEqual(resolved.metadata.labels["intent"], "cloudflare.api-token")

    def test_wrong_master_key_fails_closed_without_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            store = EncryptedSecretStore(paths["db"], master_key=_write_key(paths["key"]))
            store.initialize()
            store.create_secret(
                workspace_id="workspace-1",
                secret_id="postgres-password",
                value=b"never-show-this-password",
            )

            wrong_key_path = Path(directory) / "wrong-key"
            wrong_store = EncryptedSecretStore(
                paths["db"],
                master_key=_write_key(wrong_key_path),
            )

            with self.assertRaises(SecretTampered) as context:
                wrong_store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="postgres-password",
                )

            self.assertNotIn("never-show-this-password", str(context.exception))

    def test_tampered_ciphertext_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            key = _write_key(paths["key"])
            store = EncryptedSecretStore(paths["db"], master_key=key)
            store.initialize()
            store.create_secret(
                workspace_id="workspace-1",
                secret_id="gateway-key",
                value=b"gateway-private-signing-key",
            )
            _tamper_first_ciphertext(paths["db"])

            with self.assertRaises(SecretTampered) as context:
                store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="gateway-key",
                )

            self.assertNotIn("gateway-private-signing-key", str(context.exception))

    def test_tampered_metadata_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            key = _write_key(paths["key"])
            store = EncryptedSecretStore(paths["db"], master_key=key)
            store.initialize()
            store.create_secret(
                workspace_id="workspace-1",
                secret_id="metadata-bound",
                value=b"metadata-protected-value",
                labels={"purpose": "original"},
            )
            _tamper_labels(paths["db"], labels_json='{"purpose": "tampered"}')

            with self.assertRaises(SecretTampered):
                store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="metadata-bound",
                )

    def test_revoke_blocks_future_resolution_and_status_flip_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            key = _write_key(paths["key"])
            store = EncryptedSecretStore(paths["db"], master_key=key)
            store.initialize()
            metadata = store.create_secret(
                workspace_id="workspace-1",
                secret_id="docker-tls-key",
                value=b"docker-client-key",
            )

            revoked = store.revoke_secret(
                workspace_id="workspace-1",
                secret_id="docker-tls-key",
            )

            self.assertEqual([item.status for item in revoked], [SecretStatus.REVOKED])
            with self.assertRaises(SecretRevoked):
                store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="docker-tls-key",
                    version_id=metadata.version_id,
                )

            _tamper_status(paths["db"], status="active")
            with self.assertRaises(SecretTampered):
                store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="docker-tls-key",
                    version_id=metadata.version_id,
                )

    def test_rotate_creates_new_version_without_overwriting_old_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            key = _write_key(paths["key"])
            store = EncryptedSecretStore(paths["db"], master_key=key)
            store.initialize()
            first = store.create_secret(
                workspace_id="workspace-1",
                secret_id="oci-pull-token",
                value=b"old-token",
            )
            second = store.rotate_secret(
                workspace_id="workspace-1",
                secret_id="oci-pull-token",
                value=b"new-token",
            )

            self.assertEqual(first.version_number, 1)
            self.assertEqual(second.version_number, 2)
            self.assertNotEqual(first.version_id, second.version_id)
            self.assertEqual(
                store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="oci-pull-token",
                ).value,
                b"new-token",
            )
            self.assertEqual(
                store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="oci-pull-token",
                    version_id=first.version_id,
                ).value,
                b"old-token",
            )

    def test_resolution_correlation_pins_first_version_across_rotation_and_restart(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            key = _write_key(paths["key"])
            store = EncryptedSecretStore(paths["db"], master_key=key)
            store.initialize()
            first = store.create_secret(
                workspace_id="workspace-1",
                secret_id="postgres-password",
                value=b"version-a",
            )

            selected = store.resolve_secret_for_use(
                workspace_id="workspace-1",
                secret_id="postgres-password",
                intent="postgres.password",
                caller_subject="worker-a",
                correlation_id="effect-a",
            )
            second = store.rotate_secret(
                workspace_id="workspace-1",
                secret_id="postgres-password",
                value=b"version-b",
            )
            restarted = EncryptedSecretStore(paths["db"], master_key=key)
            restarted.initialize()
            replayed = restarted.resolve_secret_for_use(
                workspace_id="workspace-1",
                secret_id="postgres-password",
                intent="postgres.password",
                caller_subject="worker-a",
                correlation_id="effect-a",
            )
            new_effect = restarted.resolve_secret_for_use(
                workspace_id="workspace-1",
                secret_id="postgres-password",
                intent="postgres.password",
                caller_subject="worker-a",
                correlation_id="effect-b",
            )

            self.assertEqual(selected.metadata.version_id, first.version_id)
            self.assertEqual(replayed.metadata.version_id, first.version_id)
            self.assertEqual(new_effect.metadata.version_id, second.version_id)

    def test_resolution_correlation_reuse_with_changed_semantics_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            store = EncryptedSecretStore(
                paths["db"],
                master_key=_write_key(paths["key"]),
            )
            store.initialize()
            store.create_secret(
                workspace_id="workspace-1",
                secret_id="shared",
                value=b"secret-value",
            )
            store.resolve_secret_for_use(
                workspace_id="workspace-1",
                secret_id="shared",
                intent="postgres.password",
                caller_subject="worker-a",
                correlation_id="effect-a",
            )

            with self.assertRaises(SecretResolutionConflict):
                store.resolve_secret_for_use(
                    workspace_id="workspace-1",
                    secret_id="shared",
                    intent="oci.pull-credential",
                    caller_subject="worker-a",
                    correlation_id="effect-a",
                )

    def test_missing_secret_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            store = EncryptedSecretStore(paths["db"], master_key=_write_key(paths["key"]))
            store.initialize()

            with self.assertRaises(SecretMissing):
                store.resolve_secret(workspace_id="workspace-1", secret_id="missing")

    def test_duplicate_create_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            store = EncryptedSecretStore(paths["db"], master_key=_write_key(paths["key"]))
            store.initialize()
            store.create_secret(
                workspace_id="workspace-1",
                secret_id="duplicate",
                value=b"first-secret-value",
            )

            with self.assertRaises(SecretAlreadyExists) as context:
                store.create_secret(
                    workspace_id="workspace-1",
                    secret_id="duplicate",
                    value=b"second-secret-value",
                )

            self.assertNotIn("second-secret-value", str(context.exception))

    def test_labels_are_bounded_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            store = EncryptedSecretStore(paths["db"], master_key=_write_key(paths["key"]))
            store.initialize()

            with self.assertRaises(SecretMetadataInvalid):
                store.create_secret(
                    workspace_id="workspace-1",
                    secret_id="too-many-labels",
                    value=b"value",
                    labels={f"k{index}": "v" for index in range(17)},
                )

            with self.assertRaises(SecretMetadataInvalid):
                store.create_secret(
                    workspace_id="workspace-1",
                    secret_id="label-too-large",
                    value=b"value",
                    labels={"k": "v" * 257},
                )

    def test_plaintext_and_master_key_are_absent_from_database_repr_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = _paths(directory)
            key = _write_key(paths["key"])
            sentinel = b"sentinel-secret-value-1166"
            store = EncryptedSecretStore(paths["db"], master_key=key)
            store.initialize()
            metadata = store.create_secret(
                workspace_id="workspace-1",
                secret_id="sensitive",
                value=sentinel,
                labels={"purpose": "test-only"},
            )

            database_bytes = paths["db"].read_bytes()
            self.assertNotIn(sentinel, database_bytes)
            self.assertNotIn(key._key, database_bytes)
            self.assertNotIn(sentinel.decode("ascii"), repr(metadata))
            self.assertNotIn(sentinel.decode("ascii"), repr(store.raw_rows_for_tests()))
            self.assertIn(key.fingerprint, repr(store.raw_rows_for_tests()))

            _tamper_first_ciphertext(paths["db"])
            with self.assertRaises(SecretTampered) as context:
                store.resolve_secret(workspace_id="workspace-1", secret_id="sensitive")

            self.assertNotIn(sentinel.decode("ascii"), str(context.exception))
            self.assertNotIn(key._key.hex(), str(context.exception))


def _paths(directory: str) -> dict[str, Path]:
    base = Path(directory)
    return {"db": base / "secrets.sqlite3", "key": base / "master.key"}


def _write_key(path: Path) -> MasterKey:
    path.write_text(encode_master_key_for_file(os.urandom(32)), encoding="utf-8")
    return load_master_key_file(path, version=path.name)


def _tamper_first_ciphertext(database_path: Path) -> None:
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            row = connection.execute(
                "SELECT workspace_id, secret_id, version_id, ciphertext FROM secret_versions"
            ).fetchone()
            assert row is not None
            tampered = bytearray(row[3])
            tampered[-1] ^= 0x01
            connection.execute(
                """
                UPDATE secret_versions
                SET ciphertext = ?
                WHERE workspace_id = ? AND secret_id = ? AND version_id = ?
                """,
                (bytes(tampered), row[0], row[1], row[2]),
            )


def _tamper_status(database_path: Path, *, status: str) -> None:
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute("UPDATE secret_versions SET status = ?", (status,))


def _tamper_labels(database_path: Path, *, labels_json: str) -> None:
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                "UPDATE secret_versions SET labels_json = ?",
                (labels_json,),
            )


if __name__ == "__main__":
    unittest.main()
