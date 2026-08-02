from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from control_plane_kit_secrets.audit import SqliteAuditStore
from control_plane_kit_secrets.crypto import (
    encode_master_key_for_file,
    load_master_key_file,
)
from control_plane_kit_secrets.models import (
    DelegationKeyGenerationConflict,
    SecretRevoked,
    SecretTampered,
)
from control_plane_kit_secrets.store import EncryptedSecretStore


class DelegationKeyGenerationTests(unittest.TestCase):
    def test_generation_survives_restart_and_private_key_matches_public_identity(
        self,
    ) -> None:
        with _fixture() as fixture:
            first = fixture.generate()
            restarted = fixture.restarted_store()
            replay = restarted.generate_delegation_key(
                **fixture.arguments,
                provider_id="provider-a",
                audit_store=fixture.audit,
            )

            self.assertTrue(replay.replayed)
            self.assertEqual(first.key_id, replay.key_id)
            self.assertEqual(first.public_key_pem, replay.public_key_pem)
            self.assertEqual(first.metadata.version_id, replay.metadata.version_id)

            resolved = restarted.resolve_secret_for_use(
                workspace_id="workspace-1",
                secret_id="gateway-key-b",
                intent="gateway.probe-signing-key",
                caller_subject="gateway-probe-signer",
                correlation_id="sign-after-restart",
                version_id=replay.metadata.version_id,
            )
            private_key = serialization.load_pem_private_key(
                resolved.value,
                password=None,
            )
            public_key = serialization.load_pem_public_key(
                replay.public_key_pem.encode("ascii")
            )
            self.assertIsInstance(public_key, Ed25519PublicKey)
            message = b"restart-durable-delegation"
            public_key.verify(private_key.sign(message), message)

    def test_concurrent_same_correlation_generates_one_identity(self) -> None:
        with _fixture() as fixture:
            def generate():
                return fixture.store.generate_delegation_key(
                    **fixture.arguments,
                    provider_id="provider-a",
                    audit_store=fixture.audit,
                )

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = tuple(executor.map(lambda _index: generate(), range(8)))

            self.assertEqual({result.key_id for result in results}, {results[0].key_id})
            self.assertEqual(
                {result.metadata.version_id for result in results},
                {results[0].metadata.version_id},
            )
            self.assertEqual(sum(not result.replayed for result in results), 1)
            self.assertEqual(len(fixture.store.raw_rows_for_tests()), 1)

    def test_correlation_reuse_and_revoked_replay_fail_closed(self) -> None:
        with _fixture() as fixture:
            fixture.generate()
            with self.assertRaises(DelegationKeyGenerationConflict):
                fixture.store.generate_delegation_key(
                    **{**fixture.arguments, "issuer": "other-issuer"},
                    provider_id="provider-a",
                    audit_store=fixture.audit,
                )

            fixture.store.revoke_secret(
                workspace_id="workspace-1",
                secret_id="gateway-key-b",
            )
            with self.assertRaises(SecretRevoked):
                fixture.generate()

    def test_replay_verifies_encrypted_private_version_integrity(self) -> None:
        with _fixture() as fixture:
            fixture.generate()
            with closing(sqlite3.connect(fixture.database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        UPDATE secret_versions
                        SET ciphertext = ?
                        WHERE workspace_id = ? AND secret_id = ?
                        """,
                        (b"tampered", "workspace-1", "gateway-key-b"),
                    )

            with self.assertRaises(SecretTampered):
                fixture.generate()


class _GenerationFixture:
    def __init__(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.base = Path(self._directory.name)
        key_path = self.base / "master.key"
        key_path.write_text(
            encode_master_key_for_file(os.urandom(32)),
            encoding="utf-8",
        )
        self.key = load_master_key_file(key_path, version="test")
        self.database_path = self.base / "secrets.sqlite3"
        self.store = EncryptedSecretStore(self.database_path, master_key=self.key)
        self.store.initialize()
        self.audit = SqliteAuditStore(self.database_path)
        self.audit.initialize()
        self.arguments = {
            "workspace_id": "workspace-1",
            "secret_id": "gateway-key-b",
            "secret_reference": "secret://workspace-secrets/keys/gateway-b",
            "purpose": "gateway-probe",
            "issuer": "cpk-server",
            "caller_subject": "cpk-server",
            "correlation_id": "rotation-key-b",
        }

    def __enter__(self) -> _GenerationFixture:
        return self

    def __exit__(self, *args: object) -> None:
        self._directory.cleanup()

    def generate(self):
        return self.store.generate_delegation_key(
            **self.arguments,
            provider_id="provider-a",
            audit_store=self.audit,
        )

    def restarted_store(self) -> EncryptedSecretStore:
        store = EncryptedSecretStore(self.database_path, master_key=self.key)
        store.initialize()
        return store


def _fixture() -> _GenerationFixture:
    return _GenerationFixture()


if __name__ == "__main__":
    unittest.main()
