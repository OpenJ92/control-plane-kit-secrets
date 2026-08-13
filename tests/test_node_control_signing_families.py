from __future__ import annotations

import base64
import importlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from control_plane_kit_core import (
    DelegationKeyAlgorithm,
    DelegationKeyPurpose,
    DelegationPublicKey,
)
from control_plane_kit_core.secrets import SecretUseIntent
from control_plane_kit_secrets.api import create_app
from control_plane_kit_secrets.audit import SqliteAuditStore
from control_plane_kit_secrets.auth import ProviderCredential, ProviderGrant
from control_plane_kit_secrets.crypto import (
    encode_master_key_for_file,
    load_master_key_file,
)
from control_plane_kit_secrets.models import SecretMetadataInvalid, SecretTampered
from control_plane_kit_secrets.store import EncryptedSecretStore


REPO_ROOT = Path(__file__).parents[1]
CORE_COMMIT = "a62af8431afb878fa0beed3b752cbdf7a640fb48"
FAMILIES = (
    (
        DelegationKeyPurpose.GATEWAY_PROBE.value,
        SecretUseIntent.GATEWAY_PROBE_SIGNING_KEY.value,
    ),
    (
        DelegationKeyPurpose.GATEWAY_NODE_CONTROL_TRANSIT.value,
        SecretUseIntent.GATEWAY_NODE_CONTROL_TRANSIT_SIGNING_KEY.value,
    ),
    (
        DelegationKeyPurpose.WORKLOAD_NODE_CONTROL.value,
        SecretUseIntent.WORKLOAD_NODE_CONTROL_SIGNING_KEY.value,
    ),
)


class NodeControlSigningFamilyTests(unittest.TestCase):
    def test_family_contract_matches_pinned_core_while_production_stays_core_free(
        self,
    ) -> None:
        project = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        production = tuple(project["dependencies"])
        test_dependencies = tuple(project["optional-dependencies"]["test"])

        self.assertFalse(
            any("control-plane-kit-core" in dependency for dependency in production)
        )
        self.assertEqual(
            tuple(
                dependency
                for dependency in test_dependencies
                if "control-plane-kit-core" in dependency
            ),
            (
                "control-plane-kit-core @ git+https://github.com/OpenJ92/"
                f"control-plane-kit.git@{CORE_COMMIT}"
                "#subdirectory=control-plane-kit-core",
            ),
        )
        imported = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; import control_plane_kit_secrets; "
                    "assert 'control_plane_kit_core' not in sys.modules"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)

        family_module = importlib.import_module(
            "control_plane_kit_secrets.delegation_signing"
        )
        self.assertEqual(
            {
                purpose: family_module.delegation_signing_intent_for(purpose)
                for purpose, _intent in FAMILIES
            },
            dict(FAMILIES),
        )
        for unsupported in (
            DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ.value,
            "unknown-purpose",
            None,
        ):
            with self.subTest(unsupported=unsupported):
                with self.assertRaises(SecretMetadataInvalid) as caught:
                    family_module.delegation_signing_intent_for(unsupported)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)

    def test_direct_store_rejects_unsupported_or_mismatched_family_before_writes(
        self,
    ) -> None:
        with _fixture() as fixture:
            candidates = (
                ("unknown-purpose", FAMILIES[0][1]),
                (FAMILIES[1][0], FAMILIES[2][1]),
                (FAMILIES[2][0], FAMILIES[0][1]),
            )
            for index, (purpose, intent) in enumerate(candidates):
                with self.subTest(purpose=purpose, intent=intent):
                    with self.assertRaises(SecretMetadataInvalid) as caught:
                        fixture.store.generate_delegation_key(
                            **fixture.arguments(
                                purpose=purpose,
                                intent=intent,
                                suffix=f"invalid-{index}",
                            ),
                            provider_id="provider-a",
                            audit_store=fixture.audit,
                        )
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertIsNone(caught.exception.__context__)
            self.assertEqual(fixture.store.raw_rows_for_tests(), [])
            self.assertEqual(fixture.audit.rows_for_tests(), [])

    def test_api_generates_and_resolves_all_three_exact_families(self) -> None:
        with _fixture() as fixture:
            for index, (purpose, intent) in enumerate(FAMILIES):
                with self.subTest(purpose=purpose):
                    generated = fixture.generate_api(
                        purpose=purpose,
                        suffix=f"family-{index}",
                    )
                    self.assertEqual(generated.status_code, 200, generated.text)
                    payload = generated.json()
                    self.assertEqual(payload["purpose"], purpose)
                    public_key = DelegationPublicKey(
                        key_id=payload["key_id"],
                        algorithm=DelegationKeyAlgorithm(payload["algorithm"]),
                        public_key_pem=payload["public_key_pem"],
                    )
                    self.assertEqual(
                        public_key.fingerprint_sha256,
                        payload["fingerprint_sha256"],
                    )

                    resolved = fixture.resolve_api(
                        secret_id=f"key-family-{index}",
                        intent=intent,
                        correlation_id=f"resolve-family-{index}",
                    )
                    self.assertEqual(resolved.status_code, 200, resolved.text)
                    private_key = serialization.load_pem_private_key(
                        base64.b64decode(resolved.json()["value_base64"]),
                        password=None,
                    )
                    parsed_public = serialization.load_pem_public_key(
                        payload["public_key_pem"].encode("ascii")
                    )
                    self.assertIsInstance(parsed_public, Ed25519PublicKey)
                    message = f"family-{index}".encode("ascii")
                    parsed_public.verify(private_key.sign(message), message)

    def test_resolution_rejects_cross_family_intent_substitution(self) -> None:
        with _fixture() as fixture:
            generated = fixture.generate_api(
                purpose=FAMILIES[1][0],
                suffix="transit",
            )
            self.assertEqual(generated.status_code, 200, generated.text)

            for _purpose, wrong_intent in (FAMILIES[0], FAMILIES[2]):
                with self.subTest(intent=wrong_intent):
                    denied = fixture.resolve_api(
                        secret_id="key-transit",
                        intent=wrong_intent,
                        correlation_id=f"wrong-{wrong_intent}",
                    )
                    self.assertEqual(denied.status_code, 403, denied.text)
                    self.assertEqual(
                        denied.json()["detail"]["code"],
                        "secret-intent-mismatch",
                    )
            self.assertEqual(
                fixture.resolve_api(
                    secret_id="key-transit",
                    intent=FAMILIES[1][1],
                    correlation_id="right-transit",
                ).status_code,
                200,
            )

    def test_restart_replay_preserves_family_and_public_identity(self) -> None:
        with _fixture() as fixture:
            arguments = fixture.arguments(
                purpose=FAMILIES[2][0],
                intent=FAMILIES[2][1],
                suffix="restart",
            )
            first = fixture.store.generate_delegation_key(
                **arguments,
                provider_id="provider-a",
                audit_store=fixture.audit,
            )
            restarted = fixture.restarted_store()
            replayed = restarted.generate_delegation_key(
                **arguments,
                provider_id="provider-a",
                audit_store=fixture.audit,
            )

            self.assertTrue(replayed.replayed)
            self.assertEqual(replayed.purpose, FAMILIES[2][0])
            self.assertEqual(replayed.key_id, first.key_id)
            self.assertEqual(replayed.public_key_pem, first.public_key_pem)
            self.assertEqual(
                [row["intent"] for row in fixture.audit.rows_for_tests()],
                [FAMILIES[2][1], FAMILIES[2][1]],
            )

    def test_same_correlation_converges_and_audits_the_admitted_intent(self) -> None:
        with _fixture() as fixture:
            arguments = fixture.arguments(
                purpose=FAMILIES[1][0],
                intent=FAMILIES[1][1],
                suffix="concurrent",
            )

            def generate(_index: int):
                return fixture.store.generate_delegation_key(
                    **arguments,
                    provider_id="provider-a",
                    audit_store=fixture.audit,
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                generated = tuple(executor.map(generate, range(4)))

            self.assertEqual({item.key_id for item in generated}, {generated[0].key_id})
            self.assertEqual(sum(not item.replayed for item in generated), 1)
            self.assertEqual(len(fixture.store.raw_rows_for_tests()), 1)
            self.assertEqual(
                {row["intent"] for row in fixture.audit.rows_for_tests()},
                {FAMILIES[1][1]},
            )

    def test_replay_rejects_generation_row_and_authenticated_family_drift(
        self,
    ) -> None:
        with _fixture() as fixture:
            original = fixture.arguments(
                purpose=FAMILIES[1][0],
                intent=FAMILIES[1][1],
                suffix="drift",
            )
            fixture.store.generate_delegation_key(
                **original,
                provider_id="provider-a",
                audit_store=fixture.audit,
            )
            with closing(sqlite3.connect(fixture.database_path)) as connection:
                with connection:
                    connection.execute(
                        """
                        UPDATE delegation_key_generations
                        SET purpose = ?
                        WHERE workspace_id = ? AND correlation_id = ?
                        """,
                        (
                            FAMILIES[2][0],
                            original["workspace_id"],
                            original["correlation_id"],
                        ),
                    )

            with self.assertRaises(SecretTampered) as caught:
                fixture.store.generate_delegation_key(
                    **{**original, "purpose": FAMILIES[2][0], "intent": FAMILIES[2][1]},
                    provider_id="provider-a",
                    audit_store=fixture.audit,
                )
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

    def test_generation_response_audit_and_plaintext_rows_exclude_private_material(
        self,
    ) -> None:
        with _fixture() as fixture:
            generated = fixture.generate_api(
                purpose=FAMILIES[2][0],
                suffix="redaction",
            )
            self.assertEqual(generated.status_code, 200, generated.text)
            resolved = fixture.resolve_api(
                secret_id="key-redaction",
                intent=FAMILIES[2][1],
                correlation_id="resolve-redaction",
            )
            self.assertEqual(resolved.status_code, 200, resolved.text)
            private_pem = base64.b64decode(resolved.json()["value_base64"])

            with closing(sqlite3.connect(fixture.database_path)) as connection:
                database_dump = "\n".join(connection.iterdump())
            evidence = generated.text + repr(fixture.audit.rows_for_tests()) + database_dump
            self.assertNotIn("BEGIN PRIVATE KEY", evidence)
            self.assertNotIn(private_pem.decode("ascii"), evidence)
            self.assertNotIn("value_base64", generated.text)


class _Fixture:
    def __init__(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.base = Path(self._directory.name)
        key_path = self.base / "master.key"
        key_path.write_text(
            encode_master_key_for_file(os.urandom(32)),
            encoding="utf-8",
        )
        self.master_key = load_master_key_file(key_path, version="test")
        self.database_path = self.base / "secrets.sqlite3"
        self.store = EncryptedSecretStore(
            self.database_path,
            master_key=self.master_key,
        )
        self.store.initialize()
        self.audit = SqliteAuditStore(self.database_path)
        self.audit.initialize()
        intents = tuple(intent for _purpose, intent in FAMILIES)
        self.client = TestClient(
            create_app(
                store=self.store,
                audit_store=self.audit,
                credentials=(
                    ProviderCredential(
                        subject="generator",
                        token="generation-token",
                        grants=(
                            ProviderGrant(
                                "secret.generate-delegation-key",
                                "workspace-1",
                                intents,
                            ),
                        ),
                    ),
                    ProviderCredential(
                        subject="resolver",
                        token="resolver-token",
                        grants=(
                            ProviderGrant("secret.resolve", "workspace-1", intents),
                        ),
                    ),
                ),
            )
        )

    def __enter__(self) -> _Fixture:
        return self

    def __exit__(self, *args: object) -> None:
        self.client.close()
        self._directory.cleanup()

    def arguments(
        self,
        *,
        purpose: str,
        intent: str,
        suffix: str,
    ) -> dict[str, str]:
        return {
            "workspace_id": "workspace-1",
            "secret_id": f"key-{suffix}",
            "secret_reference": f"secret://workspace-secrets/keys/{suffix}",
            "purpose": purpose,
            "intent": intent,
            "issuer": "cpk-server",
            "caller_subject": "cpk-server",
            "correlation_id": f"generation-{suffix}",
        }

    def generate_api(self, *, purpose: str, suffix: str):
        return self.client.post(
            f"/v1/workspaces/workspace-1/delegation-keys/key-{suffix}/generate",
            headers={"Authorization": "Bearer generation-token"},
            json={
                "secret_reference": f"secret://workspace-secrets/keys/{suffix}",
                "purpose": purpose,
                "issuer": "cpk-server",
                "caller_subject": "cpk-server",
                "correlation_id": f"generation-{suffix}",
            },
        )

    def resolve_api(
        self,
        *,
        secret_id: str,
        intent: str,
        correlation_id: str,
    ):
        return self.client.post(
            f"/v1/workspaces/workspace-1/secrets/{secret_id}/resolve",
            headers={"Authorization": "Bearer resolver-token"},
            json={
                "intent": intent,
                "caller_subject": "signing-effect",
                "correlation_id": correlation_id,
            },
        )

    def restarted_store(self) -> EncryptedSecretStore:
        store = EncryptedSecretStore(
            self.database_path,
            master_key=self.master_key,
        )
        store.initialize()
        return store


def _fixture() -> _Fixture:
    return _Fixture()


if __name__ == "__main__":
    unittest.main()
