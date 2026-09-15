from __future__ import annotations

import base64
import importlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
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
from control_plane_kit_secrets.audit import AuditUnavailable, SqliteAuditStore
from control_plane_kit_secrets.auth import ProviderCredential, ProviderGrant
from control_plane_kit_secrets.crypto import (
    encode_master_key_for_file,
    load_master_key_file,
)
from control_plane_kit_secrets.models import (
    DelegationKeyGenerationConflict, SecretMetadataInvalid, SecretRevoked, SecretTampered,
)
from control_plane_kit_secrets import store as store_module
from control_plane_kit_secrets.store import EncryptedSecretStore
from control_plane_kit_secrets import control as control_module
from control_fixtures import ControlAuthority


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


HEALTH_FAMILIES = (
    (DelegationKeyPurpose.GATEWAY_NODE_HEALTH_READ_TRANSIT.value,
     SecretUseIntent.GATEWAY_NODE_HEALTH_READ_TRANSIT_SIGNING_KEY.value),
    (DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ.value,
     SecretUseIntent.WORKLOAD_NODE_HEALTH_READ_SIGNING_KEY.value),
)
FAMILIES += HEALTH_FAMILIES


class NodeControlSigningFamilyTests(unittest.TestCase):
    def test_family_contract_matches_pinned_core_while_source_and_root_stay_core_free(
        self,
    ) -> None:
        # #25 replaces the old test-only Core packaging assertion with the
        # explicit runtime/provenance laws in test_sdk_compatibility. Source
        # ownership, root imports and the closed signing-family behavior remain.
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
            "control_plane_kit_secrets._delegation_signing"
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
                (HEALTH_FAMILIES[0][0], HEALTH_FAMILIES[1][1]),
                (HEALTH_FAMILIES[1][0], HEALTH_FAMILIES[0][1]),
                (HEALTH_FAMILIES[0][0], FAMILIES[1][1]),
                (FAMILIES[2][0], HEALTH_FAMILIES[1][1]),
            )
            for index, (purpose, intent) in enumerate(candidates):
                with self.subTest(purpose=purpose, intent=intent):
                    with patch.object(fixture.store, "_connection", side_effect=AssertionError(
                        "invalid family reached custody"
                    )) as protected, self.assertRaises(SecretMetadataInvalid) as caught:
                        fixture.store.generate_delegation_key(
                            **fixture.arguments(
                                purpose=purpose,
                                intent=intent,
                                suffix=f"invalid-{index}",
                            ),
                            provider_id="provider-a",
                            audit_store=fixture.audit,
                        )
                    protected.assert_not_called()
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertIsNone(caught.exception.__context__)
            self.assertEqual(fixture.store.raw_rows_for_tests(), [])
            self.assertEqual(fixture.audit.rows_for_tests(), [])

    def test_api_generates_and_resolves_all_five_exact_families(self) -> None:
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
        for purpose, intent in (FAMILIES[2], *HEALTH_FAMILIES):
            with self.subTest(purpose=purpose):
                with _fixture() as fixture:
                    arguments = fixture.arguments(
                        purpose=purpose,
                        intent=intent,
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
                    self.assertEqual(replayed.purpose, purpose)
                    self.assertEqual(replayed.key_id, first.key_id)
                    self.assertEqual(replayed.public_key_pem, first.public_key_pem)
                    self.assertEqual(
                        [row["intent"] for row in fixture.audit.rows_for_tests()],
                        [intent, intent],
                    )

    def test_same_correlation_converges_and_audits_the_admitted_intent(self) -> None:
        for purpose, intent in (FAMILIES[1], *HEALTH_FAMILIES):
            with self.subTest(purpose=purpose):
                with _fixture() as fixture:
                    arguments = fixture.arguments(
                        purpose=purpose,
                        intent=intent,
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
                        {intent},
                    )

    def test_replay_rejects_generation_row_and_authenticated_family_drift(
        self,
    ) -> None:
        for purpose, intent in (FAMILIES[1], *HEALTH_FAMILIES):
            with self.subTest(purpose=purpose):
                for corrupted_labels in (False, True):
                    with self.subTest(corrupted_labels=corrupted_labels), _fixture() as fixture:
                        original = fixture.arguments(
                            purpose=purpose,
                            intent=intent,
                            suffix="drift",
                        )
                        fixture.store.generate_delegation_key(
                            **original,
                            provider_id="provider-a",
                            audit_store=fixture.audit,
                        )
                        with closing(sqlite3.connect(fixture.database_path)) as connection:
                            with connection:
                                if corrupted_labels:
                                    connection.execute(
                                        """
                                        UPDATE secret_versions
                                        SET labels_json = ?
                                        WHERE workspace_id = ? AND secret_id = ?
                                        """,
                                        (
                                            "{",
                                            original["workspace_id"],
                                            original["secret_id"],
                                        ),
                                    )
                                else:
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

                        replay = original
                        if not corrupted_labels:
                            replay = {
                                **original,
                                "purpose": FAMILIES[2][0],
                                "intent": FAMILIES[2][1],
                            }
                        with self.assertRaises(SecretTampered) as caught:
                            fixture.store.generate_delegation_key(
                                **replay,
                                provider_id="provider-a",
                                audit_store=fixture.audit,
                            )
                        self.assertIsNone(caught.exception.__cause__)
                        self.assertIsNone(caught.exception.__context__)

    def test_replay_bounds_persisted_public_identity_before_crypto(self) -> None:
        self.assertEqual(store_module.MAX_DELEGATION_PUBLIC_KEY_PEM_CHARS, 8192)
        self.assertEqual(store_module.MAX_DELEGATION_KEY_ID_CHARS, 128)
        store_module._require_bounded_delegation_public_identity(
            public_key_pem="p" * 8192,
            key_id="k" * 128,
        )
        for public_key_pem, key_id in (
            ("p" * 8193, "key-id"),
            ("public", "k" * 129),
        ):
            with self.subTest(
                public_key_pem_chars=len(public_key_pem),
                key_id_chars=len(key_id),
            ):
                with self.assertRaises(SecretTampered) as caught:
                    store_module._require_bounded_delegation_public_identity(
                        public_key_pem=public_key_pem,
                        key_id=key_id,
                    )
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)

        original_material_matches = store_module._delegation_material_matches

        def fail_if_material_matching_is_reached(**_values: object) -> bool:
            raise AssertionError("delegation material matching must not be reached")

        store_module._delegation_material_matches = fail_if_material_matching_is_reached
        try:
            for column, oversized in (
                ("public_key_pem", "p" * 8193),
                ("key_id", "k" * 129),
            ):
                with self.subTest(column=column), _fixture() as fixture:
                    original = fixture.arguments(
                        purpose=FAMILIES[1][0],
                        intent=FAMILIES[1][1],
                        suffix=f"oversized-{column}",
                    )
                    fixture.store.generate_delegation_key(
                        **original,
                        provider_id="provider-a",
                        audit_store=fixture.audit,
                    )
                    with closing(sqlite3.connect(fixture.database_path)) as connection:
                        with connection:
                            connection.execute(
                                f"""
                                UPDATE delegation_key_generations
                                SET {column} = ?
                                WHERE workspace_id = ? AND correlation_id = ?
                                """,
                                (
                                    oversized,
                                    original["workspace_id"],
                                    original["correlation_id"],
                                ),
                            )

                    with self.assertRaises(SecretTampered):
                        fixture.store.generate_delegation_key(
                            **original,
                            provider_id="provider-a",
                            audit_store=fixture.audit,
                        )
        finally:
            store_module._delegation_material_matches = original_material_matches

    def test_generation_response_audit_and_plaintext_rows_exclude_private_material(
        self,
    ) -> None:
        for purpose, intent in (FAMILIES[2], *HEALTH_FAMILIES):
            with self.subTest(purpose=purpose):
                with _fixture() as fixture:
                    generated = fixture.generate_api(
                        purpose=purpose,
                        suffix="redaction",
                    )
                    self.assertEqual(generated.status_code, 200, generated.text)
                    resolved = fixture.resolve_api(
                        secret_id="key-redaction",
                        intent=intent,
                        correlation_id="resolve-redaction",
                    )
                    self.assertEqual(resolved.status_code, 200, resolved.text)
                    private_pem = base64.b64decode(resolved.json()["value_base64"])

                    with closing(sqlite3.connect(fixture.database_path)) as connection:
                        database_dump = "\n".join(connection.iterdump())
                    evidence = generated.text + repr(fixture.audit.rows_for_tests()) + database_dump
                    self.assertTrue("BEGIN PRIVATE KEY" not in evidence, "private material marker leaked")
                    self.assertTrue(private_pem.decode("ascii") not in evidence, "private material leaked")
                    self.assertNotIn("value_base64", generated.text)


    def test_health_scope_denial_precedes_protected_store_calls(self) -> None:
        for purpose, intent in HEALTH_FAMILIES:
            with self.subTest(purpose=purpose), _fixture(
                allowed_intents=tuple(value for _, value in FAMILIES if value != intent),
            ) as fixture:
                with patch.object(fixture.store, "generate_delegation_key", side_effect=AssertionError(
                    "scope denial reached generation"
                )) as generate, patch.object(fixture.store, "resolve_secret_for_use", side_effect=AssertionError(
                    "scope denial reached resolution"
                )) as resolve:
                    denied = fixture.generate_api(purpose=purpose, suffix="denied")
                    self.assertEqual(denied.status_code, 403)
                    self.assertEqual(denied.json()["detail"]["code"], "insufficient-scope")
                    denied = fixture.resolve_api(secret_id="key-denied", intent=intent,
                                                 correlation_id="resolve-denied")
                    self.assertEqual(denied.status_code, 403)
                    self.assertEqual(denied.json()["detail"]["code"], "insufficient-scope")
                    generate.assert_not_called()
                    resolve.assert_not_called()
                self.assertEqual(fixture.store.raw_rows_for_tests(), [])
                self.assertEqual([row["outcome"] for row in fixture.audit.rows_for_tests()],
                                 ["denied", "denied"])

    def test_health_cross_family_resolution_never_decrypts_or_selects(self) -> None:
        for purpose, intent in HEALTH_FAMILIES:
            with self.subTest(purpose=purpose), _fixture() as fixture:
                self.assertEqual(fixture.generate_api(purpose=purpose, suffix="health").status_code, 200)
                with patch.object(fixture.store, "_decrypt_row", side_effect=AssertionError(
                    "wrong family reached decryption"
                )) as decrypt:
                    for index, (_, wrong_intent) in enumerate(FAMILIES):
                        if wrong_intent == intent:
                            continue
                        denied = fixture.resolve_api(secret_id="key-health", intent=wrong_intent,
                                                     correlation_id=f"wrong-health-{index}")
                        self.assertEqual(denied.status_code, 403)
                        self.assertEqual(denied.json()["detail"]["code"], "secret-intent-mismatch")
                        self.assertNotIn("value_base64", denied.json())
                    decrypt.assert_not_called()
                with closing(sqlite3.connect(fixture.database_path)) as connection:
                    self.assertEqual(connection.execute(
                        "SELECT count(*) FROM secret_resolution_selections"
                    ).fetchone()[0], 0)
                self.assertEqual([row["outcome"] for row in fixture.audit.rows_for_tests()],
                                 ["generated", *(["denied"] * 4)])
                self.assertEqual(fixture.resolve_api(secret_id="key-health", intent=intent,
                                                    correlation_id="right-health").status_code, 200)

    def test_health_generation_conflicts_and_revoked_replay_refuse(self) -> None:
        for purpose, intent in HEALTH_FAMILIES:
            with self.subTest(purpose=purpose), _fixture() as fixture:
                arguments = fixture.arguments(purpose=purpose, intent=intent, suffix="replay")
                fixture.store.generate_delegation_key(**arguments, provider_id="provider-a",
                                                     audit_store=fixture.audit)
                for changes in ({"caller_subject": "other-caller"},
                                {"purpose": FAMILIES[0][0], "intent": FAMILIES[0][1]}):
                    with self.assertRaises(DelegationKeyGenerationConflict):
                        fixture.store.generate_delegation_key(**{**arguments, **changes},
                            provider_id="provider-a", audit_store=fixture.audit)
                self.assertEqual(len(fixture.store.raw_rows_for_tests()), 1)
                self.assertEqual([row["outcome"] for row in fixture.audit.rows_for_tests()], ["generated"])
                fixture.store.revoke_secret(workspace_id="workspace-1", secret_id="key-replay")
                with self.assertRaises(SecretRevoked):
                    fixture.store.generate_delegation_key(**arguments, provider_id="provider-a",
                                                         audit_store=fixture.audit)

    def test_health_generation_audit_failure_rolls_back_custody_and_correlation(self) -> None:
        for purpose, intent in HEALTH_FAMILIES:
            with self.subTest(purpose=purpose), _fixture() as fixture:
                with patch.object(fixture.audit, "append_in_transaction", side_effect=AuditUnavailable):
                    failed = fixture.generate_api(purpose=purpose, suffix="atomic")
                self.assertEqual(failed.status_code, 503)
                self.assertEqual(failed.json()["detail"]["code"], "audit-unavailable")
                self.assertEqual(fixture.store.raw_rows_for_tests(), [])
                self.assertEqual(fixture.audit.rows_for_tests(), [])
                with closing(sqlite3.connect(fixture.database_path)) as connection:
                    self.assertEqual(connection.execute(
                        "SELECT count(*) FROM delegation_key_generations"
                    ).fetchone()[0], 0)
                retry = fixture.generate_api(purpose=purpose, suffix="atomic")
                self.assertEqual(retry.status_code, 200)
                self.assertEqual([row["outcome"] for row in fixture.audit.rows_for_tests()], ["generated"])


class _Fixture:
    def __init__(self, *, allowed_intents: tuple[str, ...] | None = None) -> None:
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
        intents = (tuple(intent for _purpose, intent in FAMILIES)
                   if allowed_intents is None else allowed_intents)
        self.client = TestClient(
            create_app(
                control=ControlAuthority().configuration(control_module),
                clock=lambda: 150,
                initialize_provider=lambda: (self.store, self.audit, (
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
                )),
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


def _fixture(*, allowed_intents: tuple[str, ...] | None = None) -> _Fixture:
    return _Fixture(allowed_intents=allowed_intents)


if __name__ == "__main__":
    unittest.main()
