from __future__ import annotations

import base64
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from control_plane_kit_secrets.api import create_app
from control_plane_kit_secrets.audit import AuditUnavailable, SqliteAuditStore
from control_plane_kit_secrets.auth import ProviderCredential, ProviderGrant
from control_plane_kit_secrets.crypto import encode_master_key_for_file, load_master_key_file
from control_plane_kit_secrets.models import SecretMissing
from control_plane_kit_secrets.store import EncryptedSecretStore


class ProviderApiTests(unittest.TestCase):
    def test_provider_generates_delegation_key_and_returns_only_public_material(
        self,
    ) -> None:
        with _client() as fixture:
            response = fixture.generate_delegation_key()

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["outcome"], "generated")
            self.assertEqual(payload["purpose"], "gateway-probe")
            self.assertEqual(payload["algorithm"], "ed25519")
            self.assertEqual(payload["correlation_id"], "rotation-key-b")
            self.assertIn("BEGIN PUBLIC KEY", payload["public_key_pem"])
            self.assertNotIn("PRIVATE", response.text)
            self.assertNotIn("value_base64", response.text)

            resolved = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/gateway-key-b/resolve",
                headers=fixture.headers("resolver-token"),
                json={
                    "intent": "gateway.probe-signing-key",
                    "caller_subject": "gateway-probe-signer",
                    "correlation_id": "sign-generated-key-b",
                },
            )
            self.assertEqual(resolved.status_code, 200, resolved.text)
            private_key = serialization.load_pem_private_key(
                base64.b64decode(resolved.json()["value_base64"]),
                password=None,
            )
            public_key = serialization.load_pem_public_key(
                payload["public_key_pem"].encode("ascii")
            )
            self.assertIsInstance(public_key, Ed25519PublicKey)
            message = b"bounded-gateway-probe"
            signature = private_key.sign(message)
            public_key.verify(signature, message)
            self.assertNotIn("BEGIN PRIVATE KEY", repr(fixture.audit_rows()))

    def test_generation_correlation_is_idempotent_and_semantically_pinned(
        self,
    ) -> None:
        with _client() as fixture:
            first = fixture.generate_delegation_key()
            replay = fixture.generate_delegation_key()
            conflict = fixture.generate_delegation_key(issuer="other-issuer")

            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertEqual(
                first.json()["public_key_pem"], replay.json()["public_key_pem"]
            )
            self.assertEqual(first.json()["key_id"], replay.json()["key_id"])
            self.assertFalse(first.json()["replayed"])
            self.assertTrue(replay.json()["replayed"])
            self.assertEqual(conflict.status_code, 409, conflict.text)
            self.assertEqual(
                conflict.json()["detail"]["code"],
                "generation-correlation-conflict",
            )
            self.assertEqual(len(fixture.store.raw_rows_for_tests()), 1)

    def test_generation_permission_is_distinct_from_write_and_execution(self) -> None:
        with _client() as fixture:
            for token in ("writer-token", "execution-token"):
                with self.subTest(token=token):
                    response = fixture.generate_delegation_key(token=token)
                    self.assertEqual(response.status_code, 403, response.text)
            wrong_workspace = fixture.generate_delegation_key(
                workspace_id="workspace-2"
            )
            unsupported_purpose = fixture.generate_delegation_key(
                purpose="arbitrary-signing"
            )
            self.assertEqual(wrong_workspace.status_code, 403, wrong_workspace.text)
            self.assertEqual(
                unsupported_purpose.status_code,
                400,
                unsupported_purpose.text,
            )
            generated = fixture.generate_delegation_key()
            self.assertEqual(generated.status_code, 200, generated.text)

    def test_duplicate_secret_identity_and_revoked_replay_are_bounded(self) -> None:
        with _client() as fixture:
            generated = fixture.generate_delegation_key()
            duplicate = fixture.generate_delegation_key(correlation_id="other-key")
            self.assertEqual(generated.status_code, 200, generated.text)
            self.assertEqual(duplicate.status_code, 409, duplicate.text)
            self.assertEqual(
                duplicate.json()["detail"]["code"], "secret-already-exists"
            )

            revoked = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/gateway-key-b/revoke",
                headers=fixture.headers("revoke-token"),
                json={
                    "caller_subject": "cpk-server",
                    "correlation_id": "revoke-key-b",
                },
            )
            replay = fixture.generate_delegation_key()
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertEqual(replay.status_code, 409, replay.text)
            self.assertEqual(replay.json()["detail"]["code"], "secret-revoked")

    def test_atomic_audit_failure_rolls_back_generated_private_custody(self) -> None:
        with _client(audit_store_factory=lambda _path: _FailingAuditStore()) as fixture:
            response = fixture.generate_delegation_key()

            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(response.json()["detail"]["code"], "audit-unavailable")
            self.assertEqual(fixture.store.raw_rows_for_tests(), [])
            with self.assertRaises(SecretMissing):
                fixture.store.metadata(
                    workspace_id="workspace-1",
                    secret_id="gateway-key-b",
                )

    def test_write_and_metadata_read_are_authenticated_and_redacted(self) -> None:
        with _client() as fixture:
            sentinel = b"cloudflare-api-token-super-secret"
            response = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/cloudflare-token",
                headers=fixture.headers("writer-token"),
                json={
                    "value_base64": _b64(sentinel),
                    "intent": "cloudflare.api-token",
                    "labels": {"intent": "cloudflare.api-token"},
                },
            )

            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["outcome"], "stored")
            self.assertNotIn(sentinel.decode("ascii"), response.text)
            self.assertNotIn(sentinel.decode("ascii"), repr(fixture.audit_rows()))

            metadata = fixture.client.get(
                "/v1/workspaces/workspace-1/secrets/cloudflare-token/metadata",
                headers=fixture.headers("metadata-token"),
            )

            self.assertEqual(metadata.status_code, 200, metadata.text)
            self.assertEqual(metadata.json()["metadata"]["secret_id"], "cloudflare-token")
            self.assertEqual(
                metadata.json()["metadata"]["labels"]["intent"],
                "cloudflare.api-token",
            )
            self.assertNotIn("value_base64", metadata.text)
            self.assertNotIn(sentinel.decode("ascii"), metadata.text)
            self.assertEqual(
                [row["outcome"] for row in fixture.audit_rows()],
                ["stored", "metadata"],
            )
            self.assertEqual(
                fixture.audit_rows()[0]["intent"],
                "cloudflare.api-token",
            )

    def test_resolve_requires_authentication_scope_and_intent(self) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="gateway-key",
                value=b"gateway-signing-key",
                intent="gateway.probe-signing-key",
            )

            unauthenticated = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/gateway-key/resolve",
                json=_resolve_body("gateway.probe-signing-key"),
            )
            self.assertEqual(unauthenticated.status_code, 401)

            wrong_action = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/gateway-key/resolve",
                headers=fixture.headers("metadata-token"),
                json=_resolve_body("gateway.probe-signing-key"),
            )
            self.assertEqual(wrong_action.status_code, 403)

            wrong_intent = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/gateway-key/resolve",
                headers=fixture.headers("resolver-token"),
                json=_resolve_body("cloudflare.api-token"),
            )
            self.assertEqual(wrong_intent.status_code, 403)

            resolved = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/gateway-key/resolve",
                headers=fixture.headers("resolver-token"),
                json=_resolve_body("gateway.probe-signing-key"),
            )

            self.assertEqual(resolved.status_code, 200, resolved.text)
            self.assertEqual(resolved.json()["outcome"], "resolved")
            self.assertEqual(
                base64.b64decode(resolved.json()["value_base64"]),
                b"gateway-signing-key",
            )
            self.assertEqual(
                [row["outcome"] for row in fixture.audit_rows()],
                ["stored", "denied", "denied", "denied", "resolved"],
            )
            self.assertNotIn("gateway-signing-key", repr(fixture.audit_rows()))

    def test_execution_permission_does_not_grant_secret_resolution(self) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="postgres-password",
                value=b"postgres-password",
                intent="postgres.password",
            )

            response = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/postgres-password/resolve",
                headers=fixture.headers("execution-token"),
                json=_resolve_body("postgres.password"),
            )

            self.assertEqual(response.status_code, 403)
            self.assertNotIn("postgres-password", response.text)
            self.assertIn("denied", [row["outcome"] for row in fixture.audit_rows()])

    def test_missing_resolve_is_audited_and_bounded(self) -> None:
        with _client() as fixture:
            response = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/missing/resolve",
                headers=fixture.headers("oci-resolver-token"),
                json=_resolve_body("oci.pull-credential"),
            )

            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json()["detail"]["outcome"], "missing")
            self.assertEqual(
                [row["outcome"] for row in fixture.audit_rows()],
                ["missing"],
            )

    def test_rotate_revoke_and_revoked_resolve_are_bounded(self) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="oci-token",
                value=b"old-oci-token",
            )
            rotated = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/rotate",
                headers=fixture.headers("rotate-token"),
                json={
                    "value_base64": _b64(b"new-oci-token"),
                    "intent": "oci.pull-credential",
                    "labels": {},
                },
            )
            self.assertEqual(rotated.status_code, 200, rotated.text)
            self.assertEqual(rotated.json()["metadata"]["version_number"], 2)
            self.assertNotIn("new-oci-token", rotated.text)

            revoked = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/revoke",
                headers=fixture.headers("revoke-token"),
                json={
                    "caller_subject": "cpk-cloudflare-interpreter",
                    "correlation_id": "generated-secret-compensation-1",
                },
            )
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertEqual(revoked.json()["outcome"], "revoked")
            self.assertNotIn("new-oci-token", revoked.text)
            revoke_rows = [
                row
                for row in fixture.audit_rows()
                if row["outcome"] == "revoked"
            ]
            self.assertEqual(
                {
                    (row["caller_subject"], row["correlation_id"])
                    for row in revoke_rows
                },
                {
                    (
                        "cpk-cloudflare-interpreter",
                        "generated-secret-compensation-1",
                    )
                },
            )

            resolved = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/resolve",
                headers=fixture.headers("oci-resolver-token"),
                json=_resolve_body("oci.pull-credential"),
            )
            self.assertEqual(resolved.status_code, 409)
            self.assertNotIn("new-oci-token", resolved.text)
            self.assertEqual(
                [row["outcome"] for row in fixture.audit_rows()],
                ["stored", "rotated", "revoked", "revoked", "revoked"],
            )
            self.assertEqual(
                {
                    row["intent"]
                    for row in fixture.audit_rows()
                    if row["outcome"] in {"stored", "rotated", "revoked"}
                },
                {"oci.pull-credential"},
            )

    def test_resolve_correlation_pins_version_and_rejects_semantic_reuse(
        self,
    ) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="oci-token",
                value=b"version-a",
            )
            first = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/resolve",
                headers=fixture.headers("oci-resolver-token"),
                json=_resolve_body("oci.pull-credential"),
            )
            rotated = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/rotate",
                headers=fixture.headers("rotate-token"),
                json={
                    "value_base64": _b64(b"version-b"),
                    "intent": "oci.pull-credential",
                    "labels": {},
                },
            )
            replay = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/resolve",
                headers=fixture.headers("oci-resolver-token"),
                json=_resolve_body("oci.pull-credential"),
            )
            next_effect = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/resolve",
                headers=fixture.headers("oci-resolver-token"),
                json={
                    **_resolve_body("oci.pull-credential"),
                    "correlation_id": "operation-session-2",
                },
            )
            mismatch = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/oci-token/resolve",
                headers=fixture.headers("oci-resolver-token"),
                json={
                    **_resolve_body("oci.pull-credential"),
                    "caller_subject": "another-worker",
                },
            )

            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(rotated.status_code, 200, rotated.text)
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertEqual(next_effect.status_code, 200, next_effect.text)
            self.assertEqual(
                replay.json()["metadata"]["version_id"],
                first.json()["metadata"]["version_id"],
            )
            self.assertEqual(
                next_effect.json()["metadata"]["version_id"],
                rotated.json()["metadata"]["version_id"],
            )
            self.assertEqual(mismatch.status_code, 409, mismatch.text)
            self.assertEqual(
                mismatch.json()["detail"]["code"],
                "resolution-correlation-conflict",
            )
            self.assertNotIn("version-a", repr(fixture.audit_rows()))
            self.assertNotIn("version-b", repr(fixture.audit_rows()))

    def test_revoke_remains_compatible_without_a_request_body(self) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="legacy-revoke",
                value=b"legacy-revoke-value",
            )

            response = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/legacy-revoke/revoke",
                headers=fixture.headers("revoke-token"),
            )

            self.assertEqual(response.status_code, 200, response.text)
            row = fixture.audit_rows()[-1]
            self.assertEqual(row["caller_subject"], "revoker")
            self.assertEqual(row["correlation_id"], "not-provided")

    def test_malformed_oversized_and_unsupported_intent_are_bounded(self) -> None:
        with _client() as fixture:
            malformed = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/bad",
                headers=fixture.headers("writer-token"),
                json={
                    "value_base64": "not base64!",
                    "intent": "oci.pull-credential",
                    "labels": {},
                },
            )
            self.assertEqual(malformed.status_code, 400)

            oversized_secret = b"x" * (64 * 1024 + 1)
            oversized = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/too-large",
                headers=fixture.headers("writer-token"),
                json={
                    "value_base64": _b64(oversized_secret),
                    "intent": "oci.pull-credential",
                    "labels": {},
                },
            )
            self.assertEqual(oversized.status_code, 400)
            self.assertNotIn("x" * 100, oversized.text)

            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="valid",
                value=b"value",
            )
            unsupported_intent = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/valid/resolve",
                headers=fixture.headers("resolver-token"),
                json=_resolve_body("freeform.give-me-string"),
            )
            self.assertEqual(unsupported_intent.status_code, 400)
            self.assertIn("malformed", [row["outcome"] for row in fixture.audit_rows()])

    def test_duplicate_write_is_bounded_and_redacted(self) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="duplicate",
                value=b"first-secret-value",
            )
            response = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/duplicate",
                headers=fixture.headers("writer-token"),
                json={
                    "value_base64": _b64(b"second-secret-value"),
                    "intent": "oci.pull-credential",
                    "labels": {},
                },
            )

            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.json()["detail"]["outcome"], "already-exists")
            self.assertNotIn("second-secret-value", response.text)
            self.assertIn("already-exists", [row["outcome"] for row in fixture.audit_rows()])

    def test_write_intent_is_required_authorized_and_canonical(self) -> None:
        with _client() as fixture:
            missing = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/missing-intent",
                headers=fixture.headers("writer-token"),
                json={"value_base64": _b64(b"value"), "labels": {}},
            )
            unsupported = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/unsupported-intent",
                headers=fixture.headers("writer-token"),
                json={
                    "value_base64": _b64(b"value"),
                    "intent": "freeform.intent",
                    "labels": {},
                },
            )
            denied = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/denied-intent",
                headers=fixture.headers("postgres-writer-token"),
                json={
                    "value_base64": _b64(b"value"),
                    "intent": "cloudflare.api-token",
                    "labels": {},
                },
            )
            conflicting = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/conflicting-intent",
                headers=fixture.headers("writer-token"),
                json={
                    "value_base64": _b64(b"value"),
                    "intent": "cloudflare.api-token",
                    "labels": {"intent": "postgres.password"},
                },
            )

            self.assertEqual(missing.status_code, 422)
            self.assertEqual(unsupported.status_code, 400)
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(conflicting.status_code, 400)
            self.assertEqual(
                [
                    (row["outcome"], row["intent"])
                    for row in fixture.audit_rows()
                    if row["secret_id"] in {
                        "unsupported-intent",
                        "denied-intent",
                        "conflicting-intent",
                    }
                ],
                [
                    ("malformed", "freeform.intent"),
                    ("denied", "cloudflare.api-token"),
                    ("malformed", "cloudflare.api-token"),
                ],
            )

    def test_rotate_and_resolve_cannot_change_durable_intent(self) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="intent-bound",
                value=b"intent-bound-value",
                intent="oci.pull-credential",
            )
            rotated = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/intent-bound/rotate",
                headers=fixture.headers("rotate-token"),
                json={
                    "value_base64": _b64(b"changed-value"),
                    "intent": "cloudflare.api-token",
                    "labels": {},
                },
            )
            resolved = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/intent-bound/resolve",
                headers=fixture.headers("resolver-token"),
                json=_resolve_body("gateway.probe-signing-key"),
            )

            self.assertEqual(rotated.status_code, 409)
            self.assertEqual(resolved.status_code, 403)
            metadata = fixture.client.get(
                "/v1/workspaces/workspace-1/secrets/intent-bound/metadata",
                headers=fixture.headers("metadata-token"),
            )
            self.assertEqual(metadata.json()["metadata"]["version_number"], 1)
            self.assertEqual(
                metadata.json()["metadata"]["labels"]["intent"],
                "oci.pull-credential",
            )
            self.assertIn(
                ("already-exists", "cloudflare.api-token", "secret-intent-conflict"),
                {
                    (row["outcome"], row["intent"], row["code"])
                    for row in fixture.audit_rows()
                },
            )
            self.assertIn(
                ("denied", "gateway.probe-signing-key", "secret-intent-mismatch"),
                {
                    (row["outcome"], row["intent"], row["code"])
                    for row in fixture.audit_rows()
                },
            )

    def test_audit_failure_blocks_resolve_material(self) -> None:
        with _client(audit_store_factory=lambda _path: _FailingAuditStore()) as fixture:
            fixture.store.create_secret(
                workspace_id="workspace-1",
                secret_id="gateway-key",
                value=b"gateway-signing-key",
            )

            response = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/gateway-key/resolve",
                headers=fixture.headers("resolver-token"),
                json=_resolve_body("gateway.probe-signing-key"),
            )

            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["detail"]["code"], "audit-unavailable")
            self.assertNotIn("gateway-signing-key", response.text)


class _ApiFixture:
    def __init__(
        self,
        *,
        audit_store_factory: object | None = None,
    ) -> None:
        self._directory = tempfile.TemporaryDirectory()
        base = Path(self._directory.name)
        key_path = base / "master.key"
        key_path.write_text(
            encode_master_key_for_file(os.urandom(32)),
            encoding="utf-8",
        )
        store = EncryptedSecretStore(
            base / "secrets.sqlite3",
            master_key=load_master_key_file(key_path, version="test"),
        )
        store.initialize()
        self.store = store
        if audit_store_factory is None:
            self.audit_store = SqliteAuditStore(base / "secrets.sqlite3")
        else:
            self.audit_store = audit_store_factory(base / "secrets.sqlite3")
        self.audit_store.initialize()
        self.client = TestClient(
            create_app(
                store=store,
                audit_store=self.audit_store,
                credentials=(
                    ProviderCredential(
                        subject="writer",
                        token="writer-token",
                        grants=(
                            ProviderGrant(
                                "secret.write",
                                "workspace-1",
                                (
                                    "cloudflare.api-token",
                                    "gateway.probe-signing-key",
                                    "oci.pull-credential",
                                    "postgres.password",
                                ),
                            ),
                        ),
                    ),
                    ProviderCredential(
                        subject="postgres-writer",
                        token="postgres-writer-token",
                        grants=(
                            ProviderGrant(
                                "secret.write",
                                "workspace-1",
                                ("postgres.password",),
                            ),
                        ),
                    ),
                    ProviderCredential(
                        subject="metadata",
                        token="metadata-token",
                        grants=(
                            ProviderGrant("secret.metadata", "workspace-1"),
                        ),
                    ),
                    ProviderCredential(
                        subject="resolver",
                        token="resolver-token",
                        grants=(
                            ProviderGrant(
                                "secret.resolve",
                                "workspace-1",
                                ("gateway.probe-signing-key",),
                            ),
                        ),
                    ),
                    ProviderCredential(
                        subject="oci-resolver",
                        token="oci-resolver-token",
                        grants=(
                            ProviderGrant(
                                "secret.resolve",
                                "workspace-1",
                                ("oci.pull-credential",),
                            ),
                        ),
                    ),
                    ProviderCredential(
                        subject="rotator",
                        token="rotate-token",
                        grants=(
                            ProviderGrant(
                                "secret.rotate",
                                "workspace-1",
                                (
                                    "cloudflare.api-token",
                                    "oci.pull-credential",
                                ),
                            ),
                        ),
                    ),
                    ProviderCredential(
                        subject="revoker",
                        token="revoke-token",
                        grants=(
                            ProviderGrant("secret.revoke", "workspace-1"),
                        ),
                    ),
                    ProviderCredential(
                        subject="delegation-key-generator",
                        token="generation-token",
                        grants=(
                            ProviderGrant(
                                "secret.generate-delegation-key",
                                "workspace-1",
                                ("gateway.probe-signing-key",),
                            ),
                        ),
                    ),
                    ProviderCredential(
                        subject="executor",
                        token="execution-token",
                        grants=(
                            ProviderGrant("graph.execute", "workspace-1"),
                        ),
                    ),
                ),
            )
        )

    def __enter__(self) -> _ApiFixture:
        return self

    def __exit__(self, *args: object) -> None:
        self.client.close()
        self._directory.cleanup()

    def headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def write_secret(
        self,
        *,
        token: str,
        workspace_id: str,
        secret_id: str,
        value: bytes,
        intent: str = "oci.pull-credential",
    ) -> None:
        response = self.client.post(
            f"/v1/workspaces/{workspace_id}/secrets/{secret_id}",
            headers=self.headers(token),
            json={
                "value_base64": _b64(value),
                "intent": intent,
                "labels": {},
            },
        )
        assert response.status_code == 200, response.text

    def audit_rows(self) -> list[dict[str, object]]:
        return self.audit_store.rows_for_tests()

    def generate_delegation_key(
        self,
        *,
        token: str = "generation-token",
        issuer: str = "cpk-server",
        workspace_id: str = "workspace-1",
        purpose: str = "gateway-probe",
        correlation_id: str = "rotation-key-b",
    ):
        return self.client.post(
            f"/v1/workspaces/{workspace_id}/delegation-keys/gateway-key-b/generate",
            headers=self.headers(token),
            json={
                "secret_reference": "secret://workspace-secrets/keys/gateway-b",
                "purpose": purpose,
                "issuer": issuer,
                "caller_subject": "cpk-server",
                "correlation_id": correlation_id,
            },
        )


def _client(*, audit_store_factory: object | None = None) -> _ApiFixture:
    return _ApiFixture(audit_store_factory=audit_store_factory)


class _FailingAuditStore:
    def initialize(self) -> None:
        return None

    def append(self, record: object) -> None:
        raise AuditUnavailable()

    def append_in_transaction(self, connection: object, record: object) -> None:
        raise AuditUnavailable()

    def rows_for_tests(self) -> list[dict[str, object]]:
        return []


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _resolve_body(intent: str) -> dict[str, str]:
    return {
        "intent": intent,
        "caller_subject": "cpk-server",
        "correlation_id": "operation-session-1",
    }


if __name__ == "__main__":
    unittest.main()
