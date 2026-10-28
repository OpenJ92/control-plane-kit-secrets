from __future__ import annotations

import base64
import logging
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import patch

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from control_plane_kit_secrets.api import ALLOWED_SECRET_USE_INTENTS, create_app
from control_plane_kit_secrets.audit import AuditUnavailable, SqliteAuditStore
from control_plane_kit_secrets.auth import ProviderCredential, ProviderGrant
from control_plane_kit_secrets.crypto import encode_master_key_for_file, load_master_key_file
from control_plane_kit_secrets.custody import admit_provider_custody
from control_plane_kit_secrets.models import SecretMissing
from control_plane_kit_secrets.store import EncryptedSecretStore
import control_plane_kit_secrets.provider_policy as provider_policy
from control_plane_kit_secrets import control as control_module
from control_fixtures import ControlAuthority


class ProviderApiTests(unittest.TestCase):
    def test_provider_purposes_remain_closed_with_two_bootstrap_consumers(self) -> None:
        self.assertEqual(ALLOWED_SECRET_USE_INTENTS, frozenset({
            "application.control-token", "cloudflare.api-token", "cloudflare.tunnel-token",
            "docker.local-socket-access-marker", "docker.remote-tls.ca-certificate",
            "docker.remote-tls.client-certificate", "docker.remote-tls.client-key",
            "gateway.probe-signing-key", "gateway.node-control-transit-signing-key",
            "oci.pull-credential", "postgres.password", "workload.node-control-signing-key",
            "secrets.custody-root-key", "secrets.provider-credentials-document",
            "gateway.node-health-read-transit-signing-key",
            "workload.node-health-read-signing-key",
        }))

    def test_bootstrap_purpose_resolution_preserves_exact_durable_authority(self) -> None:
        purposes = ("secrets.custody-root-key", "secrets.provider-credentials-document")
        for intent, other in (purposes, tuple(reversed(purposes))):
            with self.subTest(intent=intent), _client(credentials=(
                ProviderCredential("bootstrap-writer", "bootstrap-writer-token", (
                    ProviderGrant("secret.write", "workspace-1", (intent,)),)),
                ProviderCredential("bootstrap-reader", "bootstrap-reader-token", (
                    ProviderGrant("secret.resolve", "workspace-1", (intent,)),)),
                ProviderCredential("other-purpose-reader", "other-purpose-token", (
                    ProviderGrant("secret.resolve", "workspace-1", (other,)),)),
            )) as fixture:
                material = b"opaque-bootstrap-fixture-material"
                path = "/v1/workspaces/workspace-1/secrets/bootstrap-material"
                written = fixture.client.post(path,
                    headers=fixture.headers("bootstrap-writer-token"),
                    json={"value_base64": _b64(material), "intent": intent,
                          "caller_subject": "worker-a", "correlation_id": "bootstrap-write"})
                self.assertEqual(written.status_code, 200)
                self.assertEqual(written.json()["metadata"]["labels"]["intent"], intent)
                request = {"intent": intent, "caller_subject": "worker-a",
                           "correlation_id": "bootstrap-resolve"}
                resolved = fixture.client.post(path + "/resolve",
                    headers=fixture.headers("bootstrap-reader-token"), json=request)
                self.assertEqual(resolved.status_code, 200)
                self.assertTrue(base64.b64decode(resolved.json()["value_base64"]) == material,
                                "resolved opaque material mismatch")
                replayed = fixture.client.post(path + "/resolve",
                    headers=fixture.headers("bootstrap-reader-token"), json=request)
                self.assertEqual(replayed.status_code, 200)
                self.assertTrue(replayed.json() == resolved.json(), "same-use replay changed")

                denied_cases = (
                    ("unregistered-token", intent, "workspace-1", 401, "unauthenticated"),
                    ("bootstrap-writer-token", intent, "workspace-1", 403, "insufficient-scope"),
                    ("bootstrap-reader-token", intent, "workspace-2", 403, "insufficient-scope"),
                    ("other-purpose-token", intent, "workspace-1", 403, "insufficient-scope"),
                    ("bootstrap-reader-token", other, "workspace-1", 403, "insufficient-scope"),
                    ("bootstrap-reader-token", "secrets.unknown-bootstrap", "workspace-1", 400, "unsupported-intent"),
                )
                for index, (token, purpose, workspace, status, code) in enumerate(denied_cases):
                    with self.subTest(denial=index):
                        denied = fixture.client.post(
                            path.replace("workspace-1", workspace) + "/resolve",
                            headers=fixture.headers(token),
                            json={**request, "intent": purpose,
                                  "correlation_id": f"bootstrap-denied-{index}"})
                        self.assertEqual(denied.status_code, status)
                        self.assertEqual(denied.json()["detail"]["code"], code)
                        self.assertNotIn("value_base64", denied.json())
                        self.assertTrue(material.decode() not in denied.text)
                        self.assertTrue(_b64(material) not in denied.text)
                        self.assertTrue(token not in denied.text)

                rows = fixture.audit_rows()
                self.assertEqual([row["outcome"] for row in rows],
                                 ["stored", "resolved", "resolved", *(["denied"] * 5),
                                  "malformed"])
                self.assertEqual([row["code"] for row in rows[3:]],
                                 [case[4] for case in denied_cases])
                self.assertEqual({row["caller_subject"] for row in rows
                                  if row["outcome"] == "resolved"}, {"worker-a"})
                for forbidden in (material.decode(), _b64(material), "bootstrap-writer-token",
                                  "bootstrap-reader-token", "other-purpose-token"):
                    self.assertTrue(forbidden not in repr(rows), "audit leaked private fixture material")

    def test_exact_version_revocation_is_authorized_audited_and_idempotent(
        self,
    ) -> None:
        with _client() as fixture:
            first = fixture.store.create_secret(
                workspace_id="workspace-1",
                secret_id="gateway-rotation-key",
                value=b"private-key-a",
                labels={"intent": "gateway.probe-signing-key"},
            )
            second = fixture.store.rotate_secret(
                workspace_id="workspace-1",
                secret_id="gateway-rotation-key",
                value=b"private-key-b",
                labels={"intent": "gateway.probe-signing-key"},
            )
            path = (
                "/v1/workspaces/workspace-1/secrets/gateway-rotation-key/"
                f"versions/{first.version_id}/revoke"
            )
            body = {
                "version_number": first.version_number,
                "caller_subject": "rotation-program",
                "correlation_id": "retire-key-a",
            }

            wrong_workspace = fixture.client.post(
                path.replace("workspace-1", "workspace-2"),
                headers=fixture.headers("revoke-token"),
                json=body,
            )
            denied = fixture.client.post(
                path,
                headers=fixture.headers("writer-token"),
                json=body,
            )
            wrong_number = fixture.client.post(
                path,
                headers=fixture.headers("revoke-token"),
                json={**body, "version_number": 2},
            )
            missing = fixture.client.post(
                path.replace(first.version_id, "missing-version"),
                headers=fixture.headers("revoke-token"),
                json=body,
            )
            revoked = fixture.client.post(
                path,
                headers=fixture.headers("revoke-token"),
                json=body,
            )
            replayed = fixture.client.post(
                path,
                headers=fixture.headers("revoke-token"),
                json=body,
            )
            conflict = fixture.client.post(
                path,
                headers=fixture.headers("revoke-token"),
                json={**body, "correlation_id": "other-retirement"},
            )

            self.assertEqual(wrong_workspace.status_code, 403, wrong_workspace.text)
            self.assertEqual(denied.status_code, 403, denied.text)
            self.assertEqual(wrong_number.status_code, 409, wrong_number.text)
            self.assertEqual(missing.status_code, 404, missing.text)
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertEqual(replayed.status_code, 200, replayed.text)
            self.assertEqual(revoked.json(), replayed.json())
            self.assertEqual(revoked.json()["metadata"]["status"], "revoked")
            self.assertEqual(conflict.status_code, 409, conflict.text)
            self.assertEqual(
                conflict.json()["detail"]["code"],
                "version-revocation-conflict",
            )
            self.assertEqual(
                fixture.store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="gateway-rotation-key",
                    version_id=second.version_id,
                ).value,
                b"private-key-b",
            )
            rows = [
                row
                for row in fixture.audit_rows()
                if row["correlation_id"] == "retire-key-a"
            ]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["version_id"], first.version_id)
            self.assertNotIn("private-key", repr(rows))

    def test_exact_version_revocation_audit_failure_rolls_back(self) -> None:
        with _client(audit_store_factory=lambda _path: _FailingAuditStore()) as fixture:
            version = fixture.store.create_secret(
                workspace_id="workspace-1",
                secret_id="gateway-rotation-key",
                value=b"private-key-a",
                labels={"intent": "gateway.probe-signing-key"},
            )

            response = fixture.client.post(
                (
                    "/v1/workspaces/workspace-1/secrets/gateway-rotation-key/"
                    f"versions/{version.version_id}/revoke"
                ),
                headers=fixture.headers("revoke-token"),
                json={
                    "version_number": 1,
                    "caller_subject": "rotation-program",
                    "correlation_id": "retire-key-a",
                },
            )

            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(
                response.json()["detail"]["code"],
                "audit-unavailable",
            )
            self.assertEqual(
                fixture.store.resolve_secret(
                    workspace_id="workspace-1",
                    secret_id="gateway-rotation-key",
                    version_id=version.version_id,
                ).value,
                b"private-key-a",
            )
            self.assertNotIn("private-key-a", response.text)

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

    def test_policy_admin_routes_are_independent_replayable_bounded_and_audited(self) -> None:
        with _policy_client() as fixture:
            ordinary_denied = fixture.client.get(
                "/v1/provider-policy/grants",
                headers={**fixture.headers("dynamic-token"), "X-Correlation-ID": "list-denied"},
            )
            self.assertEqual(ordinary_denied.status_code, 403)

            request = {
                "subject": "dynamic-client",
                "workspace_id": "workspace-1",
                "action": "secret.metadata",
                "intent": None,
                "expected_revision": 1,
                "correlation_id": "grant-metadata-a",
            }
            granted = fixture.client.post(
                "/v1/provider-policy/grants",
                headers=fixture.headers("admin-token"), json=request,
            )
            self.assertEqual(granted.status_code, 200, granted.text)
            body = granted.json()
            self.assertEqual(
                (body["operation"], body["outcome"], body["expected_revision"],
                 body["resulting_revision"], body["actor"], body["subject"]),
                ("grant", "granted", 1, 2, "policy-admin", "dynamic-client"),
            )
            self.assertNotIn("token", granted.text)
            replay = fixture.client.post(
                "/v1/provider-policy/grants",
                headers=fixture.headers("admin-token"), json=request,
            )
            self.assertEqual(replay.json(), body)
            conflict = fixture.client.post(
                "/v1/provider-policy/grants",
                headers=fixture.headers("admin-token"),
                json={**request, "subject": "different-client"},
            )
            self.assertEqual(conflict.status_code, 409)

            rejected = (
                ("/v1/provider-policy/grants", {
                    **request, "subject": "stale-client",
                    "correlation_id": "stale-command",
                }),
                ("/v1/provider-policy/grants", {
                    **request, "correlation_id": "active-command",
                    "expected_revision": 2,
                }),
                ("/v1/provider-policy/grants/unknown-grant/revoke", {
                    **request, "correlation_id": "invalid-revoke",
                    "expected_revision": 2,
                }),
            )
            for path, rejected_request in rejected:
                with self.subTest(rejected_command=rejected_request["correlation_id"]):
                    first_rejection = fixture.client.post(
                        path, headers=fixture.headers("admin-token"),
                        json=rejected_request,
                    )
                    replayed_rejection = fixture.client.post(
                        path, headers=fixture.headers("admin-token"),
                        json=rejected_request,
                    )
                    self.assertEqual(first_rejection.status_code, 409)
                    self.assertEqual(replayed_rejection.status_code, 409)
                    self.assertEqual(replayed_rejection.json(), first_rejection.json())

            for invalid_revision in (1 << 63, "2", 2.0, True):
                with self.subTest(invalid_revision=repr(invalid_revision)):
                    invalid = fixture.client.post(
                        "/v1/provider-policy/grants",
                        headers=fixture.headers("admin-token"),
                        json={**request, "correlation_id": "invalid-revision",
                              "expected_revision": invalid_revision},
                    )
                    self.assertEqual(invalid.status_code, 422)
            self.assertEqual(fixture.policy_store.current_revision(), 2)

            command = fixture.client.get(
                "/v1/provider-policy/commands/grant-metadata-a",
                headers={**fixture.headers("admin-token"), "X-Correlation-ID": "read-command-a"},
            )
            self.assertEqual(command.status_code, 200, command.text)
            self.assertEqual(command.json(), body)
            without_admin = (
                ProviderCredential(
                    subject="policy-admin", token="admin-token", grants=(),
                    capabilities=(),
                ),
                fixture.credentials[1],
            )
            with fixture.reconstructed_client(without_admin) as rebuilt:
                lost_admin = rebuilt.get(
                    "/v1/provider-policy/commands/grant-metadata-a",
                    headers={"Authorization": "Bearer admin-token",
                             "X-Correlation-ID": "read-command-denied"},
                )
                self.assertEqual(lost_admin.status_code, 403)
                lost_admin_replay = rebuilt.post(
                    "/v1/provider-policy/grants",
                    headers={"Authorization": "Bearer admin-token"},
                    json=request,
                )
                self.assertEqual(lost_admin_replay.status_code, 403)

            invalid_read = fixture.client.get(
                "/v1/provider-policy/grants/%20",
                headers={**fixture.headers("admin-token"),
                         "X-Correlation-ID": "invalid-grant-read"},
            )
            self.assertEqual(invalid_read.status_code, 400)
            self.assertIn(
                ("grant-read", "malformed", "provider-policy-invalid"),
                fixture.policy_events(),
            )
            before_invalid_correlation = len(fixture.policy_events())
            unusable_correlation = fixture.client.get(
                "/v1/provider-policy/grants",
                headers={**fixture.headers("admin-token"), "X-Correlation-ID": "   "},
            )
            self.assertEqual(unusable_correlation.status_code, 400)
            self.assertEqual(len(fixture.policy_events()), before_invalid_correlation)
            listed = fixture.client.get(
                "/v1/provider-policy/grants?limit=1&intent_mode=none",
                headers={**fixture.headers("admin-token"), "X-Correlation-ID": "list-a"},
            )
            self.assertEqual(listed.status_code, 200, listed.text)
            self.assertEqual(listed.json()["revision"], 2)
            self.assertEqual(len(listed.json()["grants"]), 1)
            exact = fixture.client.get(
                f"/v1/provider-policy/grants/{body['grant_id']}",
                headers={**fixture.headers("admin-token"), "X-Correlation-ID": "read-grant-a"},
            )
            self.assertEqual(exact.status_code, 200, exact.text)
            self.assertEqual(exact.json()["revision"], 2)
            self.assertEqual(exact.json()["grant"]["grant_id"], body["grant_id"])

            revoked = fixture.client.post(
                f"/v1/provider-policy/grants/{body['grant_id']}/revoke",
                headers=fixture.headers("admin-token"),
                json={**request, "expected_revision": 2,
                      "correlation_id": "revoke-metadata-a"},
            )
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertEqual(revoked.json()["resulting_revision"], 3)

    def test_policy_commands_reject_unsupported_authority_and_transport_fields(self) -> None:
        with _policy_client() as fixture:
            grant_request = {
                "subject": "dynamic-client",
                "workspace_id": "workspace-1",
                "action": "secret.metadata",
                "intent": None,
                "expected_revision": 1,
                "correlation_id": "grant-closed-input",
            }
            forbidden_fields = {
                "provider_id": "forbidden-provider-sentinel",
                "actor": "forbidden-actor-sentinel",
                "endpoint": "https://forbidden-endpoint.invalid/private",
                "credential": "Bearer forbidden-credential-sentinel",
                "method": "forbidden-method-sentinel",
                "socket_path": "/run/forbidden-socket-sentinel.sock",
            }
            records: list[logging.LogRecord] = []

            class _CaptureHandler(logging.Handler):
                def emit(self, record: logging.LogRecord) -> None:
                    records.append(record)

            logger = logging.getLogger()
            previous_level = logger.level
            handler = _CaptureHandler()
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
            try:
                for field, sentinel in forbidden_fields.items():
                    with self.subTest(operation="grant", field=field):
                        before = fixture.policy_state_snapshot()
                        audit_before = fixture.audit_rows()
                        response = fixture.client.post(
                            "/v1/provider-policy/grants",
                            headers=fixture.headers("admin-token"),
                            json={**grant_request, field: sentinel},
                        )
                        self.assertEqual(response.status_code, 422, response.text)
                        self.assertEqual(response.json(), {
                            "detail": {
                                "outcome": "malformed",
                                "code": "provider-policy-request-invalid",
                            }
                        })
                        self.assertEqual(fixture.policy_state_snapshot(), before)
                        self.assertEqual(fixture.audit_rows(), audit_before)
                        self.assertNotIn(sentinel, response.text)

                granted = fixture.client.post(
                    "/v1/provider-policy/grants",
                    headers=fixture.headers("admin-token"),
                    json=grant_request,
                )
                self.assertEqual(granted.status_code, 200, granted.text)
                grant_id = granted.json()["grant_id"]
                revoke_request = {
                    **grant_request,
                    "expected_revision": 2,
                    "correlation_id": "revoke-closed-input",
                }

                for field, sentinel in forbidden_fields.items():
                    with self.subTest(operation="revoke", field=field):
                        before = fixture.policy_state_snapshot()
                        audit_before = fixture.audit_rows()
                        response = fixture.client.post(
                            f"/v1/provider-policy/grants/{grant_id}/revoke",
                            headers=fixture.headers("admin-token"),
                            json={**revoke_request, field: sentinel},
                        )
                        self.assertEqual(response.status_code, 422, response.text)
                        self.assertEqual(response.json(), {
                            "detail": {
                                "outcome": "malformed",
                                "code": "provider-policy-request-invalid",
                            }
                        })
                        self.assertEqual(fixture.policy_state_snapshot(), before)
                        self.assertEqual(fixture.audit_rows(), audit_before)
                        self.assertNotIn(sentinel, response.text)

                revoked = fixture.client.post(
                    f"/v1/provider-policy/grants/{grant_id}/revoke",
                    headers=fixture.headers("admin-token"),
                    json=revoke_request,
                )
                self.assertEqual(revoked.status_code, 200, revoked.text)
                self.assertEqual(revoked.json()["resulting_revision"], 3)

                before_invalid_list = fixture.policy_state_snapshot()
                invalid_list = fixture.client.get(
                    "/v1/provider-policy/grants?limit=not-an-integer",
                    headers={
                        **fixture.headers("admin-token"),
                        "X-Correlation-ID": "invalid-list-query",
                    },
                )
                self.assertEqual(invalid_list.status_code, 422, invalid_list.text)
                self.assertIsInstance(invalid_list.json()["detail"], list)
                self.assertIn("not-an-integer", invalid_list.text)
                self.assertEqual(fixture.policy_state_snapshot(), before_invalid_list)
            finally:
                logger.removeHandler(handler)
                logger.setLevel(previous_level)

            log_text = "\n".join(repr(vars(record)) for record in records)
            for sentinel in forbidden_fields.values():
                self.assertNotIn(sentinel, log_text)

    def test_durable_grant_and_revoke_change_authorization_without_rebuild(self) -> None:
        with _policy_client() as fixture:
            fixture.store.create_secret(
                workspace_id="workspace-1", secret_id="retained",
                value=b"retained", labels={"intent": "postgres.password"},
            )
            path = "/v1/workspaces/workspace-1/secrets/retained/metadata"
            self.assertEqual(
                fixture.client.get(path, headers=fixture.headers("dynamic-token")).status_code,
                403,
            )
            grant = fixture.client.post(
                "/v1/provider-policy/grants",
                headers=fixture.headers("admin-token"),
                json={
                    "subject": "dynamic-client", "workspace_id": "workspace-1",
                    "action": "secret.metadata", "intent": None,
                    "expected_revision": 1, "correlation_id": "grant-dynamic",
                },
            )
            self.assertEqual(grant.status_code, 200, grant.text)
            self.assertEqual(
                fixture.client.get(path, headers=fixture.headers("dynamic-token")).status_code,
                200,
            )
            revoke = fixture.client.post(
                f"/v1/provider-policy/grants/{grant.json()['grant_id']}/revoke",
                headers=fixture.headers("admin-token"),
                json={
                    "subject": "dynamic-client", "workspace_id": "workspace-1",
                    "action": "secret.metadata", "intent": None,
                    "expected_revision": 2, "correlation_id": "revoke-dynamic",
                },
            )
            self.assertEqual(revoke.status_code, 200, revoke.text)
            self.assertEqual(
                fixture.client.get(path, headers=fixture.headers("dynamic-token")).status_code,
                403,
            )

    def test_every_secret_action_uses_the_durable_policy_without_static_fallback(self) -> None:
        with _policy_client() as fixture:
            cases = (
                ("secret.write", "postgres.password"),
                ("secret.generate-delegation-key", "gateway.probe-signing-key"),
                ("secret.rotate", "postgres.password"),
                ("secret.resolve", "postgres.password"),
                ("secret.revoke", None),
                ("secret.metadata", None),
            )
            revision = 1
            grants = []
            for index, (action, intent) in enumerate(cases):
                response = fixture.client.post(
                    "/v1/provider-policy/grants",
                    headers=fixture.headers("admin-token"),
                    json={
                        "subject": "dynamic-client", "workspace_id": "workspace-1",
                        "action": action, "intent": intent,
                        "expected_revision": revision,
                        "correlation_id": f"grant-action-{index}",
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                grants.append((response.json()["grant_id"], action, intent))
                revision += 1
            fixture.assert_all_dynamic_action_paths_authorized()
            for index, (grant_id, action, intent) in enumerate(grants):
                revoked = fixture.client.post(
                    f"/v1/provider-policy/grants/{grant_id}/revoke",
                    headers=fixture.headers("admin-token"),
                    json={
                        "subject": "dynamic-client", "workspace_id": "workspace-1",
                        "action": action, "intent": intent,
                        "expected_revision": revision,
                        "correlation_id": f"revoke-action-{index}",
                    },
                )
                self.assertEqual(revoked.status_code, 200, revoked.text)
                revision += 1
            fixture.assert_all_dynamic_action_paths_denied()

    def test_admitted_request_can_finish_after_revoke_but_later_checks_deny(self) -> None:
        with _policy_client() as fixture:
            fixture.store.create_secret(
                workspace_id="workspace-1", secret_id="in-flight", value=b"retained"
            )
            grant = fixture.client.post(
                "/v1/provider-policy/grants",
                headers=fixture.headers("admin-token"),
                json={
                    "subject": "dynamic-client", "workspace_id": "workspace-1",
                    "action": "secret.metadata", "intent": None,
                    "expected_revision": 1, "correlation_id": "grant-in-flight",
                },
            ).json()
            entered = Event()
            release = Event()
            original = fixture.store.metadata

            def delayed_metadata(**kwargs):
                entered.set()
                self.assertTrue(release.wait(5), "metadata request was not released")
                return original(**kwargs)

            path = "/v1/workspaces/workspace-1/secrets/in-flight/metadata"
            with patch.object(fixture.store, "metadata", side_effect=delayed_metadata):
                with ThreadPoolExecutor(max_workers=1) as executor:
                    admitted = executor.submit(
                        fixture.client.get, path,
                        headers=fixture.headers("dynamic-token"),
                    )
                    self.assertTrue(entered.wait(5), "request was not admitted")
                    revoked = fixture.client.post(
                        f"/v1/provider-policy/grants/{grant['grant_id']}/revoke",
                        headers=fixture.headers("admin-token"),
                        json={
                            "subject": "dynamic-client", "workspace_id": "workspace-1",
                            "action": "secret.metadata", "intent": None,
                            "expected_revision": 2, "correlation_id": "revoke-in-flight",
                        },
                    )
                    self.assertEqual(revoked.status_code, 200, revoked.text)
                    release.set()
                    self.assertEqual(admitted.result().status_code, 200)
            self.assertEqual(
                fixture.client.get(path, headers=fixture.headers("dynamic-token")).status_code,
                403,
            )

    def test_policy_unavailable_is_not_a_false_scope_denial(self) -> None:
        with _policy_client() as fixture:
            with patch.object(
                fixture.policy_store, "require_active",
                side_effect=provider_policy.ProviderPolicyUnavailable(),
            ):
                response = fixture.client.post(
                    "/v1/workspaces/workspace-1/secrets/unavailable",
                    headers=fixture.headers("dynamic-token"),
                    json={"value_base64": _b64(b"value"), "intent": "postgres.password",
                          "correlation_id": "policy-unavailable"},
                )
            self.assertEqual(response.status_code, 503)
            self.assertIn(
                ("unavailable", "provider-policy-unavailable"),
                {(row["outcome"], row["code"]) for row in fixture.audit_rows()},
            )


class _ApiFixture:
    def __init__(
        self,
        *,
        audit_store_factory: object | None = None,
        credentials: tuple[ProviderCredential, ...] | None = None,
    ) -> None:
        self._directory = tempfile.TemporaryDirectory()
        base = Path(self._directory.name)
        key_path = base / "master.key"
        key_path.write_text(
            encode_master_key_for_file(os.urandom(32)),
            encoding="utf-8",
        )
        database = base / "secrets.sqlite3"
        self.database = database
        selected_credentials = credentials if credentials is not None else _default_credentials()
        store, real_audit_store = admit_provider_custody(
            database,
            master_key=load_master_key_file(key_path, version="test"),
            provider_id="provider-a",
            credentials=selected_credentials,
        )
        self.store = store
        if audit_store_factory is None:
            self.audit_store = real_audit_store
        else:
            self.audit_store = audit_store_factory(database)
        policy_store = provider_policy.ProviderPolicyStore(
            database, provider_id="provider-a"
        )
        self.client = TestClient(
            create_app(
                control=ControlAuthority().configuration(control_module),
                clock=lambda: 150,
                provider_id="provider-a",
                initialize_provider=lambda: (
                    store, self.audit_store, selected_credentials, policy_store,
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


class _PolicyApiFixture:
    def __init__(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        base = Path(self._directory.name)
        key_path = base / "master.key"
        key_path.write_text(encode_master_key_for_file(os.urandom(32)), encoding="utf-8")
        key = load_master_key_file(key_path, version="policy-test")
        self.credentials = (
            ProviderCredential(
                subject="policy-admin", token="admin-token", grants=(),
                capabilities=("secrets.policy-admin",),
            ),
            ProviderCredential(
                subject="dynamic-client", token="dynamic-token", grants=(),
                capabilities=(),
            ),
        )
        database = base / "secrets.sqlite3"
        self.database = database
        self.store, self.audit_store = admit_provider_custody(
            database, master_key=key, provider_id="provider-a",
            credentials=self.credentials,
        )
        policy_store_type = getattr(provider_policy, "ProviderPolicyStore", None)
        if not callable(policy_store_type):
            raise AssertionError("durable provider policy store is missing")
        self.policy_store = policy_store_type(database, provider_id="provider-a")
        self.client = TestClient(create_app(
            control=ControlAuthority().configuration(control_module),
            clock=lambda: 150,
            provider_id="provider-a",
            initialize_provider=lambda: (
                self.store, self.audit_store, self.credentials, self.policy_store,
            ),
        ))

    def __enter__(self) -> _PolicyApiFixture:
        return self

    def __exit__(self, *args: object) -> None:
        self.client.close()
        self._directory.cleanup()

    def headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def reconstructed_client(
        self, credentials: tuple[ProviderCredential, ...]
    ) -> TestClient:
        return TestClient(create_app(
            control=ControlAuthority().configuration(control_module),
            clock=lambda: 150,
            provider_id="provider-a",
            initialize_provider=lambda: (
                self.store, self.audit_store, credentials, self.policy_store,
            ),
        ))

    def policy_events(self) -> list[tuple[str, str, str]]:
        import sqlite3
        from contextlib import closing

        with closing(sqlite3.connect(self.database)) as connection:
            return [
                (str(row[0]), str(row[1]), str(row[2]))
                for row in connection.execute(
                    "SELECT event_kind, outcome, code FROM provider_policy_events "
                    "ORDER BY occurred_at, event_id"
                ).fetchall()
            ]

    def policy_state_snapshot(self) -> tuple[object, ...]:
        import sqlite3
        from contextlib import closing

        with closing(sqlite3.connect(self.database)) as connection:
            revision = connection.execute(
                "SELECT * FROM provider_policy_state ORDER BY provider_id"
            ).fetchall()
            seed = connection.execute(
                "SELECT * FROM provider_policy_seed ORDER BY provider_id"
            ).fetchall()
            grants = connection.execute(
                "SELECT * FROM provider_grants ORDER BY grant_id"
            ).fetchall()
            commands = connection.execute(
                "SELECT * FROM provider_policy_commands ORDER BY provider_id, correlation_id"
            ).fetchall()
            events = connection.execute(
                "SELECT * FROM provider_policy_events ORDER BY event_id"
            ).fetchall()
            return (
                tuple(revision), tuple(seed), tuple(grants), tuple(commands), tuple(events)
            )

    def audit_rows(self) -> list[dict[str, object]]:
        return self.audit_store.rows_for_tests()

    def assert_all_dynamic_action_paths_authorized(self) -> None:
        write = self.client.post(
            "/v1/workspaces/workspace-1/secrets/write-target",
            headers=self.headers("dynamic-token"),
            json={"value_base64": _b64(b"write"), "intent": "postgres.password"},
        )
        assert write.status_code == 200, write.text

        generation = self.client.post(
            "/v1/workspaces/workspace-1/delegation-keys/generated/generate",
            headers=self.headers("dynamic-token"),
            json={
                "secret_reference": "secret://workspace-secrets/keys/generated",
                "purpose": "gateway-probe", "issuer": "cpk-server",
                "caller_subject": "dynamic-client", "correlation_id": "generate-a",
            },
        )
        assert generation.status_code == 200, generation.text

        self.store.create_secret(
            workspace_id="workspace-1", secret_id="rotate-target", value=b"old",
            labels={"intent": "postgres.password"},
        )
        rotate = self.client.post(
            "/v1/workspaces/workspace-1/secrets/rotate-target/rotate",
            headers=self.headers("dynamic-token"),
            json={"value_base64": _b64(b"new"), "intent": "postgres.password"},
        )
        assert rotate.status_code == 200, rotate.text

        self.store.create_secret(
            workspace_id="workspace-1", secret_id="resolve-target", value=b"resolve",
            labels={"intent": "postgres.password"},
        )
        resolve = self.client.post(
            "/v1/workspaces/workspace-1/secrets/resolve-target/resolve",
            headers=self.headers("dynamic-token"),
            json={
                "intent": "postgres.password", "caller_subject": "dynamic-client",
                "correlation_id": "resolve-a",
            },
        )
        assert resolve.status_code == 200, resolve.text

        exact = self.store.create_secret(
            workspace_id="workspace-1", secret_id="exact-revoke-target",
            value=b"revoke", labels={"intent": "postgres.password"},
        )
        exact_revoke = self.client.post(
            f"/v1/workspaces/workspace-1/secrets/exact-revoke-target/versions/{exact.version_id}/revoke",
            headers=self.headers("dynamic-token"),
            json={
                "version_number": exact.version_number,
                "caller_subject": "dynamic-client", "correlation_id": "exact-revoke-a",
            },
        )
        assert exact_revoke.status_code == 200, exact_revoke.text

        self.store.create_secret(
            workspace_id="workspace-1", secret_id="revoke-target", value=b"revoke"
        )
        revoke = self.client.post(
            "/v1/workspaces/workspace-1/secrets/revoke-target/revoke",
            headers=self.headers("dynamic-token"), json={},
        )
        assert revoke.status_code == 200, revoke.text

        self.store.create_secret(
            workspace_id="workspace-1", secret_id="metadata-target", value=b"metadata"
        )
        metadata = self.client.get(
            "/v1/workspaces/workspace-1/secrets/metadata-target/metadata",
            headers=self.headers("dynamic-token"),
        )
        assert metadata.status_code == 200, metadata.text

    def assert_all_dynamic_action_paths_denied(self) -> None:
        responses = (
            self.client.post(
                "/v1/workspaces/workspace-1/secrets/write-denied",
                headers=self.headers("dynamic-token"),
                json={"value_base64": _b64(b"write"), "intent": "postgres.password"},
            ),
            self.client.post(
                "/v1/workspaces/workspace-1/delegation-keys/generated-denied/generate",
                headers=self.headers("dynamic-token"),
                json={
                    "secret_reference": "secret://workspace-secrets/keys/generated-denied",
                    "purpose": "gateway-probe", "issuer": "cpk-server",
                    "caller_subject": "dynamic-client",
                    "correlation_id": "generate-denied",
                },
            ),
            self.client.post(
                "/v1/workspaces/workspace-1/secrets/rotate-target/rotate",
                headers=self.headers("dynamic-token"),
                json={"value_base64": _b64(b"again"), "intent": "postgres.password"},
            ),
            self.client.post(
                "/v1/workspaces/workspace-1/secrets/resolve-target/resolve",
                headers=self.headers("dynamic-token"),
                json={
                    "intent": "postgres.password", "caller_subject": "dynamic-client",
                    "correlation_id": "resolve-denied",
                },
            ),
            self.client.post(
                "/v1/workspaces/workspace-1/secrets/revoke-target/revoke",
                headers=self.headers("dynamic-token"), json={},
            ),
            self.client.get(
                "/v1/workspaces/workspace-1/secrets/metadata-target/metadata",
                headers=self.headers("dynamic-token"),
            ),
        )
        assert [response.status_code for response in responses] == [403] * 6


def _policy_client() -> _PolicyApiFixture:
    return _PolicyApiFixture()


def _default_credentials() -> tuple[ProviderCredential, ...]:
    return (
        ProviderCredential("writer", "writer-token", (
            ProviderGrant("secret.write", "workspace-1", (
                "cloudflare.api-token", "gateway.probe-signing-key",
                "oci.pull-credential", "postgres.password",
            )),
        )),
        ProviderCredential("postgres-writer", "postgres-writer-token", (
            ProviderGrant("secret.write", "workspace-1", ("postgres.password",)),
        )),
        ProviderCredential("metadata", "metadata-token", (
            ProviderGrant("secret.metadata", "workspace-1", ()),
        )),
        ProviderCredential("resolver", "resolver-token", (
            ProviderGrant("secret.resolve", "workspace-1", ("gateway.probe-signing-key",)),
        )),
        ProviderCredential("oci-resolver", "oci-resolver-token", (
            ProviderGrant("secret.resolve", "workspace-1", ("oci.pull-credential",)),
        )),
        ProviderCredential("rotator", "rotate-token", (
            ProviderGrant("secret.rotate", "workspace-1", (
                "cloudflare.api-token", "oci.pull-credential",
            )),
        )),
        ProviderCredential("revoker", "revoke-token", (
            ProviderGrant("secret.revoke", "workspace-1", ()),
        )),
        ProviderCredential("delegation-key-generator", "generation-token", (
            ProviderGrant(
                "secret.generate-delegation-key", "workspace-1",
                ("gateway.probe-signing-key",),
            ),
        )),
        ProviderCredential("executor", "execution-token", ()),
    )


def _client(
    *, audit_store_factory: object | None = None,
    credentials: tuple[ProviderCredential, ...] | None = None,
) -> _ApiFixture:
    return _ApiFixture(audit_store_factory=audit_store_factory, credentials=credentials)


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
