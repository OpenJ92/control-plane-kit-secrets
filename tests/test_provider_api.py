from __future__ import annotations

import base64
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from control_plane_kit_secrets.api import create_app
from control_plane_kit_secrets.audit import AuditUnavailable, SqliteAuditStore
from control_plane_kit_secrets.auth import ProviderCredential, ProviderGrant
from control_plane_kit_secrets.crypto import encode_master_key_for_file, load_master_key_file
from control_plane_kit_secrets.store import EncryptedSecretStore


class ProviderApiTests(unittest.TestCase):
    def test_write_and_metadata_read_are_authenticated_and_redacted(self) -> None:
        with _client() as fixture:
            sentinel = b"cloudflare-api-token-super-secret"
            response = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/cloudflare-token",
                headers=fixture.headers("writer-token"),
                json={
                    "value_base64": _b64(sentinel),
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
            self.assertNotIn("value_base64", metadata.text)
            self.assertNotIn(sentinel.decode("ascii"), metadata.text)
            self.assertEqual(
                [row["outcome"] for row in fixture.audit_rows()],
                ["stored", "metadata"],
            )

    def test_resolve_requires_authentication_scope_and_intent(self) -> None:
        with _client() as fixture:
            fixture.write_secret(
                token="writer-token",
                workspace_id="workspace-1",
                secret_id="gateway-key",
                value=b"gateway-signing-key",
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
                json={"value_base64": _b64(b"new-oci-token"), "labels": {}},
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
                json={"value_base64": "not base64!", "labels": {}},
            )
            self.assertEqual(malformed.status_code, 400)

            oversized_secret = b"x" * (64 * 1024 + 1)
            oversized = fixture.client.post(
                "/v1/workspaces/workspace-1/secrets/too-large",
                headers=fixture.headers("writer-token"),
                json={"value_base64": _b64(oversized_secret), "labels": {}},
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
                json={"value_base64": _b64(b"second-secret-value"), "labels": {}},
            )

            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.json()["detail"]["outcome"], "already-exists")
            self.assertNotIn("second-secret-value", response.text)
            self.assertIn("already-exists", [row["outcome"] for row in fixture.audit_rows()])

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
                            ProviderGrant("secret.write", "workspace-1"),
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
                            ProviderGrant("secret.rotate", "workspace-1"),
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
    ) -> None:
        response = self.client.post(
            f"/v1/workspaces/{workspace_id}/secrets/{secret_id}",
            headers=self.headers(token),
            json={"value_base64": _b64(value), "labels": {}},
        )
        assert response.status_code == 200, response.text

    def audit_rows(self) -> list[dict[str, object]]:
        return self.audit_store.rows_for_tests()


def _client(*, audit_store_factory: object | None = None) -> _ApiFixture:
    return _ApiFixture(audit_store_factory=audit_store_factory)


class _FailingAuditStore:
    def initialize(self) -> None:
        return None

    def append(self, record: object) -> None:
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
