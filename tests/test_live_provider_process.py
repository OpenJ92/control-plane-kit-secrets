from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import httpx

from control_plane_kit_secrets.audit import SqliteAuditStore
from control_plane_kit_secrets.crypto import encode_master_key_for_file


class LiveProviderProcessTests(unittest.TestCase):
    def test_restart_rotate_revoke_and_leak_audit_through_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            db_path = base / "secrets.sqlite3"
            key_path = base / "master.key"
            key_bytes = os.urandom(32)
            key_path.write_text(encode_master_key_for_file(key_bytes), encoding="utf-8")
            key_path.chmod(0o600)
            token = "provider-token-for-live-test"
            denied_token = "metadata-only-token"
            credentials_path = base / "provider-credentials.json"
            credentials_path.write_text(
                json.dumps(
                    [
                        {
                            "subject": "provider-client",
                            "token": token,
                            "grants": [
                                {"action": "secret.write", "workspace_id": "workspace-1"},
                                {"action": "secret.rotate", "workspace_id": "workspace-1"},
                                {"action": "secret.revoke", "workspace_id": "workspace-1"},
                                {"action": "secret.metadata", "workspace_id": "workspace-1"},
                                {
                                    "action": "secret.resolve",
                                    "workspace_id": "workspace-1",
                                    "intents": ["postgres.password"],
                                },
                            ],
                        },
                        {
                            "subject": "metadata-only",
                            "token": denied_token,
                            "grants": [
                                {"action": "secret.metadata", "workspace_id": "workspace-1"},
                            ],
                        },
                    ],
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            credentials_path.chmod(0o600)
            port = _free_port()
            environment = {
                **os.environ,
                "CPK_SECRETS_DATABASE_PATH": str(db_path),
                "CPK_SECRETS_MASTER_KEY_FILE": str(key_path),
                "CPK_SECRETS_PROVIDER_ID": "provider-live",
                "CPK_SECRETS_CREDENTIALS_FILE": str(credentials_path),
            }

            process = _start_provider(port=port, environment=environment)
            try:
                _wait_ready(port)
                secret_value = b"live-secret-postgres-password"
                write = _request(
                    "POST",
                    port,
                    "/v1/workspaces/workspace-1/secrets/postgres-password",
                    token=token,
                    json_body={
                        "value_base64": _b64(secret_value),
                        "labels": {"intent": "postgres.password"},
                        "caller_subject": "acceptance",
                        "correlation_id": "write-1",
                    },
                )
                self.assertEqual(write.status_code, 200, write.text)
                self.assertNotIn(secret_value.decode("ascii"), write.text)

                wrong_key_target = b"wrong-key-active-secret"
                wrong_key_write = _request(
                    "POST",
                    port,
                    "/v1/workspaces/workspace-1/secrets/wrong-key-target",
                    token=token,
                    json_body={
                        "value_base64": _b64(wrong_key_target),
                        "labels": {"intent": "postgres.password"},
                        "caller_subject": "acceptance",
                        "correlation_id": "write-wrong-key-target",
                    },
                )
                self.assertEqual(wrong_key_write.status_code, 200, wrong_key_write.text)
            finally:
                stdout, stderr = _stop_provider(process)

            process = _start_provider(port=port, environment=environment)
            try:
                _wait_ready(port)
                resolved = _resolve(port, token=token, correlation_id="resolve-after-restart")
                self.assertEqual(resolved.status_code, 200, resolved.text)
                self.assertEqual(
                    base64.b64decode(resolved.json()["value_base64"]),
                    secret_value,
                )

                denied = _resolve(
                    port,
                    token=denied_token,
                    correlation_id="wrong-scope",
                )
                self.assertEqual(denied.status_code, 403)
                self.assertNotIn(secret_value.decode("ascii"), denied.text)

                rotated_value = b"live-secret-postgres-password-v2"
                rotated = _request(
                    "POST",
                    port,
                    "/v1/workspaces/workspace-1/secrets/postgres-password/rotate",
                    token=token,
                    json_body={
                        "value_base64": _b64(rotated_value),
                        "labels": {"intent": "postgres.password"},
                        "caller_subject": "acceptance",
                        "correlation_id": "rotate-1",
                    },
                )
                self.assertEqual(rotated.status_code, 200, rotated.text)
                self.assertNotIn(rotated_value.decode("ascii"), rotated.text)

                current = _resolve(port, token=token, correlation_id="resolve-current")
                self.assertEqual(
                    base64.b64decode(current.json()["value_base64"]),
                    rotated_value,
                )

                metadata = _request(
                    "GET",
                    port,
                    "/v1/workspaces/workspace-1/secrets/postgres-password/metadata",
                    token=token,
                )
                self.assertEqual(metadata.status_code, 200, metadata.text)
                self.assertEqual(metadata.json()["metadata"]["version_number"], 2)
                self.assertNotIn(rotated_value.decode("ascii"), metadata.text)

                revoked = _request(
                    "POST",
                    port,
                    "/v1/workspaces/workspace-1/secrets/postgres-password/revoke",
                    token=token,
                )
                self.assertEqual(revoked.status_code, 200, revoked.text)

                after_revoke = _resolve(
                    port,
                    token=token,
                    correlation_id="resolve-after-revoke",
                )
                self.assertEqual(after_revoke.status_code, 409)
                self.assertNotIn(rotated_value.decode("ascii"), after_revoke.text)
            finally:
                more_stdout, more_stderr = _stop_provider(process)
                stdout += more_stdout
                stderr += more_stderr

            audit_rows = SqliteAuditStore(db_path).rows_for_tests()
            outcomes = [row["outcome"] for row in audit_rows]
            self.assertIn("stored", outcomes)
            self.assertIn("resolved", outcomes)
            self.assertIn("denied", outcomes)
            self.assertIn("rotated", outcomes)
            self.assertIn("metadata", outcomes)
            self.assertIn("revoked", outcomes)

            leak_surface = "\n".join(
                [
                    stdout,
                    stderr,
                    repr(audit_rows),
                ]
            )
            for forbidden in (
                secret_value.decode("ascii"),
                rotated_value.decode("ascii"),
                wrong_key_target.decode("ascii"),
                token,
                denied_token,
            ):
                self.assertNotIn(forbidden, leak_surface)
                self.assertNotIn(forbidden.encode("utf-8"), db_path.read_bytes())
            self.assertNotIn(key_bytes, db_path.read_bytes())

            wrong_key_path = base / "wrong-master.key"
            wrong_key_path.write_text(
                encode_master_key_for_file(os.urandom(32)),
                encoding="utf-8",
            )
            wrong_key_path.chmod(0o600)
            wrong_environment = {
                **environment,
                "CPK_SECRETS_MASTER_KEY_FILE": str(wrong_key_path),
            }
            process = _start_provider(port=port, environment=wrong_environment)
            try:
                _wait_ready(port)
                wrong_key = _request(
                    "POST",
                    port,
                    "/v1/workspaces/workspace-1/secrets/wrong-key-target/resolve",
                    token=token,
                    json_body={
                        "intent": "postgres.password",
                        "caller_subject": "acceptance",
                        "correlation_id": "wrong-key",
                    },
                )
                self.assertEqual(wrong_key.status_code, 503)
                self.assertEqual(wrong_key.json()["detail"]["outcome"], "unavailable")
                self.assertNotIn(rotated_value.decode("ascii"), wrong_key.text)
            finally:
                wrong_stdout, wrong_stderr = _stop_provider(process)
                self.assertNotIn(rotated_value.decode("ascii"), wrong_stdout + wrong_stderr)


def _start_provider(*, port: int, environment: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "control_plane_kit_secrets.server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )


def _stop_provider(process: subprocess.Popen[str]) -> tuple[str, str]:
    process.terminate()
    try:
        return process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.communicate(timeout=10)


def _wait_ready(port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"http://127.0.0.1:{port}/health/ready", timeout=1)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
    raise AssertionError("provider did not become ready")


def _request(
    method: str,
    port: int,
    path: str,
    *,
    token: str,
    json_body: dict[str, object] | None = None,
) -> httpx.Response:
    return httpx.request(
        method,
        f"http://127.0.0.1:{port}{path}",
        headers={"Authorization": f"Bearer {token}"},
        json=json_body,
        timeout=5,
    )


def _resolve(port: int, *, token: str, correlation_id: str) -> httpx.Response:
    return _request(
        "POST",
        port,
        "/v1/workspaces/workspace-1/secrets/postgres-password/resolve",
        token=token,
        json_body={
            "intent": "postgres.password",
            "caller_subject": "acceptance",
            "correlation_id": correlation_id,
        },
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


if __name__ == "__main__":
    unittest.main()
