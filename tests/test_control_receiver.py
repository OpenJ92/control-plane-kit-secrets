"""Required host admission before private reads/custody and isolated read authority."""
import importlib
import importlib.util
import inspect
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import Match
from control_plane_kit_core.control_routes import NODE_HEALTH_ROUTES
import control_plane_kit_core as core
from control_plane_kit_secrets import api, bootstrap, crypto
from control_plane_kit_secrets.audit import SqliteAuditStore
from control_plane_kit_secrets.auth import ProviderAuthorizer
from control_plane_kit_secrets.custody import admit_provider_custody
from control_plane_kit_secrets.store import EncryptedSecretStore
from control_fixtures import ControlAuthority


class ControlReceiverTests(unittest.TestCase):
    def receiver(self):
        name = "control_plane_kit_secrets.control"
        self.assertIsNotNone(importlib.util.find_spec(name), "required public control receiver is missing")
        return importlib.import_module(name)

    def test_api_requires_control_and_one_explicit_provider_initializer(self):
        parameters = inspect.signature(api.create_app).parameters
        for name in ("control", "initialize_provider"):
            self.assertIn(name, parameters, f"required {name} admission boundary is missing")
            self.assertIs(parameters[name].default, inspect.Parameter.empty)
        self.assertNotIn("store", parameters)
        self.assertNotIn("audit_store", parameters)
        self.assertNotIn("credentials", parameters)

    def test_invalid_control_and_real_sdk_collision_precede_initializer(self):
        receiver = self.receiver()
        calls = []

        def initialize():
            calls.append("unexpected initialization")
            raise AssertionError("initializer ran before host admission")

        with self.assertRaises(receiver.SecretsControlConfigurationError):
            api.create_app(control=object(), initialize_provider=initialize)
        self.assertEqual(calls, [])
        collision = FastAPI()

        @collision.get("/__control/collision")
        def reserved_route():
            return {}

        with patch.object(api, "FastAPI", return_value=collision):
            with self.assertRaises(ValueError):
                api.create_app(control=ControlAuthority().configuration(receiver),
                               initialize_provider=initialize, clock=lambda: 150)
        self.assertEqual(calls, [])
        self.assertFalse({"/__control/capabilities", "/__control/status", "/__control/health/liveness"}
                         & {route.path for route in collision.routes})

    def test_invalid_public_startup_does_not_read_private_files(self):
        receiver = self.receiver()
        module_name = "control_plane_kit_secrets.server"
        self.assertNotIn(module_name, sys.modules)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            database = base / "uncreated" / "provider.sqlite3"
            environment = {
                "CPK_SECRETS_DATABASE_PATH": str(database),
                "CPK_SECRETS_CONTROL_CONFIGURATION_FILE": str(base / "absent-control"),
                "CPK_SECRETS_MASTER_KEY_FILE": str(base / "private-key-marker"),
                "CPK_SECRETS_CREDENTIALS_FILE": str(base / "private-credentials-marker"),
            }
            with patch.dict(os.environ, environment, clear=True):
                with patch.object(crypto, "load_master_key_from_environment",
                                  side_effect=AssertionError("private key loader ran")) as key_loader:
                    with patch.object(bootstrap, "load_provider_credentials",
                                      side_effect=AssertionError("private credential loader ran")) as credentials:
                        with self.assertRaises(receiver.SecretsControlConfigurationError):
                            importlib.import_module(module_name)
                        key_loader.assert_not_called()
                        credentials.assert_not_called()
            self.assertNotIn(module_name, sys.modules)
            self.assertFalse(database.parent.exists())

    def test_real_initializer_runs_once_after_complete_host_and_failure_returns_no_app(self):
        receiver = self.receiver()
        authority = ControlAuthority()
        app = FastAPI(title="control-plane-kit-secrets")
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            key_path = base / "master.key"
            key_path.write_text(crypto.encode_master_key_for_file(os.urandom(32)))
            key_path.chmod(0o600)
            database = base / "uncreated" / "provider.sqlite3"

            def initialize():
                calls.append("initialize")
                paths = {route.path for route in app.routes}
                self.assertTrue({"/__control/capabilities", "/__control/status",
                                 "/health/live", "/health/ready",
                                 "/docs", "/openapi.json"} <= paths)
                self.assertTrue(any(path.startswith("/v1/") for path in paths))
                health = NODE_HEALTH_ROUTES.routes[0]
                health_routes = [route for route in app.routes
                                 if route.name == health.name and route.path == health.path
                                 and route.methods == {health.method.value}]
                self.assertEqual(len(health_routes), 1)
                match, child_scope = health_routes[0].matches({
                    "type": "http", "method": "GET", "path": "/__control/health/liveness",
                    "root_path": "",
                })
                self.assertIs(match, Match.FULL)
                self.assertEqual(child_scope["path_params"], {"health_kind": "liveness"})
                self.assertFalse(database.parent.exists())
                stores = admit_provider_custody(database, master_key=crypto.load_master_key_file(key_path),
                                               provider_id="initializer-test")
                return stores[0], stores[1], ()

            with patch.object(api, "FastAPI", return_value=app):
                result = api.create_app(control=authority.configuration(receiver),
                                        initialize_provider=initialize,
                                        provider_id="initializer-test", clock=lambda: 150)
            self.assertIs(result, app)
            self.assertEqual(calls, ["initialize"])
            with TestClient(result) as client:
                self.assertEqual(client.get("/health/live").status_code, 200)
            self.assertEqual(calls, ["initialize"])

        failure_calls = []
        returned = []

        def fail_initialization():
            failure_calls.append("initialize")
            raise bootstrap.ProviderConfigurationError()

        with self.assertRaises(bootstrap.ProviderConfigurationError):
            returned.append(api.create_app(control=authority.configuration(receiver),
                                           initialize_provider=fail_initialization, clock=lambda: 150))
        self.assertEqual(failure_calls, ["initialize"])
        self.assertEqual(returned, [])

    def test_real_signed_reads_keep_instance_authority_and_do_no_provider_work(self):
        receiver = self.receiver()
        first, other = ControlAuthority(), ControlAuthority("other")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            key_path = base / "master.key"
            key_path.write_text(crypto.encode_master_key_for_file(os.urandom(32)))
            key_path.chmod(0o600)
            store, audit = admit_provider_custody(base / "provider.sqlite3",
                master_key=crypto.load_master_key_file(key_path), provider_id="read-test")
            app = api.create_app(control=first.configuration(receiver),
                                 initialize_provider=lambda: (store, audit, ()), clock=lambda: 150)
            request, static = first.signed_read(static=True)
            health_request, health = first.signed_read()
            _, foreign = other.signed_read()
            _, wrong_runtime = first.signed_read(changes={"runtime_id": other.runtime})
            _, wrong_target = first.signed_read(changes={"target": other.target})
            _, readiness = first.signed_read(kind=core.NodeHealthReadKind.READINESS)
            with patch.object(ProviderAuthorizer, "authenticate", side_effect=AssertionError("provider auth ran")):
                with patch.object(EncryptedSecretStore, "_connection", side_effect=AssertionError("store IO ran")):
                    with patch.object(SqliteAuditStore, "_connection", side_effect=AssertionError("audit IO ran")):
                        with TestClient(app) as client:
                            capabilities = client.get("/__control/capabilities",
                                headers={"Authorization": f"Bearer {static}"})
                            self.assertEqual(capabilities.status_code, 200)
                            self.assertEqual(capabilities.content, core.NodeControlSurfaceReadResultCodec(
                                request, first.declaration).capabilities_result().canonical_bytes())
                            live = client.get("/__control/health/liveness",
                                headers={"Authorization": f"Bearer {health}"})
                            self.assertEqual(live.status_code, 200)
                            self.assertIs(core.NodeHealthReadResultCodec(health_request, first.declaration)
                                          .decode(live.json()).outcome, core.NodeHealthReadOutcome.HEALTHY)
                            for token in (None, static, foreign, wrong_runtime, wrong_target, "provider-token-marker"):
                                headers = {} if token is None else {"Authorization": f"Bearer {token}"}
                                self.assertEqual(client.get("/__control/health/liveness", headers=headers).status_code, 401)
                            for token in (None, health, "provider-token-marker"):
                                headers = {} if token is None else {"Authorization": f"Bearer {token}"}
                                self.assertEqual(client.get("/__control/capabilities", headers=headers).status_code, 401)
                            self.assertNotEqual(client.get("/__control/health/readiness",
                                headers={"Authorization": f"Bearer {readiness}"}).status_code, 200)
            self.assertEqual(audit.rows_for_tests(), [])


if __name__ == "__main__":
    unittest.main()
