"""Installed dependency identity and representative real provider-host composition."""
from __future__ import annotations

from dataclasses import replace
import importlib.metadata
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import control_plane_kit_core as core
from control_plane_kit_secrets import api, control
from control_fixtures import ControlAuthority
from control_plane_kit_secrets.crypto import encode_master_key_for_file, load_master_key_file
from control_plane_kit_secrets.custody import admit_provider_custody


REPO_ROOT = Path(__file__).parents[1]
CORE_URL = (
    "https://github.com/OpenJ92/control-plane-kit/archive/"
    "b79a02d1ac8ef987dd34abeb2297a231b109f7a6.zip"
)
SDK_URL = (
    "https://github.com/OpenJ92/control-plane-kit-server-sdk/archive/"
    "2c5b588237fbe289c965029b4bc2f072715c42f3.zip"
)


class SdkCompatibilityTests(unittest.TestCase):
    def test_runtime_profile_is_explicit_and_replaces_test_only_core(self) -> None:
        project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]
        self.assertCountEqual(project["dependencies"], [
            "cryptography==50.0.0",
            f"control-plane-kit-core @ {CORE_URL}#subdirectory=control-plane-kit-core",
            f"control-plane-kit-server-sdk[fastapi] @ {SDK_URL}",
        ])
        self.assertCountEqual(project["optional-dependencies"]["test"],
                              ["httpx>=0.28", "uvicorn>=0.35"])
        self.assertEqual(project["requires-python"], ">=3.11")

    def test_installed_profile_matches_reviewed_archives_and_framework_versions(self) -> None:
        for name, url, subdirectory in (
            ("control-plane-kit-core", CORE_URL, "control-plane-kit-core"),
            ("control-plane-kit-server-sdk", SDK_URL, None),
        ):
            with self.subTest(package=name):
                distribution = importlib.metadata.distribution(name)
                recorded = distribution.read_text("direct_url.json")
                self.assertIsNotNone(recorded)
                provenance = json.loads(recorded)
                self.assertEqual(provenance["url"], url)
                self.assertEqual(provenance.get("subdirectory"), subdirectory)
                self.assertIn("archive_info", provenance)
                self.assertNotIn("dir_info", provenance)
                self.assertNotIn("vcs_info", provenance)
        for name, expected in (
            ("cryptography", "50.0.0"), ("PyJWT", "2.13.0"),
            ("fastapi", "0.141.1"), ("starlette", "1.6.0"),
        ):
            with self.subTest(package=name):
                self.assertEqual(importlib.metadata.version(name), expected)

    def test_real_sdk_composes_with_existing_provider_routes_and_docs(self) -> None:
        # The production required-control factory installs the real SDK once.
        authority = ControlAuthority("compat")
        configuration = authority.configuration(control)
        declaration = configuration.declaration
        request, token = authority.signed_read(static=True)
        health_request, health_token = authority.signed_read()
        observations = []
        snapshots = []
        install = api.install_cpk_control_routes

        def observe_install(app, **arguments):
            snapshots.append((tuple(app.routes), json.loads(json.dumps(app.openapi()))))
            dispatcher = arguments["health_dispatcher"]
            observe = dispatcher.liveness

            def observe_liveness():
                observations.append(core.NodeHealthReadKind.LIVENESS)
                return observe()

            arguments["health_dispatcher"] = replace(dispatcher, liveness=observe_liveness)
            install(app, **arguments)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            key_path = base / "master.key"
            key_path.write_text(encode_master_key_for_file(os.urandom(32)))
            key_path.chmod(0o600)
            store, audit = admit_provider_custody(
                base / "provider.sqlite3", master_key=load_master_key_file(key_path),
                provider_id="compat-provider",
            )
            with patch.object(api, "install_cpk_control_routes", side_effect=observe_install):
                app = api.create_app(control=configuration, initialize_provider=lambda: (store, audit, ()),
                                     provider_id="compat-provider", clock=lambda: 150)
            self.assertEqual(len(snapshots), 1)
            prior_routes, prior_schema = snapshots[0]
            # Regenerate after installation so the comparison cannot pass merely
            # because the pre-install schema remains in FastAPI's cache.
            app.openapi_schema = None
            self.assertEqual(tuple(app.routes[:len(prior_routes)]), prior_routes)
            with TestClient(app) as client:
                response = client.get("/__control/capabilities",
                                      headers={"Authorization": f"Bearer {token}"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, core.NodeControlSurfaceReadResultCodec(
                    request, declaration,
                ).capabilities_result().canonical_bytes())
                self.assertEqual(client.get("/__control/capabilities").status_code, 401)
                self.assertEqual(observations, [])
                live = client.get("/__control/health/liveness",
                                  headers={"Authorization": f"Bearer {health_token}"})
                self.assertEqual(live.status_code, 200)
                result = core.NodeHealthReadResultCodec(health_request, declaration).decode(live.json())
                self.assertIs(result.outcome, core.NodeHealthReadOutcome.HEALTHY)
                self.assertEqual(client.get("/__control/health/liveness").status_code, 401)
                self.assertEqual(client.get("/__control/health/liveness",
                    headers={"Authorization": f"Bearer {token}"}).status_code, 401)
                self.assertEqual(observations, [core.NodeHealthReadKind.LIVENESS])
                self.assertEqual(client.get("/health/live").json(), {"status": "live"})
                self.assertEqual(client.get("/health/ready").json(), {"status": "ready"})
                self.assertEqual(client.get("/openapi.json").json(), prior_schema)
                for path in ("/docs", "/redoc"):
                    self.assertEqual(client.get(path).status_code, 200)
                denied = client.get("/v1/workspaces/compat-workspace/secrets/missing/metadata")
                self.assertEqual(denied.status_code, 401)
                self.assertEqual(denied.json(), {
                    "detail": {"outcome": "denied", "code": "unauthenticated"},
                })
            self.assertEqual(audit.rows_for_tests(), [])


if __name__ == "__main__":
    unittest.main()
