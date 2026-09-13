"""Installed dependency identity and representative real provider-host composition."""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import control_plane_kit_core as core
from control_plane_kit_server_sdk.fastapi import install_cpk_control_routes
from control_plane_kit_server_sdk.verification import Ed25519WorkloadNodeControlSurfaceReadVerifier
from control_plane_kit_server_sdk.verifier_keys import (
    AtomicWorkloadNodeControlSurfaceReadVerifierKeySet,
    WorkloadNodeControlSurfaceReadVerifierKeySet,
)
from control_plane_kit_secrets.api import create_app
from control_plane_kit_secrets.crypto import encode_master_key_for_file, load_master_key_file
from control_plane_kit_secrets.custody import admit_provider_custody


REPO_ROOT = Path(__file__).parents[1]
CORE_URL = (
    "https://github.com/OpenJ92/control-plane-kit/archive/"
    "95452249d0340707a5cdffe737e34669e9d53165.zip"
)
SDK_URL = (
    "https://github.com/OpenJ92/control-plane-kit-server-sdk/archive/"
    "2b10d5a354ba4da9407d336703aacb96910100d4.zip"
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
        # A test-only static declaration proves host compatibility. Production
        # receiver, health declaration and startup ordering belong to child #26.
        roles = core.NodeControlGraphReferenceRole
        target = core.NodeControlTarget(
            core.NodeControlGraphReference(roles.WORKSPACE, "compat-workspace"),
            core.NodeControlGraphReference(roles.GRAPH_REVISION, "compat-revision"),
            core.NodeControlGraphReference(roles.NODE, "compat-provider"),
            core.NodeControlGraphReference(roles.PROVIDER_SOCKET, "control"),
        )
        declaration = core.WorkloadNodeControlSurfaceDeclaration(
            core.WorkloadNodeControlSurfaceDescriptor(target.provider_socket_name, ()),
        )
        private = Ed25519PrivateKey.generate()
        public = core.DelegationPublicKey(
            "compat-surface-key", core.DelegationKeyAlgorithm.ED25519,
            private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
        )
        purpose = core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ
        verifier = Ed25519WorkloadNodeControlSurfaceReadVerifier(
            AtomicWorkloadNodeControlSurfaceReadVerifierKeySet(
                WorkloadNodeControlSurfaceReadVerifierKeySet(purpose, (public,)),
            ),
            expected_issuer="compat-issuer",
            expected_audience=core.workload_node_control_audience(target),
            clock=lambda: 150,
        )
        request = core.NodeControlSurfaceReadRequest(
            target, core.NodeControlSurfaceReadKind.CAPABILITIES,
            declaration.identity(), "compat-request",
        )
        grant = core.DelegatedWorkloadNodeControlSurfaceReadGrant(
            profile=core.DelegatedWorkloadNodeControlSurfaceReadGrantProfile.V1,
            canonicalization=core.NodeControlCanonicalization.JCS_RFC8785_V1,
            purpose=purpose, issuer="compat-issuer", key_id=public.key_id,
            audience=core.workload_node_control_audience(target), target=target,
            kind=request.kind, declaration_identity=request.declaration_identity,
            request_id=request.request_id, request_digest=request.canonical_digest(),
            issued_at=100, not_before=100, expires_at=200, jti="compat-grant",
        )
        token = jwt.encode({
            "iss": grant.issuer, "aud": grant.audience, "iat": grant.issued_at,
            "nbf": grant.not_before, "exp": grant.expires_at, "jti": grant.jti,
            "workload_node_control_surface_read": grant.descriptor(),
        }, private, algorithm="EdDSA", headers={
            "kid": public.key_id, "typ": "CPK-WORKLOAD-NODE-CONTROL-SURFACE-READ+JWT",
        })
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            key_path = base / "master.key"
            key_path.write_text(encode_master_key_for_file(os.urandom(32)))
            key_path.chmod(0o600)
            store, audit = admit_provider_custody(
                base / "provider.sqlite3", master_key=load_master_key_file(key_path),
                provider_id="compat-provider",
            )
            app = create_app(store=store, audit_store=audit, credentials=(),
                             provider_id="compat-provider")
            prior_routes = tuple(app.routes)
            prior_schema = json.loads(json.dumps(app.openapi()))
            install_cpk_control_routes(app, target=target, declaration=declaration,
                                       surface_read_verifier=verifier)
            self.assertEqual(tuple(app.routes[:len(prior_routes)]), prior_routes)
            with TestClient(app) as client:
                response = client.get("/__control/capabilities",
                                      headers={"Authorization": f"Bearer {token}"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, core.NodeControlSurfaceReadResultCodec(
                    request, declaration,
                ).capabilities_result().canonical_bytes())
                self.assertEqual(client.get("/__control/capabilities").status_code, 401)
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
