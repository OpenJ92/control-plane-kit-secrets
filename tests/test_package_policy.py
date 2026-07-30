from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys
import unittest

import control_plane_kit_secrets
from control_plane_kit_secrets import SECRETS_BOUNDARY


REPO_ROOT = Path(__file__).parents[1]
SRC_ROOT = REPO_ROOT / "src" / "control_plane_kit_secrets"


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".", maxsplit=1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", maxsplit=1)[0])
    return roots


class PackagePolicyTests(unittest.TestCase):
    def test_package_root_exports_only_lightweight_boundary_values(self) -> None:
        self.assertEqual(
            control_plane_kit_secrets.__all__,
            [
                "PACKAGE_NAME",
                "SECRETS_BOUNDARY",
                "SecretsBoundary",
            ],
        )
        self.assertEqual(
            control_plane_kit_secrets.PACKAGE_NAME,
            "control-plane-kit-secrets",
        )

    def test_boundary_marker_denies_adjacent_package_ownership(self) -> None:
        self.assertEqual(SECRETS_BOUNDARY.package, "control-plane-kit-secrets")
        self.assertTrue(SECRETS_BOUNDARY.owns_encrypted_custody)
        self.assertTrue(SECRETS_BOUNDARY.owns_provider_local_audit)
        self.assertFalse(SECRETS_BOUNDARY.owns_operations_uow)
        self.assertFalse(SECRETS_BOUNDARY.owns_runtime_interpreters)
        self.assertFalse(SECRETS_BOUNDARY.owns_server_process)
        self.assertFalse(SECRETS_BOUNDARY.owns_product_descriptors)

    def test_source_does_not_import_disallowed_packages(self) -> None:
        forbidden = {
            "cloudflare",
            "control_plane_kit_interpreters",
            "control_plane_kit_operations",
            "control_plane_kit_servers",
            "control_plane_kit_servers_cpk_server",
            "docker",
            "httpx",
            "psycopg",
            "sqlalchemy",
        }

        findings: list[str] = []
        for path in sorted(SRC_ROOT.rglob("*.py")):
            overlap = imported_roots(path) & forbidden
            for name in sorted(overlap):
                findings.append(f"{path.relative_to(REPO_ROOT)} imports {name}")

        self.assertEqual(findings, [])

    def test_fastapi_is_isolated_to_provider_api_boundary(self) -> None:
        findings: list[str] = []
        allowed = SRC_ROOT / "api.py"
        for path in sorted(SRC_ROOT.rglob("*.py")):
            overlap = imported_roots(path) & {"fastapi"}
            for name in sorted(overlap):
                if path != allowed:
                    findings.append(f"{path.relative_to(REPO_ROOT)} imports {name}")

        self.assertEqual(findings, [])

    def test_base_import_does_not_eagerly_import_optional_service_packages(self) -> None:
        script = """
import sys
import control_plane_kit_secrets

for name in (
    "docker",
    "fastapi",
    "httpx",
    "psycopg",
    "sqlalchemy",
    "control_plane_kit_operations",
    "control_plane_kit_interpreters",
    "control_plane_kit_servers",
    "control_plane_kit_servers_cpk_server",
):
    assert name not in sys.modules, name
"""

        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_package_source_files_are_explicitly_owned(self) -> None:
        source_files = sorted(
            path.relative_to(SRC_ROOT).as_posix()
            for path in SRC_ROOT.rglob("*.py")
        )

        self.assertEqual(
            source_files,
            [
                "__init__.py",
                "api.py",
                "audit.py",
                "auth.py",
                "bootstrap.py",
                "boundaries.py",
                "crypto.py",
                "models.py",
                "server.py",
                "store.py",
            ],
        )


if __name__ == "__main__":
    unittest.main()
