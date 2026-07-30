from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from control_plane_kit_secrets.bootstrap import (
    ProviderConfigurationError,
    load_provider_credentials,
)


class ProviderBootstrapTests(unittest.TestCase):
    def test_production_credentials_load_from_owner_only_absolute_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "provider-credentials.json")
            path.write_text(_credentials_json(), encoding="utf-8")
            path.chmod(0o600)

            credentials = load_provider_credentials(
                {"CPK_SECRETS_CREDENTIALS_FILE": str(path)}
            )

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].subject, "cpk-server")
            self.assertNotIn("provider-bootstrap-token", repr(credentials))

    def test_production_credentials_reject_unsafe_or_ambiguous_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            credentials = base / "provider-credentials.json"
            credentials.write_text(_credentials_json(), encoding="utf-8")
            credentials.chmod(0o644)
            symlink = base / "credentials-link.json"
            symlink.symlink_to(credentials)

            invalid = (
                {},
                {"CPK_SECRETS_CREDENTIALS_FILE": "relative.json"},
                {"CPK_SECRETS_CREDENTIALS_FILE": str(credentials)},
                {"CPK_SECRETS_CREDENTIALS_FILE": str(symlink)},
                {
                    "CPK_SECRETS_CREDENTIALS_FILE": str(credentials),
                    "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": _credentials_json(),
                },
            )
            for environment in invalid:
                with self.subTest(environment_keys=tuple(environment)):
                    with self.assertRaises(ProviderConfigurationError) as context:
                        load_provider_credentials(environment)
                    self.assertNotIn(
                        "provider-bootstrap-token",
                        str(context.exception),
                    )

    def test_development_json_is_explicit_and_duplicate_keys_fail_closed(self) -> None:
        credentials = load_provider_credentials(
            {
                "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": _credentials_json(),
            }
        )
        self.assertEqual(credentials[0].subject, "cpk-server")

        with self.assertRaises(ProviderConfigurationError):
            load_provider_credentials(
                {
                    "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": (
                        '[{"subject":"a","subject":"b","token":"token","grants":[]}]'
                    ),
                }
            )


def _credentials_json() -> str:
    return json.dumps(
        [
            {
                "subject": "cpk-server",
                "token": "provider-bootstrap-token",
                "grants": [
                    {
                        "action": "secret.resolve",
                        "workspace_id": "*",
                        "intents": ["postgres.password"],
                    }
                ],
            }
        ],
        separators=(",", ":"),
        sort_keys=True,
    )


if __name__ == "__main__":
    unittest.main()
