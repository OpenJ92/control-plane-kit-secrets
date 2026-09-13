"""Actual process must reject public bootstrap before creating temporary custody."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from control_plane_kit_secrets.crypto import encode_master_key_for_file
from test_live_provider_process import _free_port, _start_provider, _stop_provider


class PublicControlProcessTests(unittest.TestCase):
    def test_missing_or_malformed_public_configuration_exits_before_custody(self):
        for case in ("missing-setting", "missing-file", "malformed-file"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                database = base / "uncreated" / "provider.sqlite3"
                key = base / "master.key"
                key.write_text(encode_master_key_for_file(os.urandom(32)))
                key.chmod(0o600)
                credentials = base / "credentials.json"
                credentials.write_text("[]")
                credentials.chmod(0o600)
                control = base / "private-path-marker"
                if case == "malformed-file":
                    control.write_text("private-document-marker")
                    control.chmod(0o444)
                environment = {name: value for name, value in os.environ.items()
                               if not name.startswith("CPK_SECRETS_")}
                environment.update({"CPK_SECRETS_DATABASE_PATH": str(database),
                                    "CPK_SECRETS_MASTER_KEY_FILE": str(key),
                                    "CPK_SECRETS_CREDENTIALS_FILE": str(credentials)})
                if case != "missing-setting":
                    environment["CPK_SECRETS_CONTROL_CONFIGURATION_FILE"] = str(control)
                process = _start_provider(port=_free_port(), environment=environment)
                exited = False
                try:
                    try:
                        stdout, stderr = process.communicate(timeout=10)
                        exited = True
                    except subprocess.TimeoutExpired:
                        stdout, stderr = _stop_provider(process)
                    self.assertTrue(exited, "provider ignored required public admission and kept serving")
                    self.assertNotEqual(process.returncode, 0)
                    output = stdout + stderr
                    self.assertIn("secret provider control configuration is invalid", output)
                    self.assertLess(len(output), 16384)
                    for forbidden in (str(base), "private-document-marker"):
                        self.assertFalse(forbidden in output, "public bootstrap detail leaked")
                    self.assertFalse(database.exists(), "public rejection created custody")
                    self.assertFalse(database.parent.exists(), "public rejection created a parent directory")
                finally:
                    if process.poll() is None:
                        _stop_provider(process)


if __name__ == "__main__":
    unittest.main()
