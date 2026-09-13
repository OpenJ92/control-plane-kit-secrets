"""Required public receiving laws; missing owner interface fails explicitly."""
from dataclasses import replace
import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import control_plane_kit_core as core
from control_fixtures import ControlAuthority


ENVIRONMENT_KEY = "CPK_SECRETS_CONTROL_CONFIGURATION_FILE"
ERROR = "secret provider control configuration is invalid"


class ControlConfigurationTests(unittest.TestCase):
    def receiver(self):
        name = "control_plane_kit_secrets.control"
        self.assertIsNotNone(importlib.util.find_spec(name), "required public control receiver is missing")
        return importlib.import_module(name)

    def assert_rejected(self, receiver, action):
        with self.assertRaises(receiver.SecretsControlConfigurationError) as caught:
            action()
        self.assertEqual(str(caught.exception), ERROR)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_typed_public_round_trip_and_exact_liveness_declaration(self):
        receiver = self.receiver()
        authority = ControlAuthority()
        configuration = authority.configuration(receiver)
        self.assertEqual(receiver.secrets_control_declaration(), authority.declaration)
        raw = receiver.encode_secrets_control_configuration(configuration)
        self.assertIs(type(raw), bytes)
        self.assertLessEqual(len(raw), 65536)
        self.assertEqual(json.loads(raw), authority.document())
        self.assertEqual(receiver.decode_secrets_control_configuration(raw), configuration)
        at_limit = raw + b" " * (65536 - len(raw))
        self.assertEqual(receiver.decode_secrets_control_configuration(at_limit), configuration)
        self.assert_rejected(receiver, lambda: receiver.decode_secrets_control_configuration(at_limit + b" "))
        self.assertEqual(configuration.declaration.surface.variables, ())
        self.assertEqual(configuration.declaration.surface.health_reads, (core.NodeHealthReadKind.LIVENESS,))

    def test_closed_document_and_bounded_redacted_failures(self):
        receiver = self.receiver()
        authority = ControlAuthority()
        cases = [b"", b"\xff", b" " * 65537, b"[]", None, authority.encoded().decode()]
        duplicate = b'{"profile":"secrets-control-configuration.v1",' + authority.encoded()[1:]
        cases.append(duplicate)
        for mutation in (
            lambda doc: doc.update(extra="private-document-marker"),
            lambda doc: doc.update(profile="unsupported"),
            lambda doc: doc.update(runtime_id=None),
            lambda doc: doc["target"].update(provider_socket_name="other"),
            lambda doc: doc["health_read"].update(private_key_pem="private-key-marker"),
            lambda doc: doc["surface_read"].update(issuer="bad issuer"),
            lambda doc: doc["surface_read"].update(public_keys=[]),
            lambda doc: doc["health_read"].update(public_keys=doc["health_read"]["public_keys"] * 2),
            lambda doc: doc["health_read"]["public_keys"][0].update(public_key_pem="private-key-marker"),
        ):
            document = authority.document()
            mutation(document)
            cases.append(json.dumps(document).encode())
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                self.assert_rejected(receiver, lambda: receiver.decode_secrets_control_configuration(raw))

    def test_typed_admission_rejects_wrong_roles_families_and_declarations(self):
        receiver = self.receiver()
        authority = ControlAuthority()
        configuration = authority.configuration(receiver)
        altered = core.WorkloadNodeControlSurfaceDeclaration(
            core.WorkloadNodeControlSurfaceDescriptor(
                authority.target.provider_socket_name, (), health_reads=(core.NodeHealthReadKind.READINESS,),
            ), profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2,
        )
        for changes in (
            {"runtime_id": authority.target.node_id}, {"health_keys": authority.surface_keys},
            {"surface_keys": authority.health_keys}, {"declaration": altered},
            {"health_issuer": ""}, {"target": object()},
        ):
            with self.subTest(fields=tuple(changes)):
                self.assert_rejected(receiver, lambda: replace(configuration, **changes))
        forged = copy.copy(configuration)
        object.__setattr__(forged, "declaration", altered)
        self.assert_rejected(receiver, lambda: receiver.encode_secrets_control_configuration(forged))

    def test_required_public_path_uses_opened_regular_bounded_file(self):
        receiver = self.receiver()
        authority = ControlAuthority()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            public = base / "control.json"
            public.write_bytes(authority.encoded())
            public.chmod(0o444)
            opened = []
            open_file = os.open

            def observe_open(path, flags, *args, **kwargs):
                opened.append(flags)
                return open_file(path, flags, *args, **kwargs)

            with patch("os.open", side_effect=observe_open):
                loaded = receiver.read_secrets_control_configuration({ENVIRONMENT_KEY: str(public)})
            self.assertEqual(loaded, authority.configuration(receiver))
            self.assertEqual(len(opened), 1)
            self.assertEqual(opened[0] & os.O_ACCMODE, os.O_RDONLY)
            for flag in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
                self.assertTrue(opened[0] & flag)
            for invalid_path in (None, "", "relative.json", "/" + "x" * 4096,
                                 "/" + "\u00e9" * 2048, "/bad\x00path"):
                with patch("os.open", side_effect=AssertionError("invalid path reached filesystem")):
                    self.assert_rejected(receiver, lambda: receiver.read_secrets_control_configuration(
                        {ENVIRONMENT_KEY: invalid_path},
                    ))
            alias = base / "alias.json"
            alias.symlink_to(public)
            for environment in (
                {}, {ENVIRONMENT_KEY: ""}, {ENVIRONMENT_KEY: "relative.json"},
                {ENVIRONMENT_KEY: "/" + "x" * 4096}, {ENVIRONMENT_KEY: "/bad\x00path"},
                {ENVIRONMENT_KEY: str(base)}, {ENVIRONMENT_KEY: str(alias)},
                {ENVIRONMENT_KEY: str(base / "absent")},
            ):
                with self.subTest(case=list(environment.values())):
                    self.assert_rejected(receiver, lambda: receiver.read_secrets_control_configuration(environment))
            public.chmod(0o600)
            public.write_bytes(b" " * 65537)
            self.assert_rejected(receiver, lambda: receiver.read_secrets_control_configuration(
                {ENVIRONMENT_KEY: str(public)},
            ))

    def test_reader_redacts_os_errors_but_does_not_swallow_base_exceptions(self):
        receiver = self.receiver()
        environment = {ENVIRONMENT_KEY: "/private-path-marker"}
        with patch("os.open", side_effect=OSError("private-file-error")):
            self.assert_rejected(receiver, lambda: receiver.read_secrets_control_configuration(environment))
        with patch("os.open", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                receiver.read_secrets_control_configuration(environment)


if __name__ == "__main__":
    unittest.main()
