"""Secrets41 receiver laws; initial red is the existing decoder's V2 refusal."""
from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
import control_plane_kit_core as core
from control_plane_kit_secrets import api, control
from control_plane_kit_secrets.auth import ProviderAuthorizer
from control_plane_kit_secrets.audit import SqliteAuditStore
from control_plane_kit_secrets.store import EncryptedSecretStore
from receiver_control_fixtures import ReceiverAuthority
from test_live_provider_process import _free_port, _start_provider, _stop_provider
from control_plane_kit_secrets.crypto import encode_master_key_for_file


COMMON_PATH = "CPK_WRAPPER_CONFIGURATION_FILE"
OLD_PATH = "CPK_SECRETS_CONTROL_CONFIGURATION_FILE"


class ReceiverAdoptionTests(unittest.TestCase):
    def admitted(self, authority):
        raw = authority.encoded()
        # Validate the SAME statically reviewed raw builder before Secrets runs.
        # A failure here invalidates the earlier conditional fixture/red premise.
        from control_plane_kit_core.receiver_configuration import ReceiverNodeControlConfigurationCodec
        codec = ReceiverNodeControlConfigurationCodec()
        expected = codec.decode_bytes(raw)
        self.assertEqual(codec.decode_bytes(codec.encode_bytes(expected)), expected)
        try:
            value = control.decode_secrets_control_configuration(raw)
        except control.SecretsControlConfigurationError:
            self.fail("Secrets must admit the statically reviewed common receiver V2 document")
        self.assertEqual(value, expected)
        return value

    def rejected(self, action):
        with self.assertRaises(control.SecretsControlConfigurationError) as caught:
            action()
        self.assertEqual(str(caught.exception), "secret provider control configuration is invalid")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_common_profile_is_core_value_and_only_common_path_is_selected(self):
        authority = ReceiverAuthority()
        configuration = self.admitted(authority)
        self.assertEqual(configuration.target.receiver_id, "a" * 32)
        self.assertNotIn("graph_revision", configuration.target.descriptor())
        self.assertEqual(configuration.declaration, control.secrets_control_declaration())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receiver.json"
            path.write_bytes(authority.encoded())
            path.chmod(0o444)
            self.assertEqual(control.read_secrets_control_configuration({COMMON_PATH: str(path)}), configuration)
            self.rejected(lambda: control.read_secrets_control_configuration({OLD_PATH: str(path)}))
            # The obsolete setting is not a second source, even if populated.
            self.assertEqual(control.read_secrets_control_configuration(
                {COMMON_PATH: str(path), OLD_PATH: str(path.parent / "absent")}), configuration)

    def test_shared_configuration_cannot_broaden_secrets_declaration(self):
        authority = ReceiverAuthority()
        configuration = self.admitted(authority)
        from control_plane_kit_core.receiver_configuration import ReceiverNodeControlConfigurationCodec
        from control_plane_kit_core.wrapper_configuration import NodeControlVerificationConfiguration
        codec = ReceiverNodeControlConfigurationCodec()
        readiness = replace(configuration.declaration, surface=replace(configuration.declaration.surface,
            health_reads=(core.NodeHealthReadKind.LIVENESS, core.NodeHealthReadKind.READINESS)))
        variable = core.ControlPlaneVariableDescriptor(
            core.NodeControlGraphReference(core.NodeControlGraphReferenceRole.VARIABLE, "private-value"),
            core.ControlPlaneVariableKind.SCALAR, core.ControlPlaneStateCodec.SCALAR_V1,
            (core.ControlPlaneVariableOperationContract(core.NodeControlOperation.READ_STATE, None,
                core.ControlPlaneResultCodec.STATE_V1),
             core.ControlPlaneVariableOperationContract(core.NodeControlOperation.APPLY_COMMAND,
                core.ControlPlaneCommandCodec.REPLACE_SCALAR_V1, core.ControlPlaneResultCodec.TRANSITION_V1)))
        variables = replace(configuration.declaration,
            surface=replace(configuration.declaration.surface, variables=(variable,)))
        command = NodeControlVerificationConfiguration(core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL,
            "receiver-command", (authority.health_public,))
        candidates = (replace(configuration, declaration=readiness),
            replace(configuration, declaration=variables, verifiers=configuration.verifiers + (command,)))
        calls = []
        for candidate in candidates:
            raw = codec.encode_bytes(candidate)
            # These are lawful generic Core configurations, disallowed by Secrets.
            self.assertEqual(codec.decode_bytes(raw), candidate)
            self.rejected(lambda: control.decode_secrets_control_configuration(raw))
            self.rejected(lambda: api.create_app(control=candidate,
                initialize_provider=lambda: calls.append("forbidden"), clock=lambda: 150))
        forged = copy.copy(configuration)
        object.__setattr__(forged, "declaration", readiness)
        self.rejected(lambda: api.create_app(control=forged,
            initialize_provider=lambda: calls.append("forbidden"), clock=lambda: 150))
        self.assertEqual(calls, [])

    def test_old_mixed_extra_and_wrong_family_documents_refuse(self):
        authority = ReceiverAuthority()
        self.admitted(authority)
        for mutate in (
            lambda doc: doc.update(profile="secrets-control-configuration.v1"),
            lambda doc: doc.update(profile="workload-node-control-configuration.v1"),
            lambda doc: doc.update(profile="unknown"),
            lambda doc: doc["target"].update(graph_revision="old-graph"),
            lambda doc: doc.update(runtime_id="old-runtime"),
            lambda doc: doc.update(private_key="private-shaped-sentinel"),
            lambda doc: doc["verifiers"].append(doc["verifiers"][0]),
            lambda doc: doc["verifiers"][1].update(purpose=core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL.value),
        ):
            document = authority.document()
            mutate(document)
            self.rejected(lambda: control.decode_secrets_control_configuration(json.dumps(document).encode()))
        duplicate = b'{"profile":"workload-node-control-configuration.v2",' + authority.encoded()[1:]
        self.rejected(lambda: control.decode_secrets_control_configuration(duplicate))

    def test_common_opened_file_is_0444_stable_and_closed_on_refusal(self):
        authority = ReceiverAuthority()
        self.admitted(authority)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receiver.json"
            path.write_bytes(authority.encoded())
            path.chmod(0o600)
            self.rejected(lambda: control.read_secrets_control_configuration({COMMON_PATH: str(path)}))
            path.chmod(0o444)
            actual_stat, actual_close = os.fstat, os.close
            observed, closed = [], []
            def changing_stat(descriptor):
                value = actual_stat(descriptor)
                observed.append(descriptor)
                return SimpleNamespace(st_mode=value.st_mode, st_size=value.st_size,
                    st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns + (len(observed) > 1))
            def close(descriptor):
                closed.append(descriptor)
                return actual_close(descriptor)
            with patch.object(os, "fstat", side_effect=changing_stat), patch.object(os, "close", side_effect=close):
                self.rejected(lambda: control.read_secrets_control_configuration({COMMON_PATH: str(path)}))
            self.assertEqual(len(observed), 2)
            self.assertEqual(closed, [observed[0]])

    def test_actual_sdk_collision_keeps_initializer_and_lifespan_untouched(self):
        authority = ReceiverAuthority()
        configuration = self.admitted(authority)
        app = FastAPI()
        @app.get("/__control/collision")
        def collision():
            return {}
        lifespan = app.router.lifespan_context
        calls = []
        with patch.object(api, "FastAPI", return_value=app), self.assertRaises(ValueError):
            api.create_app(control=configuration, initialize_provider=lambda: calls.append("forbidden"))
        self.assertEqual(calls, [])
        self.assertIs(app.router.lifespan_context, lifespan)
        self.assertFalse({"/__control/capabilities", "/__control/status"} & {route.path for route in app.routes})

    def test_installed_receiver_accepts_two_signed_contexts_without_provider_authority(self):
        authority = ReceiverAuthority()
        configuration = self.admitted(authority)
        # Opaque sentinels make any unintended store use fail; existing tests own real custody.
        initializations = []
        def initialize():
            initializations.append(True)
            return object(), object(), ()
        app = api.create_app(control=configuration, initialize_provider=initialize, clock=lambda: 150)
        self.assertEqual(initializations, [True])
        encoded = control.encode_secrets_control_configuration(configuration)
        with patch.object(ProviderAuthorizer, "authenticate", side_effect=AssertionError("provider auth reached")), \
                patch.object(EncryptedSecretStore, "_connection", side_effect=AssertionError("custody reached")), \
                patch.object(SqliteAuditStore, "_connection", side_effect=AssertionError("audit reached")):
            with TestClient(app) as client:
                for suffix in ("a", "b"):
                    context = core.NodeControlAuthorityContext("graph-" + suffix, "projection-" + suffix)
                    for static, path in ((True, "/__control/capabilities"), (False, "/__control/health/liveness")):
                        request, token = authority.signed_read(configuration, context=context, static=static)
                        response = client.get(path, headers={"Authorization": "Bearer " + token})
                        self.assertEqual(response.status_code, 200)
                        if static:
                            expected = core.ReceiverControlSurfaceReadResultCodec(request,
                                configuration.declaration).capabilities_result().canonical_bytes()
                            self.assertEqual(response.content, expected)
                        else:
                            result = core.ReceiverHealthReadResultCodec(request, configuration.declaration).decode(response.json())
                            self.assertIs(result.outcome, core.NodeHealthReadOutcome.HEALTHY)
                            self.assertEqual(result.request.authority_context, context)
                for field in ("workspace_id", "runtime_id", "node_id", "provider_socket_name", "receiver_id"):
                    target = configuration.target
                    changed = ("b" * 32 if field == "receiver_id" else replace(getattr(target, field), value="foreign"))
                    _, token = authority.signed_read(configuration, context=context, target=replace(target, **{field: changed}))
                    self.assertEqual(client.get("/__control/health/liveness",
                        headers={"Authorization": "Bearer " + token}).status_code, 401)
        self.assertEqual(control.encode_secrets_control_configuration(configuration), encoded)
        self.assertEqual(initializations, [True])

    def test_real_process_rejects_old_only_or_invalid_common_input_before_custody(self):
        authority = ReceiverAuthority()
        self.admitted(authority)
        for case in ("old-only", "mixed-profile", "extra-capability"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                database = base / "uncreated" / "provider.sqlite3"
                key = base / "master.key"
                key.write_text(encode_master_key_for_file(os.urandom(32)))
                key.chmod(0o600)
                credentials = base / "credentials.json"
                credentials.write_text("[]")
                credentials.chmod(0o600)
                document = authority.document()
                if case == "mixed-profile":
                    document["target"]["graph_revision"] = "old-graph"
                elif case == "extra-capability":
                    declaration = replace(authority.declaration, surface=replace(authority.declaration.surface,
                        health_reads=(core.NodeHealthReadKind.LIVENESS, core.NodeHealthReadKind.READINESS)))
                    document["declaration"] = declaration.descriptor()
                public = base / "receiver.json"
                public.write_text(json.dumps(document))
                public.chmod(0o444)
                environment = {name: value for name, value in os.environ.items()
                    if not name.startswith("CPK_SECRETS_") and name != COMMON_PATH}
                environment.update(CPK_SECRETS_DATABASE_PATH=str(database), CPK_SECRETS_MASTER_KEY_FILE=str(key),
                    CPK_SECRETS_CREDENTIALS_FILE=str(credentials))
                environment[OLD_PATH if case == "old-only" else COMMON_PATH] = str(public)
                process = _start_provider(port=_free_port(), environment=environment)
                try:
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertNotEqual(process.returncode, 0)
                    self.assertLess(len(stdout + stderr), 16384)
                    self.assertIn("secret provider control configuration is invalid", stdout + stderr)
                    self.assertFalse(str(base) in stdout + stderr, "startup disclosed a private path")
                    self.assertFalse(database.parent.exists())
                finally:
                    if process.poll() is None:
                        _stop_provider(process)
