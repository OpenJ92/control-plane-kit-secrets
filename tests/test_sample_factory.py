"""Secrets owns startup composition; product check/port values stay caller-owned."""
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch
import control_plane_kit_core as core
from control_plane_kit_core.algebra import ProviderSocket
from control_plane_kit_core.products import ProviderRuntimePort
from control_plane_kit_core.types import Protocol
from control_plane_kit_core.verification import HttpCheck, VerificationContract, VerificationPolicy
from control_plane_kit_core.http_verification_samples import http_verification_check_digest
from control_plane_kit_core.http_verification_sample_installation import (
    HttpVerificationSampleReceiverBinding, HttpVerificationSampleReceiverConfiguration,
    HttpVerificationSampleVerifierConfiguration, HttpVerificationSampleCheckBinding,
)
from control_plane_kit_secrets import api, control, crypto
from control_plane_kit_secrets.custody import admit_provider_custody
from control_plane_kit_secrets.provider_policy import ProviderPolicyStore
from control_fixtures import ControlAuthority


class FactoryFixture:
    def __init__(self):
        self.authority = ControlAuthority("sample-factory")
        self.control = self.authority.configuration(control)
        _, key = self.authority._key("sample-factory-key")
        # Test-owned metadata is supplied by a caller, not defined by Secrets.
        self.check = HttpCheck(check_id="fixture-ready", provider_socket="control", path="/health/ready",
            policy=VerificationPolicy(timeout_seconds=1, maximum_attempts=1, maximum_evidence_bytes=64))
        configuration = HttpVerificationSampleReceiverConfiguration(self.control.target,
            self.control.declaration.identity().value,
            HttpVerificationSampleVerifierConfiguration(
                core.DelegationKeyPurpose.WORKLOAD_HTTP_VERIFICATION_SAMPLE, "fixture-controller", (key,)),
            (HttpVerificationSampleCheckBinding(self.check.check_id, http_verification_check_digest(self.check)),))
        self.binding = HttpVerificationSampleReceiverBinding(configuration, self.control,
            VerificationContract((self.check,)), (ProviderSocket("control", Protocol.HTTP),),
            (ProviderRuntimePort("control", 8081),))


@contextmanager
def private_fixture():
    with TemporaryDirectory() as directory:
        base = Path(directory)
        key = base / "master.key"
        key.write_text(crypto.encode_master_key_for_file(os.urandom(32)))
        key.chmod(0o600)
        credentials = base / "credentials.json"
        credentials.write_text("[]")
        credentials.chmod(0o600)
        environment = {"CPK_SECRETS_DATABASE_PATH": str(base / "custody" / "provider.sqlite3"),
            "CPK_SECRETS_MASTER_KEY_FILE": str(key), "CPK_SECRETS_CREDENTIALS_FILE": str(credentials),
            "CPK_WRAPPER_CONFIGURATION_FILE": str(base / "control.json")}
        yield base, environment


class SampleFactoryTests(unittest.TestCase):
    def test_optional_binding_is_installed_before_exactly_one_initializer(self):
        fixture = FactoryFixture()
        calls = []
        app = FastAPI()
        with private_fixture() as (base, environment):
            def initialize():
                calls.append("initialize")
                self.assertIn("/__control/verification/http", {route.path for route in app.routes})
                self.assertFalse((base / "custody").exists())
                store, audit = admit_provider_custody(environment["CPK_SECRETS_DATABASE_PATH"],
                    master_key=crypto.load_master_key_file(Path(environment["CPK_SECRETS_MASTER_KEY_FILE"])),
                    provider_id="fixture-provider", credentials=())
                return store, audit, (), ProviderPolicyStore(environment["CPK_SECRETS_DATABASE_PATH"],
                                                            provider_id="fixture-provider")
            with patch.object(api, "FastAPI", return_value=app):
                try:
                    result = api.create_app(control=fixture.control, initialize_provider=initialize,
                        provider_id="fixture-provider", clock=lambda: 150,
                        http_verification_binding=fixture.binding)
                except TypeError:
                    self.fail("Secrets factory refuses an optional independent HTTP sample binding")
            self.assertIs(result, app)
            self.assertEqual(calls, ["initialize"])
            with TestClient(result) as client:
                self.assertEqual(client.get("/health/ready").json(), {"status": "ready"})
                self.assertEqual(client.get("/__control/verification/http").status_code, 401)
            self.assertEqual(calls, ["initialize"])

    def test_environment_factory_reads_control_once_or_uses_supplied_snapshot_and_initializes_once(self):
        from control_plane_kit_secrets.application import app_from_environment
        from control_plane_kit_secrets import application, bootstrap
        fixture = FactoryFixture()
        for supplied in (False, True):
            with self.subTest(supplied=supplied), private_fixture() as (base, environment):
                if not supplied:
                    path = Path(environment["CPK_WRAPPER_CONFIGURATION_FILE"])
                    path.write_bytes(core.ReceiverNodeControlConfigurationCodec().encode_bytes(fixture.control))
                    path.chmod(0o444)
                reads, private_calls = [], []
                original_read = application.read_secrets_control_configuration
                original_key = crypto.load_master_key_from_environment
                original_credentials = bootstrap.load_provider_credentials
                def read(source):
                    reads.append("control")
                    result = original_read(source)
                    # The factory must keep this one snapshot, not reopen it.
                    Path(source["CPK_WRAPPER_CONFIGURATION_FILE"]).unlink()
                    return result
                def key(source):
                    private_calls.append("key")
                    return original_key(source)
                def credentials(source):
                    private_calls.append("credentials")
                    return original_credentials(source)
                def custody(*args, **kwargs):
                    private_calls.append("custody")
                    return admit_provider_custody(*args, **kwargs)
                with patch.object(application, "read_secrets_control_configuration", side_effect=read), \
                     patch.object(crypto, "load_master_key_from_environment", side_effect=key), \
                     patch.object(bootstrap, "load_provider_credentials", side_effect=credentials), \
                     patch.object(application, "admit_provider_custody", side_effect=custody):
                    app = app_from_environment(environment, control=fixture.control if supplied else None,
                        http_verification_binding=fixture.binding, clock=lambda: 150,
                        http_sample_clock=lambda: 150)
                self.assertEqual(reads, [] if supplied else ["control"])
                self.assertEqual(private_calls, ["key", "credentials", "custody"])
                self.assertTrue(Path(environment["CPK_SECRETS_DATABASE_PATH"]).is_file())
                with TestClient(app) as client:
                    self.assertEqual(client.get("/health/ready").json(), {"status": "ready"})
                    request, token = fixture.authority.signed_read()
                    response = client.get("/__control/health/liveness", headers={"Authorization": "Bearer " + token})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(core.ReceiverHealthReadResultCodec(request, fixture.control.declaration).decode(
                        response.json()).request, request)
                    self.assertEqual(client.get("/__control/verification/http").status_code, 401)
                self.assertEqual(private_calls, ["key", "credentials", "custody"])

    def test_absent_binding_preserves_ordinary_app_without_sample_route(self):
        from control_plane_kit_secrets.application import app_from_environment
        fixture = FactoryFixture()
        with private_fixture() as (_, environment):
            app = app_from_environment(environment, control=fixture.control, clock=lambda: 150)
            self.assertNotIn("/__control/verification/http", {route.path for route in app.routes})
            with TestClient(app) as client:
                self.assertEqual(client.get("/health/ready").json(), {"status": "ready"})
                self.assertEqual(client.get("/__control/verification/http").status_code, 404)
                self.assertEqual(client.get("/v1/workspaces/fixture/secrets/missing/metadata").status_code, 401)

    def test_cross_wired_and_invalid_binding_refuse_before_private_work(self):
        from dataclasses import replace
        from control_plane_kit_secrets.application import app_from_environment
        from control_plane_kit_secrets import application, bootstrap
        fixture = FactoryFixture()
        other_control = replace(fixture.control, target=replace(fixture.control.target, receiver_id="f" * 32))
        foreign = replace(fixture.binding, receiver_configuration=other_control,
            configuration=replace(fixture.binding.configuration, target=other_control.target))
        self.assertEqual(foreign.audience, fixture.binding.audience)
        different_declaration = replace(fixture.control.declaration, surface=replace(
            fixture.control.declaration.surface, health_reads=(core.NodeHealthReadKind.READINESS,)))
        other_control = replace(fixture.control, declaration=different_declaration)
        foreign_declaration = replace(fixture.binding, receiver_configuration=other_control,
            configuration=replace(fixture.binding.configuration,
                                  declaration_identity=different_declaration.identity().value))
        for binding in (foreign, foreign_declaration, object()):
            for supplied in (False, True):
                with self.subTest(supplied=supplied), private_fixture() as (base, environment):
                    if not supplied:
                        path = Path(environment["CPK_WRAPPER_CONFIGURATION_FILE"])
                        path.write_bytes(core.ReceiverNodeControlConfigurationCodec().encode_bytes(fixture.control))
                        path.chmod(0o444)
                    calls = []
                    def forbidden(*args, **kwargs):
                        calls.append("private")
                        raise AssertionError("private initialization preceded public binding admission")
                    with patch.object(crypto, "load_master_key_from_environment", side_effect=forbidden), \
                         patch.object(bootstrap, "load_provider_credentials", side_effect=forbidden), \
                         patch.object(application, "admit_provider_custody", side_effect=forbidden):
                        with self.assertRaises(ValueError):
                            app_from_environment(environment, control=fixture.control if supplied else None,
                                http_verification_binding=binding)
                    self.assertEqual(calls, [])
                    self.assertFalse((base / "custody").exists())

    def test_initializer_failure_remains_once_and_returns_no_application(self):
        from control_plane_kit_secrets import application, bootstrap
        fixture = FactoryFixture()
        with private_fixture() as (_, environment):
            calls, returned = [], []
            def fail(*args, **kwargs):
                calls.append("custody")
                raise bootstrap.ProviderConfigurationError()
            with patch.object(application, "admit_provider_custody", side_effect=fail):
                with self.assertRaises(bootstrap.ProviderConfigurationError):
                    returned.append(application.app_from_environment(environment, control=fixture.control,
                        http_verification_binding=fixture.binding))
            self.assertEqual(calls, ["custody"])
            self.assertEqual(returned, [])

    def test_factory_import_is_inert_and_supported_server_delegates_once(self):
        import importlib
        import subprocess
        import sys
        from control_plane_kit_secrets import application
        with private_fixture() as (base, environment):
            completed = subprocess.run([sys.executable, "-c",
                "import sys; import control_plane_kit_secrets.application; "
                "assert 'control_plane_kit_secrets.server' not in sys.modules"],
                env={**os.environ, **environment}, capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((base / "custody").exists())
        name = "control_plane_kit_secrets.server"
        self.assertNotIn(name, sys.modules)
        marker = object()
        try:
            with patch.object(application, "app_from_environment", return_value=marker) as compose:
                server = importlib.import_module(name)
                self.assertIs(server.app, marker)
                self.assertIs(server.app_from_environment, compose)
                self.assertEqual(compose.call_count, 1)
        finally:
            sys.modules.pop(name, None)

    def test_explicit_environment_cannot_hide_or_redirect_the_sdk_companion(self):
        from control_plane_kit_secrets import application, bootstrap
        from control_plane_kit_core.http_verification_sample_installation import (
            HTTP_VERIFICATION_SAMPLES_CONFIGURATION_ENVIRONMENT as companion,
        )
        fixture = FactoryFixture()
        for mapped, process in (("mapped", None), (None, "process"), ("mapped", "process")):
            for binding in (None, fixture.binding):
                with self.subTest(mapped=mapped, process=process, bound=binding is not None), \
                     private_fixture() as (base, environment):
                    if mapped is not None:
                        environment[companion] = str(base / mapped)
                    process_environment = {} if process is None else {companion: str(base / process)}
                    calls = []
                    def forbidden(*args, **kwargs):
                        calls.append("private")
                        raise AssertionError("divergent companion reached private initialization")
                    with patch.dict(os.environ, process_environment, clear=True), \
                         patch.object(crypto, "load_master_key_from_environment", side_effect=forbidden), \
                         patch.object(bootstrap, "load_provider_credentials", side_effect=forbidden), \
                         patch.object(application, "admit_provider_custody", side_effect=forbidden):
                        with self.assertRaises(bootstrap.ProviderConfigurationError):
                            application.app_from_environment(environment, control=fixture.control,
                                http_verification_binding=binding)
                        self.assertEqual(dict(os.environ), process_environment)
                    self.assertEqual(calls, [])
                    self.assertFalse((base / "custody").exists())

    def test_matching_companion_path_uses_sdk_admission_before_private_work(self):
        from dataclasses import replace
        from control_plane_kit_secrets import application, bootstrap
        from control_plane_kit_core.http_verification_sample_installation import (
            HTTP_VERIFICATION_SAMPLES_CONFIGURATION_ENVIRONMENT as companion,
            HttpVerificationSampleReceiverConfigurationCodec,
        )
        fixture = FactoryFixture()
        codec = HttpVerificationSampleReceiverConfigurationCodec()
        for mode in ("missing", "malformed", "different-binding", "no-binding", "valid"):
            with self.subTest(mode=mode), private_fixture() as (base, environment):
                path = base / "samples.json"
                environment[companion] = str(path)
                if mode != "missing":
                    configuration = fixture.binding.configuration
                    if mode == "different-binding":
                        configuration = replace(configuration, verifier=replace(configuration.verifier, issuer="other-controller"))
                    path.write_bytes(b"invalid" if mode == "malformed" else codec.encode_canonical_bytes(configuration))
                    path.chmod(0o444)
                calls = []
                def custody(*args, **kwargs):
                    calls.append("custody")
                    return admit_provider_custody(*args, **kwargs)
                def forbidden(*args, **kwargs):
                    calls.append("private")
                    raise AssertionError("invalid companion reached private initialization")
                with patch.dict(os.environ, {companion: str(path)}, clear=True):
                    if mode == "valid":
                        with patch.object(application, "admit_provider_custody", side_effect=custody):
                            app = application.app_from_environment(environment, control=fixture.control,
                                http_verification_binding=fixture.binding)
                        self.assertIn("/__control/verification/http", {route.path for route in app.routes})
                        self.assertEqual(calls, ["custody"])
                        self.assertTrue((base / "custody" / "provider.sqlite3").is_file())
                    else:
                        with patch.object(crypto, "load_master_key_from_environment", side_effect=forbidden), \
                             patch.object(bootstrap, "load_provider_credentials", side_effect=forbidden), \
                             patch.object(application, "admit_provider_custody", side_effect=forbidden):
                            with self.assertRaises(ValueError):
                                application.app_from_environment(environment, control=fixture.control,
                                    http_verification_binding=None if mode == "no-binding" else fixture.binding)
                        self.assertEqual(calls, [])
                        self.assertFalse((base / "custody").exists())
