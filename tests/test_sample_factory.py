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
