"""Bounded public protocol admission, independent of private provider custody."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import stat
from typing import Callable, Mapping

import control_plane_kit_core as core
from control_plane_kit_server_sdk.health import WorkloadNodeHealthReadDispatcher
from control_plane_kit_server_sdk.verification import (
    Ed25519WorkloadNodeControlSurfaceReadVerifier,
    Ed25519WorkloadNodeHealthReadVerifier,
)
from control_plane_kit_server_sdk.verifier_keys import (
    AtomicWorkloadNodeControlSurfaceReadVerifierKeySet,
    AtomicWorkloadNodeHealthReadVerifierKeySet,
    WorkloadNodeControlSurfaceReadVerifierKeySet,
    WorkloadNodeHealthReadVerifierKeySet,
)


CONTROL_CONFIGURATION_ENVIRONMENT = "CPK_SECRETS_CONTROL_CONFIGURATION_FILE"
MAX_CONTROL_BYTES = 65_536
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")


class SecretsControlConfigurationError(ValueError):
    def __init__(self) -> None:
        super().__init__("secret provider control configuration is invalid")


def secrets_control_declaration() -> core.WorkloadNodeControlSurfaceDeclaration:
    return core.WorkloadNodeControlSurfaceDeclaration(
        core.WorkloadNodeControlSurfaceDescriptor(
            core.NodeControlGraphReference(core.NodeControlGraphReferenceRole.PROVIDER_SOCKET, "control"),
            (), health_reads=(core.NodeHealthReadKind.LIVENESS,),
        ), profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2,
    )


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class SecretsControlConfiguration:
    target: core.NodeControlTarget
    runtime_id: core.NodeControlGraphReference
    declaration: core.WorkloadNodeControlSurfaceDeclaration
    surface_issuer: str
    surface_keys: WorkloadNodeControlSurfaceReadVerifierKeySet
    health_issuer: str
    health_keys: WorkloadNodeHealthReadVerifierKeySet

    def __post_init__(self) -> None:
        valid = False
        try:
            valid = (
                type(self.target) is core.NodeControlTarget
                and type(self.runtime_id) is core.NodeControlGraphReference
                and self.runtime_id.role is core.NodeControlGraphReferenceRole.RUNTIME
                and type(self.declaration) is core.WorkloadNodeControlSurfaceDeclaration
                and self.declaration == secrets_control_declaration()
                and self.target.provider_socket_name == self.declaration.surface.provider_socket_name
                and type(self.surface_keys) is WorkloadNodeControlSurfaceReadVerifierKeySet
                and type(self.health_keys) is WorkloadNodeHealthReadVerifierKeySet
                and self.surface_keys.purpose is core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ
                and self.health_keys.purpose is core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ
                and all(type(value) is str and _REFERENCE.fullmatch(value)
                        for value in (self.surface_issuer, self.health_issuer,
                                      core.workload_node_control_audience(self.target)))
            )
        except Exception:
            valid = False
        if not valid:
            raise SecretsControlConfigurationError()


def _object(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ValueError
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _family(value, snapshot_type, purpose):
    value = _object(value, {"issuer", "public_keys"})
    entries = value["public_keys"]
    if type(entries) is not list or not 1 <= len(entries) <= 16:
        raise ValueError
    keys = []
    for entry in entries:
        entry = _object(entry, {"key_id", "algorithm", "public_key_pem"})
        keys.append(core.DelegationPublicKey(
            entry["key_id"], core.DelegationKeyAlgorithm(entry["algorithm"]), entry["public_key_pem"],
        ))
    return value["issuer"], snapshot_type(purpose, tuple(keys))


def decode_secrets_control_configuration(raw: bytes) -> SecretsControlConfiguration:
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CONTROL_BYTES:
            raise ValueError
        value = _object(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object),
                        {"profile", "target", "runtime_id", "declaration", "surface_read", "health_read"})
        if value["profile"] != "secrets-control-configuration.v1":
            raise ValueError
        target = _object(value["target"], {"workspace_id", "graph_revision", "node_id", "provider_socket_name"})
        roles = core.NodeControlGraphReferenceRole
        target = core.NodeControlTarget(**{
            name: core.NodeControlGraphReference(role, target[name])
            for name, role in (("workspace_id", roles.WORKSPACE), ("graph_revision", roles.GRAPH_REVISION),
                               ("node_id", roles.NODE), ("provider_socket_name", roles.PROVIDER_SOCKET))
        })
        surface_issuer, surface_keys = _family(
            value["surface_read"], WorkloadNodeControlSurfaceReadVerifierKeySet,
            core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ,
        )
        health_issuer, health_keys = _family(
            value["health_read"], WorkloadNodeHealthReadVerifierKeySet,
            core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ,
        )
        return SecretsControlConfiguration(
            target=target, runtime_id=core.NodeControlGraphReference(roles.RUNTIME, value["runtime_id"]),
            declaration=core.WorkloadNodeControlSurfaceDeclarationCodec().decode(value["declaration"]),
            surface_issuer=surface_issuer, surface_keys=surface_keys,
            health_issuer=health_issuer, health_keys=health_keys,
        )
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure


def encode_secrets_control_configuration(configuration: SecretsControlConfiguration) -> bytes:
    try:
        if type(configuration) is not SecretsControlConfiguration:
            raise ValueError
        configuration.__post_init__()

        def family(issuer, snapshot):
            return {"issuer": issuer, "public_keys": [
                {"key_id": key.key_id, "algorithm": key.algorithm.value, "public_key_pem": key.public_key_pem}
                for key in snapshot.public_keys
            ]}

        raw = json.dumps({
            "profile": "secrets-control-configuration.v1", "target": configuration.target.descriptor(),
            "runtime_id": configuration.runtime_id.value, "declaration": configuration.declaration.descriptor(),
            "surface_read": family(configuration.surface_issuer, configuration.surface_keys),
            "health_read": family(configuration.health_issuer, configuration.health_keys),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        decode_secrets_control_configuration(raw)
        return raw
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure


def read_secrets_control_configuration(environment: Mapping[str, str]) -> SecretsControlConfiguration:
    try:
        path = environment.get(CONTROL_CONFIGURATION_ENVIRONMENT)
        if (type(path) is not str or not path or not os.path.isabs(path)
                or "\x00" in path or len(path.encode("utf-8")) > 4096):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(MAX_CONTROL_BYTES + 1)
        finally:
            os.close(descriptor)
        return decode_secrets_control_configuration(raw)
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure


def create_control_read_dependencies(
    configuration: SecretsControlConfiguration, *, clock: Callable[[], int],
) -> tuple[Ed25519WorkloadNodeControlSurfaceReadVerifier, WorkloadNodeHealthReadDispatcher]:
    try:
        admitted = decode_secrets_control_configuration(encode_secrets_control_configuration(configuration))
        audience = core.workload_node_control_audience(admitted.target)
        surface = Ed25519WorkloadNodeControlSurfaceReadVerifier(
            AtomicWorkloadNodeControlSurfaceReadVerifierKeySet(admitted.surface_keys),
            expected_issuer=admitted.surface_issuer, expected_audience=audience, clock=clock,
        )
        health = Ed25519WorkloadNodeHealthReadVerifier(
            AtomicWorkloadNodeHealthReadVerifierKeySet(admitted.health_keys),
            expected_issuer=admitted.health_issuer, expected_audience=audience, clock=clock,
        )
        return surface, WorkloadNodeHealthReadDispatcher(
            target=admitted.target, runtime_id=admitted.runtime_id, declaration=admitted.declaration,
            verifier=health, liveness=lambda: core.NodeHealthReadOutcome.HEALTHY, readiness=None,
        )
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure
