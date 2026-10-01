"""Secrets capability and file admission over the shared public receiver value."""
from __future__ import annotations

import os
import stat
from typing import Mapping

import control_plane_kit_core as core
from control_plane_kit_core.receiver_configuration import (
    ReceiverNodeControlConfiguration, ReceiverNodeControlConfigurationCodec,
)
from control_plane_kit_core.wrapper_configuration import (
    MAX_WRAPPER_CONFIGURATION_BYTES, WORKLOAD_NODE_CONTROL_CONFIGURATION_ENVIRONMENT,
)


CONTROL_CONFIGURATION_ENVIRONMENT = WORKLOAD_NODE_CONTROL_CONFIGURATION_ENVIRONMENT
MAX_CONTROL_BYTES = MAX_WRAPPER_CONFIGURATION_BYTES


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


def require_secrets_control_configuration(value: object) -> ReceiverNodeControlConfiguration:
    try:
        codec = ReceiverNodeControlConfigurationCodec()
        admitted = codec.decode_bytes(codec.encode_bytes(value))
        if admitted.declaration != secrets_control_declaration():
            raise ValueError
        return admitted
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure


def decode_secrets_control_configuration(raw: bytes) -> ReceiverNodeControlConfiguration:
    try:
        return require_secrets_control_configuration(ReceiverNodeControlConfigurationCodec().decode_bytes(raw))
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure


def encode_secrets_control_configuration(configuration: ReceiverNodeControlConfiguration) -> bytes:
    try:
        return ReceiverNodeControlConfigurationCodec().encode_bytes(require_secrets_control_configuration(configuration))
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure


def read_secrets_control_configuration(environment: Mapping[str, str]) -> ReceiverNodeControlConfiguration:
    """Read the explicit common slot once; private provider inputs remain separate."""
    try:
        path = environment.get(CONTROL_CONFIGURATION_ENVIRONMENT)
        if (type(path) is not str or not path or not os.path.isabs(path)
                or "\x00" in path or len(path.encode("utf-8")) > 4096):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o444
                    or before.st_size > MAX_CONTROL_BYTES):
                raise ValueError
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(MAX_CONTROL_BYTES + 1)
            after = os.fstat(descriptor)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError
        finally:
            os.close(descriptor)
        return decode_secrets_control_configuration(raw)
    except Exception:
        failure = SecretsControlConfigurationError()
    raise failure
