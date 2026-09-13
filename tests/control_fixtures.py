"""Synthetic protocol authority for owner-container tests; no production defaults."""
from dataclasses import replace
import json

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import control_plane_kit_core as core
from control_plane_kit_server_sdk.verifier_keys import (
    WorkloadNodeControlSurfaceReadVerifierKeySet,
    WorkloadNodeHealthReadVerifierKeySet,
)


class ControlAuthority:
    def __init__(self, suffix="a"):
        roles = core.NodeControlGraphReferenceRole
        self.target = core.NodeControlTarget(
            core.NodeControlGraphReference(roles.WORKSPACE, f"workspace-{suffix}"),
            core.NodeControlGraphReference(roles.GRAPH_REVISION, f"revision-{suffix}"),
            core.NodeControlGraphReference(roles.NODE, f"provider-{suffix}"),
            core.NodeControlGraphReference(roles.PROVIDER_SOCKET, "control"),
        )
        self.runtime = core.NodeControlGraphReference(roles.RUNTIME, f"runtime-{suffix}")
        self.declaration = core.WorkloadNodeControlSurfaceDeclaration(
            core.WorkloadNodeControlSurfaceDescriptor(
                self.target.provider_socket_name, (), health_reads=(core.NodeHealthReadKind.LIVENESS,),
            ), profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2,
        )
        self.surface_issuer = f"surface-{suffix}"
        self.health_issuer = f"health-{suffix}"
        self.surface_private, surface_public = self._key(f"surface-{suffix}")
        self.health_private, health_public = self._key(f"health-{suffix}")
        self.surface_keys = WorkloadNodeControlSurfaceReadVerifierKeySet(
            core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ, (surface_public,),
        )
        self.health_keys = WorkloadNodeHealthReadVerifierKeySet(
            core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ, (health_public,),
        )

    @staticmethod
    def _key(key_id):
        private = Ed25519PrivateKey.generate()
        public = core.DelegationPublicKey(
            key_id, core.DelegationKeyAlgorithm.ED25519,
            private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
        )
        return private, public

    def configuration(self, receiver):
        return receiver.SecretsControlConfiguration(
            target=self.target, runtime_id=self.runtime, declaration=self.declaration,
            surface_issuer=self.surface_issuer, surface_keys=self.surface_keys,
            health_issuer=self.health_issuer, health_keys=self.health_keys,
        )

    def document(self):
        def family(issuer, keys):
            return {"issuer": issuer, "public_keys": [
                {"key_id": key.key_id, "algorithm": key.algorithm.value,
                 "public_key_pem": key.public_key_pem} for key in keys.public_keys
            ]}
        return {
            "profile": "secrets-control-configuration.v1", "target": self.target.descriptor(),
            "runtime_id": self.runtime.value, "declaration": self.declaration.descriptor(),
            "surface_read": family(self.surface_issuer, self.surface_keys),
            "health_read": family(self.health_issuer, self.health_keys),
        }

    def encoded(self):
        return json.dumps(self.document(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signed_read(self, *, static=False, kind=None, issued_at=100, lifetime=100, changes=None):
        if static:
            request = core.NodeControlSurfaceReadRequest(
                self.target, kind or core.NodeControlSurfaceReadKind.CAPABILITIES,
                self.declaration.identity(), "surface-request",
            )
            grant_type = core.DelegatedWorkloadNodeControlSurfaceReadGrant
            profile = core.DelegatedWorkloadNodeControlSurfaceReadGrantProfile.V1
            issuer, keys, private = self.surface_issuer, self.surface_keys, self.surface_private
            payload_key = "workload_node_control_surface_read"
            token_type = "CPK-WORKLOAD-NODE-CONTROL-SURFACE-READ+JWT"
        else:
            request = core.NodeHealthReadRequest(
                self.target, self.runtime, kind or core.NodeHealthReadKind.LIVENESS,
                self.declaration.identity(), "health-request",
            )
            grant_type = core.DelegatedWorkloadNodeHealthReadGrant
            profile = core.DelegatedWorkloadNodeHealthReadGrantProfile.V1
            issuer, keys, private = self.health_issuer, self.health_keys, self.health_private
            payload_key = "workload_node_health_read"
            token_type = "CPK-WORKLOAD-NODE-HEALTH-READ+JWT"
        request = replace(request, **(changes or {}))
        grant = grant_type(
            profile=profile, canonicalization=core.NodeControlCanonicalization.JCS_RFC8785_V1,
            purpose=keys.purpose, issuer=issuer, key_id=keys.public_keys[0].key_id,
            audience=core.workload_node_control_audience(self.target), target=request.target,
            kind=request.kind, declaration_identity=request.declaration_identity,
            request_id=request.request_id, request_digest=request.canonical_digest(),
            issued_at=issued_at, not_before=issued_at, expires_at=issued_at + lifetime,
            jti="owner-control-fixture", **({} if static else {"runtime_id": request.runtime_id}),
        )
        token = jwt.encode({
            "iss": issuer, "aud": grant.audience, "iat": issued_at, "nbf": issued_at,
            "exp": issued_at + lifetime, "jti": grant.jti, payload_key: grant.descriptor(),
        }, private, algorithm="EdDSA", headers={"kid": grant.key_id, "typ": token_type})
        return request, token
