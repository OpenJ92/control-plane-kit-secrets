"""Independent V2 public wire; keep this builder unchanged across pin adoption."""
import json

import control_plane_kit_core as core
import jwt
from control_fixtures import ControlAuthority


class ReceiverAuthority:
    def __init__(self):
        self.declaration = core.WorkloadNodeControlSurfaceDeclaration(
            core.WorkloadNodeControlSurfaceDescriptor(
                core.NodeControlGraphReference(core.NodeControlGraphReferenceRole.PROVIDER_SOCKET, "control"),
                (), health_reads=(core.NodeHealthReadKind.LIVENESS,)),
            profile=core.WorkloadNodeControlSurfaceDeclarationProfile.V2)
        self.surface_private, self.surface_public = ControlAuthority._key("receiver-surface")
        self.health_private, self.health_public = ControlAuthority._key("receiver-health")

    def document(self):
        def family(purpose, issuer, public):
            return {"purpose": purpose.value, "issuer": issuer, "public_keys": [{
                "key_id": public.key_id, "algorithm": public.algorithm.value,
                "public_key_pem": public.public_key_pem}]}
        return {
            "profile": "workload-node-control-configuration.v2",
            "target": {"workspace_id": "workspace-a", "runtime_id": "runtime-a",
                       "node_id": "provider-a", "provider_socket_name": "control", "receiver_id": "a" * 32},
            "declaration": self.declaration.descriptor(),
            "verifiers": [
                family(core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ,
                       "receiver-surface", self.surface_public),
                family(core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ,
                       "receiver-health", self.health_public)],
        }

    def encoded(self):
        return json.dumps(self.document(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signed_read(self, configuration, *, context, target=None, static=False, kind=None):
        # Successor symbols are reached only after the genuine admission premise.
        scope = configuration.target if target is None else target
        if static:
            request = core.ReceiverControlSurfaceReadRequest(scope, context,
                kind or core.NodeControlSurfaceReadKind.CAPABILITIES,
                self.declaration.identity(), "receiver-surface-read")
            grant_type = core.DelegatedWorkloadReceiverControlSurfaceReadGrant
            profile = core.DelegatedWorkloadReceiverControlSurfaceReadGrantProfile.V2
            purpose = core.DelegationKeyPurpose.WORKLOAD_NODE_CONTROL_SURFACE_READ
            issuer, public, private = "receiver-surface", self.surface_public, self.surface_private
            claim, typ = "workload_node_control_surface_read", "CPK-WORKLOAD-NODE-CONTROL-SURFACE-READ+JWT"
        else:
            request = core.ReceiverHealthReadRequest(scope, context, kind or core.NodeHealthReadKind.LIVENESS,
                self.declaration.identity(), "receiver-health-read")
            grant_type = core.DelegatedWorkloadReceiverHealthReadGrant
            profile = core.DelegatedWorkloadReceiverHealthReadGrantProfile.V2
            purpose = core.DelegationKeyPurpose.WORKLOAD_NODE_HEALTH_READ
            issuer, public, private = "receiver-health", self.health_public, self.health_private
            claim, typ = "workload_node_health_read", "CPK-WORKLOAD-NODE-HEALTH-READ+JWT"
        grant = grant_type(profile=profile, canonicalization=core.NodeControlCanonicalization.JCS_RFC8785_V1,
            purpose=purpose, issuer=issuer, key_id=public.key_id,
            audience=core.receiver_node_control_audience(configuration.target), target=scope,
            authority_context=context, kind=request.kind, declaration_identity=request.declaration_identity,
            request_id=request.request_id, request_digest=request.canonical_digest(),
            issued_at=100, not_before=100, expires_at=200, jti="receiver-test")
        return request, jwt.encode({"iss": issuer, "aud": grant.audience, "iat": 100,
            "nbf": 100, "exp": 200, "jti": grant.jti, claim: grant.descriptor()},
            private, algorithm="EdDSA", headers={"kid": public.key_id, "typ": typ})
