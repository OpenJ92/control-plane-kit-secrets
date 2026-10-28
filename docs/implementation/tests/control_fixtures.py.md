Source: [tests/control_fixtures.py](../../../tests/control_fixtures.py).
Maintain this note alongside its helper and adopted contracts.

The governing owner fixture now constructs actual Core receiver scope and separate authority context, the unchanged Secrets control/liveness declaration, exact surface/health families and a common configuration. Its public document uses the V2 receiver schema; typed input uses Core's value. Ed25519 key generation is unchanged and ephemeral. Signed requests/grants are receiver V2; surface results are V3 and health results V2. Runtime mismatch belongs inside the full target. Kind, scope, context and time remain independently mutable negative inputs; actual subprocess tests use current issuance and the original bounded interval. This supplies no production defaults or Operations authority.

The separate receiver_control_fixtures.py raw builder is immutable across Secrets41 red→green; changing this governing fixture does not replace that independent premise. The original92 method identities remain, while their old graph-revision/configuration representation is translated to the accepted public interface.
