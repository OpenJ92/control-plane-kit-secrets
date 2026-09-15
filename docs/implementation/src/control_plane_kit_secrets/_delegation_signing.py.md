Source: [src/control_plane_kit_secrets/_delegation_signing.py](../../../../src/control_plane_kit_secrets/_delegation_signing.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This provider-local map admits five exact purpose/intent pairs: gateway probe, gateway node-control transit, workload node control, gateway health-read transit and workload health read. It requires actual strings and rejects unsupported or mismatched pairs with fixed SecretMetadataInvalid. It neither generates keys nor grants capability execution.

This source module remains independent from Core imports. The [runtime dependency profile](../../../../pyproject.toml) explicitly installs Coreb79a02d1ac8ef987dd34abeb2297a231b109f7a6 alongside SDK[fastapi]; compare this finite family map with that adopted contract on dependency changes rather than assuming all Core purposes are supported. The required public receiver in control.py has a separate protocol-only allowance. Receiving SDK static/health read authority does not add a provider generation family. Signing-source import restrictions and lightweight root behavior remain separate from installed dependency ownership.

[api.py](../../../../src/control_plane_kit_secrets/api.py) derives the generation intent; [store.py](../../../../src/control_plane_kit_secrets/store.py) independently requires the exact pair before writes. [test_node_control_signing_families.py](../../../../tests/test_node_control_signing_families.py) checks compatibility and rejection.

#29 adds only the two health entries. Their intents are respectively
`gateway.node-health-read-transit-signing-key` and
`workload.node-health-read-signing-key`. Unknown, surface-read and mismatched
pairs still fail the same exact string checks. This is provider key-family
admission, not request signing or Operations issuance authority.
