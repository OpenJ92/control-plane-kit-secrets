Source: [src/control_plane_kit_secrets/_delegation_signing.py](../../../../src/control_plane_kit_secrets/_delegation_signing.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This provider-local map admits three exact purpose/intent pairs for gateway probe, gateway node-control transit and workload node control. It requires actual strings and rejects unsupported or mismatched pairs with fixed SecretMetadataInvalid. It neither generates keys nor grants capability execution.

This source module remains independent from Core imports. The [runtime dependency profile](../../../../pyproject.toml) explicitly installs Core95452249d0340707a5cdffe737e34669e9d53165 alongside SDK[fastapi]; compare this finite family map with that adopted contract on dependency changes rather than assuming all Core purposes are supported. Installing or receiving SDK static/health read authority does not add a provider generation family. Source import restrictions and lightweight root behavior remain separate from installed dependency ownership.

[api.py](../../../../src/control_plane_kit_secrets/api.py) derives the generation intent; [store.py](../../../../src/control_plane_kit_secrets/store.py) independently requires the exact pair before writes. [test_node_control_signing_families.py](../../../../tests/test_node_control_signing_families.py) checks compatibility and rejection.
