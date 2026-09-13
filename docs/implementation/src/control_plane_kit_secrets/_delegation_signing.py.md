Source: [src/control_plane_kit_secrets/_delegation_signing.py](../../../../src/control_plane_kit_secrets/_delegation_signing.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This provider-local map admits three exact purpose/intent pairs for gateway probe, gateway node-control transit and workload node control. It requires actual strings and rejects unsupported or mismatched pairs with fixed SecretMetadataInvalid. It neither generates keys nor grants capability execution.

Production remains independent from Core. The [test-only dependency](../../../../pyproject.toml) selects Core a62af8431afb878fa0beed3b752cbdf7a640fb48; compare this finite family map with that adopted contract on dependency changes rather than assuming all Core purposes are supported. Surface-read is not another generation family.

[api.py](../../../../src/control_plane_kit_secrets/api.py) derives the generation intent; [store.py](../../../../src/control_plane_kit_secrets/store.py) independently requires the exact pair before writes. [test_node_control_signing_families.py](../../../../tests/test_node_control_signing_families.py) checks compatibility and rejection.
