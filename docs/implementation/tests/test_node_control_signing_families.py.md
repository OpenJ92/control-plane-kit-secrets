Source: [tests/test_node_control_signing_families.py](../../../tests/test_node_control_signing_families.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These tests compare the provider's finite family map with the exact test-only Core pin while checking that production package import stays Core-free. Direct-store negatives protect rejection before writes; API cases check family-specific resolution and cross-family denial.

Restart/concurrent replay preserves family and public identity. Tampering cases distinguish generation-row drift from authenticated secret metadata. Oversized persisted public PEM/key IDs must fail before material matching; a temporary sentinel replacement checks that ordering without defining another production validator.

Generation response/audit/database-dump checks exclude selected private PEM, while authorized resolution reveals it to the fixture. This is provider custody evidence, not node-control capability execution or live gateway acceptance. See [_delegation_signing.py](../../../src/control_plane_kit_secrets/_delegation_signing.py), [store.py](../../../src/control_plane_kit_secrets/store.py) and [pyproject.toml](../../../pyproject.toml).
