Source: [tests/test_delegation_key_generation.py](../../../tests/test_delegation_key_generation.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

Real temporary-SQLite and cryptographic checks prove that generated private material survives restart and verifies against the returned public identity. Concurrent same-correlation requests converge on one key/version with one fresh generation; changed semantics, revoked replay and ciphertext tampering fail.

The fixture intentionally resolves private material for a local sign/verify assertion. This does not exercise remote capability validation or deployment authorization. [store.py](../../../src/control_plane_kit_secrets/store.py) owns generation persistence; [test_node_control_signing_families.py](../../../tests/test_node_control_signing_families.py) adds cross-family and public-identity bounds.
