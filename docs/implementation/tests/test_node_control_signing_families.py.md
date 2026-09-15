Source: [tests/test_node_control_signing_families.py](../../../tests/test_node_control_signing_families.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These tests compare the provider's finite family map with the exact adopted runtime Core contract while checking that importing the package root does not import Core. The old test-only Core packaging assertion was deliberately replaced by explicit runtime and installed-provenance laws in [test_sdk_compatibility.py](../../../tests/test_sdk_compatibility.py). The target contract preserves all three old pairs and adds the two exact health pairs, while surface-read and unsupported-purpose refusal remain required. Direct-store negatives protect rejection before writes; API cases check family-specific resolution and cross-family denial.

Restart/concurrent replay preserves family and public identity. API fixtures supply explicit synthetic public control and a required initializer returning their existing real stores and unchanged credentials; this preserves behavior without claiming startup-order proof. Tampering cases distinguish generation-row drift from authenticated secret metadata. Oversized persisted public PEM/key IDs must fail before material matching; a temporary sentinel replacement checks that ordering without defining another production validator.

Generation response/audit/database-dump checks exclude selected private PEM, while authorized resolution reveals it to the fixture. This is provider custody evidence, not node-control capability execution or live gateway acceptance. See [_delegation_signing.py](../../../src/control_plane_kit_secrets/_delegation_signing.py), [store.py](../../../src/control_plane_kit_secrets/store.py) and [pyproject.toml](../../../pyproject.toml).

SDK #30 supplies the compatible Core/SDK archive pair. These #29 targets precede
the provider family/allowlist implementation: new health positives are expected
to fail until that source is admitted. Both health families extend existing
restart, concurrency, metadata-drift and redaction witnesses. Four focused
methods add scope denial before store calls, cross-family denial before decrypt
or selection commit, conflicting/revoked replay, and generation audit rollback
including the correlation row. Boundary patches fail if protected work occurs;
real stores and audit remain in use. Denial audit and metadata reads are allowed
where specified. Boolean leak assertions avoid printing private fixture values.
No compact health request is constructed or signed by this provider test.
