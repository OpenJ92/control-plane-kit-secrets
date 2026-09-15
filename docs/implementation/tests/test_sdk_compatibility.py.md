Source: [tests/test_sdk_compatibility.py](../../../tests/test_sdk_compatibility.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

Three tests protect exact declared runtime/test requirements and Python metadata; installed Core/SDK commit-archive provenance plus selected framework/crypto versions; and actual SDK composition through the production required-control factory. Archive metadata identifies selected source, not a new independent cryptographic audit or complete transitive dependency lock. Read [pyproject.toml](../../../pyproject.toml) with the actual selected SDK metadata on adoption.

The composition fixture uses real temporary SQLite custody and [api.create_app](../../../src/control_plane_kit_secrets/api.py), with required synthetic public control, an initializer returning the existing stores/empty credentials and actual production-prepared SDK verifiers. A forwarding observer records the complete pre-install route/schema and wraps the real liveness callback to count observations, then calls the actual SDK installer exactly once. It introduces no alternative dispatcher semantics or second installation. Assertions retain the canonical static response, typed signed liveness, missing/wrong-purpose denial, one observation and no audit rows. It regenerates OpenAPI after installation before full schema comparison, so the pre-install cache cannot stand in for proof. Legacy health/docs and provider authentication denial remain observable.

The temporary master-key file is0600; generated authority is local to the existing test container, with no credential material or derived hashes in evidence. This now exercises production receiving composition, but preinitialized stores do not establish startup effect ordering or public artifact delivery. [test_control_receiver.py](../../../tests/test_control_receiver.py) owns explicit ordering/authority laws; existing signing/custody/auth/bootstrap/restart tests remain the wider compatibility context. Run only the owning [test.sh](../../../test.sh) after its approved preflight, and report executable results separately from this description.

For #29, exact archive expectations advance together to accepted Core
`b79a02d1ac8ef987dd34abeb2297a231b109f7a6` and SDK
`2c5b588237fbe289c965029b4bc2f072715c42f3` after SDK #30 acceptance.
The three existing provenance/composition tests and framework version assertions
are unchanged; this is the prerequisite for collecting the new health intents.
