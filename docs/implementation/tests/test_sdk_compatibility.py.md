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

For #33, archive expectations advanced together to Core
`e074bda49fa0c46f420d675e45a93f787b460c02` and reviewed SDK #34 merge
`d8b72e52c8ebca65bf21a2a2ae51df663b1c8a77`. Only the two URL constants
change; declared requirements, installed archive/subdirectory checks, framework
versions, real receiving composition and denial assertions remain unchanged.
There are no coordinate replacement needles in this suite. Compatibility must
be established by the unchanged owner gate, not inferred from these constants.

For #35, the same two URL constants select Core
`f1e6cf2420bf2ec381aab745f462d4e64baef5fc` and the actual reviewed SDK #37
merge `22f1267bde5015efe2fea4f07be4ce8ddf83bc0c`. All declaration,
installed-provenance, real SDK receiver and denial assertions remain unchanged.
This is dependency compatibility evidence, not image or live qualification.
