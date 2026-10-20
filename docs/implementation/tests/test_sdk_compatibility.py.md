Source: [tests/test_sdk_compatibility.py](../../../tests/test_sdk_compatibility.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

Three tests protect exact declared runtime/test requirements and Python metadata; installed Core/SDK commit-archive provenance plus selected framework/crypto versions; and actual SDK composition through the production required-control factory. Archive metadata identifies selected source, not a new independent cryptographic audit or complete transitive dependency lock. Read [pyproject.toml](../../../pyproject.toml) with the actual selected SDK metadata on adoption.

Secrets #62 changes only the two archive constants to accepted Core
`ec61e2b17c3a3f1bdea1dd6bc8fc64ac1b9528b0` and actual SDK #65 merge
`eff09090755eb21028695f0224eec7b81f2db535`. The SDK selects the same Core archive.
Core's added product requirements and declared selection do not change the
actual receiver codec or signed contracts consumed here. Metadata/subdirectory
and installed archive assertions, framework versions, real SDK composition,
wrong-purpose denial and empty-audit observations remain unchanged. Existing
tests must prove the selected closure in the owning Docker gate; no artificial
red, dependency override or claim of live provider acceptance is introduced.

Historical Secrets #60 changes only the two archive constants to accepted Core
`73d87e99bf711ff8a88112ca56c5eee8055ac5b7` and actual SDK #63 merge
`1657cb91b143931bafcdb32108950d2bbbb66d95`. Core's new private declaration
relation and selection/planning changes do not alter this provider's receiver
codec or protocol. SDK runtime source and extras are unchanged. Exact metadata,
installed archive provenance, framework versions, real production receiver
composition, denial and audit assertions remain intact. Normal Docker package
validation must prove compatibility; no artificial red or dependency override
is needed, and no provider deployment follows from this package evidence.

Historical Secrets #58 changes only the two archive constants to accepted Core
`9861e536e79314005499ae07379f627bfb1599a2` and SDK #61 merge
`d4e7c4d91c054f139e2971774ae5e37fc741262d`. Core changes only its managed-update
compiler; SDK runtime source is unchanged. Exact metadata, installed archive
provenance, framework versions, production receiver composition, denial and
audit assertions remain intact. The unchanged owning Docker gate must establish
normal resolution and behavior without overrides; no artificial red is needed.

Historical selected-secret alignment changes only the two archive constants to accepted
Core `87e231c661879e44816ba71ff9320c040c868d60` and actual accepted SDK #55 merge
`ad0582937d7e41f1e7a41295fa1de58c2ce4cba2`. Exact declarations, installed archive
provenance, framework versions, real production-factory receiver composition,
denial and audit assertions remain intact. Core adds selected-secret and
planning/runtime contracts outside the receiver definitions used here; SDK
runtime source is unchanged. The normal Docker gate must prove compatible
installation and behavior. No artificial behavioral red, dependency bypass,
provider mutation or live deployment claim follows from this coordinate update.

Historical Secrets #50 / Servers #251's image-update alignment changes only the two archive
constants to accepted Core `05b5f28a624e6e03f1dadbe6ad77ece2bec09601` and actual
accepted SDK #53 merge `9aa01ef7b2df6106f6ad87c1625a7feb93394b88`. All declared and installed archive
checks, framework versions, real receiver composition, denial and audit
assertions remain intact. No new behavioral test or fabricated red is required
for this mechanical update. The unchanged owning Docker gate must establish
normal installation and package compatibility; it does not prove downstream
Servers runtime or live deployment. Prior coordinates below are historical.

For that historical alignment, Core's changed production module is the managed-update compiler, which this
owner does not consume. The adopted SDK changes metadata and exact checks only;
receiver/signing contracts and actual Secrets composition remain unchanged.
After normal gate validation and North acceptance, Interpreters selects the
accepted Secrets successor. No published artifact rebuild follows from this pin.

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

For #37, the two expected archive URLs advance to Core79c1a8b and accepted
SDK06e9346, matching production metadata and the SDK's own Core requirement.
All declaration, installed provenance, framework-version, composition and
negative assertions remain unchanged. The test still exercises the existing
explicit provider route installation; it does not claim automatic wrapper
configuration delivery, which remains downstream Servers237 work.

For #39, only the two archive URL constants advance to accepted Core6b2d173 and
SDK e19b7ed. Declaration and installed direct_url checks, framework versions,
actual production-factory receiving composition and all denial/audit assertions
remain intact. The SDK runtime diff from the preceding selection is empty;
the normal Docker gate still supplies the installation and compatibility proof.

#41 updates exact archive expectations to Core1f28 and SDKf40 together. The forwarding observer now wraps actual install_cpk_wrapper, supplies a test liveness observation callback through its public argument, and still invokes the real SDK installer exactly once. This preserves route/schema, callback count and protected auth/result laws; ReceiverAdoptionTests and ControlReceiverTests exercise the unmodified production default liveness separately. No fake verifier/dispatcher is introduced. Result assertions use receiver surfaceV3/healthV2 codecs. Framework/crypto and installed archive/subdirectory assertions remain unchanged.

#43 changes only the two archive constants to accepted Core250d65e and
SDK5dc93b9. All declaration, installed provenance, framework/crypto, actual
receiver composition, denial and audit assertions remain intact. This mechanical
adoption preserves the existing 99 package tests and needs no artificial red;
the ordinary Docker gate must prove the new dependency closure.

#45 advances only the two archive constants to Core da17efb and the actual
accepted SDK47/PR48 merge 447a3c4. All declaration, direct_url archive/subdirectory,
framework/crypto, actual SDK composition, denial and audit assertions remain
unchanged. The tests-only commit proves the old selection fails exactly these
coordinate assertions before metadata adoption; collection and the remaining
behavioral tests still pass. The unchanged Docker gate must then prove the
aligned dependency closure. This test does not establish provider deployment
or interpreter replacement/cleanup behavior.

Servers #237's alignment checkpoint changes only the two archive constants to
accepted C* `ba0bd45e7fa7673b837366f7f5da5f9159b0dee8` and SDK49 merge
`23500b1445dc6a748bd92a441e781d7f9ed90299`. All declaration, actual installed
archive/subdirectory, framework-version, production-factory receiver, denial
and audit assertions remain intact. This mechanical pin-only update introduces
no behavior requiring an artificial red test; the unchanged owner gate proves
normal dependency resolution and compatibility without an override. No provider
truth or broader #237 completion is inferred from package acceptance.
