Source: [pyproject.toml](../../pyproject.toml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This package metadata selects setuptools discovery under src, Python >=3.11, and includes the py.typed marker. Runtime dependencies explicitly select Core c7b16007467085be997f8dc3025e90e78649b00a from its commit archive/core subdirectory, SDK[fastapi] 3192360c36934feadc37bb9ae3733ce7da755c31 from its commit archive, and cryptography50.0.0. The selected SDK extra requires FastAPI0.141.1, Starlette1.6.0 and PyJWT2.13.0 with the same crypto version. This is an exact compatibility profile for those packages, not a complete transitive lockfile.

Secrets #81 adopts accepted Core `c7b16007467085be997f8dc3025e90e78649b00a`
and actual SDK #75 merge `3192360c36934feadc37bb9ae3733ce7da755c31`.
Core adds only the pure provider-policy module and root exports; consumed
receiver/wrapper/signing contracts remain unchanged. SDK runtime and extras
are unchanged and select exactly the same Core archive. Existing installed
provenance and real receiver/custody tests govern compatibility. This preserves
main's three-value provider initializer and does not adopt Secrets E or its
policy store. Interpreters #232 must wait for the actual accepted successor;
preparation is not permission to merge main or evidence of live adoption.

Historical Secrets #77 adopts accepted Core `fec0816281aeb83ede98616adcc4f96dfe5777a8`
and actual SDK #73 merge `cd4722fbfb942e7c2467a39b3cd0e32ded4a90ac`.
Core's production delta is confined to operations HTTP/parity/projections;
the receiver configuration, wrapper, signed health and key contracts consumed
by this provider remain unchanged. SDK runtime and extras are unchanged and
select that same Core archive. Existing declared/installed provenance and
production receiver/custody tests own compatibility. No schema, provider,
auth, signing or runner behavior changes. The accepted Secrets merge supplies
Interpreters #230, then Servers #349; no live adoption follows from this pin.

Historical Secrets #68 adopts accepted Core `879efb9576ac0580a6236d0a7372c036537b4dfe`
and actual SDK #69 merge `43838fd0f4391428cfffa87f8c4dbd5cc6d5eab1`.
Core changes control-plane command/read facts and the provision policy scope;
the provider-consumed receiver, wrapper, signing and health contracts are
unchanged. SDK runtime and extras are unchanged and select the same Core archive.
Existing declared/installed provenance and real receiving/custody tests govern
normal Docker adoption. No provider, schema, authentication, signing or runner
change is made. The accepted Secrets merge supplies Interpreters #222; it does
not establish Servers #311 composition or published/live behavior. Historical
adoption records below retain their original coordinates.

Historical Secrets #64 adopts accepted Core `955666898218e4f2956b6e9fcd33bdba97ffdb06`
and actual SDK #67 merge `cad5cc3dacbff1da79e6cc8b4c0c88526363e033`.
Core adds the pure retained-image ingress compiler and its exports; this
provider does not consume that planner. Receiver configuration, codec and
signed contracts are unchanged. SDK runtime and extras are unchanged and
select the identical Core archive. Existing declared/installed provenance,
real receiver composition, custody and denial tests govern the ordinary
Docker gate. No production, schema, auth, signing, provider or runner changes.
The accepted Secrets merge supplies Interpreters #214's dependency cohort;
it does not prove retained-image observation or live deployment. The runner
removes its selected test container but intentionally retains the built image.

Historical Secrets #62 adopts accepted Core required-configuration support and actual
SDK #65 merge together. Core adds structural product requirements, declared
selection, material guards and related secret-selection composition; this
provider still consumes actual receiver configuration through the unchanged
value/codec and signed contracts. SDK runtime source and extras are unchanged
and select the same Core archive. Exact installed provenance and existing
receiver, initialization, custody and denial laws must pass in the ordinary
Docker gate. No production source, schema, auth, signing, runner or provider
behavior changes. The actual accepted Secrets merge feeds Interpreters #211
and Servers #280; no managed-image or live acceptance follows from this pin.
The runner attempts best-effort removal of its selected container on entry/exit
but retains the built image; execution evidence must distinguish verified
container absence from intentional image retention.

Historical Secrets #60 adopts accepted Core #2005 and actual SDK #63 merge together.
Core adds a private receiver declaration-compatibility relation consumed by
secret-selection authoring and management planning; this provider calls neither.
The receiver codec and protocol definitions used by control.py are unchanged.
SDK runtime source and extras are unchanged and require the same Core archive.
Existing strict metadata, installed provenance and real receiver composition
tests govern the ordinary Docker gate. No custody, schema, auth, signing,
installer, route or provider behavior changes. Acceptance supplies the actual
Secrets merge for Interpreters, then Servers #254; it does not prove a live
declaration cutover. Earlier adoption accounts below remain historical.

Secrets #58 adopts accepted Core/Operations #1979 and actual SDK #61 merge together.
Core's only production delta from the previous selected `012a7b8b` is its
managed-update compiler's coupled declaration/route relation; Secrets does not
consume that planner. SDK runtime
source and extras are unchanged and select the same exact Core archive.
Existing declared/installed provenance and real receiver composition tests
govern the unchanged owning Docker gate. No custody, schema, auth, signing,
route, installer or provider behavior changes. The actual accepted Secrets
merge feeds Interpreters #205, followed by Servers #254; package adoption does
not establish installed declaration cutover or live grandparent acceptance.

Historical selected-secret alignment adopts accepted Core/Operations #1988 and actual
SDK #55 merge `ad0582937d7e41f1e7a41295fa1de58c2ce4cba2`. Core adds secret
selection/grant/receipt and planning/runtime contracts; the receiver, wrapper,
health and key contracts consumed by Secrets remain unchanged. SDK production
source is unchanged and declares the same exact Core archive. Existing strict
declared/installed provenance and real receiver composition tests must pass in
the unchanged owning gate. Custody, schema, auth, signing, routes, installers,
framework versions and provider behavior are unchanged. The accepted Secrets
merge will unblock Interpreters #190/#191 dependency assembly; it does not prove
selected-secret installation or Servers #237/#252 acceptance.

Historical Secrets #50 / Servers #251 adopts accepted Core `05b5f28` and SDK #53 merge
`9aa01ef7` together. Core's only changed production module since `fe8d44fa` is
the managed-update compiler; this owner does not consume it. Receiver, wrapper,
health, key and receipt contracts are unchanged. SDK's accepted change is also
metadata/checks/documentation only and selects the identical Core archive.
Existing exact provenance and real receiver composition tests remain intact;
the unchanged normal owning gate must establish this adoption. No custody,
schema, auth, signing, route, installer or provider behavior changes. Acceptance
supplies the actual Secrets successor for Interpreters, then Servers #251.

Historical Servers #249's retained-update alignment adopts the actual accepted Core/O1 #1981
and SDK #51 merges together. Core expands its common managed-update compiler
since the prior `a3f21206` selection. Its strict actual V2 codec and
Secrets-consumed receiver contracts are unchanged. SDK production source,
extras and gate are unchanged from `f1bc730a`; its exact Core archive matches
this package. Existing declared/installed provenance and real receiver tests
govern normal resolution through the unchanged owning Docker gate. No custody,
schema, authorization, signing, route or provider behavior changes. Acceptance
supplies the Secrets coordinate for Interpreters, then Servers #249;
it does not complete #237 runtime or grandparent/live acceptance. Earlier
checkpoint coordinates below remain historical provenance.

The test extra retains HTTPX>=0.28 and Uvicorn>=0.35; the old test-only Core dependency is removed. Installing Core does not broadly authorize source ownership or expand signing families. The required receiver uses one explicit protocol-only Core allowance in control.py; other source owners remain Core-free. [test_sdk_compatibility.py](../../tests/test_sdk_compatibility.py) checks declarations, installed archive provenance and framework/crypto versions, plus actual production-factory SDK composition with synthetic authority. Coordinate adoption with [test_node_control_signing_families.py](../../tests/test_node_control_signing_families.py), [Dockerfile.test](../../Dockerfile.test) and package import policy. There is no console-script entrypoint declared here.

The #29 profile aligns with accepted SDK #30 before health-family target
execution. Its Core URL exactly matches the SDK declaration; no override or
missing-dependency guard substitutes for a compatible installation. Provider
family admission remains its own source change.

#33 advanced Core and the reviewed SDK #34 merge together. SDK functional
source is unchanged from the prior selection; Core changes only management
planning compilation and observations, outside Secrets' consumed protocol.
The shared Core URL remains exact. Owner-gate installation and existing
provenance/composition tests must establish compatibility; this adoption adds
no custody, schema, signing or deployment behavior.

#35 selects Core f1e6cf2 and the reviewed SDK #37 merge22f1267. Since #33,
Core changed operations HTTP/lifecycle/parity/recovery and planning/saga,
outside Secrets' consumed public control/health/key protocol. SDK functional
source is unchanged. The exact Core URL matches SDK's selection, preserving
normal resolver behavior. Existing declaration/provenance/receiving tests and
the ordinary owner gate govern this adoption; no new custody behavior follows.

#37 selects accepted Core79c1a8bfe049ab17604466da00d43a1258ae33f9 and
SDK06e9346d7257ce29dcfebc74ddcb4c11e6525cb5 together. The Core archive URL
matches the SDK requirement exactly. SDK adds common wrapper setup while
preserving the explicit installer, dispatcher and verifier APIs consumed by
this provider. The existing provider configuration, custody and route owners
remain unchanged; adopting dependencies does not migrate this provider to the
new wrapper setup. Existing provenance and real receiving composition tests
plus the ordinary owner gate establish compatibility. This resolves the
concrete transitive pin conflict for Servers237 and Interpreters171 without
installation overrides or new security/authority behavior.

#39 advances to accepted Core1877 and SDK41/PR42 together. The Core delta since
79c1a8b adds only the public workload-verifier read's operations route/projection/
parity declarations. The accepted SDK delta changes only dependency metadata,
strict guard/provenance expectations and documentation; runtime source is
unchanged. The two exact Core URLs still match. Existing provider source,
configuration, custody, signing and receiver laws remain unchanged, and the
ordinary owning suite establishes compatibility. This supplies a coherent
Secrets dependency for Interpreters173 and Servers237, not live deployment.

#41 adopts the receiver configuration/protocol, so this paired update includes actual control/API consumer migration. Core1f28 matches SDKf40 exactly; framework/crypto coordinates and test extras remain unchanged. Package acceptance remains separate from downstream Servers/Interpreters selection.

#43 advances together to accepted Core250d65e and SDK5dc93b9. Core's only
production change replaces the gateway transit advertisement with the canonical
receiver health V2 protocol; Secrets does not consume that advertisement.
SDK runtime source is unchanged and selects the same exact Core archive.
Provider configuration, receiver composition, signing admission and private
custody remain unchanged. Existing provenance and composition assertions and
the unchanged Docker owner gate establish compatibility at these coordinates;
this adoption does not qualify downstream products or a live deployment.

#45 selects accepted Core da17efb and SDK47/PR48 merge 447a3c4 together.
SDK runtime source is unchanged. Core's delta adds configuration instance and
invocation contracts and changes approval/planning/runtime-effect modules;
the receiver, wrapper, health and key contracts consumed by Secrets are
unchanged. The two declared Core URLs match exactly. The existing declaration,
installed provenance and real receiver composition tests establish compatibility
through the unchanged Docker gate. Custody, authorization, persistence, routes,
framework versions and test extras remain unchanged. The accepted Secrets merge
will supply the dependency for Interpreters180; package acceptance is separate
from replacement, cleanup, image publication and live deployment.

Servers #237's bounded alignment checkpoint selects accepted common Core
`ba0bd45e7fa7673b837366f7f5da5f9159b0dee8` and SDK49's accepted merge
`23500b1445dc6a748bd92a441e781d7f9ed90299`. The SDK has no production source
change from the preceding `447a3c4` selection and declares this same exact Core
archive. Core adds managed-update planning and shared routes/installation
receipts; the receiver, wrapper, health and key definitions consumed by Secrets
are unchanged. The existing installed `direct_url.json` and real receiver
composition assertions remain the proof obligations. No generated-coordinate
manifest exists in this repository; metadata and the two expected archive URLs
are its current dependency owners. Custody, schema, auth, routes, framework
versions, test extras and the owning gate are unchanged. Acceptance provides
Secrets* for Interpreters #186; it does not close full Servers #237 or establish
receipt production, provider deployment or live acceptance.
