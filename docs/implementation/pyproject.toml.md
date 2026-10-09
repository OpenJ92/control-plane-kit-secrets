Source: [pyproject.toml](../../pyproject.toml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This package metadata selects setuptools discovery under src, Python >=3.11, and includes the py.typed marker. Runtime dependencies explicitly select Core da17efb1303ed2176374548dd998d19a655055bf from its commit archive/core subdirectory, SDK[fastapi] 447a3c4c5a20b5c56402c813f6cfde1685eefda0 from its commit archive, and cryptography50.0.0. The selected SDK extra requires FastAPI0.141.1, Starlette1.6.0 and PyJWT2.13.0 with the same crypto version. This is an exact compatibility profile for those packages, not a complete transitive lockfile.

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
