# Secrets #29: health signing-key family admission

The provider adds the exact gateway health-read transit and workload health-read
purpose/intent pairs to its existing generation map and API intent allowlist.
It generates and stores keys, returns public generation identity, and resolves
material under existing credential grants. It does not sign health requests or
remove Operations' separate health-generation refusal.

Accepted base: `0e0fa2c8fc1464f8ea3ac4ad9a515a9b438820be`, targeting `main`.
SDK #30 first aligned its dependency; accepted SDK
`2c5b588237fbe289c965029b4bc2f072715c42f3` and Core
`b79a02d1ac8ef987dd34abeb2297a231b109f7a6` now share one exact archive profile.
Both design reviews passed before targets were written.

Existing family, replay, concurrency, tamper and redaction laws were extended
to both health families while retaining old cases. Four new methods protect
scope-before-store, mismatch-before-decrypt/selection, conflicting/revoked
replay, and atomic generation/audit rollback including correlation identity.
An initial static HOLD caught payload-bearing assertion diagnostics. The six
conditions were retained with categorical messages before both static reviews
passed amended target `a3b133f6650c2852a2dc71a3fe4a8b3d5804eab6`.

Native target composition `cb66c2d95e52599039fa53110a065884a951e74b` ran 92
methods: 11 failures and 11 unsupported-health errors across 11 methods;
81 other methods passed. Support, compilation and all three installed-profile
and receiver-composition tests passed. Both causal reviews accepted this as
missing admission, with no deeper credit for cases stopped at prerequisites.
The post-tests clean import did not run. See [terminal evidence](https://github.com/OpenJ92/control-plane-kit-secrets/pull/30#issuecomment-5688850458)
and [causal dispositions](https://github.com/OpenJ92/control-plane-kit-secrets/pull/30#issuecomment-5688865927).

North then released only the two family pairs, two API intents and affected
documentation. Store, schema, authorization, audit transactions, public APIs
and gate remain unchanged. Current API admission also covers existing scoped
write/rotate, without changing wildcard grant semantics. Denial may read
metadata and append audit; it must not decrypt or commit a wrong-family
selection. Generation audit rollback differs from resolve's separate audit.

At this source checkpoint, native green and final review are still pending;
the PR records terminal validation and accepted merge separately. No provider,
live, image or credential action occurred. Interpreters #149 owns later
request signing/material delivery; this owner provides no execution approval.
