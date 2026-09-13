# Secrets #25: dependency compatibility checkpoint

Parent [#24](https://github.com/OpenJ92/control-plane-kit-secrets/issues/24),
child [#25](https://github.com/OpenJ92/control-plane-kit-secrets/issues/25),
base `68d0da6aed3a383d6bdc284cf4a6a6063a31487e`, destination `main`.
The reviewed design separates installed dependency compatibility from the
required receiver in dependent #26.

## Governing laws and source dry run

| Existing test context | Law and observable result | Classification here |
| --- | --- | --- |
| `test_package_policy` | Every source module rejects direct Core and adjacent ownership imports; only `api.py` imports FastAPI; root stays lightweight and exports the same three values | Isomorphic, unchanged |
| `test_node_control_signing_families` | Three admitted signing families match Core; unsupported purposes reject without custody writes; root import does not import Core | Isomorphic, assertions retained |
| Old test-only Core dependency assertion | Dependencies now explicitly install the reviewed Core/SDK archives and exact framework/crypto versions | New law replacing an obsolete packaging assumption |
| `test_encrypted_store` | Binding/schema admission, rejection without logical writes, one concurrent identity, transactional rollback, encryption/tamper/restart/rotation laws | Isomorphic, unchanged |
| `test_provider_bootstrap` | Closed bounded typed private input and owner-only file admission; fixed redacted errors | Isomorphic, unchanged |
| `test_provider_api` | Auth/scope/intent separation, atomic audit and custody, bounded redaction and idempotent correlation | Isomorphic, unchanged |
| `test_live_provider_process` | Actual process rejects invalid private input before DB or parent creation; retained restart/rotate/revoke and leak checks | Isomorphic, unchanged |
| New `test_sdk_compatibility` | Actual SDK composes on the existing full provider host, preserving routes/docs and producing an authenticated canonical static result | New compatibility law |

Source review found ordinary literal `/v1`, legacy `/health` and default docs
routes. The actual SDK's complete-host admission supports this existing host;
there is no root wildcard to migrate. No application module or public factory
needs a change in #25. Installing Core changes dependency ownership, not source
ownership: the source AST ban remains unchanged, including pure signing/custody.

Target tests inspect both declared dependencies and installed `direct_url.json`
archive provenance, plus actual crypto/framework versions. The composition test
uses the real provider app, SQLite custody and SDK verifier with an ephemeral
in-memory signing key. A static test-only declaration is enough to establish
host compatibility; it is not the future production health declaration. The
existing API, private bootstrap and actual subprocess tests supply the broader
behavioral compatibility evidence instead of duplicating those suites.

Focused laws were committed as `43d8c98` before dependency implementation. No executable red
run is claimed: North released source preparation only, and the ordinary owner
gate awaits candidate/fixture review and its concrete release. The pre-change
metadata lacks the required SDK and pins the old test-only Core; that is source
evidence, not an executed failure. No alternate harness is introduced.

## Decision and security

Use exact Core `95452249d0340707a5cdffe737e34669e9d53165` and SDK
`2b10d5a354ba4da9407d336703aacb96910100d4` archives, SDK `[fastapi]`, and direct
`cryptography==50.0.0`. Keep Python metadata and test tools unchanged. Explicit
direct Core ownership avoids concealing the dependency through SDK. Retaining
the old test-only Core pin would conflict with SDK; broad framework versions
would fail to identify the reviewed compatibility profile.

No production routes, required inputs, schema, custody transactions, provider
authority or signing purposes change. Dependency upgrades can affect crypto and
framework behavior, which is why the full owning tests remain required. The
test uses temporary private files and in-memory synthetic signing material;
credentials and credential-derived hashes are never evidence. No network
listener or external provider is added; existing subprocess tests use loopback
inside the normal Docker test container. Python versions beyond that container's
3.14 are support metadata, not new validation evidence.

Validation and review are pending. Only the established `./test.sh` is allowed.
Its exact issue-specific image/container names must be reviewed before execution
because the script removes its named container at entry and exit. Source, gate,
Dockerfile and workflow changes are not needed. #26 must use #25's accepted merge
and add its own required receiver, startup-order and health tests. Servers #189
and #191 retain product artifact and image qualification ownership.
