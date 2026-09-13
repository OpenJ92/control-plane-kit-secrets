# Secrets #26: required public receiver

Accepted base `77abb77c48302b3fcf128e09b89564f046e32e3e`, branch
`codex/26-secrets-health-receiver`, destination `main`. Parent #24's
[reviewed design](https://github.com/OpenJ92/control-plane-kit-secrets/issues/24#issuecomment-5651166765)
and #26's [law/source dry run](https://github.com/OpenJ92/control-plane-kit-secrets/issues/26#issuecomment-5651398091)
govern this slice. The dry run was published before target tests.

## Predecessor and laws

#25 established installed Core954/SDK2b10 compatibility with21 policy and77 package
tests, matching hosted success and verified owner-runner cleanup. Its
[final evidence](https://github.com/OpenJ92/control-plane-kit-secrets/pull/27#issuecomment-5651367036)
is retained; no baseline rerun is required before extracting laws.

Keep the existing signing-family, lightweight root/source ownership, private
bootstrap, custody binding/schema/concurrency/rollback, provider auth/audit and
actual process restart/rotate/revoke/leak laws isomorphic. Strengthen process
startup and API composition to require public admission before private reads
and custody. The only source ownership change is a protocol-only Core allowance
in new control.py; custody and other owners remain unchanged. SDK read authority
does not authorize another provider signing family.

The dry run identified one minimal effect seam: server supplies a named delayed
initializer containing its existing private loads and custody call. API defines
the complete ordinary host, admits required public control and installs actual
SDK routes before invoking that initializer once and binding real store/audit/
authorizer closures. No app escapes failure; no subsequent request initializes
custody. Existing preinitialized API fixtures remain behavioral context, not
proof of startup ordering. A real SDK namespace collision and actual route
inspection at initializer entry protect this order.

Target interface is the parent design's SecretsControlConfiguration, declaration,
decode/encode/read functions and prepared verifier/dispatcher pair; required
api.create_app(control, initialize_provider, provider_id, clock). Public input
uses its own explicit absolute path and bounded regular opened file. Keep the
private loader's mode/readability rules without inventing UID ownership checks.
No product/artifact factory, readiness probe, mutable variable or new custody
state machine belongs here.

## Initial target-test checkpoint

Eleven new target tests cover the closed typed document and encoder revalidation,
required path/flags/size/regularity/redaction, required API arguments, actual SDK
collision, no private reads on invalid public startup, one real initializer after
complete routes, failure without a returned app, signed static/liveness and
purpose/target/runtime/instance denial without provider/auth/store/audit work,
and actual subprocess public-admission rejection. A test-only helper constructs
valid Core/SDK public values and separate in-memory signing keys independently
of the missing production codec.

The original77 tests are unchanged in this checkpoint. New tests collect with
accepted modules; direct receiver tests assert the missing named interface
explicitly before importing it, while the API signature test and real subprocess
law independently expose missing behavior. No module stub, skip, xfail or
optional fallback supplies the missing receiver. The reviewed checkpoint was then
executed once through the owner gate; its classified result is recorded below.

The public subprocess test has three cases with valid generated private inputs.
On the old predecessor, missing public admission can start the process and create
only temporary in-container SQLite custody. Each case waits at most10 seconds
before the existing terminate/communicate10, then kill/communicate10 cleanup.
It then fails for ignored required public admission. This expected target-red
effect is explicit; it uses no user credentials, provider resources or external
ingress. Output checks are bounded after capture, not continuously capped pipes.

## Implementation and fixture translation

After classified target-red and the coordinated source release, implementation
adds control.py and changes only api.py/server.py production startup composition.
Custody, auth, private loaders, signing and dependencies remain unchanged. The
source policy permits Core only in control.py and adds SDK to the cold-root ban.
The three existing factory callers now supply required synthetic control plus
their real initializer, preserving API/signing assertions. The compatibility
test forwards through actual production SDK installation exactly once, retaining
canonical static/typed health, denial/observation and fresh-schema parity laws.

Every existing invalid-private subprocess case gets valid public control so
its original private error remains the trigger. Restart fixtures get isolated
public documents and fresh scoped grants from in-memory keys, while keeping
private0600/custody/audit/leak assertions. Fixture grants use explicit test clocks
or120-second real-process lifetimes; mint fresh requests as new test
setup, never retry an uncertain live effect. Existing owner Docker container,
TemporaryDirectory and loopback subprocess bounds remain the mechanisms.

Maintain canonical companions for new/changed source and tests and review
unchanged dependency consumers. The initial documentation inventory is historical.
The gate remains the existing ./test.sh; exact red/green image/container names,
entry cleanup preflight, terminal results and independent runner absence must be
reviewed and recorded. No alternative runner or hidden reduction is introduced.

## Classified target-red and current evidence limit

The [minimal reviewed red result](https://github.com/OpenJ92/control-plane-kit-secrets/issues/26#issuecomment-5651505907)
records21 policy and all77 predecessor package tests green. All88 package tests
collected;13 failure records were exactly nine missing-receiver guards, one
required-control signature failure and three process deadline subcases. No
collection, fixture or apparatus errors occurred. Downstream guarded assertions,
later process redaction/no-DB checks and the final standalone import stage were
unreached. Both independent reviewers accepted the causal red without retry.

The detailed execution record stays local; only the separately reviewed minimal
summary was published. Implementation has not yet received a green run. Source
review added exact byte-ceiling and pure path-before-IO checks within existing
target methods; no separate red is claimed for those added assertions. Submit
the completed source/fixture/companion seal before any green or hosted execution.

## Security and handoff

Public configuration is integrity-sensitive but contains no private authority.
Keep separate typed static/health verifiers, liveness-only truth, no sensitive
provider work from SDK reads and no stronger storage-readiness claim. Parent24,
Servers189/191 product/image adoption, Core1821/Interpreters149 authorized delivery
and public/grandparent acceptance remain separate. No provider credential use,
registry upload, native adapter or held163 retry follows from this checkpoint.
