# control-plane-kit-secrets

Durable secret provider for Control Plane Kit.

This repository is the future custody boundary for secret material referenced by
Control Plane Kit language values. Core may name `SecretReference` and secret
delivery intent. Operations may authorize use and record audit correlation.
Interpreters may resolve and materialize values at the IO boundary.
`control-plane-kit-secrets` stores encrypted secret values, versions and revokes
them, and audits provider-local access.

Current status: provider-local audit. #1166 added provider-local encrypted
records, versions, rotation, revocation, and tamper-safe load behavior. #1167
added a narrow FastAPI boundary for authenticated write, resolve, rotate,
revoke, and metadata operations. #1168 adds provider-local audit records and
fail-closed resolve behavior when audit persistence is unavailable.

## Delegation Key Generation

The provider owns a closed set of Ed25519 generation operations for gateway
probe, gateway node-control transit, and workload node-control delegation. A
caller supplies only bounded identity and correlation metadata:

```text
workspace + SecretReference + admitted purpose + issuer + correlation
  -> provider generates private key
    -> encrypted custody + generation identity + audit commit atomically
      -> public key, reference, version, and correlation evidence returned
```

Each admitted purpose has exactly one provider-local resolution intent. Private
key bytes never cross the generation response. Authorized signing effects may
resolve the paired intent later through the normal use-specific provider route.
Exact retries return the original public identity. Reusing a correlation for
different semantics, substituting an intent, or drifting authenticated family
metadata fails closed, and a revoked generated reference cannot be replayed
into service. Compact profile construction and signing remain outside this
provider.

## Exact Version Revocation

Whole-reference revocation remains available for retiring an entire secret.
Key rotation uses a separate exact-version route so retiring version A cannot
revoke active version B:

```text
workspace + secret id + version id/number + actor + correlation
  -> revoke exactly one encrypted version
    -> persist replay binding and provider-local audit atomically
      -> return bounded revoked-version metadata
```

Exact replay returns the same metadata after restart. Correlation reuse with a
different target or actor fails closed, as does attempting to claim an already
revoked version under a new correlation. No secret value enters the request,
response, replay record, or audit record.

```text
#1169 restart/rotation/revocation acceptance
```

## Backup And Key-Rotation Notes

First flight uses two pieces of durable custody:

```text
encrypted provider database
mounted master-key file
mounted provider-credentials file
```

Back up both. The database without the master-key file is intentionally not
enough to recover secret values. The master-key file without the database is not
enough to recover version history, revocation state, metadata, or audit records.

Production provider credentials are loaded from the absolute owner-only path in
`CPK_SECRETS_CREDENTIALS_FILE`. The explicitly development-only
`CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON` setting remains for disposable source
fixtures; configure exactly one source. Provider credentials are bootstrap
roots and must not resolve recursively through this provider.

Both sources accept a UTF-8 JSON array bounded to 64 KiB of encoded bytes. Each
credential requires `subject` and `token`; optional `grants` defaults to `[]`.
Each grant requires `action` and `workspace_id`; optional `intents` defaults to
`["*"]`. An empty credential array authenticates nobody. Empty grants authorize
nothing; empty intents deny intent-qualified requests while preserving actions
that do not carry an intent. Explicit workspace and intent wildcards remain
supported. Unknown nonmatching action/intent text grants no current capability.

All these fields and intent entries must be strings, not whitespace-only, and
contain no C0 (`U+0000..U+001F`) or DEL (`U+007F`) controls. Tokens must also be
ASCII with no leading/trailing whitespace; internal spaces are accepted. Accepted
text is preserved exactly, without coercion or normalization. There is no
independent token or collection size limit beyond the document ceiling. Duplicate
JSON keys, unknown credential/grant fields, and duplicate bearer tokens reject.
Distinct tokens may share a subject; repeated grants/intents remain lawful.
These are document-loader rules; programmatic auth constructors are unchanged.

Unset the unused credential source. Existing empty-value behavior is preserved:
a valid file with empty development JSON selects the file; an empty file setting
with nonempty development JSON rejects. Both nonempty or both absent/empty reject.

Startup requires the explicit absolute path in
`CPK_SECRETS_CONTROL_CONFIGURATION_FILE`. This separate public JSON input uses
profile `secrets-control-configuration.v1` and contains target/runtime identity,
the exact V2 liveness declaration on socket `control`, and separate static/health
issuer and public-verifier-key snapshots. The byte ceiling is 64 KiB; the path
ceiling is 4096 UTF-8 bytes. No default or disable fallback is provided. The
public reader checks the opened regular file, uses no-follow/nonblocking flags,
and permits public read-only modes such as0444. Trusted parent-path integrity
and authorized delivery remain the caller's responsibility.

The complete ordinary FastAPI host and actual SDK routes are admitted before
the one delayed initializer reads existing private master-key/credential inputs
and opens custody. Missing or invalid public configuration exits with
`secret provider control configuration is invalid`; real SDK namespace collision
also fails before private reads or custody. Invalid private configuration still
exits with `secret provider configuration is invalid`. These public and private
loaders remain separate, with their own fixed outward errors.

Standalone launchers supply their trusted absolute public path. Server product
adoption belongs to Servers #189, which supplies the canonical public artifact
at `/etc/cpk/secrets-server/control.json` and its path environment while retaining
the provider's private inputs, data lifecycle and control port8081/UID10006.
This package provides the public codec/encoder, not a product artifact factory.

The provider then admits custody under one explicit SQLite transaction. Fresh or
positively object-free storage receives the complete custody/audit schema and one
authenticated root-key/provider/schema binding together. A retained bound store
must match the exact required schema and authenticate that binding before the app
can become ready. Compatible restart performs no logical schema or row writes.
The effective provider ID is compared exactly: omission defaults to
`local-dev-provider`; explicitly supplied strings, including empty, stay distinct.
Credential documents remain independently configurable bootstrap inputs.

Existing unbound databases, including empty legacy schemas, are refused unchanged;
there is no automatic adoption or migration. Wrong key/provider, binding tamper or
schema mismatch exits with `secret provider custody is incompatible`. Unresolved
SQLite locking, recovery or transaction failure exits with `secret provider custody
is unavailable`. Both errors suppress underlying sensitive details; neither causes
an internal retry, repair, reset or rekey. A later explicit start inspects current
committed truth before deciding. Concurrent starts serialize at admission and
cannot establish conflicting committed identities.

This supports ordinary local regular SQLite files and rejects observed symlink or
nonregular targets. Logical no-write does not mean byte-identical journal files or
protection against hostile filesystem replacement. Startup checks the binding and
schema, not every retained ciphertext; resolution still authenticates individual
secret rows. Direct store APIs retain their existing behavior and do not claim
provider startup admission. No new status endpoint exposes binding/key evidence.

Secret-version rows record key fingerprint and key-version evidence; the custody
binding separately authenticates provider/schema identity. Neither stores the raw
master key. Future key rotation should add
an explicit rewrap or new-version flow; it must not silently change the key used
to decrypt existing ciphertext.

## Resolution Version Policy

Provider resolution uses `current-at-first-effect, pinned-for-retry` semantics.
The first resolve for one workspace/correlation atomically selects the current
active version. Exact replay of that correlation uses the selected version even
after rotation. A new correlation selects the new current version.

Correlation reuse with a different secret, intent, or caller fails closed.
Revocation blocks unresolved uses and later retries of a selected version; it
does not rewrite completed audit history. Selection records contain identifiers
and version metadata only, never plaintext or ciphertext.

## Boundary

```text
control-plane-kit-core
  SecretReference and delivery language

control-plane-kit-operations
  provider admission, use authorization, audit correlation

control-plane-kit-secrets
  encrypted durable custody and provider-local audit

control-plane-kit-interpreters
  IO-boundary resolution and delivery

cpk-server
  dependency composition, not durable custody
```

This package does not own topology, graph truth, deployment planning,
operations UnitOfWork, runtime execution, cpk-server routes, product
descriptors, Dockerfiles, OCI image publication, or Cloudflare/Docker
interpreter behavior.

## Validation

The runtime dependency profile explicitly installs Core
`95452249d0340707a5cdffe737e34669e9d53165` and server SDK `[fastapi]`
`2b10d5a354ba4da9407d336703aacb96910100d4` from commit archives. The shared profile
uses cryptography 50.0.0, PyJWT 2.13.0, FastAPI 0.141.1 and Starlette 1.6.0.
Core is now an explicit runtime dependency; the prior test-only Core pin has
been removed. Direct Core imports are confined to the public protocol owner
`control.py`; custody, signing and other provider owners remain Core-free, and
the package root stays lightweight. Existing closed signing families and
custody/auth/audit behavior remain the provider's contracts.

Production now requires the public receiver and installs authenticated SDK static
and liveness routes. Programmatic `api.create_app` callers supply required
`control` plus `initialize_provider`, returning the existing store/audit pair and
admitted provider credentials. Every handler is bound before the app returns.
SDK reads use separate typed authority and perform no provider authentication,
secret access or audit writes. Liveness means the initialized process is serving;
neither it nor the unchanged constant legacy readiness response proves current
database writability. No readiness callback or mutable variable is advertised.
See the [#26 law and decision record](docs/learning/runtime-control/secrets-26.md)
and the retained [#25 dependency checkpoint](docs/learning/runtime-control/secrets-25.md).

Run:

```bash
./test.sh
```

The test harness is Docker-first and uses `unittest`.

The package gate is also the CI contract. It runs, in order:

1. the package-integrity contract's adversarial tests;
2. an integrity scan of current source, tests, and `test.sh`;
3. the package image build;
4. compileall and all provider tests, including the real process restart test;
5. a clean installed-package import outside the source tree.

The integrity stage fails closed on hidden unittest collection, unapproved
skips, placeholder tests, swallowed exceptions, mutable legacy imports,
pytest, and proof-changing optional modes. It reports mock use as review
evidence without treating every mock as a failure.
