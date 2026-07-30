# control-plane-kit-secrets

Durable secret provider for Control Plane Kit.

This repository is the future custody boundary for secret material referenced by
Control Plane Kit language values. Core may name `SecretReference` and secret
delivery intent. Operations may authorize use and record audit correlation.
Interpreters may resolve and materialize values at the IO boundary.
`control-plane-kit-secrets` is the package that will eventually store encrypted
secret values, version them, revoke them, and audit provider-local access.

Current status: provider-local audit. #1166 added provider-local encrypted
records, versions, rotation, revocation, and tamper-safe load behavior. #1167
added a narrow FastAPI boundary for authenticated write, resolve, rotate,
revoke, and metadata operations. #1168 adds provider-local audit records and
fail-closed resolve behavior when audit persistence is unavailable.

```text
#1169 restart/rotation/revocation acceptance
```

## Backup And Key-Rotation Notes

First flight uses two pieces of durable custody:

```text
encrypted provider database
mounted master-key file
```

Back up both. The database without the master-key file is intentionally not
enough to recover secret values. The master-key file without the database is not
enough to recover version history, revocation state, metadata, or audit records.

The provider stores only key fingerprint and key-version evidence in the
database. It does not store the raw master key. Future key rotation should add
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

Run:

```bash
./test.sh
```

The test harness is Docker-first and uses `unittest`.
