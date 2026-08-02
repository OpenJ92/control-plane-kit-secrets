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

The provider owns the closed Ed25519 generation operation used for gateway
probe delegation. A caller supplies only bounded identity and correlation
metadata:

```text
workspace + SecretReference + gateway-probe purpose + issuer + correlation
  -> provider generates private key
    -> encrypted custody + generation identity + audit commit atomically
      -> public key, reference, version, and correlation evidence returned
```

Private key bytes never cross the generation response. Authorized signers may
resolve the admitted `gateway.probe-signing-key` reference later through the
normal use-specific provider route. Exact retries return the original public
identity. Reusing a correlation for different semantics fails closed, and a
revoked generated reference cannot be replayed into service.

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
