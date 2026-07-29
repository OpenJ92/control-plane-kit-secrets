# control-plane-kit-secrets

Durable secret provider for Control Plane Kit.

This repository is the future custody boundary for secret material referenced by
Control Plane Kit language values. Core may name `SecretReference` and secret
delivery intent. Operations may authorize use and record audit correlation.
Interpreters may resolve and materialize values at the IO boundary.
`control-plane-kit-secrets` is the package that will eventually store encrypted
secret values, version them, revoke them, and audit provider-local access.

Current status: scaffold only. #1165 intentionally adds no encrypted store, API
routes, migrations, or provider audit behavior. Those arrive in the following
issues:

```text
#1166 encrypted store/version/revocation primitives
#1167 authenticated scoped provider API
#1168 provider-local audit and fail-closed policy
#1169 restart/rotation/revocation acceptance
```

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
