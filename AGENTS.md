# control-plane-kit-secrets Agent Guide

Canonical contract: `cpk-agent-contract/v1`

Source: [CPK #1741](https://github.com/OpenJ92/control-plane-kit/issues/1741).
This root guide carries the shared contract needed to work in this repository
without another checkout. Local custody rules may tighten it; they may not
weaken authorization, Docker-only validation, truthful uncertainty, test
ownership, GitHub-memory, credential-custody, or redaction requirements.

## Shared Product Boundary

CPK is a human-authorized, AI-assisted infrastructure control plane. Providers
own external runtime truth. CPK owns topology, inspectable plans, execution of
approved actions, durable history, and truthful bounded reports.

- Provider reads and bounded reporting may be automatic.
- Consequential mutation requires an inspectable plan and appropriate user
  authorization.
- Destructive cleanup, public exposure, cost/capacity or credential changes,
  cross-provider movement, adoption, and ambiguous retries require explicit
  approval.
- Never blindly redispatch an interrupted or ambiguous external mutation.
- Never fabricate success, ownership, graph advancement, or cleanup.
- Do not assume autonomous recovery, compensation, failover, or adoption.

Secret creation, rotation, revocation, custody-policy changes, and authority
changes are consequential mutations. This repository never grants broader
provider or topology authority merely because it can resolve a secret.

## Durable Memory And Collaboration

GitHub issues, PRs, and material comments are durable project memory. Commits,
hashes, local logs, `/tmp` packets, inventories, task messages, and chat are
supporting coordinates only. Durable handoffs contain bounded categorical
credential facts, never secret material or secret-derived hashes.

When roles are assigned, North coordinates scope, authority, topology, and
merge disposition; Vale implements; Meridian reviews independently and reports
findings-first `PASS` or `HOLD`. Assignments and handoffs name the GitHub
artifact, base/destination, scope, suite/prerequisites, authority limits, stop
conditions, and next reviewer. Silence is not approval.

Tests prove this repository's custody, authentication, authorization,
redaction, and persistence boundary. They do not recreate Core/Operations state
machines, police helper layout, or turn fixture examples into runtime
invariants.

## Shared Validation And Stops

All executable validation uses the established Docker-backed `./test.sh`. Do
not use host Python/PostgreSQL, venvs, host `pip`, alternate databases, shims,
or custom wrappers. If the suite or prerequisite is missing, cannot start, or
fails for apparatus, stop and ask; do not improvise, silently retry, rebaseline,
or repair shared state.

One-shot wrappers, leases, live/provider-mutating gates, credential use, and
destructive cleanup require explicit issue-specific authority. Never print,
persist in evidence, or return credentials or credential-derived hashes. Stop
on uncertain custody, subject, grant, ownership, authority, base/destination,
prerequisite, or effect outcome.

## Branch Flow

This repository currently develops directly from `main`:

```text
main -> codex/<issue-id>-<slug> -> PR into main
```

This repository owns durable secret custody for Control Plane Kit. It is a
separate security boundary from operations, interpreters, cpk-server, and server
product publication.

## Ownership

This repository may own:

- encrypted durable secret storage;
- provider-local secret version, rotation, and revocation metadata;
- authenticated scoped write and resolve APIs;
- provider-local audit records for every write, resolve, deny, miss, revoke,
  and failure;
- provider process code and storage migrations once their issues open.

This repository must not own:

- graph truth, topology compilation, graph diffing, or planning;
- operations UnitOfWork, stores, approval, admission, lifecycle, or read models;
- runtime-effect dispatch or concrete Docker/Cloudflare/cloud interpreter code;
- cpk-server FastAPI/MCP wrapper routes;
- server product descriptors, Dockerfiles, OCI images, or catalogue metadata.

## Secret Laws

Raw secret values must never appear in descriptors, graph data,
RuntimeEffectRequest descriptors, events, observations, read models, logs, route
responses, test assertions, or error messages.

The first production provider uses a mounted master-key file such as:

```text
CPK_SECRETS_MASTER_KEY_FILE=/run/secrets/cpk-secrets/master-key
```

The master key must not be stored in the provider database. Provider persistence
may store only bounded key fingerprint and key-version evidence.

Do not implement home-grown encryption. Use a maintained authenticated
encryption library when #1166 introduces encrypted storage.

## Development

Use Docker-first validation:

```bash
./test.sh
```

Use `unittest` only. Do not add pytest.

Keep package roots lightweight. Importing `control_plane_kit_secrets` must not
import FastAPI, Docker SDK, Cloudflare clients, Postgres drivers, operations,
cpk-server product code, server-products, or concrete runtime interpreters.
