# control-plane-kit-secrets Agent Guide

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
