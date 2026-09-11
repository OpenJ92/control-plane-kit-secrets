Source: [tests/test_live_provider_process.py](../../../tests/test_live_provider_process.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This suite launches Uvicorn on loopback with temporary SQLite custody, generated test keys and explicit fixture credentials. It covers invalid-bootstrap refusal before database creation, persistence across restart, scoped resolution, rotation/revocation, incompatible retained key/provider rejection, and successful access after rejected startup.

The test compares logical SQLite snapshots and key/credential bytes around incompatible startup, not every SQLite filesystem byte. Leak checks inspect selected fixture material in process output, audit rows and database bytes; authorized resolution deliberately returns encoded material.

The free-port probe closes before Uvicorn binds and is not an atomic reservation. Cleanup terminates, then kills on communication timeout; captured pipes are not continuously byte-capped. This is local package-process integration, not Internet/provider or deployment acceptance. Use the owning Docker-backed [test.sh](../../../test.sh) when authorized, never a host fallback. See [server.py](../../../src/control_plane_kit_secrets/server.py) and [custody.py](../../../src/control_plane_kit_secrets/custody.py).
