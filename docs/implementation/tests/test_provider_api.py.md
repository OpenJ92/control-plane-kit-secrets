Source: [tests/test_provider_api.py](../../../tests/test_provider_api.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

FastAPI TestClient composes the real local authorizer, SQLite encrypted store and audit store in temporary directories. Fixture credentials distinguish write, resolve, generation, metadata and revoke powers. These are provider HTTP laws, not CPK or deployed transport semantics.

Cases cover intent canonicalization/substitution, correlation-pinned resolution, exact-version revocation/replay, public-only generation output and selected bounded errors. Injected audit faults protect atomic rollback for generation/exact-version revoke and withholding of resolve material. They do not prove that every mutation rolls back after a separate audit failure. Selected response/audit sentinel checks are not universal metadata or framework-validation redaction.

Related owners: [api.py](../../../src/control_plane_kit_secrets/api.py), [auth.py](../../../src/control_plane_kit_secrets/auth.py), [store.py](../../../src/control_plane_kit_secrets/store.py). [test_live_provider_process.py](../../../tests/test_live_provider_process.py) owns local process/HTTP evidence separately.
