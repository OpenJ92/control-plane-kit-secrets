Source: [src/control_plane_kit_secrets/custody.py](../../../../src/control_plane_kit_secrets/custody.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

admit_provider_custody binds one retained SQLite store to the supplied provider identity, master key and exact declared schema before returning secret/audit stores. This is custody admission, not CPK graph ownership, a generic migration engine or automatic recovery.

SQLite's BEGIN IMMEDIATE serializes the admission transaction. An object-free database receives secret/audit/binding schema and an authenticated witness together; an existing database must match the complete expected schema and decrypt the one binding under the same provider/root context. Failure rolls back logical changes. Existing unbound or incompatible stores are rejected, not adopted or repaired.

Contract-bearing dependencies are [EncryptedSecretStore's schema and transaction initializer](../../../../src/control_plane_kit_secrets/store.py), [SqliteAuditStore's schema and transaction initializer](../../../../src/control_plane_kit_secrets/audit.py) and [MasterKey](../../../../src/control_plane_kit_secrets/crypto.py). Changing either store schema changes admission compatibility even when this file is untouched. A corresponding data decision is required; documentation cannot turn drift into an approved migration.

Fixed rejected/unavailable categories distinguish incompatible custody from operational inability to establish it. SQLite still owns its own locking/recovery. Logical-state preservation is not byte-identical filesystem preservation: the function may create parent directories and SQLite may manage journals. Path checks do not claim protection from hostile path replacement.

The first custody tests in [test_encrypted_store.py](../../../../tests/test_encrypted_store.py) cover empty/populated restart, wrong provider/key, tampered binding, unbound/changed schema, concurrent admission and initialization rollback. These are local custody laws, not live provider readiness or capstone acceptance. [AGENTS.md](../../../../AGENTS.md) retains the governing authority limits.
