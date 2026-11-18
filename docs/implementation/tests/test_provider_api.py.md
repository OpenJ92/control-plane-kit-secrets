Source: [tests/test_provider_api.py](../../../tests/test_provider_api.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

FastAPI TestClient composes real local authentication, SQLite encrypted/audit stores and the durable provider-policy store in temporary directories. The fixture supplies explicit synthetic public control and a one-shot initializer returning those real services and its original credentials. Provider assertions are preserved; preinitialized fixture stores are not startup-order evidence. Fixture credentials distinguish write, resolve, generation, metadata and revoke powers. These are provider HTTP laws, not CPK or deployed transport semantics.

Cases cover intent canonicalization/substitution, correlation-pinned resolution, exact-version revocation/replay, public-only generation output and selected bounded errors. Injected audit faults protect atomic rollback for generation/exact-version revoke and withholding of resolve material. They do not prove that every mutation rolls back after a separate audit failure. Selected response/audit sentinel checks are not universal metadata or framework-validation redaction.

Related owners: [api.py](../../../src/control_plane_kit_secrets/api.py), [auth.py](../../../src/control_plane_kit_secrets/auth.py), [store.py](../../../src/control_plane_kit_secrets/store.py). [test_live_provider_process.py](../../../tests/test_live_provider_process.py) owns local process/HTTP evidence separately.

#71 adds administrative command/read coverage, success and rejected-command replay/revision/conflict semantics, strict revision input, process-reconstruction loss of admin capability including mutation replay, immediate grant/revoke enforcement for every action, admitted-before-revoke linearization, durable-policy unavailable audit categorization and proof that every secret action consults durable policy without static fallback. Valid-correlation malformed reads are audited; unusable correlations reject without fabricated identity. All fixtures use synthetic credentials and assert bounded nonsecret responses/events.

The Gate 2 correction injects unsupported provider, actor, endpoint, credential, method and socket-path fields into otherwise valid grant and revoke commands. It requires framework rejection before revision, grant/revocation, command, policy-event or provider-audit mutation, while known-field commands still succeed. Response and captured-log-record checks prove the rejected synthetic credential, bearer and URL sentinels are not echoed. A malformed policy-list query retains FastAPI's default validation response and makes no policy mutation, proving the bounded command handler does not replace unrelated validation. This is pre-command validation, not an admitted policy command or a new audit-event category.

The #29 closed allowlist target appends only the two exact health signing intents;
all existing entries and API assertions remain. The separate source step adds
those same entries; updated dependencies alone do not admit provider intents.
