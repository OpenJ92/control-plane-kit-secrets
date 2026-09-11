Source: [src/control_plane_kit_secrets/store.py](../../../../src/control_plane_kit_secrets/store.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

## Durable owner

EncryptedSecretStore owns provider versions, pinned resolution selections, delegation-generation correlations and exact-version revocation correlations in SQLite. It does not authenticate callers, issue grants or own deployment history. [api.py](../../../../src/control_plane_kit_secrets/api.py) admits requests; [custody.py](../../../../src/control_plane_kit_secrets/custody.py) binds the retained database to the provider/key/schema. Calling initialize alone creates tables; it is not equivalent to custody admission.

Writes use BEGIN IMMEDIATE and a connection-owned commit/rollback scope; foreign keys and a five-second busy timeout are configured. Rotation appends a numbered version instead of overwriting older versions. Whole-reference revocation visits all versions. Exact-version revocation binds the requested version and caller to a workspace/correlation, rejects conflicting reuse, and preserves siblings. Revocation changes authenticated status and re-encrypts the retained value; it is not physical erasure.

## Replay and cryptographic boundaries

resolve_secret_for_use pins the first admitted version to a workspace/correlation with reference, intent and caller. Replays remain on that version across rotation, but still reject revocation or incompatible intent; a new correlation can select the newest version. The simpler resolve_secret has no durable selection or intent admission. Metadata reads decode rows but do not decrypt/authenticate the ciphertext.

Version encryption delegates to [MasterKey](../../../../src/control_plane_kit_secrets/crypto.py), binding version identity, status, labels and other metadata as associated data. Fresh nonces are used for insertion and revocation. Decryption checks the algorithm/key fingerprint and authenticated ciphertext. Labels are bounded and string-coerced, not a secret-content classifier. Raw test rows expose ciphertext and key metadata and must not become public evidence by convenience.

Delegation generation admits the local signing family, generates Ed25519 material, and atomically stores encrypted private material, public metadata, correlation and audit. Replay verifies the existing private/public identity rather than generating another key. Exact-version revoke also appends audit in the same transaction; both replay paths append replay audit rows. Ordinary create/rotate/resolve/whole-reference revoke do not receive an audit store and must not be described as sharing the API's separate audit transaction.

## Maintenance and evidence

Schema changes affect exact custody compatibility and need a deliberate data decision, not silent initialization or repair. SQLite failures and crypto failures can retain chained causes; fixed public error translation belongs to the API. This owner provides no provider retry, cross-system transaction or recovery policy.

[test_encrypted_store.py](../../../../tests/test_encrypted_store.py) covers persistence, tamper rejection, version selection and concurrency; [test_delegation_key_generation.py](../../../../tests/test_delegation_key_generation.py) and [test_node_control_signing_families.py](../../../../tests/test_node_control_signing_families.py) cover generated identities and family admission. These are local provider laws, not external runtime acceptance.
