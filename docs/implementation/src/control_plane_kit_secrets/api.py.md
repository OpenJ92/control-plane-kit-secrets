Source: [src/control_plane_kit_secrets/api.py](../../../../src/control_plane_kit_secrets/api.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

## HTTP boundary

create_app composes injected stores with bearer authentication and action/workspace/intent authorization. It exposes secret write, rotate, resolve, revoke, exact-version revoke, delegation generation and metadata operations; it does not own CPK planning, execution or MCP. Health endpoints return fixed live/ready values, not per-request database checks.

Request caller_subject is supplied audit/correlation context, not another authenticated identity. Credential grants authorize the action. Write/rotate canonicalize the intent label; resolution requires matching durable intent. Generation has a distinct permission and derives intent from the local signing-family map. Revocation requires secret.revoke.

## Disclosure and transaction limits

Only authorized resolve deliberately returns recoverable material as value_base64; base64 is not redaction. Other successful responses contain metadata or public key identity. Metadata includes labels and key fingerprint/version, so it is not a universal safe-publication surface.

Handled failures use fixed outcome/code details. No global scrubber replaces framework model-validation errors or arbitrary exception chains. The decoded value has a 64 KiB cap; this is not a whole HTTP request-body bound.

Resolve appends audit before returning material, but its version-selection transaction may already be committed. Generation and exact-version revocation couple audit and mutation inside the store transaction. Ordinary write/rotate/whole-reference revoke commit before separate audit appends: audit failure does not imply no mutation. Audit coverage differs among route branches, authentication failures and framework rejection paths.

Read [auth.py](../../../../src/control_plane_kit_secrets/auth.py), [store.py](../../../../src/control_plane_kit_secrets/store.py), [audit.py](../../../../src/control_plane_kit_secrets/audit.py) and [server.py](../../../../src/control_plane_kit_secrets/server.py). [test_provider_api.py](../../../../tests/test_provider_api.py) protects local HTTP composition, not external provider acceptance.
