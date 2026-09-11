Source: [src/control_plane_kit_secrets/models.py](../../../../src/control_plane_kit_secrets/models.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These are provider-local storage results and fixed storage error categories, not Core authorization grants or Operations history. SecretMetadata copies labels into an immutable mapping; its other fields are not comprehensively validated by the dataclass. Store and API admission remain separate responsibilities.

ResolvedSecret deliberately hides its plaintext from repr, but its value property returns the bytes. It still exposes workspace/reference/version coordinates in repr. GeneratedDelegationKey returns public key and provider metadata while the store retains encrypted private material. Neither result is a general redaction filter: labels and identifiers must be appropriate for the surface that publishes them.

Fixed subclass messages avoid interpolating storage values. Some store callers chain underlying exceptions, so safe top-level messages do not promise safe arbitrary tracebacks. Consult [store.py](../../../../src/control_plane_kit_secrets/store.py), [api.py](../../../../src/control_plane_kit_secrets/api.py) and the selected repr/tamper assertions in [test_encrypted_store.py](../../../../tests/test_encrypted_store.py) before changing these values.
