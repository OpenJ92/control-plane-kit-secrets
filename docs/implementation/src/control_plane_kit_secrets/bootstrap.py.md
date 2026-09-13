Source: [src/control_plane_kit_secrets/bootstrap.py](../../../../src/control_plane_kit_secrets/bootstrap.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This is the credential-source and document admission boundary, producing configured [provider credentials](../../../../src/control_plane_kit_secrets/auth.py) without starting the provider or resolving secrets. Production uses the explicit file input; development JSON is a separate explicit alternative, not a fallback after a file failure.

Both routes enforce the UTF-8 byte ceiling. The file path delegates to [bootstrap_files.py](../../../../src/control_plane_kit_secrets/bootstrap_files.py); duplicate JSON keys, unknown fields, malformed text and duplicate tokens reject. Empty credential lists and repeated subjects/grants remain accepted; an omitted grant list grants nothing, while omitted intents on a grant use its wildcard default. Do not invent a closed action vocabulary here: the API chooses the action being checked.

Source selection deliberately has observable empty-value asymmetry: an empty file variable alongside valid development JSON is rejected rather than silently choosing development. [the bootstrap tests](../../../../tests/test_provider_bootstrap.py) records this behavior. Its original product motivation is not established by this note; changing it is a contract decision, not prose cleanup.

Known file/decode/JSON failures leave this boundary as fixed configuration errors without exposing the document or private path. It neither writes credential files nor grants broader topology authority. Follow the configured consumer and actual selected package version when the bootstrap ABI changes.
