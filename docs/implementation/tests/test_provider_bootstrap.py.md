Source: [tests/test_provider_bootstrap.py](../../../tests/test_provider_bootstrap.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These tests exercise [credential admission](../../../src/control_plane_kit_secrets/bootstrap.py) and [grant matching](../../../src/control_plane_kit_secrets/auth.py) with disposable documents/files. They preserve meaningful distinctions: no credentials versus a credential with no grants, absent versus empty intent permissions, duplicate token rejection versus lawful repeated subjects, and exact text rather than coercion.

Byte bounds cover both file and development input. Unsafe paths/modes, ambiguous sources and configuration traceback canaries guard the bootstrap disclosure boundary. The empty source-variable asymmetry is explicitly tested; do not simplify it by assuming truthiness selects the same branch as presence.

Fixture token strings are disposable examples, not credential recommendations. The tests do not perform live secret resolution, CPK admission or provider effects. Request-level audit/denial behavior belongs to [test_provider_api.py](../../../tests/test_provider_api.py); durable encrypted custody belongs to [test_encrypted_store.py](../../../tests/test_encrypted_store.py). Run executable validation only through the owning Docker-backed [test.sh](../../../test.sh), not host file experiments.
