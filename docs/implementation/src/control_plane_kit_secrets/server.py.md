Source: [src/control_plane_kit_secrets/server.py](../../../../src/control_plane_kit_secrets/server.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This environment-bound process entrypoint creates app at module import. It loads key/credential files and may inspect or initialize SQLite custody; it is not the package root's lightweight import surface.

A database path is required; provider identity has a default. Key and credential loading precede custody construction, and invalid loader configuration becomes a fixed ProviderConfigurationError. The admitted stores are passed to create_app. Exact retained schema/key/provider compatibility belongs to custody.py, not to health routes. Bind address, TLS termination and process supervision belong to the launcher.

Relevant owners: [bootstrap.py](../../../../src/control_plane_kit_secrets/bootstrap.py), [crypto.py](../../../../src/control_plane_kit_secrets/crypto.py), [custody.py](../../../../src/control_plane_kit_secrets/custody.py), [api.py](../../../../src/control_plane_kit_secrets/api.py). [test_live_provider_process.py](../../../../tests/test_live_provider_process.py) protects startup/restart/refusal. This note authorizes no credential access or process execution.
