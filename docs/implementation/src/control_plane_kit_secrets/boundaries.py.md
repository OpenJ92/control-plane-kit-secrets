Source: [src/control_plane_kit_secrets/boundaries.py](../../../../src/control_plane_kit_secrets/boundaries.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This frozen value records the package's selected ownership vocabulary: encrypted custody and provider-local audit, not Operations UoW, concrete runtime interpreters or product descriptors. It is metadata, not an authorization mechanism or dependency analyzer.

The existing owns_server_process=False marker must not be read as proof that the repository has no process entrypoint: [server.py](../../../../src/control_plane_kit_secrets/server.py) really does bootstrap the provider at import time. Preserve this distinction rather than silently changing source policy during documentation work. [test_package_policy.py](../../../../tests/test_package_policy.py) checks the marker and actual imports separately.
