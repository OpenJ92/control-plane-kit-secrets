Source: [tests/test_package_policy.py](../../../tests/test_package_policy.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These tests check exact lightweight exports, boundary-marker values, explicit source-file ownership and AST import restrictions. A cold subprocess verifies that importing the base package does not load service/adjacent package dependencies. FastAPI source imports are confined to api.py; Core is disallowed in production source even though signing-family tests use a pinned test dependency.

The owns_server_process marker assertion is a selected vocabulary check, not evidence that server.py is effect-free or absent. AST imports also cannot prove arbitrary dynamic imports never occur. Read actual [__init__.py](../../../src/control_plane_kit_secrets/__init__.py), [boundaries.py](../../../src/control_plane_kit_secrets/boundaries.py) and [server.py](../../../src/control_plane_kit_secrets/server.py) when changing ownership. No provider or external-runtime acceptance is established here.
