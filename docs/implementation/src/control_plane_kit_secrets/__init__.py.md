Source: [src/control_plane_kit_secrets/__init__.py](../../../../src/control_plane_kit_secrets/__init__.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

The package root exports only its package name and boundary marker values. It deliberately avoids importing API/server/storage/crypto owners, so ordinary package import does not initialize custody or load credentials. Importing server.py is explicitly different.

[boundaries.py](../../../../src/control_plane_kit_secrets/boundaries.py) owns the marker; [test_package_policy.py](../../../../tests/test_package_policy.py) checks exact exports and cold import isolation. Do not add convenient service exports without reviewing that lightweight contract.
