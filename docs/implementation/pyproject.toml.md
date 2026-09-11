Source: [pyproject.toml](../../pyproject.toml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This package metadata selects setuptools discovery under src, Python >=3.11, and includes the py.typed marker. Production depends on cryptography and FastAPI using lower-bound ranges, not a full lockfile. Core is not a production dependency.

The test extra selects Core a62af8431afb878fa0beed3b752cbdf7a640fb48 via its Git subdirectory and adds HTTPX/Uvicorn. That selected contract supports the signing-family compatibility tests; newer Core APIs are not implicitly adopted. Coordinate changes with [test_node_control_signing_families.py](../../tests/test_node_control_signing_families.py), [Dockerfile.test](../../Dockerfile.test) and package import policy. There is no console-script entrypoint declared here.
