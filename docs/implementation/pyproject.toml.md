Source: [pyproject.toml](../../pyproject.toml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This package metadata selects setuptools discovery under src, Python >=3.11, and includes the py.typed marker. Runtime dependencies explicitly select Coree074bda49fa0c46f420d675e45a93f787b460c02 from its commit archive/core subdirectory, SDK[fastapi]d8b72e52c8ebca65bf21a2a2ae51df663b1c8a77 from its commit archive, and cryptography50.0.0. The selected SDK extra requires FastAPI0.141.1, Starlette1.6.0 and PyJWT2.13.0 with the same crypto version. This is an exact compatibility profile for those packages, not a complete transitive lockfile.

The test extra retains HTTPX>=0.28 and Uvicorn>=0.35; the old test-only Core dependency is removed. Installing Core does not broadly authorize source ownership or expand signing families. The required receiver uses one explicit protocol-only Core allowance in control.py; other source owners remain Core-free. [test_sdk_compatibility.py](../../tests/test_sdk_compatibility.py) checks declarations, installed archive provenance and framework/crypto versions, plus actual production-factory SDK composition with synthetic authority. Coordinate adoption with [test_node_control_signing_families.py](../../tests/test_node_control_signing_families.py), [Dockerfile.test](../../Dockerfile.test) and package import policy. There is no console-script entrypoint declared here.

The #29 profile aligns with accepted SDK #30 before health-family target
execution. Its Core URL exactly matches the SDK declaration; no override or
missing-dependency guard substitutes for a compatible installation. Provider
family admission remains its own source change.

#33 advances Core and the reviewed SDK #34 merge together. SDK functional
source is unchanged from the prior selection; Core changes only management
planning compilation and observations, outside Secrets' consumed protocol.
The shared Core URL remains exact. Owner-gate installation and existing
provenance/composition tests must establish compatibility; this adoption adds
no custody, schema, signing or deployment behavior.
