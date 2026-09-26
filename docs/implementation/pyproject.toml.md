Source: [pyproject.toml](../../pyproject.toml).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This package metadata selects setuptools discovery under src, Python >=3.11, and includes the py.typed marker. Runtime dependencies explicitly select Coref1e6cf2420bf2ec381aab745f462d4e64baef5fc from its commit archive/core subdirectory, SDK[fastapi]22f1267bde5015efe2fea4f07be4ce8ddf83bc0c from its commit archive, and cryptography50.0.0. The selected SDK extra requires FastAPI0.141.1, Starlette1.6.0 and PyJWT2.13.0 with the same crypto version. This is an exact compatibility profile for those packages, not a complete transitive lockfile.

The test extra retains HTTPX>=0.28 and Uvicorn>=0.35; the old test-only Core dependency is removed. Installing Core does not broadly authorize source ownership or expand signing families. The required receiver uses one explicit protocol-only Core allowance in control.py; other source owners remain Core-free. [test_sdk_compatibility.py](../../tests/test_sdk_compatibility.py) checks declarations, installed archive provenance and framework/crypto versions, plus actual production-factory SDK composition with synthetic authority. Coordinate adoption with [test_node_control_signing_families.py](../../tests/test_node_control_signing_families.py), [Dockerfile.test](../../Dockerfile.test) and package import policy. There is no console-script entrypoint declared here.

The #29 profile aligns with accepted SDK #30 before health-family target
execution. Its Core URL exactly matches the SDK declaration; no override or
missing-dependency guard substitutes for a compatible installation. Provider
family admission remains its own source change.

#33 advanced Core and the reviewed SDK #34 merge together. SDK functional
source is unchanged from the prior selection; Core changes only management
planning compilation and observations, outside Secrets' consumed protocol.
The shared Core URL remains exact. Owner-gate installation and existing
provenance/composition tests must establish compatibility; this adoption adds
no custody, schema, signing or deployment behavior.

#35 selects Core f1e6cf2 and the reviewed SDK #37 merge22f1267. Since #33,
Core changed operations HTTP/lifecycle/parity/recovery and planning/saga,
outside Secrets' consumed public control/health/key protocol. SDK functional
source is unchanged. The exact Core URL matches SDK's selection, preserving
normal resolver behavior. Existing declaration/provenance/receiving tests and
the ordinary owner gate govern this adoption; no new custody behavior follows.
