Source: [test.sh](../../test.sh).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This is the owning Docker-backed package gate. It runs support tests and static package integrity in a policy image with read-only source mounts, builds the test image, runs compileall/unittest discovery, then checks lightweight installed-package import outside /app. Run from the repository root: the build context and Dockerfile arguments use the caller's working directory.

Image/container variables select resources, not a reduced test selection. The configured runner name is removed before execution and again by an EXIT trap; cleanup suppresses errors and performs no final absence audit or foreign-ownership check. Thus a completed suite and verified cleanup are different claims. Do not infer cleanup success from the trap or invoke against a shared/foreign name.

Build/install/image availability can require network access; this is not a no-network immutable wrapper. [Dockerfile.test](../../Dockerfile.test) and [package_integrity.py](../../test_support/package_integrity.py) own the concrete stages. On missing prerequisites or apparatus failure, follow [AGENTS.md](../../AGENTS.md): stop and ask, without host fallback, custom replacement or silent retry. Documentation changes do not execute this gate.
