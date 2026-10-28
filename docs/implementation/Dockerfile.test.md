Source: [Dockerfile.test](../../Dockerfile.test).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

The package stage installs production dependencies and source on the selected Python slim base (default 3.14). Its default command imports the lightweight package root and prints readiness text; that is not provider startup or custody readiness.

The test stage installs Git and the test extra, then copies tests and guidance for unittest discovery. The shell gate overrides the default command for compile/discovery. These builds resolve dependencies and can use network access; the file does not define a hermetic digest-locked image or credential provisioning. Compare [pyproject.toml](../../pyproject.toml), [test.sh](../../test.sh) and [server.py](../../src/control_plane_kit_secrets/server.py) before changing the process boundary.
