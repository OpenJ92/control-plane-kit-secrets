Source: [src/control_plane_kit_secrets/bootstrap_files.py](../../../../src/control_plane_kit_secrets/bootstrap_files.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This small filesystem boundary returns bounded bytes from an absolute bootstrap file. It opens read-only with O_NOFOLLOW where available, checks the opened descriptor is a nonempty regular file with no group/other permission bits, enforces the caller's size limit, and closes the descriptor even on failure.

Do not overstate these checks: they do not require exactly mode 0400, do not compare the file's uid to the process uid, and do not protect every parent-path component from replacement. File readability is still enforced by the OS. The bound and descriptor checks are not a claim of a filesystem snapshot.

[bootstrap.py](../../../../src/control_plane_kit_secrets/bootstrap.py) uses this reader for the credential document; [crypto.py](../../../../src/control_plane_kit_secrets/crypto.py) uses it in the environment-selected master-key loader. Each consumer owns decoding and safe outward failure. The helper's exception may retain an underlying cause, so it is not itself a traceback-redaction endpoint.

Tests enter through the bootstrap and encrypted-store owners using disposable files. Their mode/symlink/size cases prove those local admission rules, not production mount provenance or user authorization.
