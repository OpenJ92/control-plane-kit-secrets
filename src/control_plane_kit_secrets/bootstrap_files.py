from __future__ import annotations

import os
from pathlib import Path
import stat


class ProtectedBootstrapFileError(Exception):
    """Raised without exposing protected bootstrap file contents or paths."""


def read_protected_bootstrap_file(
    path_value: str,
    *,
    maximum_bytes: int,
) -> bytes:
    descriptor: int | None = None
    try:
        path = Path(path_value)
        if not path.is_absolute() or maximum_bytes < 1:
            raise ValueError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            raise ValueError
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise ValueError
        return payload
    except Exception as exc:
        raise ProtectedBootstrapFileError() from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
