"""Opt-in private filesystem primitives; existing component I/O is unchanged."""

from __future__ import annotations

import os
from contextlib import AbstractContextManager
from pathlib import Path

from ._types import (
    ConfidentialDirectory,
    ConfidentialTransaction,
    FileIdentity,
    FileMetadata,
    PrivateDirectory,
    PrivateFSError,
    PrivateTransaction,
)

__all__ = [
    "ConfidentialDirectory",
    "ConfidentialTransaction",
    "FileIdentity",
    "FileMetadata",
    "PrivateDirectory",
    "PrivateFSError",
    "PrivateTransaction",
    "current_principal_id",
    "open_confidential_directory",
    "open_optional_confidential_directory",
    "open_optional_private_directory",
    "open_private_directory",
    "read_public_build_output",
]
_platform = os.name


def open_private_directory(path: str | Path, *, create: bool = False) -> AbstractContextManager[PrivateDirectory]:
    if _platform == "posix":
        from ._posix import open_private_directory as posix_opener

        return posix_opener(path, create=create)
    elif _platform == "nt":
        from ._windows_io import open_private_directory as windows_opener

        return windows_opener(path, create=create)
    else:
        raise PrivateFSError("unsupported", "open_directory")


def open_confidential_directory(
    path: str | Path, *, create: bool = False
) -> AbstractContextManager[ConfidentialDirectory]:
    if _platform != "nt":
        raise PrivateFSError("unsupported", "open_confidential_directory")
    from ._windows_io import open_confidential_directory as opener

    return opener(path, create=create)


def open_optional_confidential_directory(path: str | Path) -> AbstractContextManager[ConfidentialDirectory | None]:
    if _platform != "nt":
        raise PrivateFSError("unsupported", "open_optional_confidential_directory")
    from ._windows_io import open_optional_confidential_directory as opener

    return opener(path)


def open_optional_private_directory(path: str | Path) -> AbstractContextManager[PrivateDirectory | None]:
    if _platform != "nt":
        raise PrivateFSError("unsupported", "open_optional_private_directory")
    from ._windows_io import open_optional_private_directory as opener

    return opener(path)


def read_public_build_output(path: str | Path, *, max_bytes: int) -> bytes:
    """Bounded immutable Windows build-source read; allows source-only hardlinks."""
    if _platform != "nt":
        raise PrivateFSError("unsupported", "read_public_build_output")
    from ._windows_public import read_public_build_output as reader

    return reader(path, max_bytes=max_bytes)


def current_principal_id() -> bytes:
    """Return the validated effective Windows token SID, without name lookup."""
    if _platform != "nt":
        raise PrivateFSError("unsupported", "current_principal_id")
    from ._windows_security import current_user_sid

    return current_user_sid()
