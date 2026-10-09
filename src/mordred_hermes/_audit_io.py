"""Secure, process-shared filesystem primitives for Mordred audit writers."""

from __future__ import annotations

import contextlib
import errno
import gzip
import os
import shutil
import stat
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from ._audit_session import AuditProbe as AuditProbe
from ._audit_session import AuditSession as AuditSession
from ._audit_session import AuditSnapshot as AuditSnapshot
from ._audit_session import audit_session as audit_session
from ._audit_session import decode_audit_bytes as decode_audit_bytes
from ._audit_session import read_audit_snapshot as read_audit_snapshot

try:  # POSIX on every supported Phase 1-3 platform (macOS/Linux/WSL2).
    import fcntl
except ImportError:  # pragma: no cover - Windows native is not supported yet
    fcntl = None  # type: ignore[assignment]

_AUDIT_THREAD_LOCK: Final = threading.RLock()
_FILE_MODE: Final = 0o600
_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)


def audit_lock_path(path: Path) -> Path:
    """Return the hidden sidecar name, outside ``audit.log*`` rotations."""
    return path.with_name(f".{path.name}.lock")


def audit_path_stat(path: Path) -> os.stat_result | None:
    """Return ``lstat(path)`` only when it names a regular file.

    Missing is represented by ``None``. Symlinks and special files are
    rejected before an open can follow a victim path or block on a FIFO.
    """
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError(
            errno.EINVAL,
            "audit path must be a regular file (not a symlink, FIFO, device, or directory)",
            str(path),
        )
    return metadata


def open_audit_file(
    path: Path,
    flags: int,
    *,
    mode: int = _FILE_MODE,
    tighten: bool | None = None,
) -> int:
    """Open one regular audit inode without following links or FIFO waits.

    The path is checked before and after ``open`` and against ``fstat`` to
    detect replacement during the open window. The opened inode — never a
    path-following chmod target — is tightened to ``mode`` when ``tighten`` is
    true, which by default means "the caller asked for write access".

    A plain read must not mutate metadata: a reader is not an owner, and
    asserting the mode on an inherited 0644 log would turn "loose" into
    "unreadable". Callers that deliberately repair permissions (the writers'
    take-ownership step) pass ``tighten=True`` explicitly.
    """
    if tighten is None:
        tighten = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
    before = audit_path_stat(path)
    secure_flags = flags | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK
    fd = os.open(path, secure_flags, mode)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(
                errno.EINVAL,
                "opened audit path is not a regular file",
                str(path),
            )
        after = audit_path_stat(path)
        if after is None or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError(errno.EAGAIN, "audit path changed while opening", str(path))
        if before is not None and (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise OSError(errno.EAGAIN, "audit path changed while opening", str(path))
        if tighten:
            os.fchmod(fd, mode)
            if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
                raise OSError(errno.EPERM, f"audit file must be mode 0o{mode:o}", str(path))
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_first_line(path: Path, *, limit: int) -> bytes | None:
    """Read at most ``limit`` bytes of the first line from a safe inode."""
    if audit_path_stat(path) is None:
        return None
    fd = open_audit_file(path, os.O_RDONLY)
    try:
        chunks: list[bytes] = []
        remaining = limit
        while remaining:
            chunk = os.read(fd, min(4096, remaining))
            if not chunk:
                break
            line, separator, _rest = chunk.partition(b"\n")
            chunks.append(line)
            remaining -= len(line)
            if separator:
                break
        return b"".join(chunks)
    finally:
        os.close(fd)


@contextlib.contextmanager
def exclusive_audit_lock(path: Path) -> Iterator[None]:
    """Serialize all cooperating audit writers on ``.<name>.lock``."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = audit_lock_path(path)
    with _AUDIT_THREAD_LOCK:
        try:
            fd = open_audit_file(lock_path, os.O_CREAT | os.O_RDWR)
        except OSError as exc:
            raise OSError(
                errno.EPERM,
                "audit lock is unsafe or unavailable",
                str(lock_path),
            ) from exc
        try:
            if fcntl is None:  # pragma: no cover - non-POSIX thread-only fallback
                yield
                return
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _unlink_same_inode(path: Path, identity: tuple[int, int]) -> None:
    metadata = audit_path_stat(path)
    if metadata is None:
        return
    if (metadata.st_dev, metadata.st_ino) != identity:
        raise OSError(errno.EAGAIN, "audit path changed before unlink", str(path))
    path.unlink()


def compress_rotated_file(source: Path, target: Path) -> None:
    """Gzip one rotated regular file without following either pathname."""
    source_fd = open_audit_file(source, os.O_RDONLY)
    target_fd: int | None = None
    target_identity: tuple[int, int] | None = None
    try:
        # Inside the try: an fstat failure here would otherwise leak source_fd.
        source_meta = os.fstat(source_fd)
        target_fd = open_audit_file(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        target_meta = os.fstat(target_fd)
        target_identity = (target_meta.st_dev, target_meta.st_ino)
        src = os.fdopen(source_fd, "rb")
        source_fd = -1
        raw_dst = os.fdopen(target_fd, "wb")
        target_fd = None
        with (
            src,
            raw_dst,
            gzip.GzipFile(fileobj=raw_dst, mode="wb") as dst,
        ):
            shutil.copyfileobj(src, dst)
        _unlink_same_inode(source, (source_meta.st_dev, source_meta.st_ino))
    except BaseException:
        if target_identity is not None:
            with contextlib.suppress(OSError):
                _unlink_same_inode(target, target_identity)
        raise
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)
