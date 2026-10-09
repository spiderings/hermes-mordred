"""mordred_hermes.keyvault._storage — file-safety helpers.

Phase 4 PR4 step-B (2026-05-15). Private to the keyvault module; api.py
and the encrypt/decrypt/generate/backup layers consume these helpers.
Frozen contract: SPEC.md §"PR4 API contract / File-safety semantics".

Codex pre-implementation review HIGH #4 demanded:

- ``os.open(O_NOFOLLOW)`` — no symlink-follow on any keyvault path.
- File mode ``0o600`` and directory mode ``0o700`` enforced via
  ``fstat`` after open (mismatch → :exc:`KeyvaultPermissionError`).
- Atomic writes: ``<file>.tmp + durable-fsync(tmp_fd) + os.replace +
  durable-fsync(parent_fd)``. "durable-fsync" is :func:`_fsync_durable`,
  NOT a bare ``os.fsync`` — see its docstring for why plain ``os.fsync``
  is not sufficient on macOS.
- Exclusive ``fcntl.flock`` on ``<root>/.lock`` for write transactions.
- ``meta.json`` corruption raises :exc:`KeyvaultCorruptError` whose
  ``str()`` does NOT include the corrupted file contents (audit safety
  — a partially-overwritten file could contain secret-shaped bytes).
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import secrets
import stat
import threading

try:
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX platform (Windows)
    # A POSIX build must never reach this branch: a shadowed or stripped
    # ``fcntl`` there would silently downgrade every write transaction to
    # unlocked, so genuine platform absence is the only accepted reason.
    if os.name == "posix":
        raise
    # This module must stay *importable* off POSIX: extension.pairing imports
    # ``atomic_write`` at module scope, and its own fcntl guard was defeated
    # by a bare import here (review 2026-07-29). Keyvault write transactions
    # off POSIX degrade to single-process best effort (no flock); the actual
    # keyvault feature is gated far earlier by the platform helpers
    # (_seckey_backend), so no hardware-backed state is reachable this way.
    fcntl = None  # type: ignore[assignment]

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .._home import hermes_home as _hermes_home

_META_VERSION = 1
_FILE_MODE = 0o600
_DIR_MODE = 0o700
RESET_JOURNAL_NAME = ".keyvault.reset.json"
"""Stable-parent reset journal published before native-key destruction."""

GENERATION_EPOCH_NAME = ".keyvault.generation"
"""Stable-parent 128-bit profile generation lease."""

_GENERATION_EPOCH_LEN = 16
# ``O_NOFOLLOW`` does not exist on Windows; 0 is the no-op flag value. The
# symlink-refusal posture there degrades to the explicit ``is_symlink`` /
# ``lstat`` checks (no open-time TOCTOU defense), which is acceptable off
# POSIX where the keyvault feature itself is gated by the platform helpers.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

# ``flock`` is process-scoped on some supported kernels and unavailable on
# non-POSIX imports.  Keep a process-local guard as well so lifecycle
# operations (notably ``keyvault reset``) serialize with ordinary writers in
# every thread.  Cross-process serialization is still provided by ``flock``.
_LIFECYCLE_THREAD_LOCK = threading.RLock()
_LOCK_PROCESS_PID = os.getpid()
_ACTIVE_LOCK_FDS: set[int] = set()


class _ThreadLockState(threading.local):
    """Per-thread advisory-lock recursion depths for this process."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        self.depths: dict[str, int] = {}


_THREAD_LOCK_STATE = _ThreadLockState()


def _reset_process_lock_state() -> None:
    """Discard inherited descriptors, mutexes, and recursion state after fork."""
    global _ACTIVE_LOCK_FDS, _LIFECYCLE_THREAD_LOCK, _LOCK_PROCESS_PID, _THREAD_LOCK_STATE

    # ``flock`` follows the open-file description across fork. Merely clearing
    # the recursion depth would leave a child blocking on a lock held through
    # its own inherited descriptor. Close (never LOCK_UN) the child's copies;
    # the parent's descriptors continue to own the lock independently.
    inherited_fds = _ACTIVE_LOCK_FDS
    _ACTIVE_LOCK_FDS = set()
    for fd in inherited_fds:
        with contextlib.suppress(OSError):
            os.close(fd)

    _LIFECYCLE_THREAD_LOCK = threading.RLock()
    _LOCK_PROCESS_PID = os.getpid()
    _THREAD_LOCK_STATE = _ThreadLockState()


if hasattr(os, "register_at_fork"):  # pragma: no branch — true on supported POSIX
    os.register_at_fork(after_in_child=_reset_process_lock_state)


def _refresh_process_lock_state() -> None:
    """PID fallback for runtimes where the at-fork callback did not run."""
    if os.getpid() != _LOCK_PROCESS_PID:
        _reset_process_lock_state()


def _thread_lock_depths() -> dict[str, int]:
    """Return recursion depths, never reusing state inherited across ``fork``."""
    pid = os.getpid()
    if _THREAD_LOCK_STATE.pid != pid:
        _THREAD_LOCK_STATE.pid = pid
        _THREAD_LOCK_STATE.depths = {}
    return _THREAD_LOCK_STATE.depths


class KeyvaultPermissionError(OSError):
    """Filesystem permissions disagree with the keyvault security posture.

    Raised when a keyvault directory is not mode ``0o700``, a keyvault
    file is not mode ``0o600``, or a path is a symlink (``O_NOFOLLOW``
    refusal). Subclass of :class:`OSError` so callers using
    ``except OSError`` for filesystem error handling catch it naturally.
    """


class KeyvaultCorruptError(ValueError):
    """A keyvault state file failed to parse.

    Subclass of :class:`ValueError` (mirrors
    :class:`mordred_hermes.keyvault.digest.VerificationDigestMismatch`).
    The ``str()`` representation does NOT include corrupted file
    contents — a partially-overwritten file could contain secret-shaped
    bytes that must not leak into exception traces or log scrapers.
    """


class KeyvaultResetInProgressError(OSError):
    """The profile has entered irreversible reset and cannot be reused.

    Reset publishes a durable parent journal before deleting any native key. If
    native deletion, process execution, or directory removal later fails, the
    profile must remain unusable until reset is retried. Subclassing
    :class:`OSError` preserves the existing clean
    error handling used for unavailable keyvault storage.
    """


class KeyvaultResetJournalRestoreError(OSError):
    """A failed journal-unlink flush could not restore its visible tombstone."""


def resolve_keyvault_dir(home: Path | None = None) -> Path:
    """Return the keyvault root directory.

    ``home=None`` uses :func:`mordred_hermes._home.hermes_home`. The
    function does NOT create any directories; call :func:`ensure_layout`
    for that.
    """
    base = home if home is not None else _hermes_home()
    return base / "mordred" / "keyvault"


def _check_dir_mode(path: Path) -> None:
    """Validate that ``path`` is a real directory with mode ``0o700``.

    Uses ``lstat`` (not ``stat``) so a symlinked directory is refused
    even when the target has correct mode (codex pre-merge P2-2:
    symlinked keyvault directories would otherwise pass the mode check
    and redirect writes outside the keyvault tree).

    Accepted TOCTOU caveat (in-tree code-reviewer LOW-1, 2026-05-15): the
    lstat result is not atomically tied to the subsequent open / mkdir
    that callers perform after the check. A same-host, same-UID attacker
    who can race the gap between ``_check_dir_mode`` and ``atomic_write``
    could in principle swap the directory for a symlink. Closing that
    window cleanly would require ``O_DIRECTORY | O_NOFOLLOW`` open +
    ``fdopen``-backed reads on every helper, which is not portable
    across Python versions on macOS. The SPEC threat model excludes
    same-UID attackers (mode ``0o700`` already gates non-owner access),
    so the project accepts this gap.
    """
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link to keyvault directory", str(path))
    if not stat.S_ISDIR(st.st_mode):
        raise KeyvaultPermissionError(errno.ENOTDIR, "keyvault path exists but is not a directory", str(path))
    actual = stat.S_IMODE(st.st_mode)
    if actual != _DIR_MODE:
        raise KeyvaultPermissionError(
            errno.EPERM,
            f"keyvault directory must be mode 0o{_DIR_MODE:o}, got 0o{actual:o}",
            str(path),
        )


def _assert_regular_at_mode(st: os.stat_result, path: Path) -> None:
    """Assert an already-stat'ed keyvault file is regular with mode ``0o600``.

    The ``S_ISREG`` + ``S_IMODE`` pair shared verbatim by
    :func:`_check_file_mode` (lstat side) and :func:`safe_read`'s under-fd
    re-check (fstat side). Rejecting non-regular files (FIFO / device /
    directory) matters because a 0o600 FIFO would otherwise pass the mode
    bit check and cause reads to block or operate on the wrong kind of
    inode (codex second-pass P2-C, 2026-05-15). The lock-path validator
    (:func:`_validate_lock_stat`) keeps its own copy — its messages are
    label-parameterized and must stay byte-stable.
    """
    if not stat.S_ISREG(st.st_mode):
        raise KeyvaultPermissionError(
            errno.EINVAL,
            "keyvault file must be a regular file (not FIFO, device, directory)",
            str(path),
        )
    actual = stat.S_IMODE(st.st_mode)
    if actual != _FILE_MODE:
        raise KeyvaultPermissionError(
            errno.EPERM,
            f"keyvault file must be mode 0o{_FILE_MODE:o}, got 0o{actual:o}",
            str(path),
        )


def _check_file_mode(path: Path) -> None:
    """Validate that ``path`` is a real file with mode ``0o600``.

    Uses ``lstat`` so a symlinked file is refused regardless of the
    target's mode (file-safety contract — codex pre-merge P2-2). The
    regular-file + mode assertion is shared with ``safe_read`` via
    :func:`_assert_regular_at_mode`.
    """
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link to keyvault file", str(path))
    _assert_regular_at_mode(st, path)


def ensure_layout(root: Path) -> None:
    """Idempotently create the keyvault directory tree.

    Layout (PATHS.md §Expected substructure):

    - ``root/`` (mode ``0o700``)
    - ``root/.lock`` (mode ``0o600``, empty; fcntl.flock target)
    - ``root/meta.json`` (mode ``0o600``, ``{"version": 1, "keys": {}}`` initially)
    - ``root/digests/`` (mode ``0o700``)
    - ``root/ciphertexts/`` (mode ``0o700``)

    Idempotent: re-running on an existing layout validates the modes
    without clobbering content. Wrong mode on any existing path raises
    :exc:`KeyvaultPermissionError`.
    """
    # The lifecycle lock intentionally lives one level above ``root``. Create
    # only that stable parent first; reset never removes it, and an absent-root
    # reset may linearize before this initializer without racing any mutation
    # inside the keyvault tree.
    root.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    with keyvault_lifecycle_lock(root):
        _ensure_layout_locked(root)


def _ensure_layout_root(root: Path) -> None:
    """Materialize/validate the keyvault root directory itself.

    Split out of :func:`_ensure_layout_locked` for cyclomatic headroom only.
    The caller samples ``root.exists()`` for the generation-epoch decision
    *before* calling this, so the pre-existing double stat is unchanged.
    """
    if root.exists():
        if not root.is_dir():
            raise KeyvaultPermissionError(errno.ENOTDIR, "keyvault root exists but is not a directory", str(root))
        _check_dir_mode(root)
    else:
        try:
            root.mkdir(mode=_DIR_MODE, parents=True)
        except FileExistsError:
            # A concurrent initializer won the absent→mkdir race. Validate
            # its object exactly as the pre-existing branch would.
            _check_dir_mode(root)
        else:
            os.chmod(root, _DIR_MODE)


def _ensure_layout_subdirs(root: Path) -> None:
    """Materialize/validate ``digests/`` and ``ciphertexts/`` at ``0o700``.

    Split out of :func:`_ensure_layout_locked` for cyclomatic headroom only;
    the per-subdirectory exists/mkdir/race-validate sequence is unchanged.
    """
    for sub in ("digests", "ciphertexts"):
        d = root / sub
        if d.exists():
            _check_dir_mode(d)
        else:
            try:
                d.mkdir(mode=_DIR_MODE)
            except FileExistsError:
                _check_dir_mode(d)
            else:
                os.chmod(d, _DIR_MODE)


def _ensure_layout_locked(root: Path) -> None:
    """Implement :func:`ensure_layout` while its lifecycle lock is held."""
    # Check the stable parent journal before creating ``root``. A crash may
    # leave the journal after rmtree already removed the old generation; an
    # initializer must not publish an empty successor tree over that pending
    # reset transaction.
    assert_keyvault_active(root)
    root_existed = root.exists()
    _ensure_layout_root(root)

    # A root created at this pathname is a new generation even if the
    # filesystem immediately reuses the predecessor's dev/inode pair.
    ensure_generation_epoch(root, force_new=not root_existed)

    _ensure_layout_subdirs(root)

    lock = root / ".lock"
    ensure_lock_file(lock)
    _check_file_mode(lock)

    meta = root / "meta.json"
    if not meta.exists():
        _write_meta_atomic(meta, {"version": _META_VERSION, "keys": {}})
    _check_file_mode(meta)


def ensure_lock_file(path: Path) -> None:
    """Create the ``fcntl.flock`` target at ``path`` (mode ``0o600``) if absent.

    Shared by :func:`ensure_layout` and the vault layer (``vault._ensure_lock``),
    which materialize their flock targets the same way. ``O_EXCL | O_NOFOLLOW``
    so a pre-planted symlink is refused rather than followed. Losing the
    creation race to a concurrent creator is fine — the winner's lock file
    serves both processes; the caller's subsequent flock (or
    :func:`_check_file_mode`) uses/validates it exactly as if we had created it.
    """
    try:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
            _FILE_MODE,
        )
    except FileExistsError:
        pass
    else:
        try:
            # A restrictive umask may remove requested bits. The new inode is
            # never broader than 0600, so restoring the exact contract here is
            # safe before another caller validates/opens it.
            os.fchmod(fd, _FILE_MODE)
        finally:
            os.close(fd)
    _check_file_mode(path)


def _fsync_durable(fd: int) -> None:
    """Flush ``fd`` through to stable storage — NOT just the drive cache.

    On Linux (and most POSIX platforms) ``os.fsync`` is sufficient: it
    blocks until the kernel has handed the data to the device and the
    device reports it durable.

    On macOS this is NOT true. Apple's ``fsync(2)`` man page states that
    ``fsync`` only flushes data to the drive's on-board write cache, not
    through it — the drive is free to hold the bytes in volatile cache
    and report "flushed" before they are physically on stable storage. A
    power loss between that report and the actual platter/NAND write
    loses the data despite a successful ``fsync``. Apple documents
    ``fcntl(fd, F_FULLFSYNC)`` as the call that actually waits for the
    underlying device to flush its cache, and recommends it for
    applications (like this one) that need real crash-consistency
    guarantees.

    ``fcntl.F_FULLFSYNC`` only exists on Darwin builds of CPython, so the
    attribute lookup is guarded rather than assumed. The fallback to
    plain ``os.fsync`` also covers the case where ``F_FULLFSYNC`` is
    UNSUPPORTED by the filesystem — some network / virtual filesystems
    mounted on macOS return ``ENOTSUP`` / ``EOPNOTSUPP`` / ``EINVAL`` for
    it — so the fallback is load-bearing in production, not just a
    theoretical branch for non-Darwin platforms.

    Crucially, the fallback fires ONLY for those "not supported" errnos. A
    real device error (``EIO``, ``ENOSPC``, ``EDQUOT``) from ``F_FULLFSYNC``
    means the flush genuinely failed and MUST propagate: swallowing it and
    reporting success via a second ``os.fsync`` would let :func:`atomic_write`
    claim durability it never achieved — a silent data-loss fail-open in the
    one function whose contract is crash-consistency.
    """
    full_fsync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_fsync is not None:
        try:
            fcntl.fcntl(fd, full_fsync)
            return
        except OSError as e:
            # Only "filesystem can't do F_FULLFSYNC" degrades to os.fsync;
            # anything else is a genuine flush failure and must not be hidden.
            if e.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
                raise
    os.fsync(fd)


def atomic_write(path: Path, data: bytes) -> None:
    """Atomic write of ``data`` to ``path`` at mode ``0o600``.

    Sequence: open ``<path>.<rand>.tmp`` with ``O_EXCL | O_NOFOLLOW`` →
    ``os.write`` → :func:`_fsync_durable` (tmp fd) → ``os.replace(tmp,
    final)`` → :func:`_fsync_durable` (parent dir fd). Cleans up the tmp
    file on any failure so the directory does not accumulate orphaned
    ``*.tmp`` files.

    Durability guarantee: on macOS, :func:`_fsync_durable` issues
    ``fcntl(fd, F_FULLFSYNC)`` — the call Apple documents as reaching
    stable storage — rather than a bare ``os.fsync``, which on macOS only
    reaches the drive's write cache. On every other platform (and on any
    macOS filesystem where ``F_FULLFSYNC`` is unsupported) the guarantee
    is whatever plain ``os.fsync`` provides for that OS/filesystem.

    Refuses to follow symlinks at the final path (existing symlink →
    :exc:`KeyvaultPermissionError`). If ``path`` already exists as a
    regular file, its current mode must be ``0o600`` or
    :exc:`KeyvaultPermissionError` is raised before any tmp file is
    created.
    """
    if path.is_symlink():
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to write through a symbolic link", str(path))
    if path.exists():
        _check_file_mode(path)

    tmp_path = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")

    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
        _FILE_MODE,
    )
    try:
        try:
            # ``os.write`` is not guaranteed to flush the entire buffer
            # in a single call; loop until every byte is written so a
            # short write does not commit a truncated file via the
            # subsequent ``os.replace`` (codex pre-merge P2-3).
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise OSError("os.write returned 0 bytes — disk full or fd closed")
                offset += written
            _fsync_durable(fd)
        finally:
            os.close(fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise

    try:
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise

    if os.name == "posix":
        parent_fd = os.open(path.parent, os.O_RDONLY)
        try:
            _fsync_durable(parent_fd)
        finally:
            os.close(parent_fd)
    # Off POSIX a directory cannot be opened as an fd (os.open raises
    # PermissionError on Windows), so the directory-entry flush is skipped;
    # NTFS metadata durability is filesystem-managed there (review 2026-07-29).


def reset_journal_path(root: Path) -> Path:
    """Return the reset journal outside the destructively removed tree."""
    return root.parent / RESET_JOURNAL_NAME


def write_reset_journal(root: Path, data: bytes) -> None:
    """Durably publish reset recovery data before native-key destruction.

    Caller holds :func:`keyvault_lifecycle_lock`. The reset layer owns and
    validates the JSON payload; storage owns the stable location and atomic
    durability.
    """
    atomic_write(reset_journal_path(root), data)


def clear_reset_journal(root: Path) -> None:
    """Remove a completed reset journal and durably flush its parent entry.

    Caller has already confirmed that the old root is absent and holds
    :func:`keyvault_lifecycle_lock`.
    """
    marker = reset_journal_path(root)
    recovery_data = safe_read(marker)
    marker.unlink()
    try:
        fsync_keyvault_parent(root)
    except BaseException as exc:
        # A failed directory flush leaves the unlink's durability unknown and,
        # more immediately, makes the tombstone absent from the live namespace.
        # Re-publish the exact validated-by-caller bytes before returning the
        # failure so ensure_layout/public reads remain fail-closed.
        try:
            atomic_write(marker, recovery_data)
        except BaseException as recovery_exc:
            raise KeyvaultResetJournalRestoreError(
                errno.EIO,
                f"reset journal unlink was not durable ({exc}) and its visible tombstone "
                f"could not be restored ({recovery_exc})",
                str(marker),
            ) from recovery_exc
        raise


def fsync_keyvault_parent(root: Path) -> None:
    """Durably flush directory-entry changes in the stable keyvault parent.

    Reset calls this once after removing ``root`` and again indirectly after
    unlinking its recovery journal.  The first flush is load-bearing: after it
    succeeds, a crash cannot resurrect the old root while losing the journal
    that made the old generation fail closed.

    Native Windows cannot open a directory as a file descriptor, so this is a
    no-op there, matching :func:`atomic_write`'s platform-specific durability
    boundary while keeping the storage module importable.
    """
    if os.name != "posix":
        return
    parent_fd = os.open(root.parent, os.O_RDONLY | _O_CLOEXEC)
    try:
        _fsync_durable(parent_fd)
    finally:
        os.close(parent_fd)


def generation_epoch_path(root: Path) -> Path:
    """Return the stable parent file carrying the profile generation lease."""
    return root.parent / GENERATION_EPOCH_NAME


def read_generation_epoch(root: Path) -> bytes:
    """Read and validate the current 128-bit profile generation lease."""
    data = safe_read(generation_epoch_path(root))
    if len(data) != _GENERATION_EPOCH_LEN:
        raise KeyvaultCorruptError("keyvault generation epoch must be exactly 16 bytes")
    return data


def ensure_generation_epoch(root: Path, *, force_new: bool = False) -> bytes:
    """Return the generation lease, creating or rotating it when requested.

    ``force_new`` is used for absent-root initialization and reset's
    irreversible commit. Caller holds :func:`keyvault_lifecycle_lock`.
    """
    epoch_path = generation_epoch_path(root)
    if force_new:
        atomic_write(epoch_path, secrets.token_bytes(_GENERATION_EPOCH_LEN))
    else:
        try:
            epoch_path.lstat()
        except FileNotFoundError:
            atomic_write(epoch_path, secrets.token_bytes(_GENERATION_EPOCH_LEN))
    return read_generation_epoch(root)


def assert_keyvault_active(root: Path) -> None:
    """Fail when an earlier reset crossed its irreversible commit point.

    Any directory entry at the stable journal path is sufficient to fail
    closed. Its contents are deliberately irrelevant here, so a damaged or
    replaced journal cannot turn a reset profile active again. The reset
    recovery path separately validates its exact target payload before use.

    Callers that require a race-free result hold
    :func:`keyvault_lifecycle_lock`.
    """
    marker = reset_journal_path(root)
    try:
        marker.lstat()
    except FileNotFoundError:
        return
    raise KeyvaultResetInProgressError(
        errno.EBUSY,
        "keyvault reset is in progress or incomplete; retry reset before using this profile",
        str(root),
    )


@contextlib.contextmanager
def keyvault_read_lock(root: Path) -> Iterator[bool]:
    """Serialize a public state snapshot with reset without creating a vault.

    Yield ``False`` for a completely absent root and reset journal. Callers must
    return their absent-state result without touching profile paths in that
    branch: only that immediate result linearizes before any later
    initialization. Once either entry exists, acquire the stable lifecycle lock
    and yield ``True`` so callers can re-check
    :func:`assert_keyvault_active` and read all related files from one
    generation.
    """
    try:
        root.lstat()
    except FileNotFoundError:
        try:
            reset_journal_path(root).lstat()
        except FileNotFoundError:
            yield False
            return
    with keyvault_lifecycle_lock(root):
        # The preflight observation may be stale after waiting for reset.
        # Re-check the parent journal first, then either bind this snapshot to a
        # real safe root or report the now-absent post-reset state.
        assert_keyvault_active(root)
        try:
            _check_dir_mode(root)
        except FileNotFoundError:
            yield False
            return
        yield True


def safe_read(path: Path) -> bytes:
    """Read ``path`` with ``O_NOFOLLOW`` + mode ``0o600`` enforcement.

    Raises:

    - :exc:`KeyvaultPermissionError` if ``path`` is a symlink, a
      non-regular file (FIFO / device / directory), or its mode is not
      ``0o600``.
    - :exc:`FileNotFoundError` if ``path`` does not exist (the standard
      :class:`OSError` subclass — callers handle it the same way they
      would for any missing file).
    """
    # Pre-check via lstat so we never call ``os.open`` on a FIFO (which
    # would block until a writer connects) or a symlink (which would
    # surface as ELOOP but only after the syscall — cheaper to refuse
    # here). The O_NOFOLLOW open below still defends against a
    # symlink-swap race after this check (codex second-pass P2-C).
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link", str(path))
    if not stat.S_ISREG(st.st_mode):
        raise KeyvaultPermissionError(
            errno.EINVAL,
            "keyvault file must be a regular file (not FIFO, device, directory)",
            str(path),
        )

    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise KeyvaultPermissionError(errno.ELOOP, "refusing to follow symbolic link", str(path)) from exc
        raise

    try:
        st = os.fstat(fd)
        # Re-check S_ISREG and mode under the open fd to close the TOCTOU
        # window between lstat above and this open (codex second-pass P2-C).
        _assert_regular_at_mode(st, path)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _lock_path_key(path: Path) -> str:
    """Canonical recursion key without following the lock path itself."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    return os.fspath(absolute.parent.resolve(strict=False) / absolute.name)


def _validate_lock_stat(st: os.stat_result, path: Path, *, label: str, from_lstat: bool) -> None:
    """Validate a lock inode from ``lstat`` or an already-open descriptor."""
    if from_lstat and stat.S_ISLNK(st.st_mode):
        raise KeyvaultPermissionError(errno.ELOOP, f"refusing to follow symbolic link to {label}", str(path))
    if not stat.S_ISREG(st.st_mode):
        raise KeyvaultPermissionError(
            errno.EINVAL,
            f"{label} must be a regular file (not FIFO, device, directory)",
            str(path),
        )
    mode = stat.S_IMODE(st.st_mode)
    if mode != _FILE_MODE:
        raise KeyvaultPermissionError(
            errno.EPERM,
            f"{label} file must be mode 0o{_FILE_MODE:o}, got 0o{mode:o}",
            str(path),
        )


def _lock_inode_identity(st: os.stat_result) -> tuple[int, int, int]:
    """Identity used to detect a lock inode replaced during ``open``.

    ``(st_dev, st_ino)`` alone is not sufficient: Linux readily hands the
    just-freed inode number back to the very next ``create``, so an
    unlink+recreate race is invisible by device/inode. ``st_ctime_ns`` closes
    that gap — a recreated inode carries a fresh change time, while merely
    opening an untouched file for read/write never advances it, so this adds no
    false positives. Coarse-granularity filesystems can still alias a
    same-tick recreate, which is why this remains one layer under the mode
    checks and the ``flock`` itself rather than the only defense.
    """
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


#: Attempts for :func:`_open_validated_lock` when only the change time moved.
_LOCK_OPEN_ATTEMPTS = 3


def _open_validated_lock(path: Path, *, label: str) -> int:
    """Open a lock without following/blocking on special files or inode swaps.

    macOS can advance ``st_ctime`` of an untouched file on its own (e.g. when
    it attaches the ``com.apple.provenance`` extended attribute the first time
    a new process opens it), which looks like a swap. Each retry repeats every
    check from scratch, so a real swap still fails after the last attempt.
    """
    for attempt in range(_LOCK_OPEN_ATTEMPTS):
        try:
            return _open_validated_lock_once(path, label=label)
        except KeyvaultPermissionError as exc:
            if exc.errno != errno.EAGAIN or attempt == _LOCK_OPEN_ATTEMPTS - 1:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


def _open_validated_lock_once(path: Path, *, label: str) -> int:
    before = path.lstat()
    _validate_lock_stat(before, path, label=label, from_lstat=True)
    try:
        fd = os.open(path, os.O_RDWR | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise KeyvaultPermissionError(
                errno.ELOOP,
                f"refusing to follow symbolic link to {label}",
                str(path),
            ) from None
        raise
    try:
        opened = os.fstat(fd)
        _validate_lock_stat(opened, path, label=label, from_lstat=False)
        after = path.lstat()
        _validate_lock_stat(after, path, label=label, from_lstat=True)
        opened_identity = _lock_inode_identity(opened)
        if _lock_inode_identity(before) != opened_identity or _lock_inode_identity(after) != opened_identity:
            raise KeyvaultPermissionError(
                errno.EAGAIN,
                f"{label} changed while it was being opened",
                str(path),
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def _advisory_file_lock(path: Path, *, label: str) -> Iterator[None]:
    """Acquire one OS lock per path/thread and make nested use reentrant."""
    key = _lock_path_key(path)
    depths = _thread_lock_depths()
    depth = depths.get(key, 0)
    if depth:
        depths[key] = depth + 1
        try:
            yield
        finally:
            depths[key] -= 1
        return

    fd = _open_validated_lock(path, label=label)
    owner_pid = os.getpid()
    _ACTIVE_LOCK_FDS.add(fd)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        depths[key] = 1
        try:
            yield
        finally:
            depths.pop(key, None)
            # A forked child shares the parent's open-file description. It
            # must never explicitly unlock that description on the parent's
            # behalf; the at-fork callback already closed the child's copy.
            if fcntl is not None and os.getpid() == owner_pid:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        if os.getpid() == owner_pid:
            _ACTIVE_LOCK_FDS.discard(fd)
            os.close(fd)


@contextlib.contextmanager
def keyvault_lifecycle_lock(root: Path) -> Iterator[None]:
    """Serialize operations that may create, use, or remove ``root``.

    The lock lives at ``<root.parent>/.keyvault.lifecycle.lock`` rather than
    inside ``root``.  A stable, outside-the-tree inode is required for
    destructive operations: locking ``root/.lock`` and then deleting ``root``
    would let a concurrent creator lock a newly-created inode and proceed at
    the same time.

    ``keyvault_lock`` acquires this lifecycle lock before its traditional
    per-root lock.  ``keyvault reset`` acquires it directly because reset must
    be able to reject or remove a malformed root without trusting any inode
    inside that root.
    """
    _refresh_process_lock_state()
    thread_lock = _LIFECYCLE_THREAD_LOCK
    with thread_lock:
        lock_path = root.parent / ".keyvault.lifecycle.lock"
        ensure_lock_file(lock_path)
        with _advisory_file_lock(lock_path, label="keyvault lifecycle lock"):
            yield


@contextlib.contextmanager
def keyvault_lock(root: Path) -> Iterator[None]:
    """Acquire stable lifecycle and exclusive ``<root>/.lock`` locks.

    Holds the lock for the duration of the context. The lock file must
    already exist (call :func:`ensure_layout` first). On macOS and Linux
    the flock serializes contention across both threads and processes
    even though each opens its own file descriptor — POSIX-ish advisory
    lock semantics.

    The lock file is held to the same posture as every other keyvault
    file: it must be a regular file at mode ``0o600`` (verified via
    ``fstat`` on the open fd, mirroring :func:`safe_read`), or
    :exc:`KeyvaultPermissionError` is raised before any flock attempt.

    Nested acquisition by the same thread is reentrant. Off POSIX (no
    :mod:`fcntl`) the posture checks still run but only the process-local
    lifecycle mutex serializes callers.
    """
    with keyvault_lifecycle_lock(root):
        assert_keyvault_active(root)
        with _advisory_file_lock(root / ".lock", label="keyvault lock"):
            yield


def _write_meta_atomic(path: Path, meta: dict[str, Any]) -> None:
    """Internal: serialize ``meta`` as canonical JSON and atomic-write to ``path``."""
    data = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
    atomic_write(path, data)


def load_meta(root: Path) -> dict[str, Any]:
    """Read ``root/meta.json`` and validate the schema.

    Returns ``{"version": 1, "keys": {}}`` when the file does not exist
    (allows :func:`ensure_layout` callers to recover after a manual
    ``meta.json`` deletion). Raises :exc:`KeyvaultCorruptError` on:

    - JSON parse failure.
    - Root is not a JSON object.
    - Missing ``"version"`` field.
    - ``"version"`` is not ``1``.

    The exception's ``str()`` never includes the corrupted file contents
    (audit safety per SPEC.md §"File-safety semantics").
    """
    meta_path = root / "meta.json"
    if not meta_path.exists():
        return {"version": _META_VERSION, "keys": {}}
    raw = safe_read(meta_path)
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # `from None` suppresses __cause__ + __context__ so the original
        # decoder error (which may echo the offending document bytes/slice in
        # its repr) does not leak through the cause chain.
        raise KeyvaultCorruptError("meta.json is not valid UTF-8 JSON") from None
    if not isinstance(parsed, dict):
        raise KeyvaultCorruptError("meta.json root must be a JSON object")
    if "version" not in parsed:
        raise KeyvaultCorruptError("meta.json is missing the required 'version' field")
    if parsed["version"] != _META_VERSION:
        raise KeyvaultCorruptError(f"meta.json version must be {_META_VERSION}; got an unsupported version")
    # codex pre-merge P2-4: the downstream read-modify-write code assumes
    # ``parsed["keys"]`` is a dict. An absent / non-object keys field
    # would surface as KeyError / TypeError far from the parse site;
    # reject here so the caller sees a clean KeyvaultCorruptError.
    if "keys" not in parsed:
        raise KeyvaultCorruptError("meta.json is missing the required 'keys' field")
    if not isinstance(parsed["keys"], dict):
        raise KeyvaultCorruptError("meta.json 'keys' field must be a JSON object")
    return parsed


def save_meta(root: Path, meta: dict[str, Any]) -> None:
    """Atomically write ``meta`` to ``root/meta.json``.

    Caller is expected to hold :func:`keyvault_lock` around any
    read-modify-write transaction. ``save_meta`` itself does not take
    the lock so callers can compose multi-step transactions (e.g.
    update meta.json + write digest commit in one critical section).
    """
    _write_meta_atomic(root / "meta.json", meta)
