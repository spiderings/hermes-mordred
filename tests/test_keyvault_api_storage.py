"""Tests for ``mordred_hermes.keyvault._storage`` — file-safety helpers.

Phase 4 PR4 step-B RED (2026-05-15) — implementation lands in step-B GREEN.

Codex pre-implementation review HIGH #4 demanded explicit file-safety
semantics for keyvault state:

- ``os.open(path, O_NOFOLLOW)`` to refuse symlink-following.
- File mode ``0600`` and directory mode ``0700`` enforced via ``fstat``
  after open (mode mismatch → ``KeyvaultPermissionError``).
- Atomic writes via ``<file>.tmp + durable-fsync(tmp_fd) + os.replace(tmp,
  final) + durable-fsync(parent_dir_fd)``, where "durable-fsync" issues
  ``fcntl(fd, F_FULLFSYNC)`` on macOS (falling back to plain ``os.fsync``
  elsewhere, and when ``F_FULLFSYNC`` itself is unsupported).
- Exclusive ``fcntl.flock`` on ``<root>/.lock`` for the duration of any
  write transaction.
- ``meta.json`` corruption raises :exc:`KeyvaultCorruptError` whose
  ``str()`` does NOT include the corrupted contents (audit safety —
  partially-overwritten JSON could contain secret-shaped bytes).

These tests pin the contract. See SPEC.md §"PR4 API contract / File-
safety semantics" for the canonical wording.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import select
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage

# ---------------------------- resolve_keyvault_dir ----------------------------


class TestResolveKeyvaultDir:
    def test_explicit_home_returns_keyvault_subdir(self, tmp_path: Path) -> None:
        assert _storage.resolve_keyvault_dir(tmp_path) == tmp_path / "mordred" / "keyvault"

    def test_none_home_uses_hermes_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Monkeypatch the hermes_home resolver so the test does not depend on
        # the user's real ~/.hermes directory.
        monkeypatch.setattr("mordred_hermes.keyvault._storage._hermes_home", lambda: tmp_path)
        assert _storage.resolve_keyvault_dir(None) == tmp_path / "mordred" / "keyvault"

    def test_signature_matches_spec(self) -> None:
        import inspect
        import typing

        sig = inspect.signature(_storage.resolve_keyvault_dir)
        hints = typing.get_type_hints(_storage.resolve_keyvault_dir)
        assert list(sig.parameters) == ["home"]
        assert hints["home"] == (Path | None)
        assert hints["return"] is Path
        assert sig.parameters["home"].default is None


# ---------------------------- ensure_layout ----------------------------


class TestEnsureLayout:
    def test_creates_root_with_0700_mode(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        assert root.is_dir()
        assert stat.S_IMODE(root.stat().st_mode) == 0o700

    def test_creates_digests_subdir_with_0700(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        assert (root / "digests").is_dir()
        assert stat.S_IMODE((root / "digests").stat().st_mode) == 0o700

    def test_creates_ciphertexts_subdir_with_0700(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        assert (root / "ciphertexts").is_dir()
        assert stat.S_IMODE((root / "ciphertexts").stat().st_mode) == 0o700

    def test_creates_lock_file_with_0600(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        lock = root / ".lock"
        assert lock.is_file()
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600

    def test_creates_initial_meta_json(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        meta = json.loads((root / "meta.json").read_text())
        assert meta == {"version": 1, "keys": {}}
        assert stat.S_IMODE((root / "meta.json").stat().st_mode) == 0o600

    def test_idempotent_on_existing_layout(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        # Stamp meta.json with a real key so we can verify it is not clobbered.
        (root / "meta.json").write_text('{"version": 1, "keys": {"k1": {}}}')
        _storage.ensure_layout(root)
        meta = json.loads((root / "meta.json").read_text())
        assert meta["keys"] == {"k1": {}}

    def test_existing_root_wrong_mode_raises_permission_error(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o755)  # too permissive
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_existing_meta_wrong_mode_raises_permission_error(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        os.chmod(root / "meta.json", 0o644)  # too permissive
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_lock_creation_race_is_tolerated(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Two processes racing the first ensure_layout: the loser's
        ``exists()`` pre-check sees no ``.lock`` yet, then its O_EXCL open
        hits ``FileExistsError`` because the winner created it in between.
        The loser must treat that as success (the winner's lock is just as
        good), not crash. Simulated by forcing the ``exists()`` pre-check
        to report False while the lock file is actually present."""
        root = tmp_path / "kv"
        _storage.ensure_layout(root)  # .lock now exists on disk
        real_exists = Path.exists

        def fake_exists(self: Path, **kwargs: bool) -> bool:
            if self.name == ".lock":
                return False  # the racing loser's stale pre-check view
            return real_exists(self, **kwargs)

        monkeypatch.setattr(Path, "exists", fake_exists)
        _storage.ensure_layout(root)  # must not raise FileExistsError

    def test_waits_for_lifecycle_lock_before_creating_root(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        finished = threading.Event()
        errors: list[BaseException] = []

        def initialize() -> None:
            try:
                _storage.ensure_layout(root)
            except BaseException as exc:
                errors.append(exc)
            finally:
                finished.set()

        with _storage.keyvault_lifecycle_lock(root):
            thread = threading.Thread(target=initialize)
            thread.start()
            assert not finished.wait(timeout=0.1)
            assert not root.exists()

        assert finished.wait(timeout=5)
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert errors == []
        assert root.is_dir()


# ---------------------------- atomic_write ----------------------------


class TestAtomicWrite:
    def test_writes_data_to_final_path(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        _storage.atomic_write(target, b"hello")
        assert target.read_bytes() == b"hello"

    def test_file_mode_is_0600_after_write(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        _storage.atomic_write(target, b"x")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_overwrites_existing_atomically(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"old")
        os.chmod(target, 0o600)
        _storage.atomic_write(target, b"new")
        assert target.read_bytes() == b"new"

    def test_tmp_file_removed_after_success(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        _storage.atomic_write(target, b"data")
        # No leftover *.tmp files in the directory.
        assert list(tmp_path.glob("*.tmp")) == []

    def test_symlink_target_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real.bin"
        real.write_bytes(b"original")
        os.chmod(real, 0o600)
        link = tmp_path / "link.bin"
        link.symlink_to(real)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.atomic_write(link, b"attacker-controlled")
        # The symlink target must be untouched (O_NOFOLLOW prevented the write).
        assert real.read_bytes() == b"original"

    def test_existing_target_with_wrong_mode_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"x")
        os.chmod(target, 0o644)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.atomic_write(target, b"new")

    def test_tmp_file_cleaned_up_on_write_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate a mid-write failure: force os.write to raise on the first call.
        target = tmp_path / "file.bin"
        original_write = os.write
        call_count = {"n": 0}

        def flaky_write(fd: int, data: bytes) -> int:
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated write failure")
            return original_write(fd, data)

        monkeypatch.setattr("os.write", flaky_write)
        with pytest.raises(OSError):
            _storage.atomic_write(target, b"data")
        # No leftover tmp file from the failed write.
        assert list(tmp_path.glob("*.tmp")) == []
        # The final file does not exist either (we never committed via rename).
        assert not target.exists()


# ---------------------------- _fsync_durable ----------------------------
#
# On macOS, bare os.fsync(2) only reaches the drive's write cache — Apple
# documents fcntl(fd, F_FULLFSYNC) as the call that actually reaches
# stable storage. These tests pin _fsync_durable's dispatch and, crucially,
# its fallback-to-os.fsync behavior for the cases where F_FULLFSYNC cannot
# be used (unsupported filesystem, or a non-Darwin build of CPython that
# does not define the attribute at all).


class TestFsyncDurable:
    def test_uses_f_fullfsync_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fcntl_calls: list[tuple[int, int]] = []
        fsync_calls: list[int] = []
        monkeypatch.setattr(_storage.fcntl, "F_FULLFSYNC", 12345, raising=False)
        monkeypatch.setattr(_storage.fcntl, "fcntl", lambda fd, cmd: fcntl_calls.append((fd, cmd)))
        monkeypatch.setattr(_storage.os, "fsync", lambda fd: fsync_calls.append(fd))

        _storage._fsync_durable(7)

        assert fcntl_calls == [(7, 12345)]
        # os.fsync must NOT be used when F_FULLFSYNC succeeds — that would
        # defeat the whole point (os.fsync on macOS is the weaker guarantee).
        assert fsync_calls == []

    @pytest.mark.parametrize("not_supported_errno", [errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL])
    def test_falls_back_to_os_fsync_when_f_fullfsync_raises(
        self, monkeypatch: pytest.MonkeyPatch, not_supported_errno: int
    ) -> None:
        """Regression test for the MEDIUM crash-consistency finding: some
        filesystems (certain network/virtual filesystems mounted on macOS)
        return ENOTSUP / EOPNOTSUPP / EINVAL for F_FULLFSYNC even on Darwin,
        so the fallback to os.fsync must actually run for each of those
        "filesystem can't do it" errnos rather than letting the OSError
        escape."""
        fsync_calls: list[int] = []
        monkeypatch.setattr(_storage.fcntl, "F_FULLFSYNC", 12345, raising=False)

        def raising_fcntl(fd: int, cmd: int) -> int:
            raise OSError(not_supported_errno, "Operation not supported")

        monkeypatch.setattr(_storage.fcntl, "fcntl", raising_fcntl)
        monkeypatch.setattr(_storage.os, "fsync", lambda fd: fsync_calls.append(fd))

        _storage._fsync_durable(9)  # must not raise

        assert fsync_calls == [9]

    def test_falls_back_to_os_fsync_when_f_fullfsync_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """fcntl.F_FULLFSYNC only exists on Darwin builds of CPython — the
        attribute lookup must be guarded (getattr with a default), not
        assumed to exist."""
        fsync_calls: list[int] = []
        monkeypatch.delattr(_storage.fcntl, "F_FULLFSYNC", raising=False)
        monkeypatch.setattr(_storage.os, "fsync", lambda fd: fsync_calls.append(fd))

        _storage._fsync_durable(3)

        assert fsync_calls == [3]

    def test_real_device_error_propagates_without_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A genuine device error (EIO — disk failing, ENOSPC, EDQUOT) from
        F_FULLFSYNC means the flush actually failed. Swallowing it and
        reporting success via a second os.fsync would let atomic_write claim
        durability it never achieved — a silent data-loss fail-open in the
        one function whose whole contract is crash-consistency. Only the
        "filesystem can't do F_FULLFSYNC" errnos (ENOTSUP/EOPNOTSUPP/EINVAL)
        may degrade to os.fsync; EIO must propagate instead."""
        fsync_calls: list[int] = []
        monkeypatch.setattr(_storage.fcntl, "F_FULLFSYNC", 12345, raising=False)

        def raising_fcntl(fd: int, cmd: int) -> int:
            raise OSError(errno.EIO, "Input/output error")

        monkeypatch.setattr(_storage.fcntl, "fcntl", raising_fcntl)
        monkeypatch.setattr(_storage.os, "fsync", lambda fd: fsync_calls.append(fd))

        with pytest.raises(OSError) as excinfo:
            _storage._fsync_durable(11)

        assert excinfo.value.errno == errno.EIO
        # os.fsync must NEVER run for a real device error — that would
        # silently report a durability guarantee that was never met.
        assert fsync_calls == []


class TestAtomicWriteUsesFsyncDurable:
    def test_atomic_write_calls_fsync_durable_for_tmp_and_parent_fd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """atomic_write must route BOTH fsyncs (tmp file, parent dir)
        through _fsync_durable rather than calling os.fsync directly —
        otherwise the durability fix is dead code."""
        calls: list[int] = []
        monkeypatch.setattr(_storage, "_fsync_durable", lambda fd: calls.append(fd))

        target = tmp_path / "file.bin"
        _storage.atomic_write(target, b"data")

        assert len(calls) == 2

    def test_atomic_write_propagates_real_device_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end: a real F_FULLFSYNC device error (EIO) must escape
        atomic_write rather than being swallowed as a false "write
        succeeded" — the caller (e.g. keyvault meta.json save) needs to see
        the failure, not silently lose data it believes was durably
        committed."""
        monkeypatch.setattr(_storage.fcntl, "F_FULLFSYNC", 12345, raising=False)

        def raising_fcntl(fd: int, cmd: int) -> int:
            raise OSError(errno.EIO, "Input/output error")

        monkeypatch.setattr(_storage.fcntl, "fcntl", raising_fcntl)

        target = tmp_path / "file.bin"
        with pytest.raises(OSError) as excinfo:
            _storage.atomic_write(target, b"data")

        assert excinfo.value.errno == errno.EIO


# ---------------------------- safe_read ----------------------------


class TestSafeRead:
    def test_reads_normal_file(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"content")
        os.chmod(target, 0o600)
        assert _storage.safe_read(target) == b"content"

    def test_symlink_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real.bin"
        real.write_bytes(b"secret")
        os.chmod(real, 0o600)
        link = tmp_path / "link.bin"
        link.symlink_to(real)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.safe_read(link)

    def test_wrong_mode_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"x")
        os.chmod(target, 0o644)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.safe_read(target)

    def test_missing_file_raises_file_not_found_error(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            _storage.safe_read(tmp_path / "missing.bin")


# ---------------------------- keyvault_lock ----------------------------


class TestKeyvaultLock:
    def test_nested_lifecycle_and_keyvault_locks_are_reentrant(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        script = """
import sys
from pathlib import Path
from mordred_hermes.keyvault import _storage

root = Path(sys.argv[1])
with _storage.keyvault_lifecycle_lock(root):
    with _storage.keyvault_lifecycle_lock(root):
        with _storage.keyvault_lock(root):
            with _storage.keyvault_lock(root):
                pass
"""
        result = subprocess.run(
            [sys.executable, "-c", script, os.fspath(root)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr

    def test_holds_stable_parent_lifecycle_lock(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        lifecycle = root.parent / ".keyvault.lifecycle.lock"

        with _storage.keyvault_lock(root):
            fd = os.open(lifecycle, os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

        # Unlike root/.lock, this inode remains available to serialize a
        # later destructive reset with re-creation of the root.
        assert lifecycle.is_file()
        assert stat.S_IMODE(lifecycle.stat().st_mode) == 0o600

    def test_acquires_exclusive_lock(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        with _storage.keyvault_lock(root):
            # While we hold the lock, a non-blocking acquire from a separate
            # file descriptor must fail.
            fd = os.open(root / ".lock", os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    def test_releases_on_context_exit(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        with _storage.keyvault_lock(root):
            pass
        # After release, a non-blocking acquire succeeds.
        fd = os.open(root / ".lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_releases_on_exception(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        with pytest.raises(RuntimeError), _storage.keyvault_lock(root):
            raise RuntimeError("simulated")
        # Lock must still be released after the exception propagated.
        fd = os.open(root / ".lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_serializes_concurrent_writers(self, tmp_path: Path) -> None:
        # Two threads contend on the lock; the second must wait for the first.
        import time

        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        order: list[str] = []

        def writer(name: str, hold_ms: int) -> None:
            with _storage.keyvault_lock(root):
                order.append(f"{name}-enter")
                time.sleep(hold_ms / 1000.0)
                order.append(f"{name}-exit")

        t1 = threading.Thread(target=writer, args=("A", 30))
        t2 = threading.Thread(target=writer, args=("B", 0))
        t1.start()
        # Give A a head start so the order is deterministic.
        time.sleep(0.005)
        t2.start()
        t1.join()
        t2.join()
        assert order == ["A-enter", "A-exit", "B-enter", "B-exit"]

    def test_lock_with_wrong_mode_refused(self, tmp_path: Path) -> None:
        """The lock file is part of the keyvault tree, so acquiring it must
        enforce the same 0o600 posture ``safe_read`` applies — a loosened
        lock file (e.g. chmod 0644 by a backup tool) is refused instead of
        silently flock'd."""
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        os.chmod(root / ".lock", 0o644)  # too permissive
        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_lock(root):
            pass  # pragma: no cover — the lock must refuse before entry

    def test_missing_inner_lock_fails_closed_inside_nested_lifecycle(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / ".lock").unlink()

        with (
            _storage.keyvault_lifecycle_lock(root),
            pytest.raises(FileNotFoundError),
            _storage.keyvault_lock(root),
        ):
            pass  # pragma: no cover — no critical-section entry

    def test_symlinked_inner_lock_is_refused_without_touching_target(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        victim = tmp_path / "victim"
        victim.write_bytes(b"unchanged")
        os.chmod(victim, 0o600)
        (root / ".lock").unlink()
        (root / ".lock").symlink_to(victim)

        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_lock(root):
            pass

        assert victim.read_bytes() == b"unchanged"

    def test_fifo_inner_lock_is_refused_without_blocking(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / ".lock").unlink()
        os.mkfifo(root / ".lock", mode=0o600)

        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_lock(root):
            pass

    def test_replaced_inner_lock_inode_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # A lock inode that keeps being replaced while it is opened is refused.
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        lock_path = root / ".lock"
        real_open = os.open

        def racing_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
            if Path(path) == lock_path and not flags & os.O_CREAT:
                lock_path.unlink()
                replacement_fd = real_open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(replacement_fd)
            return real_open(path, flags, mode)

        monkeypatch.setattr(_storage.os, "open", racing_open)
        with pytest.raises(_storage.KeyvaultPermissionError, match="changed"), _storage.keyvault_lock(root):
            pass

    def test_single_lock_inode_replacement_is_retried(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # One replacement (or macOS bumping the change time once) is re-checked
        # from scratch; the lock then holds the inode the path names now.
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        lock_path = root / ".lock"
        real_open = os.open
        swapped = False

        def racing_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
            nonlocal swapped
            if Path(path) == lock_path and not swapped:
                swapped = True
                lock_path.unlink()
                replacement_fd = real_open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(replacement_fd)
            return real_open(path, flags, mode)

        monkeypatch.setattr(_storage.os, "open", racing_open)
        with _storage.keyvault_lock(root):
            assert swapped

    def test_forked_child_drops_inherited_lock_state_and_waits_for_parent(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        ready_r, ready_w = os.pipe()
        acquired_r, acquired_w = os.pipe()
        child_pid = -1
        try:
            with _storage.keyvault_lifecycle_lock(root):
                child_pid = os.fork()
                if child_pid == 0:  # pragma: no cover — assertions happen in parent
                    os.close(ready_r)
                    os.close(acquired_r)
                    os.write(ready_w, b"r")
                    with _storage.keyvault_lifecycle_lock(root):
                        os.write(acquired_w, b"a")
                    os._exit(0)

                os.close(ready_w)
                os.close(acquired_w)
                assert select.select([ready_r], [], [], 2)[0]
                assert os.read(ready_r, 1) == b"r"
                assert not select.select([acquired_r], [], [], 0.1)[0]

            assert select.select([acquired_r], [], [], 5)[0]
            assert os.read(acquired_r, 1) == b"a"
            waited_pid, status = os.waitpid(child_pid, 0)
            child_pid = -1
            assert waited_pid > 0
            assert os.waitstatus_to_exitcode(status) == 0
        finally:
            for fd in (ready_r, acquired_r):
                with contextlib.suppress(OSError):
                    os.close(fd)
            if child_pid > 0:
                os.kill(child_pid, signal.SIGKILL)
                os.waitpid(child_pid, 0)


class TestLifecycleLockPathSafety:
    def test_symlinked_lifecycle_lock_is_refused_without_touching_target(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        lifecycle = root.parent / ".keyvault.lifecycle.lock"
        victim = tmp_path / "victim"
        victim.write_bytes(b"unchanged")
        os.chmod(victim, 0o600)
        lifecycle.unlink()
        lifecycle.symlink_to(victim)

        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_lifecycle_lock(root):
            pass

        assert victim.read_bytes() == b"unchanged"

    def test_fifo_lifecycle_lock_is_refused_without_blocking(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        lifecycle = root.parent / ".keyvault.lifecycle.lock"
        lifecycle.unlink()
        os.mkfifo(lifecycle, mode=0o600)

        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_lifecycle_lock(root):
            pass


class TestKeyvaultReadLock:
    def test_absent_profile_does_not_create_parent_or_lock(self, tmp_path: Path) -> None:
        root = tmp_path / "missing-parent" / "kv"

        with _storage.keyvault_read_lock(root):
            pass

        assert not root.parent.exists()

    def test_existing_profile_waits_for_lifecycle_owner(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        entered = threading.Event()
        finished = threading.Event()

        def reader() -> None:
            with _storage.keyvault_read_lock(root):
                entered.set()
            finished.set()

        with _storage.keyvault_lifecycle_lock(root):
            thread = threading.Thread(target=reader)
            thread.start()
            assert not entered.wait(timeout=0.1)
            assert not finished.is_set()

        thread.join(timeout=5)
        assert not thread.is_alive()
        assert entered.is_set()
        assert finished.is_set()

    def test_symlinked_root_is_refused_before_snapshot(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        root = tmp_path / "kv"
        root.symlink_to(target, target_is_directory=True)

        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_read_lock(root):
            pass

    def test_fifo_root_is_refused_without_blocking(self, tmp_path: Path) -> None:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation is unavailable")
        root = tmp_path / "kv"
        os.mkfifo(root, mode=0o600)

        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_read_lock(root):
            pass


class TestResetJournalDurability:
    def test_failed_clear_flush_restores_visible_journal(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        payload = b'{"pending":"reset"}'

        def fail_flush(_root: Path) -> None:
            raise OSError("simulated directory flush failure")

        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, payload)
            monkeypatch.setattr(_storage, "fsync_keyvault_parent", fail_flush)
            with pytest.raises(OSError, match="simulated directory flush failure"):
                _storage.clear_reset_journal(root)

        assert _storage.safe_read(_storage.reset_journal_path(root)) == payload
        with pytest.raises(_storage.KeyvaultResetInProgressError):
            _storage.ensure_layout(root)

    def test_failed_clear_and_republish_raises_critical_restore_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b'{"pending":"reset"}')

            def fail_flush(_root: Path) -> None:
                raise OSError("simulated directory flush failure")

            def fail_republish(_path: Path, _data: bytes) -> None:
                raise OSError("simulated journal republish failure")

            monkeypatch.setattr(_storage, "fsync_keyvault_parent", fail_flush)
            monkeypatch.setattr(_storage, "atomic_write", fail_republish)
            with pytest.raises(_storage.KeyvaultResetJournalRestoreError, match="could not be restored"):
                _storage.clear_reset_journal(root)


# ---------------------------- load_meta / save_meta ----------------------------


class TestLoadMeta:
    def test_returns_empty_struct_when_missing(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        # ensure_layout writes the initial meta, so this hits the "exists" path.
        # Verify behavior when the file is then removed:
        (root / "meta.json").unlink()
        assert _storage.load_meta(root) == {"version": 1, "keys": {}}

    def test_parses_valid_meta(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": {"k1": {"foo": "bar"}}}')
        os.chmod(root / "meta.json", 0o600)
        meta = _storage.load_meta(root)
        assert meta == {"version": 1, "keys": {"k1": {"foo": "bar"}}}

    def test_invalid_json_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("not json{{")
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_non_utf8_json_raises_corrupt_without_leaking_bytes(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        secret_marker = b"\xffSECRET_NON_UTF8_MARKER"
        (root / "meta.json").write_bytes(secret_marker)

        with pytest.raises(_storage.KeyvaultCorruptError, match="UTF-8 JSON") as raised:
            _storage.load_meta(root)

        assert "SECRET_NON_UTF8_MARKER" not in str(raised.value)
        assert raised.value.__cause__ is None

    def test_missing_version_field_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"keys": {}}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_version_mismatch_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 2, "keys": {}}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_corrupt_error_does_not_include_file_contents(self, tmp_path: Path) -> None:
        # Audit-safety: KeyvaultCorruptError's str() must not include the
        # corrupted JSON bytes, because a partially-overwritten file could
        # contain secret-shaped material that we do not want leaking into
        # exception traces or log scraping.
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        secret_marker = "SECRET_DO_NOT_LEAK_INTO_TRACEBACK"
        (root / "meta.json").write_text(f'{{"corrupt": "{secret_marker}"}}')
        try:
            _storage.load_meta(root)
        except _storage.KeyvaultCorruptError as exc:
            assert secret_marker not in str(exc)
            assert secret_marker not in repr(exc)
        else:
            pytest.fail("expected KeyvaultCorruptError")


class TestSaveMeta:
    def test_writes_canonical_json(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        _storage.save_meta(root, {"version": 1, "keys": {"k1": {"x": 1}}})
        on_disk = json.loads((root / "meta.json").read_text())
        assert on_disk == {"version": 1, "keys": {"k1": {"x": 1}}}

    def test_atomic_via_tmp_rename(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        _storage.save_meta(root, {"version": 1, "keys": {}})
        # No leftover tmp files.
        assert list(root.glob("*.tmp")) == []

    def test_round_trips_through_load(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        meta = {"version": 1, "keys": {"a": {"nested": [1, 2, 3]}, "b": {}}}
        _storage.save_meta(root, meta)
        assert _storage.load_meta(root) == meta

    def test_preserves_0600_mode(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        _storage.save_meta(root, {"version": 1, "keys": {"k": {}}})
        assert stat.S_IMODE((root / "meta.json").stat().st_mode) == 0o600


# ---------------------- codex pre-merge review-fix tests ----------------------


class TestEnsureLayoutRefusesSymlinks:
    """Codex P2-2: ``_check_dir_mode`` used ``path.stat()`` which follows
    symlinks. A symlinked root/digests/ciphertexts directory passed the
    mode check whenever the *target* had mode 0o700, redirecting later
    keyvault reads/writes outside the keyvault tree. The fix uses
    ``lstat`` (or equivalent ``O_NOFOLLOW`` open) so the symlink itself
    is rejected."""

    def test_symlinked_root_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(link)

    def test_symlinked_digests_subdir_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        target = tmp_path / "elsewhere"
        target.mkdir(mode=0o700)
        (root / "digests").symlink_to(target)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_symlinked_ciphertexts_subdir_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        target = tmp_path / "elsewhere"
        target.mkdir(mode=0o700)
        (root / "ciphertexts").symlink_to(target)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)


class TestAtomicWriteShortWrites:
    """Codex P2-3: ``os.write`` is not guaranteed to flush the full buffer;
    short writes truncated the file as if the transaction succeeded."""

    def test_partial_writes_are_resumed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "file.bin"
        payload = bytes(range(256)) * 64  # 16 KiB
        original_write = os.write
        offsets: list[int] = []

        def chunked_write(fd: int, data: bytes) -> int:
            # Return at most 64 bytes per call to force the resume loop.
            offsets.append(len(data))
            return original_write(fd, data[:64])

        monkeypatch.setattr("os.write", chunked_write)
        _storage.atomic_write(target, payload)
        assert target.read_bytes() == payload
        # The implementation looped at least len(payload)/64 times.
        assert len(offsets) >= len(payload) // 64


class TestLoadMetaKeysFieldValidation:
    """Codex P2-4: ``load_meta`` accepted ``{"version": 1}`` (no keys) or
    ``{"version": 1, "keys": [...]}`` (wrong type). Both shapes break the
    read-modify-write pattern downstream. Fix: reject in load_meta."""

    def test_missing_keys_field_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_keys_field_as_list_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": []}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_keys_field_as_string_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": "oops"}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_keys_field_as_null_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": null}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)


# ---------------- second codex pass — P2-C non-regular file refusal ----------------


class TestNonRegularFileRefusal:
    """Codex second-pass P2-C: ``_check_file_mode`` only checked permission
    bits, so a FIFO / device / directory at mode 0o600 would have passed.
    ``ensure_layout`` could then ``bless`` a non-file as meta.json or
    .lock, and ``safe_read`` / ``keyvault_lock`` would block or operate
    on the wrong kind of inode."""

    def test_fifo_at_meta_json_path_refused_by_ensure_layout(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        (root / "digests").mkdir(mode=0o700)
        (root / "ciphertexts").mkdir(mode=0o700)
        # Create the .lock as a regular file so ensure_layout reaches meta.json.
        lock_fd = os.open(root / ".lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(lock_fd)
        # Replace meta.json with a FIFO at the expected mode.
        os.mkfifo(root / "meta.json", mode=0o600)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_fifo_at_lock_path_refused_by_ensure_layout(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        (root / "digests").mkdir(mode=0o700)
        (root / "ciphertexts").mkdir(mode=0o700)
        os.mkfifo(root / ".lock", mode=0o600)
        # Touch a regular meta.json so the lock is the failing path.
        meta_fd = os.open(root / "meta.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(meta_fd)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_safe_read_refuses_fifo(self, tmp_path: Path) -> None:
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo, mode=0o600)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.safe_read(fifo)


class TestCheckFileModeSymlinkRefusal:
    """The lstat-side ELOOP refusal in ``_check_file_mode`` is a guard
    distinct from the shared ``_assert_regular_at_mode`` pair: a symlink
    pointing at a perfectly valid 0o600 regular file must be refused as
    ELOOP, never validated through its target. Pinning the errno keeps the
    symlink branch from being silently folded into (or dropped from) the
    shared assertion (2026-08-02 security-review MEDIUM)."""

    def test_symlink_to_valid_0600_file_refused_with_eloop(self, tmp_path: Path) -> None:
        real = tmp_path / "real.bin"
        real.write_bytes(b"x")
        os.chmod(real, 0o600)
        link = tmp_path / "link.bin"
        link.symlink_to(real)
        with pytest.raises(_storage.KeyvaultPermissionError) as excinfo:
            _storage._check_file_mode(link)
        assert excinfo.value.errno == errno.ELOOP


# ---------------------------- exception types ----------------------------


class TestExceptionTypes:
    def test_keyvault_permission_error_is_oserror(self) -> None:
        # Subclass OSError so callers using `except OSError` for FS error
        # handling catch it naturally.
        assert issubclass(_storage.KeyvaultPermissionError, OSError)

    def test_keyvault_corrupt_error_is_valueerror(self) -> None:
        # Subclass ValueError so callers using `except ValueError` for input
        # validation catch it (mirrors VerificationDigestMismatch from digest.py).
        assert issubclass(_storage.KeyvaultCorruptError, ValueError)

    def test_both_exceptions_are_publicly_accessible(self) -> None:
        from mordred_hermes.keyvault._storage import (
            KeyvaultCorruptError,
            KeyvaultPermissionError,
        )

        assert KeyvaultPermissionError is _storage.KeyvaultPermissionError
        assert KeyvaultCorruptError is _storage.KeyvaultCorruptError
