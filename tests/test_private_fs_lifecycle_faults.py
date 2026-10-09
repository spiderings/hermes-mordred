"""Fault seams preserve real lifecycle state and native validation policy."""

from __future__ import annotations

import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes import _private_fs as fs
from mordred_hermes._private_fs import _windows_io as win
from mordred_hermes._private_fs._windows_api import Metadata, OwnedHandle
from mordred_hermes._private_fs._windows_paths import CheckedDirectory
from mordred_hermes._private_fs._windows_security import ADMINISTRATORS, SYSTEM, Ace, Descriptor


class FakeAPI:
    def __init__(self):
        self.contents = {"source": bytearray(b"old")}
        self.handles = {}
        self.next_handle = 2
        self.fail = ""
        self.attempted = False
        self.position = 0
        self.native_failure = fs.PrivateFSError("io", "injected", native_code=1117)

    def open(self, path, *, access=0x120089, share=3, create=False):
        name = path.rsplit("\\", 1)[-1]
        if name not in self.contents:
            raise fs.PrivateFSError("missing", "open")
        if access & 0x10000 or access & 0x40000000:
            assert share == 0, "mutating handle must exclude concurrent opens"
        self.next_handle += 1
        self.handles[self.next_handle] = name
        self.position = 0
        return OwnedHandle(self, self.next_handle)

    def metadata(self, handle):
        if handle.value == 1:
            return Metadata(fs.FileIdentity(1, b"directory"), True, False, 1, 0)
        name = self.handles[handle.value]
        return Metadata(fs.FileIdentity(1, b"file"), False, False, 1, len(self.contents[name]))

    def mtime_ns(self, handle):
        return 123000

    def descriptor(self, handle):
        return Descriptor(b"user", True, [Ace(0, 0, 0x1F01FF, s) for s in (b"user", SYSTEM, ADMINISTRATORS)])

    def user_sid(self):
        return b"user"

    def final_path(self, handle):
        return "C:\\private\\" + self.handles[handle.value]

    def CloseHandle(self, value):
        if value in self.handles:
            del self.handles[value]
        if self.fail == "close" and self.attempted:
            raise self.native_failure
        return True

    def checked(self, result, operation):
        assert result

    def discard(self, handle):
        self.attempted = True
        if self.fail == "delete":
            raise self.native_failure
        del self.contents[self.handles[handle.value]]

    def rename(self, handle, destination, *, replace):
        assert replace is False
        target = destination.rsplit("\\", 1)[-1]
        if target in self.contents:
            raise fs.PrivateFSError("exists", "rename")
        self.attempted = True
        if self.fail == "rename_before":
            raise self.native_failure
        old = self.handles[handle.value]
        self.contents[target] = self.contents.pop(old)
        self.handles[handle.value] = target
        if self.fail == "rename_after":
            raise self.native_failure

    def seek(self, handle, offset):
        self.position = offset

    def truncate(self, handle, length):
        if self.fail == "rollback":
            raise fs.PrivateFSError("io", "truncate")
        del self.contents[self.handles[handle.value]][length:]

    def read(self, handle, count):
        data = bytes(self.contents[self.handles[handle.value]][self.position : self.position + count])
        self.position += len(data)
        return data

    def write(self, handle, data):
        if self.attempted and self.fail in ("write", "rollback"):
            raise self.native_failure
        self.attempted = True
        self.contents[self.handles[handle.value]].extend(data[:2])
        return min(2, len(data))

    def flush(self, handle):
        if self.fail == "flush":
            raise self.native_failure

    def names(self, handle):
        yield from self.contents


@pytest.fixture
def windows_fs():
    api = FakeAPI()
    directory = win._Directory(CheckedDirectory(OwnedHandle(api, 1), fs.FileIdentity(1, b"directory"), "C:\\private"))
    return api, directory, win._Transaction(directory)


def test_windows_checked_read_metadata_and_list(windows_fs):
    _api, _directory, tx = windows_fs
    assert tx.stat("source").size == 3
    assert tx.stat("source").mtime_ns == 123000
    assert tx.read_prefix("source", max_bytes=2) == b"ol"
    assert tx.list_names(max_entries=1) == ("source",)


@pytest.mark.parametrize("operation", ["delete", "rename", "append"])
@pytest.mark.parametrize("failure", ["success", "close"])
def test_windows_lifecycle_checked_native_roundtrip(windows_fs, operation, failure):
    api, _directory, tx = windows_fs
    api.fail = failure

    def act():
        if operation == "delete":
            tx.delete_file("source")
        elif operation == "rename":
            tx.rename_file("source", "target")
        else:
            tx.append_bytes("source", b"new")

    if failure == "close":
        with pytest.raises(fs.PrivateFSError) as err:
            act()
        assert err.value is api.native_failure
        assert err.value.commit_state == "uncertain"
    else:
        act()
    assert tx.published and _directory.published
    assert api.contents == (
        {} if operation == "delete" else {"target": b"old"} if operation == "rename" else {"source": b"oldnew"}
    )


@pytest.mark.parametrize(
    "failure,state,content",
    [
        ("write", "not_committed", b"old"),
        ("rollback", "uncertain", b"oldne"),
        ("flush", "uncertain", b"old"),
    ],
)
def test_windows_append_rollback(windows_fs, failure, state, content):
    api, _directory, tx = windows_fs
    api.fail = failure
    with pytest.raises(fs.PrivateFSError) as err:
        tx.append_bytes("source", b"new")
    assert err.value is api.native_failure
    assert err.value.commit_state == state
    assert api.contents["source"] == content


@pytest.mark.parametrize(
    "failure,state,source_exists",
    [
        ("rename_before", "not_committed", True),
        ("rename_after", "uncertain", False),
    ],
)
def test_windows_rename_reconciles_identity(windows_fs, failure, state, source_exists):
    api, _directory, tx = windows_fs
    api.fail = failure
    with pytest.raises(fs.PrivateFSError) as err:
        tx.rename_file("source", "target")
    assert err.value.commit_state == state
    assert ("source" in api.contents) == source_exists


def test_windows_delete_attempt_failure_is_uncertain(windows_fs):
    api, _directory, tx = windows_fs
    api.fail = "delete"
    with pytest.raises(fs.PrivateFSError) as err:
        tx.delete_file("source")
    assert err.value is api.native_failure
    assert err.value.commit_state == "uncertain"
    assert api.contents == {"source": b"old"}


@pytest.mark.skipif(os.name != "posix", reason="POSIX failure injection")
@pytest.mark.parametrize("rollback_fails", [False, True])
def test_posix_partial_append_rollback(tmp_path: Path, monkeypatch, rollback_fails):
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"old")
        write = os.write
        attempted = False

        def partial(fd, data):
            nonlocal attempted
            if attempted:
                raise OSError(errno.EIO, "write")
            attempted = True
            return write(fd, data[:2])

        with monkeypatch.context() as scoped:
            scoped.setattr(os, "write", partial)
            if rollback_fails:

                def fail(*args):
                    raise OSError(errno.EIO, "truncate")

                scoped.setattr(os, "ftruncate", fail)
            with pytest.raises(fs.PrivateFSError) as err:
                tx.append_bytes("source", b"new")
        assert err.value.commit_state == ("uncertain" if rollback_fails else "not_committed")
        assert (root / "source").read_bytes() == (b"oldne" if rollback_fails else b"old")


@pytest.mark.skipif(os.name != "posix", reason="POSIX failure injection")
@pytest.mark.parametrize("body_error", [False, True])
def test_posix_unlock_failure_is_reported_after_mutation(tmp_path: Path, monkeypatch, body_error):
    import fcntl

    real = fcntl.flock
    original = fs.PrivateFSError("io", "body")

    def fail(fd, operation):
        real(fd, operation)
        if operation == fcntl.LOCK_UN:
            raise OSError(errno.EIO, "unlock")

    with (
        pytest.raises(fs.PrivateFSError) as err,
        fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d,
        monkeypatch.context() as scoped,
    ):
        scoped.setattr(fcntl, "flock", fail)
        with d.transaction() as tx:
            tx.create_bytes("source", b"old")
            if body_error:
                raise original
    assert err.value.commit_state == "uncertain"
    if body_error:
        assert err.value is original
        assert original.__notes__


def test_native_metadata_time_seek_truncate_and_disposition_abi():
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import NativeAPI

    api = object.__new__(NativeAPI)
    observed = []

    def get_info(handle, kind, output, size):
        assert kind == 0 and size == 40
        c.cast(output, c.POINTER(c.c_int64))[2] = 116444736000000000 + 123
        return True

    def set_info(handle, kind, output, size):
        observed.append((kind, size, c.string_at(output, size)))
        return True

    api.GetInfo = get_info
    api.SetInfo = set_info
    api.Seek = lambda handle, offset, result, method: observed.append((offset, method)) or True
    api.EndOfFile = lambda handle: observed.append("truncate") or True
    handle = SimpleNamespace(value=7)
    assert api.mtime_ns(handle) == 12300
    api.seek(handle, 3)
    api.truncate(handle, 2)
    api.discard(handle)
    assert observed == [(3, 0), (2, 0), "truncate", (4, 1, b"\x01")]


@pytest.mark.parametrize("malformed", [False, True])
def test_native_enumeration_bounded_buffer_and_offsets(malformed):
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import NativeAPI

    api = object.__new__(NativeAPI)
    batches = 0

    def get_info(handle, kind, output, size):
        nonlocal batches
        assert size == 65536
        if batches:
            assert kind == 14
            return False
        assert kind == 15
        batches += 1
        raw = bytearray(72)
        raw[60:64] = (90000 if malformed else 2).to_bytes(4, "little")
        raw[68:70] = b"a\x00"
        c.memmove(output, bytes(raw), len(raw))
        return True

    api.GetInfo = get_info
    api.last_error = lambda: 18
    if malformed:
        with pytest.raises(fs.PrivateFSError) as err:
            tuple(api.names(SimpleNamespace(value=7)))
        assert err.value.reason == "unsafe"
    else:
        assert tuple(api.names(SimpleNamespace(value=7))) == ("a",)


@pytest.mark.parametrize("operation", ["prefix", "list", "stat", "append", "delete", "rename"])
def test_bad_arguments_precede_native_metadata(windows_fs, operation, monkeypatch):
    api, _directory, tx = windows_fs

    def forbidden(*args):
        pytest.fail("native metadata touched before argument validation")

    monkeypatch.setattr(api, "metadata", forbidden)
    with pytest.raises(ValueError if operation in ("prefix", "list") else fs.PrivateFSError):
        if operation == "prefix":
            tx.read_prefix("source", max_bytes=0)
        elif operation == "list":
            tx.list_names(max_entries=0)
        elif operation == "stat":
            tx.stat("../invalid")
        elif operation == "append":
            tx.append_bytes("../invalid", b"data")
        elif operation == "delete":
            tx.delete_file("../invalid")
        else:
            tx.rename_file("source", "../invalid")


@pytest.mark.skipif(os.name != "posix", reason="POSIX failure injection")
def test_posix_partial_rename_retains_duplicate(tmp_path: Path, monkeypatch):
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"keep")
        with monkeypatch.context() as scoped:

            def fail(*args, **kwargs):
                raise OSError(errno.EIO, "unlink")

            scoped.setattr(os, "unlink", fail)
            with pytest.raises(fs.PrivateFSError) as err:
                tx.rename_file("source", "target")
        assert err.value.commit_state == "uncertain"
        assert (root / "source").read_bytes() == b"keep"
        assert (root / "target").read_bytes() == b"keep"


def test_windows_staging_entries_consume_enumeration_budget(windows_fs):
    api, _directory, tx = windows_fs
    api.contents = {f".mordred-fs-tmp-{index}": b"" for index in range(3)}
    with pytest.raises(fs.PrivateFSError) as err:
        tx.list_names(max_entries=1)
    assert err.value.operation == "list_limit"


def test_windows_create_postpublication_error_preserves_exception(windows_fs, monkeypatch):
    api, _directory, tx = windows_fs
    open_file = api.open

    def create(path, **kwargs):
        if kwargs.get("create"):
            api.contents[path.rsplit("\\", 1)[-1]] = bytearray()
        return open_file(path, **kwargs)

    monkeypatch.setattr(api, "open", create)
    count = 0

    def flush(handle):
        nonlocal count
        count += 1
        if count == 2:
            raise api.native_failure

    monkeypatch.setattr(api, "flush", flush)
    with pytest.raises(fs.PrivateFSError) as err:
        tx.create_bytes("target", b"new")
    assert err.value is api.native_failure
    assert err.value.commit_state == "uncertain"
    assert api.contents["target"] == b"new"


@pytest.mark.parametrize("operation", ["delete", "rename", "append"])
@pytest.mark.parametrize("cleanup", ["unlock", "directory"])
@pytest.mark.parametrize("body_error", [False, True])
def test_windows_lifecycle_cleanup_retains_uncertainty(windows_fs, monkeypatch, operation, cleanup, body_error):
    import contextlib

    api, directory, _tx = windows_fs
    original = fs.PrivateFSError("io", "body")

    @contextlib.contextmanager
    def lock(*args, **kwargs):
        try:
            yield
        finally:
            if cleanup == "unlock":
                import sys

                from mordred_hermes._private_fs._types import cleanup_failure

                cleanup_failure(sys.exception(), api.native_failure, committed=False)

    @contextlib.contextmanager
    def checked(*args, **kwargs):
        try:
            yield directory.checked
        finally:
            if cleanup == "directory":
                import sys

                from mordred_hermes._private_fs._types import cleanup_failure

                cleanup_failure(sys.exception(), api.native_failure, committed=False)

    monkeypatch.setattr(win, "exclusive_lock", lock)
    monkeypatch.setattr(win, "checked_directory", checked)
    with pytest.raises(fs.PrivateFSError) as err, win.open_private_directory("unused") as d, d.transaction() as tx:
        if operation == "delete":
            tx.delete_file("source")
        elif operation == "rename":
            tx.rename_file("source", "target")
        else:
            tx.append_bytes("source", b"new")
        if body_error:
            raise original
    assert err.value is (original if body_error else api.native_failure)
    assert err.value.commit_state == "uncertain"
    if body_error:
        assert original.__notes__


@pytest.mark.skipif(os.name != "posix", reason="POSIX failure injection")
@pytest.mark.parametrize("cleanup", ["unlock", "lock_close", "directory_close"])
@pytest.mark.parametrize("mutate", [False, True])
def test_posix_raw_body_error_retains_cleanup_uncertainty(tmp_path: Path, monkeypatch, cleanup, mutate):
    import fcntl
    import stat

    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"keep")
    original = OSError(errno.EIO, "body failure")
    close, flock = os.close, fcntl.flock
    armed = False
    injected = False

    def fail_close(fd):
        nonlocal injected
        selected = (
            armed
            and not injected
            and (
                (cleanup == "directory_close" and fd == directory_fd)
                or (cleanup == "lock_close" and stat.S_ISREG(os.fstat(fd).st_mode))
            )
        )
        close(fd)
        if selected:
            injected = True
            raise OSError(errno.EIO, "close failure")

    def fail_unlock(fd, operation):
        nonlocal injected
        flock(fd, operation)
        if armed and cleanup == "unlock" and operation == fcntl.LOCK_UN:
            injected = True
            raise OSError(errno.EIO, "unlock failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "close", fail_close)
        scoped.setattr(fcntl, "flock", fail_unlock)
        with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(root) as d:
            directory_fd = d.fd
            with d.transaction() as tx:
                if mutate:
                    tx.delete_file("source")
                if cleanup != "directory_close":
                    armed = True
                    raise original
            armed = True
            raise original
    assert injected
    assert err.value.commit_state == ("uncertain" if mutate else "not_committed")
    assert err.value.__cause__ is original
    assert getattr(original, "__notes__", None) or getattr(err.value, "__notes__", None)
    assert (root / "source").exists() is not mutate
