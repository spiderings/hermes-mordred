"""POSIX security and publication failures of the new, opt-in API."""

from __future__ import annotations

import errno
import importlib
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX backend contract")


@pytest.fixture
def fs():
    assert importlib.util.find_spec("mordred_hermes._private_fs") is not None, "private filesystem API missing"
    return importlib.import_module("mordred_hermes._private_fs")


def test_symlink_and_hardlink_refused(fs, tmp_path: Path) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"original")
        (root / "symbolic").symlink_to(root / "secret")
        os.link(root / "secret", root / "hard")
        for name in ("symbolic", "hard", "secret"):
            with pytest.raises(fs.PrivateFSError) as err:
                d.read_bytes(name, max_bytes=100)
            assert err.value.reason == "unsafe"
        assert (root / "secret").read_bytes() == b"original"


@pytest.mark.parametrize("kind", ["directory", "file", "ancestor", "fifo"])
def test_unsafe_objects_never_repaired(fs, tmp_path: Path, kind: str) -> None:
    parent = tmp_path.resolve()
    root = parent / "private"
    root.mkdir(mode=0o700)
    if kind == "directory":
        root.chmod(0o755)
    elif kind == "ancestor":
        parent.chmod(0o777)
    else:
        if kind == "fifo":
            os.mkfifo(root / "secret", 0o600)
        else:
            (root / "secret").write_bytes(b"keep")
            (root / "secret").chmod(0o644)
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(root) as d:
        d.read_bytes("secret", max_bytes=100)
    assert err.value.reason == "unsafe"
    if kind == "file":
        assert (root / "secret").read_bytes() == b"keep"
        assert stat.S_IMODE((root / "secret").stat().st_mode) == 0o644


def test_posix_import_does_not_load_windows(fs) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import mordred_hermes._private_fs; "
            'assert not any(n.startswith("mordred_hermes._private_fs._windows") for n in sys.modules)',
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_unsupported_os_never_falls_back(fs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs, "_platform", "unknown")
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(tmp_path):
        pass
    assert err.value.reason == "unsupported"


@pytest.mark.parametrize("stage", ["write", "file_flush", "directory_flush"])
def test_publication_failure_preserves_correct_version(
    fs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
        real_fsync = os.fsync

        def fail_flush(fd):
            is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
            if (stage == "directory_flush") == is_dir:
                raise OSError(errno.EIO, "injected flush failure")
            real_fsync(fd)

        if stage == "write":
            monkeypatch.setattr(os, "write", lambda fd, data: 0)
        else:
            monkeypatch.setattr(os, "fsync", fail_flush)
        with pytest.raises(fs.PrivateFSError) as err:
            tx.replace_bytes("secret", b"new")
        assert err.value.commit_state == ("uncertain" if stage == "directory_flush" else "not_committed")
        assert (root / "secret").read_bytes() == (b"new" if stage == "directory_flush" else b"old")


def test_short_writes_do_not_truncate(fs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_write = os.write
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        monkeypatch.setattr(os, "write", lambda fd, data: real_write(fd, data[:2]))
        tx.create_bytes("secret", b"complete payload")
        assert d.read_bytes("secret", max_bytes=100) == b"complete payload"


@pytest.mark.skipif(sys.platform != "darwin", reason="actual macOS extended ACLs")
@pytest.mark.parametrize(
    "ace",
    [
        "everyone allow read,execute,file_inherit,directory_inherit",
        "everyone allow delete_child,add_file,add_subdirectory",
        "everyone allow read,execute,file_inherit,directory_inherit,only_inherit",
    ],
)
def test_macos_ancestor_acl_refused_before_private_creation(fs, tmp_path: Path, ace: str) -> None:
    parent = tmp_path.resolve()
    subprocess.run(["/bin/chmod", "+a", ace, str(parent)], check=True)
    before = subprocess.check_output(["/bin/ls", "-lde", str(parent)])
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(parent / "private", create=True):
        pytest.fail("unsafe ancestor reached the operation body")
    assert err.value.reason == "unsafe"
    assert not (parent / "private").exists()
    assert subprocess.check_output(["/bin/ls", "-lde", str(parent)]) == before


@pytest.mark.skipif(sys.platform != "darwin", reason="actual macOS extended ACLs")
@pytest.mark.parametrize("target", ["directory", "file", "lock"])
def test_macos_private_acl_refused_without_repair(fs, tmp_path: Path, target: str) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"keep")
    path = root if target == "directory" else root / ("secret" if target == "file" else ".mordred-fs.lock")
    subprocess.run(["/bin/chmod", "+a", "everyone allow read,execute", str(path)], check=True)
    before = subprocess.check_output(["/bin/ls", "-lde", str(path)])
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(root) as d:
        if target == "file":
            d.read_bytes("secret", max_bytes=100)
        else:
            with d.transaction():
                pytest.fail("unsafe ACL entered the transaction")
    assert err.value.reason == "unsafe"
    assert (root / "secret").read_bytes() == b"keep"
    assert subprocess.check_output(["/bin/ls", "-lde", str(path)]) == before


@pytest.mark.skipif(sys.platform != "darwin", reason="actual macOS extended ACLs")
def test_macos_deny_only_acl_does_not_break_normal_profiles(fs, tmp_path: Path) -> None:
    parent = tmp_path.resolve()
    subprocess.run(["/bin/chmod", "+a", "everyone deny delete", str(parent)], check=True)
    try:
        with fs.open_private_directory(parent / "private", create=True) as d, d.transaction() as tx:
            tx.create_bytes("secret", b"private")
            assert tx.read_bytes("secret", max_bytes=100) == b"private"
    finally:
        subprocess.run(["/bin/chmod", "-N", str(parent)], check=True)


def test_postpublication_refusal_message_matches_uncertain_state(fs, tmp_path: Path, monkeypatch) -> None:
    from mordred_hermes._private_fs import _posix

    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        real_private = _posix._private

        def fail_after_publish(fd, directory=False):
            if not directory and (root / "secret").exists():
                raise fs.PrivateFSError("unsafe", "validate_object")
            return real_private(fd, directory)

        with monkeypatch.context() as scoped:
            scoped.setattr(_posix, "_private", fail_after_publish)
            with pytest.raises(fs.PrivateFSError) as err:
                tx.create_bytes("secret", b"complete")
        assert err.value.commit_state == "uncertain"
        assert "uncertain" in str(err.value)
        assert "not_committed" not in str(err.value)
        assert (root / "secret").read_bytes() == b"complete"


@pytest.mark.skipif(sys.platform != "darwin", reason="actual macOS extended ACLs")
@pytest.mark.parametrize("failure", ["query", "valid", "entry", "tag", "unknown_tag", "free"])
def test_macos_acl_query_failure_refuses_and_frees_copy(fs, tmp_path: Path, monkeypatch, failure: str) -> None:
    import ctypes as c

    from mordred_hermes._private_fs import _macos_acl

    parent = tmp_path.resolve()
    subprocess.run(["/bin/chmod", "+a", "everyone deny delete", str(parent)], check=True)
    library = _macos_acl._libc()
    allocated = []
    freed = []

    class FailingLibrary:
        def acl_get_fd_np(self, fd, acl_type):
            if failure == "query":
                c.set_errno(errno.EIO)
                return None
            acl = library.acl_get_fd_np(fd, acl_type)
            if acl:
                allocated.append(acl)
            return acl

        def acl_free(self, acl):
            freed.append(acl)
            result = library.acl_free(acl)
            if failure == "free":
                c.set_errno(errno.EIO)
                return -1
            return result

        def __getattr__(self, name):
            if name == {"valid": "acl_valid", "entry": "acl_get_entry", "tag": "acl_get_tag_type"}.get(failure):

                def fail(*args):
                    c.set_errno(errno.EIO)
                    return -1

                return fail
            if name == "acl_get_tag_type" and failure == "unknown_tag":

                def unknown(entry, output):
                    c.cast(output, c.POINTER(c.c_int))[0] = 99
                    return 0

                return unknown
            return getattr(library, name)

    monkeypatch.setattr(_macos_acl, "_libc", FailingLibrary)
    try:
        with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(parent / "private", create=True):
            pytest.fail("failed ACL validation reached the operation body")
        assert err.value.reason == ("unsafe" if failure == "unknown_tag" else "io")
        if failure != "unknown_tag":
            assert err.value.native_code == errno.EIO
        assert not (parent / "private").exists()
        assert freed == allocated
        assert bool(allocated) == (failure != "query")
    finally:
        subprocess.run(["/bin/chmod", "-N", str(parent)], check=True)


@pytest.mark.skipif(sys.platform != "darwin", reason="actual macOS extended ACLs")
def test_macos_acl_changed_during_transaction_refuses_before_writing(fs, tmp_path: Path) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        subprocess.run(
            ["/bin/chmod", "+a", "everyone allow read,execute,file_inherit,directory_inherit", str(root)],
            check=True,
        )
        before = sorted(path.name for path in root.iterdir())
        with pytest.raises(fs.PrivateFSError) as err:
            tx.create_bytes("secret", b"must not be written")
        assert err.value.reason == "unsafe"
        assert sorted(path.name for path in root.iterdir()) == before


def test_directory_identity_live_stable_then_closed(fs, tmp_path):
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as directory:
        identity = directory.directory_identity()
        assert identity.volume == root.stat().st_dev
        assert directory.directory_identity() == identity
    with pytest.raises(RuntimeError):
        directory.directory_identity()


@pytest.mark.parametrize("change", ["thread", "process", "mode", "rename", "ancestor", "symlink"])
def test_directory_identity_revalidates_descriptor_and_path(fs, tmp_path, monkeypatch, change):
    from concurrent.futures import ThreadPoolExecutor

    parent = tmp_path.resolve() / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "private"
    with fs.open_private_directory(root, create=True) as directory:
        assert directory.directory_identity()
        if change == "thread":
            with ThreadPoolExecutor(max_workers=1) as executor, pytest.raises(RuntimeError):
                executor.submit(directory.directory_identity).result()
            return
        if change == "process":
            monkeypatch.setattr(os, "getpid", lambda: -1)
        elif change == "mode":
            root.chmod(0o755)
        elif change == "ancestor":
            parent.chmod(0o777)
        elif change == "rename":
            root.rename(parent / "moved")
            root.mkdir(mode=0o700)
        else:
            root.rename(parent / "moved")
            root.symlink_to(parent / "moved", target_is_directory=True)
        with pytest.raises(RuntimeError if change == "process" else fs.PrivateFSError):
            directory.directory_identity()


@pytest.mark.parametrize("change", ["mode", "rename"])
def test_transaction_identity_rechecks_posix_directory(fs, tmp_path, change):
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as directory, directory.transaction() as transaction:
        assert transaction.directory_identity() == directory.directory_identity()
        if change == "mode":
            root.chmod(0o755)
        else:
            root.rename(root.with_name("moved"))
            root.mkdir(mode=0o700)
        with pytest.raises(fs.PrivateFSError):
            transaction.directory_identity()
