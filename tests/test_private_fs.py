"""Behavioral contract for private storage; real files, not mocked contents."""

from __future__ import annotations

import importlib
import importlib.util
import os
from pathlib import Path

import pytest


@pytest.fixture
def fs():
    assert importlib.util.find_spec("mordred_hermes._private_fs") is not None, "private filesystem API missing"
    return importlib.import_module("mordred_hermes._private_fs")


@pytest.fixture
def private_path(tmp_path: Path) -> Path:
    return tmp_path.resolve() / "private"


def test_private_create_read_replace(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as directory:
        with directory.transaction() as tx:
            tx.create_bytes("秘密 with spaces", b"old\x00bytes")
            assert tx.read_bytes("秘密 with spaces", max_bytes=9) == b"old\x00bytes"
            tx.replace_bytes("秘密 with spaces", b"new")
        assert directory.read_bytes("秘密 with spaces", max_bytes=3) == b"new"
    if os.name == "posix":
        assert private_path.stat().st_mode & 0o777 == 0o700
        assert (private_path / "秘密 with spaces").stat().st_mode & 0o777 == 0o600


def test_create_preserves_existing(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"original")
        before = (private_path / "secret").stat().st_ino
        with pytest.raises(fs.PrivateFSError) as err:
            tx.create_bytes("secret", b"replacement")
        assert (err.value.reason, err.value.commit_state) == ("exists", "not_committed")
        assert tx.read_bytes("secret", max_bytes=100) == b"original"
        assert (private_path / "secret").stat().st_ino == before


def test_replace_requires_existing(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        with pytest.raises(fs.PrivateFSError) as err:
            tx.replace_bytes("missing", b"new")
        assert err.value.reason == "missing"
        assert not (private_path / "missing").exists()


def test_read_limit_refuses_oversize(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"1234")
        with pytest.raises(fs.PrivateFSError):
            d.read_bytes("secret", max_bytes=3)
        assert d.read_bytes("secret", max_bytes=4) == b"1234"
        for limit in (0, -1):
            with pytest.raises(ValueError):
                d.read_bytes("secret", max_bytes=limit)


def test_context_use_after_close(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d:
        with d.transaction() as tx:
            tx.create_bytes("secret", b"original")
        with pytest.raises(RuntimeError):
            tx.replace_bytes("secret", b"wrong")
    with pytest.raises(RuntimeError):
        d.read_bytes("secret", max_bytes=100)
    with pytest.raises(RuntimeError), d.transaction():
        pass


@pytest.mark.parametrize(
    "name", ["", ".", "..", "../victim", "a/b", "a\\b", "x:y", "a\x00b", ".mordred-fs.lock", ".mordred-fs-tmp-forged"]
)
def test_reserved_leaf_refused(fs, private_path: Path, name: str) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        with pytest.raises(fs.PrivateFSError) as err:
            tx.create_bytes(name, b"data")
        assert err.value.reason == "unsafe"


def test_empty_payload_is_valid(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        tx.create_bytes("empty", b"")
        assert d.read_bytes("empty", max_bytes=1) == b""


def test_missing_directory_does_not_get_created_by_read(fs, private_path: Path) -> None:
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(private_path):
        pass
    assert err.value.reason == "missing"
    assert not private_path.exists()


@pytest.mark.parametrize("stage", ["staging", "lock", "directory", "unlock"])
@pytest.mark.parametrize("body_error", [False, True])
def test_cleanup_failure_after_publication_is_never_retry_safe(
    fs, private_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, body_error: bool
) -> None:
    if stage == "unlock" and os.name != "nt":
        pytest.skip("POSIX unlock failure is recovered by closing the lock fd")
    armed = False
    injected = False
    original = fs.PrivateFSError("io", "body", commit_state="uncertain")

    if os.name == "nt":
        from mordred_hermes._private_fs._windows_api import NativeAPI, OwnedHandle

        close = OwnedHandle.close
        unlock = NativeAPI.unlock

        def failing_close(handle):
            nonlocal injected
            selected = False
            if armed and not injected and handle.value is not None and handle.api.GetType(handle.value) == 1:
                path = handle.api.final_path(handle).casefold()
                selected = (
                    (stage == "staging" and path.endswith("\\secret"))
                    or (stage == "lock" and path.endswith("\\.mordred-fs.lock"))
                    or (stage == "directory" and path.endswith("\\private"))
                )
            close(handle)
            if selected:
                injected = True
                raise fs.PrivateFSError("io", "close", native_code=6)

        def failing_unlock(api, handle):
            nonlocal injected
            unlock(api, handle)
            if armed and stage == "unlock" and not injected:
                injected = True
                raise fs.PrivateFSError("io", "unlock", native_code=6)

        monkeypatch.setattr(OwnedHandle, "close", failing_close)
        monkeypatch.setattr(NativeAPI, "unlock", failing_unlock)
    else:
        import fcntl
        import stat

        close = os.close

        def failing_close(fd):
            nonlocal injected
            selected = False
            if armed and not injected:
                info = os.fstat(fd)
                selected = (
                    (stage == "staging" and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_WRONLY)
                    or (stage == "lock" and stat.S_ISREG(info.st_mode) and info.st_size == 0)
                    or (stage == "directory" and stat.S_ISDIR(info.st_mode))
                )
            close(fd)
            if selected:
                injected = True
                raise OSError(5, "injected close error")

        monkeypatch.setattr(os, "close", failing_close)

    with (
        pytest.raises(fs.PrivateFSError) as err,
        fs.open_private_directory(private_path, create=True) as d,
        d.transaction() as tx,
    ):
        # For a staging close, arm at the file flush boundary; all other
        # cleanup errors occur only after the write returned successfully.
        if stage == "staging":
            armed = True
        tx.create_bytes("secret", b"complete")
        armed = True
        if body_error:
            raise original
    assert injected
    assert err.value.commit_state == "uncertain"
    assert "uncertain" in str(err.value)
    assert "not_committed" not in str(err.value)
    if body_error and stage != "staging":
        assert err.value is original
    assert (private_path / "secret").read_bytes() == b"complete"


def test_directory_identity_is_stable_across_checked_reopens(fs, private_path):
    with fs.open_private_directory(private_path, create=True) as directory:
        first = directory.directory_identity()
        assert isinstance(first, fs.FileIdentity)
        assert directory.directory_identity() == first
    with pytest.raises(RuntimeError):
        directory.directory_identity()
    with fs.open_private_directory(private_path) as reopened:
        assert reopened.directory_identity() == first


def test_transaction_identity_is_borrowable_only_while_active(fs, private_path):
    with fs.open_private_directory(private_path, create=True) as directory:
        identity = directory.directory_identity()
        with directory.transaction() as transaction:
            assert transaction.directory_identity() == identity
            assert transaction.directory_identity() == identity
        with pytest.raises(RuntimeError):
            transaction.directory_identity()


@pytest.mark.parametrize("change", ["thread", "process"])
def test_transaction_identity_rejects_foreign_lifetime(fs, private_path, monkeypatch, change):
    from concurrent.futures import ThreadPoolExecutor

    with fs.open_private_directory(private_path, create=True) as directory, directory.transaction() as transaction:
        assert transaction.directory_identity() == directory.directory_identity()
        if change == "thread":
            with ThreadPoolExecutor(max_workers=1) as executor, pytest.raises(RuntimeError):
                executor.submit(transaction.directory_identity).result()
        else:
            with monkeypatch.context() as patch:
                patch.setattr(os, "getpid", lambda: -1)
                with pytest.raises(RuntimeError):
                    transaction.directory_identity()
