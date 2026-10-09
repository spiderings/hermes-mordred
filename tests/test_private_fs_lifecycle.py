"""Checked lifecycle contract, exercised against real native files."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mordred_hermes import _private_fs as fs


def test_lifecycle_roundtrip(tmp_path: Path) -> None:
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d:
        with d.transaction() as tx:
            tx.create_bytes("source", b"abcdef")
            before = tx.stat("source")
            assert before.size == 6
            assert before.mtime_ns > 0
            assert d.stat("source") == before
            assert tx.read_prefix("source", max_bytes=3) == b"abc"
            assert d.read_prefix("source", max_bytes=20) == b"abcdef"
            with pytest.raises(fs.PrivateFSError):
                tx.read_bytes("source", max_bytes=3)
            tx.append_bytes("source", b"ghi")
            assert tx.read_bytes("source", max_bytes=9) == b"abcdefghi"
            tx.rename_file("source", "destination", expected_identity=before.identity)
            assert tx.stat("destination").identity == before.identity
            assert tx.list_names(max_entries=1) == ("destination",)
            tx.delete_file("destination", expected_identity=before.identity)
            assert tx.list_names(max_entries=1) == ()
        assert d.list_names(max_entries=1) == ()


@pytest.mark.parametrize("operation", ["stat", "prefix", "delete", "rename", "append"])
def test_lifecycle_requires_existing(tmp_path: Path, operation: str) -> None:
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        with pytest.raises(fs.PrivateFSError) as err:
            invoke(tx, operation, "missing")
        assert err.value.reason == "missing"
        assert tx.list_names(max_entries=1) == ()


def invoke(tx, operation, name):
    if operation == "prefix":
        return tx.read_prefix(name, max_bytes=1)
    if operation == "append":
        return tx.append_bytes(name, b"addition")
    if operation == "rename":
        return tx.rename_file(name, "destination")
    if operation == "delete":
        return tx.delete_file(name)
    return tx.stat(name)


@pytest.mark.parametrize("operation", ["delete_file", "rename_file"])
def test_identity_mismatch_preserves_file(tmp_path: Path, operation: str) -> None:
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"keep")
        args = ("source", "destination") if operation == "rename_file" else ("source",)
        with pytest.raises(fs.PrivateFSError) as err:
            getattr(tx, operation)(*args, expected_identity=fs.FileIdentity(0, b"wrong"))
        assert err.value.commit_state == "not_committed"
        assert tx.read_bytes("source", max_bytes=4) == b"keep"


def test_rename_does_not_replace_destination(tmp_path: Path) -> None:
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"source")
        tx.create_bytes("destination", b"target")
        with pytest.raises(fs.PrivateFSError) as err:
            tx.rename_file("source", "destination")
        assert err.value.reason == "exists"
        assert err.value.commit_state == "not_committed"
        assert tx.read_bytes("source", max_bytes=6) == b"source"
        assert tx.read_bytes("destination", max_bytes=6) == b"target"


@pytest.mark.parametrize("operation", ["stat", "prefix", "delete", "rename", "append"])
@pytest.mark.parametrize("name", ["../escape", ".MORDRED-FS.LOCK", ".mordred-fs-tmp-reserved"])
def test_lifecycle_reserved_names(tmp_path: Path, operation: str, name: str) -> None:
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        with pytest.raises(fs.PrivateFSError) as err:
            invoke(tx, operation, name)
        assert err.value.reason == "unsafe"


@pytest.mark.parametrize("limit", [0, -1, 1.5, True])
def test_limits_and_enumeration_overflow(tmp_path: Path, limit) -> None:
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        tx.create_bytes("a", b"a")
        tx.create_bytes("b", b"b")
        with pytest.raises(ValueError):
            tx.read_prefix("a", max_bytes=limit)
        with pytest.raises(ValueError):
            tx.list_names(max_entries=limit)
        with pytest.raises(fs.PrivateFSError) as err:
            tx.list_names(max_entries=1)
        assert err.value.operation == "list_limit"
        assert tx.list_names(max_entries=2) == ("a", "b")


@pytest.mark.parametrize("operation", ["stat", "prefix", "delete", "rename", "append"])
@pytest.mark.parametrize("kind", ["hardlink", "directory", "symlink"])
def test_lifecycle_refuses_nonprivate_objects(tmp_path: Path, operation: str, kind: str) -> None:
    if os.name == "nt" and kind == "symlink":
        pytest.skip("native junction coverage does not require symlink privilege")
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("original", b"keep")
        if kind == "hardlink":
            os.link(root / "original", root / "bad")
        elif kind == "symlink":
            (root / "bad").symlink_to(root / "original")
        else:
            (root / "bad").mkdir()
        with pytest.raises(fs.PrivateFSError) as err:
            invoke(tx, operation, "bad")
        assert err.value.reason == "unsafe"
        assert (root / "original").read_bytes() == b"keep"


@pytest.mark.parametrize("operation", ["stat", "prefix", "delete", "rename", "append", "list"])
def test_lifecycle_expired_transaction(tmp_path: Path, operation: str) -> None:
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d:
        with d.transaction() as tx:
            tx.create_bytes("source", b"keep")
        with pytest.raises(RuntimeError):
            if operation == "list":
                tx.list_names(max_entries=1)
            else:
                invoke(tx, operation, "source")


@pytest.mark.parametrize("operation", ["stat", "prefix", "delete", "rename", "append", "list"])
def test_lifecycle_foreign_thread(tmp_path: Path, operation: str) -> None:
    from concurrent.futures import ThreadPoolExecutor

    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"keep")
        with ThreadPoolExecutor(1) as executor:
            future = (
                executor.submit(tx.list_names, max_entries=1)
                if operation == "list"
                else executor.submit(invoke, tx, operation, "source")
            )
            with pytest.raises(RuntimeError):
                future.result()
        assert tx.read_bytes("source", max_bytes=4) == b"keep"


def test_enumeration_omits_only_reserved_and_does_not_follow(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"keep")
        (root / ".mordred-fs-tmp-abandoned").write_bytes(b"unused")
        (root / "subdirectory").mkdir()
        assert tx.list_names(max_entries=3) == ("secret", "subdirectory")
        with pytest.raises(fs.PrivateFSError):
            tx.stat("subdirectory")


def test_reserved_staging_entries_consume_enumeration_budget(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        for index in range(3):
            (root / f".mordred-fs-tmp-{index}").write_bytes(b"staging")
        with pytest.raises(fs.PrivateFSError) as err:
            tx.list_names(max_entries=1)
        assert err.value.operation == "list_limit"
