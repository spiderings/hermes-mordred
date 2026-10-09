"""Fault injection at the foundation capability boundary, without raw audit IO."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from pathlib import PureWindowsPath

import pytest

from mordred_hermes import _audit_io as audit
from mordred_hermes import _private_fs as fs
from mordred_hermes._private_fs import _windows_paths as paths
from tests.test_audit_session import audit_path as audit_path_fixture  # noqa: F401
from tests.test_private_fs_confidential import PRIVATE, Native, Node


@pytest.fixture
def native(monkeypatch):
    api = Native()
    api.nodes["C:\\home"].descriptor = PRIVATE
    monkeypatch.setattr(paths, "get_api", lambda: api)
    monkeypatch.setattr(fs, "_platform", "nt")
    return api


def test_checked_absence_does_not_create_and_cleanup_failure_propagates(native):
    path = PureWindowsPath("C:\\home\\absent\\audit.log")
    with audit.audit_session(path) as session:
        assert session.stat("audit.log") is None
        assert session.snapshot("audit.log", max_bytes=3) is None
        assert session.probe("audit.log").kind == "missing"
        assert session.list_names() == ()
        with pytest.raises(fs.PrivateFSError):
            session.create("audit.log", b"bad")
    assert "C:\\home\\absent" not in native.nodes
    assert not native.handles
    native.fail_close = True
    with pytest.raises(fs.PrivateFSError):
        audit.read_audit_snapshot(path, max_bytes=3)


def test_missing_intermediate_and_unsafe_parent_never_become_absence(native):
    with pytest.raises(fs.PrivateFSError), audit.audit_session(PureWindowsPath("C:\\absent\\parent\\audit")):
        pass
    native.nodes["C:\\home"].reparse = True
    with pytest.raises(fs.PrivateFSError), audit.audit_session(PureWindowsPath("C:\\home\\absent\\audit")):
        pass


def test_confidential_transaction_over_private_parent_cannot_be_borrowed(native):
    with fs.open_confidential_directory("C:\\home") as directory, directory.transaction() as tx:
        with (
            pytest.raises(fs.PrivateFSError) as err,
            audit.audit_session(PureWindowsPath("C:\\home\\audit"), transaction=tx),
        ):
            pass
        assert err.value.operation == "private_admission"


def test_foreign_transaction_refuses_and_owner_keeps_lock(native):
    native.nodes["C:\\other"] = Node(True, PRIVATE)
    with fs.open_private_directory("C:\\other") as directory, directory.transaction() as tx:
        with (
            pytest.raises(fs.PrivateFSError) as err,
            audit.audit_session(PureWindowsPath("C:\\home\\audit"), transaction=tx),
        ):
            pass
        assert err.value.operation == "audit_borrow_identity"
        tx.assert_private_admission()
    with pytest.raises(RuntimeError), audit.audit_session(PureWindowsPath("C:\\other\\audit"), transaction=tx):
        pass


def test_borrowed_scope_cleanup_after_mutation_is_uncertain(audit_path, monkeypatch):
    opener = fs.open_optional_private_directory

    @contextmanager
    def fail_close(path):
        with opener(path) as directory:
            yield directory
        raise fs.PrivateFSError("missing", "close")

    with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:
        monkeypatch.setattr(fs, "open_optional_private_directory", fail_close)
        with pytest.raises(fs.PrivateFSError) as err, audit.audit_session(audit_path, transaction=tx) as session:
            session.create(session.active_name, b"one")
        assert err.value.commit_state == "uncertain"
        assert tx.read_bytes("custom.jsonl", max_bytes=3) == b"one"


@pytest.mark.parametrize(
    "operation,state", [("descriptor", "not_committed"), ("close", "not_committed"), ("open", "uncertain")]
)
def test_unrelated_or_uncertain_missing_is_never_absent(audit_path, monkeypatch, operation, state):
    with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:

        def fail(name):
            raise fs.PrivateFSError("missing", operation, native_code=2, commit_state=state)

        monkeypatch.setattr(tx, "stat", fail)
        with audit.audit_session(audit_path, transaction=tx) as session, pytest.raises(fs.PrivateFSError):
            session.stat("audit.log")


@pytest.mark.parametrize("changed", ["identity", "size", "mtime"])
def test_snapshot_rejects_metadata_change_during_read(audit_path, monkeypatch, changed):
    with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:
        tx.create_bytes("one", b"old")
        read = tx.read_bytes
        stat = tx.stat

        def switched(name, **kwargs):
            data = read(name, **kwargs)
            original = stat(name)
            change = (
                {"identity": fs.FileIdentity(0, b"foreign")}
                if changed == "identity"
                else {"size" if changed == "size" else "mtime_ns": 999}
            )
            monkeypatch.setattr(tx, "stat", lambda name: replace(original, **change))
            return data

        monkeypatch.setattr(tx, "read_bytes", switched)
        with audit.audit_session(audit_path, transaction=tx) as session, pytest.raises(fs.PrivateFSError):
            session.snapshot("one", max_bytes=3)


def test_post_append_stat_failure_is_uncertain(audit_path, monkeypatch):
    with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:
        tx.create_bytes("one", b"old")
        identity = tx.stat("one").identity
        append = tx.append_bytes

        def appended(name, data):
            append(name, data)

            def fail(name):
                raise fs.PrivateFSError("io", "metadata")

            monkeypatch.setattr(tx, "stat", fail)

        monkeypatch.setattr(tx, "append_bytes", appended)
        with audit.audit_session(audit_path, transaction=tx) as session:
            with pytest.raises(fs.PrivateFSError) as err:
                session.append("one", b"new", expected_identity=identity)
            assert err.value.commit_state == "uncertain"
        assert tx.read_bytes("one", max_bytes=6) == b"oldnew"


def test_borrowed_owner_cleanup_defines_success(audit_path, monkeypatch):
    @contextmanager
    def owning_scope():
        with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:
            yield tx
        raise fs.PrivateFSError("io", "owner_cleanup", commit_state="uncertain")

    with pytest.raises(fs.PrivateFSError) as err, owning_scope() as tx:
        with audit.audit_session(audit_path, transaction=tx) as session:
            snapshot = session.create("one", b"new")
        assert snapshot.size == 3
    assert err.value.operation == "owner_cleanup"


@pytest.mark.parametrize("name", ["CON", "alias.", "trailing ", "LPT1.log", "bad?"])
def test_absent_view_still_refuses_windows_invalid_leaf(native, name):
    with (
        audit.audit_session(PureWindowsPath("C:\\home\\absent\\audit.log")) as session,
        pytest.raises(fs.PrivateFSError),
    ):
        session.stat(name)


@pytest.mark.parametrize("rollback", [True, False])
def test_append_failure_is_not_retried_and_preserves_primitive_outcome(audit_path, monkeypatch, rollback):
    with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:
        tx.create_bytes("one", b"old")
        identity = tx.stat("one").identity
        append = tx.append_bytes

        def fail(name, data):
            if not rollback:
                append(name, data[:1])
            raise fs.PrivateFSError("io", "append", commit_state="not_committed" if rollback else "uncertain")

        monkeypatch.setattr(tx, "append_bytes", fail)
        with audit.audit_session(audit_path, transaction=tx) as session:
            with pytest.raises(fs.PrivateFSError) as err:
                session.append("one", b"new", expected_identity=identity)
            assert err.value.commit_state == ("not_committed" if rollback else "uncertain")
            assert session.snapshot("one", max_bytes=10).data == (b"old" if rollback else b"oldn")


def test_session_rejects_inherited_process_capability(audit_path, monkeypatch):
    from mordred_hermes import _audit_session as module

    with audit.audit_session(audit_path) as session, monkeypatch.context() as patch:
        patch.setattr(module.os, "getpid", lambda: -1)
        with pytest.raises(RuntimeError):
            session.list_names()


def test_borrowed_foreign_missing_parent_is_not_created(audit_path):
    target = audit_path.parent.parent / "foreign" / "audit"
    with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:
        with pytest.raises(fs.PrivateFSError), audit.audit_session(target, create=True, transaction=tx):
            pass
        assert not target.parent.exists()
