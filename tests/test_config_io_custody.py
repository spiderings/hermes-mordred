"""Protected capability loans cannot bypass policy coordination or lose uncertainty."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._private_fs import PrivateFSError
from tests.test_config_io import fs as fs


@pytest.fixture
def loan_fs(fs, monkeypatch):
    backend, paths = fs
    tx = backend.policy
    monkeypatch.setattr(tx, "assert_private_admission", lambda: backend.event("policy:private"), raising=False)
    monkeypatch.setattr(tx, "list_names", lambda *, max_entries: tuple(sorted(tx.files)), raising=False)
    monkeypatch.setattr(tx, "read_prefix", lambda name, *, max_bytes: tx.files[name][0][:max_bytes], raising=False)

    def append(name, data):
        tx.replace_bytes(name, tx.files[name][0] + data)

    def rename(name, destination, *, expected_identity=None):
        if destination in tx.files:
            raise PrivateFSError("exists", "rename")
        if expected_identity is not None and tx.stat(name).identity != expected_identity:
            raise PrivateFSError("unsafe", "identity")
        tx.files[destination] = tx.files.pop(name)

    monkeypatch.setattr(tx, "append_bytes", append, raising=False)
    monkeypatch.setattr(tx, "rename_file", rename, raising=False)
    return backend, paths


def test_loan_uses_held_transaction_without_releasing_it(loan_fs):
    b, paths = loan_fs
    with cio.canonical_session(paths, scope="home") as session:
        with session.borrow_mordred_transaction() as tx:
            tx.assert_private_admission()
            assert tx.directory_identity() == b.policy.ident
            tx.create_bytes("custody.json", b"one")
            tx.append_bytes("custody.json", b"two")
            assert tx.read_bytes("custody.json", max_bytes=6) == b"onetwo"
            assert tx.read_prefix("custody.json", max_bytes=3) == b"one"
            identity = tx.stat("custody.json").identity
            tx.rename_file("custody.json", "retained.json", expected_identity=identity)
            assert tx.list_names(max_entries=1) == ("retained.json",)
            tx.delete_file("retained.json", expected_identity=identity)
        assert b.policy.locked
        assert session.read_pair().policy is None
        with pytest.raises(RuntimeError):
            tx.list_names(max_entries=1)
    assert [e for e in b.events if e.endswith((":lock", ":unlock"))] == [
        "home:lock",
        "policy:lock",
        "policy:unlock",
        "home:unlock",
    ]


PROTECTED = [
    "policy.json",
    "POLICY.JSON",
    "custom.json",
    ".policy-write.pending",
    ".policy-write.lock",
    ".mordred-fs.lock",
    ".mordred-fs-tmp-test",
    "policy.json.tmp",
    "custom.json.abc.tmp",
    ".policy-write.pending.abc.tmp",
]


@pytest.mark.parametrize("name", PROTECTED)
@pytest.mark.parametrize(
    "operation",
    [
        "stat",
        "read_bytes",
        "read_prefix",
        "create_bytes",
        "replace_bytes",
        "append_bytes",
        "delete_file",
        "rename_source",
        "rename_destination",
    ],
)
def test_loan_refuses_coordinator_names_on_every_operand(loan_fs, name, operation):
    b, paths = loan_fs
    paths = cio.CanonicalPaths(paths.home, policy_name="custom.json")
    with cio.canonical_session(paths, scope="policy") as session, session.borrow_mordred_transaction() as tx:
        before = dict(b.policy.files)
        with pytest.raises((ValueError, PrivateFSError)):
            if operation.startswith("read_"):
                getattr(tx, operation)(name, max_bytes=1)
            elif operation in {"create_bytes", "replace_bytes", "append_bytes"}:
                getattr(tx, operation)(name, b"bad")
            elif operation == "rename_source":
                tx.rename_file(name, "safe")
            elif operation == "rename_destination":
                tx.rename_file("safe", name)
            else:
                getattr(tx, operation)(name)
        assert b.policy.files == before


def test_loan_filters_protected_names_and_pending_marker_refuses(loan_fs):
    b, paths = loan_fs
    b.policy.create_bytes("policy.json", b"{}")
    b.policy.create_bytes(".policy-write.lock", b"")
    b.policy.create_bytes("custody.json", b"safe")
    with cio.canonical_session(paths, scope="policy") as session, session.borrow_mordred_transaction() as tx:
        assert tx.list_names(max_entries=10) == ("custody.json",)
    b.policy.create_bytes(".policy-write.pending", b"pending")
    with (
        cio.canonical_session(paths, scope="policy") as session,
        pytest.raises(cio.PolicyPendingError),
        session.borrow_mordred_transaction(),
    ):
        pass


@pytest.mark.parametrize("scope", ["home", "policy"])
def test_loan_missing_directory_cannot_create_without_authorization(loan_fs, scope):
    b, paths = loan_fs
    b.policy_present = False
    with cio.canonical_session(paths, scope=scope) as session:
        with pytest.raises(PrivateFSError) as caught, session.borrow_mordred_transaction():
            pass
        assert caught.value.reason == "missing"
    assert not b.policy_present


@pytest.mark.parametrize("capability", ["loan", "receipt"])
def test_capability_rejects_foreign_thread_and_expired_lifetime(loan_fs, capability):
    _, paths = loan_fs
    with cio.canonical_session(paths, scope="policy") as session:
        context = session.borrow_mordred_transaction() if capability == "loan" else session.publication_receipt()
        with context as borrowed:
            call = borrowed.directory_identity if capability == "loan" else borrowed.mark_published
            with ThreadPoolExecutor(1) as executor, pytest.raises(RuntimeError):
                executor.submit(call).result()
        with pytest.raises(RuntimeError):
            call()


@pytest.mark.parametrize("capability", ["loan", "receipt"])
def test_caught_uncertainty_is_sticky_until_outer_exit(loan_fs, monkeypatch, capability):
    b, paths = loan_fs
    original = PrivateFSError("io", "publication", commit_state="uncertain")

    def fail(*args):
        raise original

    monkeypatch.setattr(b.policy, "create_bytes", fail)
    with pytest.raises(PrivateFSError) as caught, cio.canonical_session(paths, scope="policy") as session:
        if capability == "loan":
            with pytest.raises(PrivateFSError), session.borrow_mordred_transaction() as tx:
                tx.create_bytes("custody.json", b"pending")
        else:
            with session.publication_receipt() as receipt:
                receipt.mark_uncertain(original)
        b.fault = "home:close"
    assert caught.value is original
    assert original.commit_state == "uncertain"


@pytest.mark.parametrize("capability", ["loan", "receipt"])
def test_reported_publication_promotes_late_outer_cleanup_failure(loan_fs, capability):
    b, paths = loan_fs
    with pytest.raises(PrivateFSError) as caught, cio.canonical_session(paths, scope="policy") as session:
        if capability == "loan":
            with session.borrow_mordred_transaction() as tx:
                tx.create_bytes("custody.json", b"published")
        else:
            with session.publication_receipt() as receipt:
                receipt.mark_published()
        b.fault = "home:close"
    assert caught.value.operation == "home:close"
    assert caught.value.commit_state == "uncertain"


def test_nested_nonblocking_loan_extends_with_nonblocking_lock(loan_fs):
    b, paths = loan_fs
    with (
        cio.canonical_session(paths, scope="home"),
        cio.canonical_session(paths, scope="home", blocking=False) as nested,
        nested.borrow_mordred_transaction(),
    ):
        pass
    assert b.blocking == [True, False]


def test_caught_uncertain_admission_failure_poison_survives_loan(loan_fs, monkeypatch):
    b, paths = loan_fs
    original = PrivateFSError("io", "admission", commit_state="uncertain")
    with (
        pytest.raises(PrivateFSError) as caught,
        cio.canonical_session(paths, scope="policy") as session,
        session.borrow_mordred_transaction() as tx,
    ):

        def fail():
            raise original

        monkeypatch.setattr(b.policy, "assert_private_admission", fail)
        with pytest.raises(PrivateFSError):
            tx.assert_private_admission()
    assert caught.value is original


def test_receipt_escaping_child_cleanup_failure_preserves_original(loan_fs):
    _, paths = loan_fs
    original = PrivateFSError("io", "child_cleanup")
    with (
        pytest.raises(PrivateFSError) as caught,
        cio.canonical_session(paths, scope="home") as session,
        pytest.raises(PrivateFSError),
        session.publication_receipt() as receipt,
    ):
        receipt.mark_published()
        raise original
    assert caught.value is original
    assert original.commit_state == "uncertain"


def test_loan_definite_collision_does_not_poison_owner(loan_fs):
    b, paths = loan_fs
    b.policy.create_bytes("custody.json", b"original")
    with cio.canonical_session(paths, scope="policy") as session, session.borrow_mordred_transaction() as tx:
        with pytest.raises(PrivateFSError) as caught:
            tx.create_bytes("custody.json", b"collision")
        assert caught.value.commit_state == "not_committed"
        assert tx.read_bytes("custody.json", max_bytes=8) == b"original"


@pytest.mark.parametrize("capability", ["loan", "receipt"])
def test_capability_rejects_forked_process_identity(loan_fs, monkeypatch, capability):
    _, paths = loan_fs
    with cio.canonical_session(paths, scope="policy") as session:
        context = session.borrow_mordred_transaction() if capability == "loan" else session.publication_receipt()
        with context as borrowed, monkeypatch.context() as child:
            child.setattr(cio.os, "getpid", lambda: -1)
            with pytest.raises(RuntimeError):
                if capability == "loan":
                    borrowed.directory_identity()
                else:
                    borrowed.mark_published()


def test_receipt_records_child_publication_before_parent_revalidation(loan_fs):
    b, paths = loan_fs
    with (
        pytest.raises(PrivateFSError) as caught,
        cio.canonical_session(paths, scope="policy") as session,
        session.publication_receipt() as receipt,
    ):
        b.home.ident = b.identity()
        receipt.mark_published()
    assert caught.value.operation == "home_identity"
    assert caught.value.commit_state == "uncertain"


def test_receipt_retains_child_uncertainty_before_parent_revalidation(loan_fs):
    b, paths = loan_fs
    original = PrivateFSError("io", "child_cleanup", commit_state="uncertain")
    with (
        pytest.raises(PrivateFSError) as caught,
        cio.canonical_session(paths, scope="policy") as session,
        session.publication_receipt() as receipt,
    ):
        b.home.ident = b.identity()
        receipt.mark_uncertain(original)
    assert caught.value is original


def test_home_identity_returns_checked_binding_without_reacquiring_lock(fs):
    backend, paths = fs
    with cio.canonical_session(paths, scope="home") as session:
        assert session.home_directory_identity() == backend.home.ident
        assert session.home_directory_identity() == backend.home.ident
    assert [event for event in backend.events if event.endswith((":lock", ":unlock"))] == ["home:lock", "home:unlock"]
    with pytest.raises(RuntimeError):
        session.home_directory_identity()


def test_home_identity_returns_none_only_for_checked_absence(fs):
    backend, paths = fs
    backend.home_present = False
    with cio.canonical_session(paths, scope="home") as session:
        assert session.home_directory_identity() is None
    assert not backend.home_present
    assert not [event for event in backend.events if event.endswith(":lock")]
    with pytest.raises(RuntimeError):
        session.home_directory_identity()


@pytest.mark.parametrize("boundary", ["thread", "process", "identity"])
def test_home_identity_rechecks_owner_and_directory_binding(fs, monkeypatch, boundary):
    backend, paths = fs
    with cio.canonical_session(paths, scope="home") as session:
        if boundary == "thread":
            with ThreadPoolExecutor(1) as executor, pytest.raises(RuntimeError):
                executor.submit(session.home_directory_identity).result()
        elif boundary == "process":
            with monkeypatch.context() as child:
                child.setattr(cio.os, "getpid", lambda: -1)
                with pytest.raises(RuntimeError):
                    session.home_directory_identity()
        else:
            original = backend.home.ident
            backend.home.ident = backend.identity()
            try:
                with pytest.raises(PrivateFSError) as caught:
                    session.home_directory_identity()
                assert caught.value.operation == "home_identity"
            finally:
                backend.home.ident = original
