"""Checked filesystem and real MRKW crypto across custody failure boundaries."""

import os
from contextlib import ExitStack, contextmanager
from dataclasses import replace

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
from tests._keyvault_fakes import FakeBackend
from tests.test_windows_custody_profile import SID


def modules():
    from mordred_hermes.keyvault import _memory_storage as storage
    from mordred_hermes.keyvault import _windows_custody as custody

    return custody, storage


@pytest.fixture
def fs(monkeypatch, tmp_path):
    custody, storage = modules()

    @contextmanager
    def optional(path):
        with ExitStack() as stack:
            try:
                directory = stack.enter_context(open_private_directory(path))
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
                directory = None
            yield directory

    monkeypatch.setattr(cio, "open_confidential_directory", open_private_directory)
    monkeypatch.setattr(cio, "open_optional_confidential_directory", optional)
    monkeypatch.setattr(cio, "open_optional_private_directory", optional)
    monkeypatch.setattr(custody, "open_optional_confidential_directory", optional)
    monkeypatch.setattr(storage, "open_optional_confidential_directory", optional)
    monkeypatch.setattr(custody, "current_principal_id", lambda: SID)
    home = tmp_path / "home"
    with open_private_directory(home, create=True):
        pass
    return custody, storage, home, FakeBackend()


def test_unmanaged_resolver_does_not_create_mordred_or_accept_ambient_key(fs, monkeypatch):
    c, _, home, backend = fs
    monkeypatch.setattr(c, "windows_backend", lambda: backend)
    from mordred_hermes.keyvault._memory_key import resolve_memory_key

    assert resolve_memory_key(home=home, platform="win32", environ={"HERMES_MEMORY_KEY": "11" * 32}) is None
    assert not (home / "mordred").exists()
    assert backend.calls == []


def test_create_only_enrollment_roundtrip_and_load_do_not_regenerate(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        key = session.enroll_memory()
        lease = session.lease("memory")
        assert len(key) == 32
        assert session.load_memory_key() == key
    assert len((home / "mordred" / "memory-key.wrapped").read_bytes()) == 127
    assert not (home / "mordred" / "windows-memory.pending.json").exists()
    assert not (home / "mordred" / "memory-vault.marker").exists()
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.load_memory_key() == key
        session.validate_lease(lease)
        with pytest.raises(c.CustodyError):
            session.enroll_memory()
    assert [op for op, _ in backend.calls].count("generate") == 1
    with pytest.raises(RuntimeError):
        session.load_memory_key()


@pytest.mark.parametrize(
    "artifact", ["memory-vault.marker", "memory-vault.optout", "memory-key.wrapped", "windows-memory.pending.json"]
)
def test_retained_state_without_manifest_never_generates(fs, artifact):
    c, _, home, backend = fs
    with open_private_directory(home / "mordred", create=True) as d, d.transaction() as tx:
        tx.create_bytes(artifact, b"broken")
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    assert not backend.calls


def test_native_create_failure_retains_intent_and_recovery_never_generates(fs, monkeypatch):
    c, _, home, backend = fs

    def denied(*args, **kwargs):
        raise c.CustodyError("native unavailable")

    monkeypatch.setattr(backend, "generate_enclave_key", denied)
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    journal = home / "mordred" / "windows-memory.pending.json"
    before = journal.read_bytes()
    with c.windows_custody_session(home, backend=backend) as session:
        with pytest.raises(c.CustodyError):
            session.load_memory_key()
        with pytest.raises(WrapKeyNotFound):
            session.reconcile_pending("memory")
    assert journal.read_bytes() == before
    assert not (home / "mordred" / "memory-key.wrapped").exists()


def test_explicit_recovery_reuses_only_positively_proven_exact_key(fs, monkeypatch):
    c, _, home, backend = fs
    create = backend.generate_enclave_key

    def interrupted(key_id, **kwargs):
        create(key_id, **kwargs)
        raise c.CustodyError("interrupted after native publication")

    monkeypatch.setattr(backend, "generate_enclave_key", interrupted)
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    with c.windows_custody_session(home, backend=backend) as session:
        lease = session.reconcile_pending("memory")
        assert lease.role == "memory"
        assert len(session.load_memory_key()) == 32
    assert [op for op, _ in backend.calls].count("generate") == 1
    assert not (home / "mordred" / "windows-memory.pending.json").exists()


def test_explicit_adoption_authenticates_backup_before_native_action(fs):
    c, _, home, backend = fs
    from mordred_hermes.keyvault.memory_crypto import seal

    name = "MEMORY.md.bak.old"
    with open_private_directory(home / "memories", create=True) as d, d.transaction() as tx:
        tx.create_bytes(name, seal(b"secret", key=b"A" * 32, name=name))
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        with pytest.raises(c.CustodyError):
            session.enroll_memory(adopted_key=b"B" * 32)
        assert not backend.calls
        assert session.enroll_memory(adopted_key=b"A" * 32) == b"A" * 32


def test_missing_native_key_does_not_replace_retained_wrapper(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    wrapped = (home / "mordred" / "memory-key.wrapped").read_bytes()
    backend._keys.clear()
    with c.windows_custody_session(home, backend=backend) as session:
        with pytest.raises(WrapKeyNotFound):
            session.load_memory_key()
        with pytest.raises(c.CustodyError):
            session.enroll_memory()
    assert (home / "mordred" / "memory-key.wrapped").read_bytes() == wrapped
    assert [op for op, _ in backend.calls].count("generate") == 1


def test_role_leases_are_independent_and_reject_forged_generation(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
        audit = session.enroll_role("audit")
        session.validate_lease(memory)
        assert audit.native_key_id != memory.native_key_id
        with pytest.raises(c.CustodyError):
            session.validate_lease(replace(audit, role="memory"))


def test_inventory_failure_is_not_empty_and_never_generates(fs):
    c, _, home, backend = fs
    memories = home / "memories"
    memories.mkdir(mode=0o700)
    (memories / "MEMORY.md").mkdir(mode=0o700)
    with c.windows_custody_session(home, create=True, backend=backend) as session, pytest.raises(PrivateFSError):
        session.enroll_memory()
    assert not backend.calls


def opt_out(home):
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("memory-vault.optout", b"1\n")


def test_memory_delete_preserves_independent_audit_and_requires_stopped_gate(fs, monkeypatch):
    c, _, home, backend = fs
    gates = []
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: gates.append(path))
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
        audit = session.enroll_role("audit")
    opt_out(home)
    with c.windows_custody_session(home, backend=backend) as session:
        session.delete_role(memory)
        session.validate_lease(audit)
        with pytest.raises(c.CustodyError):
            session.lease("memory")
    assert gates == [home]
    assert memory.native_key_id not in backend._keys
    assert audit.native_key_id in backend._keys
    assert not (home / "mordred" / "memory-key.wrapped").exists()


def test_unknown_gateway_refuses_native_deletion_and_journal(fs, monkeypatch):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
    opt_out(home)

    def unknown(home):
        raise RuntimeError("unknown gateway inventory")

    monkeypatch.setattr(c, "require_stopped_windows_gateways", unknown)
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(RuntimeError):
        session.delete_role(memory)
    assert memory.native_key_id in backend._keys
    assert not (home / "mordred" / "windows-memory.pending.json").exists()


def test_ambiguous_native_delete_never_treats_missing_as_success(fs, monkeypatch):
    c, _, home, backend = fs
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: None)
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
    opt_out(home)
    delete = backend.delete_enclave_key

    def ambiguous(key_id):
        delete(key_id)
        raise c.CustodyError("native response lost")

    monkeypatch.setattr(backend, "delete_enclave_key", ambiguous)
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, backend=backend) as session:
        session.delete_role(memory)
    before = (home / "mordred" / "windows-memory.pending.json").read_bytes()
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.reconcile_pending("memory")
    assert (home / "mordred" / "windows-memory.pending.json").read_bytes() == before
    assert (home / "mordred" / "memory-key.wrapped").exists()
    assert [op for op, _ in backend.calls].count("delete") == 1


def test_audit_retained_generation_requires_explicit_erase_authorization(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        old = session.enroll_role("audit")
        new = session.enroll_role("audit", retain_current=True)
        session.validate_lease(old)
        with pytest.raises(c.CustodyError):
            session.delete_role(old)
        session.delete_role(old, erase_authorized=True)
        session.validate_lease(new)
        with pytest.raises(c.CustodyError):
            session.validate_lease(old)
    assert old.native_key_id not in backend._keys
    assert new.native_key_id in backend._keys


@pytest.mark.parametrize(
    "method,name,after",
    [
        ("create_bytes", "windows-custody.json", False),
        ("create_bytes", "windows-memory.pending.json", False),
        ("create_bytes", "windows-memory.pending.json", True),
        ("replace_bytes", "windows-memory.pending.json", False),
        ("replace_bytes", "windows-memory.pending.json", True),
        ("create_bytes", "memory-key.wrapped", False),
        ("create_bytes", "memory-key.wrapped", True),
        ("replace_bytes", "windows-custody.json", False),
        ("replace_bytes", "windows-custody.json", True),
        ("delete_file", "windows-memory.pending.json", False),
        ("delete_file", "windows-memory.pending.json", True),
    ],
)
@pytest.mark.skipif(os.name == "nt", reason="POSIX primitive fault injector; native Windows has its own cases")
def test_every_publication_failure_retains_evidence_and_never_recreates(fs, monkeypatch, method, name, after):
    c, _, home, backend = fs
    from mordred_hermes._private_fs import _posix

    original = getattr(_posix._Transaction, method)
    triggered = False

    def fault(tx, leaf, *args, **kwargs):
        nonlocal triggered
        if leaf == name and not triggered:
            triggered = True
            if after:
                original(tx, leaf, *args, **kwargs)
            raise PrivateFSError("io", "injected_publication", commit_state="uncertain" if after else "not_committed")
        return original(tx, leaf, *args, **kwargs)

    monkeypatch.setattr(_posix._Transaction, method, fault)
    with pytest.raises(PrivateFSError), c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    assert triggered
    generates = [op for op, _ in backend.calls].count("generate")
    monkeypatch.setattr(_posix._Transaction, method, original)
    if generates:
        assert (home / "mordred" / "windows-memory.pending.json").exists() or (
            home / "mordred" / "memory-key.wrapped"
        ).exists()
        with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
            session.enroll_memory()
        assert [op for op, _ in backend.calls].count("generate") == generates


def test_caught_postpublication_verification_uncertainty_poisons_owner(fs, monkeypatch):
    c, _, home, backend = fs
    original = c.WindowsCustodySession._publish

    def corrupt_verify(session, name, data, **kwargs):
        if name == "memory-key.wrapped":
            tx = session._transaction()
            read = tx.read_bytes

            def corrupt(leaf, *, max_bytes):
                data = read(leaf, max_bytes=max_bytes)
                return b"corrupt" if leaf == name else data

            monkeypatch.setattr(tx, "read_bytes", corrupt)
        original(session, name, data, **kwargs)

    monkeypatch.setattr(c.WindowsCustodySession, "_publish", corrupt_verify)
    with (
        pytest.raises(PrivateFSError) as outer,
        c.windows_custody_session(home, create=True, backend=backend) as session,
        pytest.raises(PrivateFSError) as inner,
    ):
        session.enroll_memory()
    assert outer.value is inner.value
    assert outer.value.commit_state == "uncertain"


def test_nested_session_reuses_home_lock_and_rejects_another_home(fs):
    c, _, home, backend = fs
    other = home.parent / "other"
    with open_private_directory(other, create=True):
        pass
    with cio.canonical_session(cio.CanonicalPaths(home), scope="policy", create=True) as canonical:
        with c.windows_custody_session(home, canonical=canonical, backend=backend) as session:
            session.enroll_memory()
        with pytest.raises(c.CustodyError), c.windows_custody_session(other, canonical=canonical, backend=backend):
            pass
        assert canonical.home_directory_identity() is not None


def test_memory_inventory_includes_case_alias_backups_and_bounds_before_native(fs, monkeypatch):
    c, storage, home, backend = fs
    with open_private_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("memory.MD.BAK.1", b"abcdefgh")
    monkeypatch.setattr(storage, "MEMORY_FILE_LIMIT", 7)
    with pytest.raises(PrivateFSError), c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    assert not backend.calls


def test_retained_deleted_journal_finishes_without_second_native_delete(fs, monkeypatch):
    c, _, home, backend = fs
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: None)
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
    opt_out(home)
    original = c.WindowsCustodySession._finish_delete

    def interrupt(*args):
        raise c.CustodyError("crash after durable deleted phase")

    monkeypatch.setattr(c.WindowsCustodySession, "_finish_delete", interrupt)
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, backend=backend) as session:
        session.delete_role(memory)
    monkeypatch.setattr(c.WindowsCustodySession, "_finish_delete", original)
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.reconcile_pending("memory") is None
    assert [op for op, _ in backend.calls].count("delete") == 1
    assert not (home / "mordred" / "memory-key.wrapped").exists()


def test_successful_memory_purge_returns_unmanaged_without_losing_audit(fs, monkeypatch):
    c, _, home, backend = fs
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: None)
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
        audit = session.enroll_role("audit")
    opt_out(home)
    with c.windows_custody_session(home, backend=backend) as session:
        session.delete_role(memory)
        assert session.resolve_memory_key() is None
        session.validate_lease(audit)
        session.enroll_memory()
        assert session.lease("memory").generation != memory.generation
        session.validate_lease(audit)


def test_runtime_dispatch_uses_existing_memory_failure_contract(fs, monkeypatch):
    c, _, home, backend = fs
    from mordred_hermes.keyvault._memory_key import MemoryKeyError, resolve_memory_key

    monkeypatch.setattr(c, "windows_backend", lambda: backend)
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
    backend._keys.clear()
    with pytest.raises(MemoryKeyError):
        resolve_memory_key(home=home, platform="win32", environ={})


def test_concurrent_enrollment_has_one_native_creation_winner(fs):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    c, _, home, backend = fs
    start = threading.Barrier(2)

    def enroll():
        start.wait(timeout=5)
        try:
            with c.windows_custody_session(home, create=True, backend=backend) as session:
                return session.enroll_memory()
        except c.CustodyError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: enroll(), range(2)))
    assert sum(value is not None for value in results) == 1
    assert [op for op, _ in backend.calls].count("generate") == 1


def test_physical_rename_keeps_key_but_copied_home_refuses(fs):

    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        key = session.enroll_memory()
    moved = home.parent / "Renamed home 日本"
    home.rename(moved)
    with c.windows_custody_session(moved, backend=backend) as session:
        assert session.load_memory_key() == key
    copied = home.parent / "copied"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        for name in ("windows-custody.json", "memory-key.wrapped"):
            tx.create_bytes(name, (moved / "mordred" / name).read_bytes())
    with c.windows_custody_session(copied, backend=backend) as session:
        with pytest.raises(c.CustodyError):
            session.load_memory_key()
        with pytest.raises(c.CustodyError):
            session.enroll_memory()
    assert [op for op, _ in backend.calls].count("generate") == 1


def test_session_cannot_cross_threads(fs):
    from concurrent.futures import ThreadPoolExecutor

    c, _, home, backend = fs
    with (
        c.windows_custody_session(home, create=True, backend=backend) as session,
        ThreadPoolExecutor(max_workers=1) as pool,
        pytest.raises(RuntimeError),
    ):
        pool.submit(session.enroll_memory).result()
    assert not backend.calls


def test_missing_helper_refuses_before_creating_irrecoverable_native_intent(fs, monkeypatch):
    c, _, home, _ = fs

    def missing():
        raise c.CustodyError("helper absent")

    monkeypatch.setattr(c, "windows_backend", missing)
    with c.windows_custody_session(home, create=True) as session, pytest.raises(c.CustodyError):
        session.enroll_memory()
    assert not (home / "mordred" / "windows-memory.pending.json").exists()


def test_caught_native_delete_ledger_failure_remains_uncertain_on_outer_exit(fs, monkeypatch):
    c, _, home, backend = fs
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: None)
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
    opt_out(home)
    journal = c.WindowsCustodySession._journal

    def fail_deleted(session, pending, **kwargs):
        if pending.phase == "deleted":
            raise PrivateFSError("io", "deleted_ledger")
        journal(session, pending, **kwargs)

    monkeypatch.setattr(c.WindowsCustodySession, "_journal", fail_deleted)
    with (
        pytest.raises(PrivateFSError) as outer,
        c.windows_custody_session(home, backend=backend) as session,
        pytest.raises(PrivateFSError) as inner,
    ):
        session.delete_role(memory)
    assert outer.value is inner.value
    assert outer.value.commit_state == "uncertain"
    assert memory.native_key_id not in backend._keys
    assert (home / "mordred" / "windows-memory.pending.json").exists()


def test_exhausted_epoch_refuses_before_native_deletion_or_wrapper_cleanup(fs, monkeypatch):
    import json

    c, _, home, backend = fs
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: None)
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
    opt_out(home)
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        manifest = json.loads(tx.read_bytes("windows-custody.json", max_bytes=65536))
        manifest["epoch"] = 9007199254740991
        tx.replace_bytes("windows-custody.json", json.dumps(manifest).encode())
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, backend=backend) as session:
        session.delete_role(memory)
    assert memory.native_key_id in backend._keys
    assert (home / "mordred" / "memory-key.wrapped").exists()
    assert not (home / "mordred" / "windows-memory.pending.json").exists()
