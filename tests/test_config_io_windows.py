"""Actual NTFS coordinator locks, inherited descriptors and interrupted writers."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mordred_hermes._config_io import (
    CanonicalPaths,
    PolicyPendingError,
    canonical_session,
    read_canonical_snapshot,
)
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows canonical coordination")


def line(process):
    output = queue.Queue()
    threading.Thread(target=lambda: output.put(process.stdout.readline().strip()), daemon=True).start()
    return output.get(timeout=20)


def test_native_noop_preserves_inherited_descriptor_and_case_nesting(shared_home):
    paths = CanonicalPaths(shared_home)
    parent_before = descriptor(shared_home)
    config_before = descriptor(shared_home / "config.yaml")
    with canonical_session(paths, scope="policy", create=True) as session:
        with canonical_session(CanonicalPaths(Path(str(shared_home).upper())), scope="home") as nested:
            assert nested.read_pair().config.data == b"old"
        with session.policy_update() as update:
            update.put_config(b"old")
            update.commit()
    assert descriptor(shared_home) == parent_before
    assert descriptor(shared_home / "config.yaml") == config_before


def test_native_reader_in_fresh_process_fails_closed_on_busy(shared_home):
    program = """
import sys
from pathlib import Path
from mordred_hermes._config_io import CanonicalPaths, read_canonical_snapshot
from mordred_hermes._private_fs import PrivateFSError
try:
    read_canonical_snapshot(CanonicalPaths(Path(sys.argv[1])))
except PrivateFSError as exc:
    print(exc.reason)
else:
    raise AssertionError("reader entered a locked pair")
"""
    with canonical_session(CanonicalPaths(shared_home), scope="policy", create=True):
        result = subprocess.run(
            [sys.executable, "-c", program, str(shared_home)], check=True, capture_output=True, text=True, timeout=20
        )
        assert result.stdout.strip() == "busy"


def test_native_crash_between_members_leaves_marker_until_explicit_recovery(shared_home):
    program = """
import sys
from pathlib import Path
from mordred_hermes._config_io import CanonicalPaths, canonical_session
from mordred_hermes._private_fs import _windows_io
original = _windows_io._Transaction.create_bytes
def paused(self, name, data):
    if name == "policy.json":
        print("partial", flush=True)
        sys.stdin.readline()
    return original(self, name, data)
_windows_io._Transaction.create_bytes = paused
paths = CanonicalPaths(Path(sys.argv[1]))
with canonical_session(paths, scope="policy", create=True) as session, session.policy_update() as update:
    update.put_config(b"new")
    update.put_policy(b"{}")
    update.commit()
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", program, str(shared_home)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    paths = CanonicalPaths(shared_home)
    try:
        assert line(child) == "partial"
        from mordred_hermes._private_fs import PrivateFSError

        with pytest.raises(PrivateFSError) as err:
            read_canonical_snapshot(paths)
        assert err.value.reason == "busy"
        child.kill()
        child.wait(timeout=20)
        with pytest.raises(PolicyPendingError):
            read_canonical_snapshot(paths)
        with canonical_session(paths, scope="policy") as session, session.policy_update(recover_pending=True) as update:
            assert session.read_pair().config.data == b"new"
            update.put_config(b"new")
            update.put_policy(b"{}")
            update.commit()
        snapshot = read_canonical_snapshot(paths)
        assert snapshot.config.data == b"new" and snapshot.policy.data == b"{}"
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=20)


def test_native_custody_loan_and_audit_share_owned_policy_lock(shared_home):
    from mordred_hermes._audit_session import audit_session

    paths = CanonicalPaths(shared_home)
    log = shared_home / "mordred" / "audit.ndjson"
    with canonical_session(paths, scope="home", create=True) as session:
        with session.borrow_mordred_transaction() as tx:
            tx.create_bytes("custody.json", b"synthetic ownership")
            with pytest.raises(ValueError):
                tx.replace_bytes("POLICY.JSON", b"bypass")
            with audit_session(log, transaction=tx) as audit:
                metadata = audit.create(log.name, b'{"event":"synthetic"}\n')
                audit.append(log.name, b'{"event":"next"}\n', expected_identity=metadata.identity)
            assert tx.list_names(max_entries=2) == ("audit.ndjson", "custody.json")
        with pytest.raises(RuntimeError):
            tx.directory_identity()
    assert not (shared_home / "mordred" / "policy.json").exists()
    with canonical_session(paths, scope="policy") as session, session.borrow_mordred_transaction() as tx:
        assert tx.read_bytes("custody.json", max_bytes=64) == b"synthetic ownership"
        assert tx.read_bytes(log.name, max_bytes=128) == b'{"event":"synthetic"}\n{"event":"next"}\n'


def test_native_child_publication_receipt_reports_caught_uncertainty(shared_home):
    from mordred_hermes._private_fs import PrivateFSError, open_confidential_directory

    paths = CanonicalPaths(shared_home)
    original = PrivateFSError("io", "synthetic_child_cleanup", commit_state="uncertain")
    with (
        pytest.raises(PrivateFSError) as caught,
        canonical_session(paths, scope="policy", create=True) as session,
        session.publication_receipt() as receipt,
    ):
        with (
            open_confidential_directory(shared_home / "memories", create=True) as directory,
            directory.transaction() as tx,
        ):
            tx.create_bytes("MEMORY.md", b"synthetic ciphertext")
            receipt.mark_published()
        receipt.mark_uncertain(original)
    assert caught.value is original
    with open_confidential_directory(shared_home / "memories") as directory:
        assert directory.read_bytes("MEMORY.md", max_bytes=64) == b"synthetic ciphertext"


def test_native_canonical_home_identity_is_shared_by_checked_case_alias(shared_home):
    with canonical_session(CanonicalPaths(shared_home), scope="home") as outer:
        original = outer.home_directory_identity()
        assert original is not None
        with canonical_session(CanonicalPaths(Path(str(shared_home).upper())), scope="home") as alias:
            assert alias.home_directory_identity() == original
        assert outer.home_directory_identity() == original
    with pytest.raises(RuntimeError):
        alias.home_directory_identity()
