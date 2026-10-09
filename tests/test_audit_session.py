"""Opt-in shared sessions tested against real checked filesystem transactions."""

from __future__ import annotations

import gzip
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from mordred_hermes import _audit_io as audit
from mordred_hermes import _private_fs as fs


@pytest.fixture(name="audit_path")
def audit_path(tmp_path, monkeypatch):
    # POSIX has no optional-directory API; existing-directory tests still use
    # real checked opens/locks/reads. Native absence is tested separately.
    if os.name != "nt":
        monkeypatch.setattr(fs, "open_optional_private_directory", fs.open_private_directory)
    path = tmp_path / "private" / "custom.jsonl"
    with fs.open_private_directory(path.parent, create=True):
        pass
    return path


def test_session_create_append_snapshot_and_lifetime(audit_path):
    with audit.audit_session(audit_path) as session:
        original = session.create(session.active_name, b"{}\n")
        session.append(session.active_name, b'{"x":1}\n', expected_identity=original.identity)
        snapshot = session.snapshot(session.active_name, max_bytes=11)
        assert snapshot.data == b'{}\n{"x":1}\n'
        assert snapshot.metadata.identity == original.identity
        assert session.stat("absent") is None
        assert session.list_names() == ("custom.jsonl",)
    assert snapshot.data.endswith(b"\n")
    with pytest.raises(RuntimeError):
        session.stat("custom.jsonl")
    assert audit.read_audit_snapshot(audit_path, max_bytes=11) == snapshot


@pytest.mark.parametrize(
    "payload,kind,line",
    [
        (b"", "empty", None),
        (b"{}\n", "ndjson", b"{}"),
        (b'{"fmt":"MRAL","version":99}\n', "mral", b'{"fmt":"MRAL","version":99}'),
        (b"{}", "unknown", None),
        (b"\n", "unknown", b""),
        (b'{"x":1,"x":2}\n', "unknown", b'{"x":1,"x":2}'),
        (b'{"fmt":"MRAL",broken}\n', "unknown", b'{"fmt":"MRAL",broken}'),
        (b"[]\n", "unknown", b"[]"),
        (b"\xff\n", "unknown", b"\xff"),
        (b'{"nested":{"x":1,"x":2}}\n', "unknown", b'{"nested":{"x":1,"x":2}}'),
        (b'{"x":NaN}\n', "unknown", b'{"x":NaN}'),
    ],
    ids=[
        "empty",
        "ndjson",
        "future-mral",
        "incomplete",
        "blank",
        "duplicate",
        "malformed",
        "array",
        "utf8",
        "nested-duplicate",
        "nan",
    ],
)
def test_probe_fail_closed(audit_path, payload, kind, line):
    with audit.audit_session(audit_path) as session:
        assert session.probe("absent").kind == "missing"
        session.create(session.active_name, payload)
        probe = session.probe(session.active_name)
        assert (probe.kind, probe.first_line) == (kind, line)


def test_probe_cap_and_snapshot_aggregate(audit_path):
    with audit.audit_session(audit_path) as session:
        session.create("one", b"{}\n")
        session.create("two", b"{}\n")
        assert session.probe("one", max_line_bytes=2).kind == "ndjson"
        assert session.probe("one", max_line_bytes=1).first_line is None
        with pytest.raises(fs.PrivateFSError):
            session.snapshot_many(["one", "two"], max_file_bytes=3, max_total_bytes=5)
        assert len(session.snapshot_many(["one", "absent", "two"], max_file_bytes=3, max_total_bytes=6)) == 2
        with pytest.raises(ValueError):
            session.snapshot_many(["one", "one"], max_file_bytes=3, max_total_bytes=6)
        with pytest.raises(fs.PrivateFSError):
            session.snapshot("one", max_bytes=2)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_limits_validate_before_io(audit_path, limit):
    with audit.audit_session(audit_path) as session:
        for call in [
            lambda: session.probe("absent", max_line_bytes=limit),
            lambda: session.snapshot("absent", max_bytes=limit),
            lambda: session.list_names(max_entries=limit),
            lambda: session.snapshot_many([], max_file_bytes=limit, max_total_bytes=3),
        ]:
            with pytest.raises(ValueError):
                call()
    with pytest.raises(ValueError):
        audit.decode_audit_bytes(b"", max_output_bytes=limit)


def test_nesting_borrowing_identity_and_thread(audit_path, tmp_path):
    with fs.open_private_directory(audit_path.parent) as directory, directory.transaction() as tx:
        with audit.audit_session(audit_path, transaction=tx) as first:
            with audit.audit_session(audit_path.with_name("second")) as nested:
                assert first.directory_identity() == nested.directory_identity()
                nested.create("second", b"one")
            with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(RuntimeError):
                pool.submit(first.list_names).result()
            with fs.open_private_directory(tmp_path / "other", create=True):
                pass
            with pytest.raises(fs.PrivateFSError), audit.audit_session(tmp_path / "other" / "log"):
                pass
        assert tx.read_bytes("second", max_bytes=3) == b"one"
    with pytest.raises(RuntimeError), audit.audit_session(audit_path, transaction=tx):
        pass


def test_wrong_identity_and_reserved_leaf_refuse(audit_path):
    with audit.audit_session(audit_path) as session:
        session.create("one", b"keep")
        wrong = fs.FileIdentity(0, b"foreign")
        for call in [
            lambda: session.append("one", b"lost", expected_identity=wrong),
            lambda: session.rename("one", "two", expected_identity=wrong),
            lambda: session.delete("one", expected_identity=wrong),
            lambda: session.stat(".mordred-fs.lock"),
            lambda: session.stat("../one"),
        ]:
            with pytest.raises(fs.PrivateFSError):
                call()
        assert session.snapshot("one", max_bytes=4).data == b"keep"


def test_decode_bounded_concatenated_and_invalid_gzip():
    member = gzip.compress(b"a" * 100, mtime=0)
    assert audit.decode_audit_bytes(member + member, max_output_bytes=200) == b"a" * 200
    assert audit.decode_audit_bytes(b"plain", max_output_bytes=5) == b"plain"
    for payload, cap in [(member, 99), (member[:-1], 100), (member + b"garbage", 100), (b"plain", 4)]:
        with pytest.raises((fs.PrivateFSError, OSError, EOFError)):
            audit.decode_audit_bytes(payload, max_output_bytes=cap)


def test_identity_bound_mutations_cannot_opt_out(audit_path):
    with audit.audit_session(audit_path) as session:
        session.create("one", b"keep")
        with pytest.raises(ValueError):
            session.rename("one", "two", expected_identity=None)
        with pytest.raises(ValueError):
            session.delete("one", expected_identity=None)
        assert session.snapshot("one", max_bytes=4).data == b"keep"


def test_snapshot_many_rejects_windows_case_alias_duplicates(audit_path):
    with audit.audit_session(audit_path) as session, pytest.raises(ValueError):
        session.snapshot_many(["one", "ONE"], max_file_bytes=1, max_total_bytes=2)
