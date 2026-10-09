"""Checked rotation never treats a partially mutated stream as retryable."""

from __future__ import annotations

import gzip
import os
from datetime import date

import pytest

from mordred_hermes import _audit_io as audit
from mordred_hermes import _log_rotation as rotation
from mordred_hermes import _private_fs as fs
from tests.test_audit_session import audit_path as audit_path_fixture  # noqa: F401


def test_rotation_collisions_and_verified_compression(audit_path):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"{}\n")
        session.create("custom.jsonl.2026-10-08", b"old raw")
        session.create("custom.jsonl.2026-10-08.1.gz", b"old gzip")
        result = rotation.rotate_audit(session, "2026-10-08")
        assert (result.raw_name, result.gzip_name, result.compression) == (
            None,
            "custom.jsonl.2026-10-08.2.gz",
            "compressed",
        )
        assert session.stat(session.active_name) is None
        assert session.stat("custom.jsonl.2026-10-08.2") is None
        assert gzip.decompress(session.snapshot(result.gzip_name, max_bytes=100).data) == b"{}\n"
        assert session.snapshot("custom.jsonl.2026-10-08", max_bytes=100).data == b"old raw"


@pytest.mark.parametrize(
    "compress,cap,want", [(False, 100, "not_needed"), (True, 2, "raw_oversize"), (True, 100, "raw_error")]
)
def test_raw_preserved_on_disabled_oversize_or_gzip_limit(audit_path, compress, cap, want):
    with audit.audit_session(audit_path) as session:
        original = session.create(session.active_name, b"{}\n")
        result = rotation.rotate_audit(session, "2026-10-08", compress=compress, max_raw_bytes=cap, max_gzip_bytes=1)
        assert result.compression == want
        assert result.gzip_name is None
        assert session.stat(result.raw_name).identity == original.identity
        protected = frozenset(name for name in (result.raw_name, result.gzip_name) if name is not None)
        assert rotation.sweep_audit_retention(session, cutoff_mtime_ns=2**63, protected_names=protected) == ()


def test_exact_name_parser_and_retention_by_mtime(audit_path):
    names = [
        "custom.jsonl.2024-02-29",
        "custom.jsonl.2024-02-29.gz",
        "custom.jsonl.2024-02-29.2",
        "custom.jsonl.2024-02-29.10.gz",
        "custom.jsonl.2023-02-29",
        "custom.jsonl.backup",
        "custom.jsonl.lock",
        ".custom.jsonl.lock",
        "custom.jsonl.2024-02-29.-1",
        "other.2024-02-29",
    ]
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"active")
        for name in names:
            session.create(name, b"old")
        expected = (
            (names[0], date(2024, 2, 29), 0, False),
            (names[1], date(2024, 2, 29), 0, True),
            (names[2], date(2024, 2, 29), 2, False),
            (names[3], date(2024, 2, 29), 10, True),
        )
        assert rotation.audit_rotation_names(session) == expected
        assert rotation.sweep_audit_retention(session, cutoff_mtime_ns=0) == ()
        assert rotation.sweep_audit_retention(session, cutoff_mtime_ns=2**63) == tuple(names[:4])
        assert session.snapshot(session.active_name, max_bytes=6).data == b"active"
        assert all(session.stat(name) is not None for name in names[4:])


@pytest.mark.parametrize(
    "reason,state,degrade",
    [
        ("io", "not_committed", True),
        ("access_denied", "not_committed", True),
        ("busy", "not_committed", True),
        ("unsafe", "not_committed", False),
        ("unsupported", "not_committed", False),
        ("missing", "not_committed", False),
        ("exists", "not_committed", False),
        ("io", "uncertain", False),
    ],
)
def test_gzip_publication_errors_are_precisely_classified(audit_path, monkeypatch, reason, state, degrade):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"{}\n")
        failure = fs.PrivateFSError(reason, "publish", native_code=123, commit_state=state)

        def fail(name, data):
            raise failure

        monkeypatch.setattr(session, "create", fail)
        if degrade:
            result = rotation.rotate_audit(session, "2026-10-08")
            assert result.compression == "raw_error"
            assert result.warning and "123" not in result.warning
        else:
            with pytest.raises(fs.PrivateFSError) as err:
                rotation.rotate_audit(session, "2026-10-08")
            assert err.value is failure
            assert err.value.commit_state == "uncertain"
            assert err.value.native_code == 123
        assert session.snapshot("custom.jsonl.2026-10-08", max_bytes=3).data == b"{}\n"


def test_gzip_delete_failure_keeps_both_and_promotes_uncertainty(audit_path, monkeypatch):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"{}\n")

        def fail(*args, **kwargs):
            raise fs.PrivateFSError("access_denied", "delete")

        monkeypatch.setattr(session, "delete", fail)
        with pytest.raises(fs.PrivateFSError) as err:
            rotation.rotate_audit(session, "2026-10-08")
        assert err.value.commit_state == "uncertain"
        assert session.stat("custom.jsonl.2026-10-08") is not None
        assert session.stat("custom.jsonl.2026-10-08.gz") is not None


def test_local_compression_failure_requires_raw_identity_survival(audit_path, monkeypatch):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"{}\n")

        def fail(*args, **kwargs):
            raise OSError("sensitive content must not enter warning")

        monkeypatch.setattr(rotation.gzip, "compress", fail)
        result = rotation.rotate_audit(session, "2026-10-08")
        assert result.compression == "raw_error"
        assert "sensitive" not in result.warning


def test_retention_partial_failure_is_uncertain(audit_path, monkeypatch):
    with audit.audit_session(audit_path) as session:
        for suffix in ("2026-01-01", "2026-01-02"):
            session.create(f"custom.jsonl.{suffix}", b"keep")
        real = session.delete

        def delete(name, **kwargs):
            if name.endswith("02"):
                raise fs.PrivateFSError("unsafe", "identity")
            real(name, **kwargs)

        monkeypatch.setattr(session, "delete", delete)
        with pytest.raises(fs.PrivateFSError) as err:
            rotation.sweep_audit_retention(session, cutoff_mtime_ns=2**63)
        assert err.value.commit_state == "uncertain"
        assert any("custom.jsonl.2026-01-01" in note for note in err.value.__notes__)
        assert session.stat("custom.jsonl.2026-01-02") is not None


def test_no_replace_race_retries_only_confirmed_unchanged_source(audit_path, monkeypatch):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"{}\n")
        original = session.rename

        def race(name, target, **kwargs):
            if target == "custom.jsonl.2026-10-08":
                session.create(target, b"other")
                raise fs.PrivateFSError("exists", "rename")
            return original(name, target, **kwargs)

        monkeypatch.setattr(session, "rename", race)
        result = rotation.rotate_audit(session, "2026-10-08", compress=False)
        assert result.raw_name == "custom.jsonl.2026-10-08.1"
        assert session.snapshot("custom.jsonl.2026-10-08", max_bytes=5).data == b"other"


def test_collision_bound_and_invalid_date_leave_active_unchanged(audit_path):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"{}\n")
        for suffix in ("", ".1"):
            session.create(f"custom.jsonl.2026-10-08{suffix}", b"occupied")
        for kwargs in [{"date_suffix": "2026-02-29"}, {"date_suffix": "2026-10-08", "max_entries": 1}]:
            with pytest.raises((ValueError, fs.PrivateFSError)):
                rotation.rotate_audit(session, **kwargs)
        assert session.snapshot(session.active_name, max_bytes=3).data == b"{}\n"


def test_normal_threshold_incompressible_gzip_roundtrip(audit_path):
    payload = os.urandom(10 * 1024 * 1024)
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, payload)
        result = rotation.rotate_audit(session, "2026-10-08")
        compressed = session.snapshot(result.gzip_name, max_bytes=16 * 1024 * 1024)
    assert audit.decode_audit_bytes(compressed.data, max_output_bytes=len(payload)) == payload


@pytest.mark.parametrize("fault", ["source_lost", "gzip_corrupt", "rename_uncertain"])
def test_uncertain_rotation_never_deletes_evidence_or_retries(audit_path, monkeypatch, fault):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"{}\n")
        if fault == "source_lost":

            def compress(*args, **kwargs):
                raw = session.stat("custom.jsonl.2026-10-08")
                session.delete("custom.jsonl.2026-10-08", expected_identity=raw.identity)
                raise OSError("compress failed")

            monkeypatch.setattr(rotation.gzip, "compress", compress)
        elif fault == "gzip_corrupt":
            real = session.snapshot

            def corrupt(name, **kwargs):
                from dataclasses import replace

                result = real(name, **kwargs)
                return replace(result, data=b"corrupt") if name.endswith(".gz") else result

            monkeypatch.setattr(session, "snapshot", corrupt)
        else:
            real = session.rename

            def uncertain(name, target, **kwargs):
                real(name, target, **kwargs)
                raise fs.PrivateFSError("io", "rename", commit_state="uncertain")

            monkeypatch.setattr(session, "rename", uncertain)
        with pytest.raises(fs.PrivateFSError) as err:
            rotation.rotate_audit(session, "2026-10-08")
        assert err.value.commit_state == "uncertain"
        assert session.stat(session.active_name) is None
        assert session.stat("custom.jsonl.2026-10-08.1") is None
        if fault != "source_lost":
            assert session.stat("custom.jsonl.2026-10-08") is not None
        if fault == "gzip_corrupt":
            assert session.stat("custom.jsonl.2026-10-08.gz") is not None


@pytest.mark.parametrize("timing", ["before_selection", "after_selection"])
def test_retention_checked_absence_only_before_selection(audit_path, monkeypatch, timing):
    name = "custom.jsonl.2026-01-01"
    with audit.audit_session(audit_path) as session:
        session.create(name, b"old")
        listing = session.list_names
        stat = session.stat
        delete = session.delete
        if timing == "before_selection":

            def disappeared(**kwargs):
                names = listing(**kwargs)
                delete(name, expected_identity=stat(name).identity)
                return names

            monkeypatch.setattr(session, "list_names", disappeared)
            assert rotation.sweep_audit_retention(session, cutoff_mtime_ns=2**63) == ()
        else:

            def swapped(selected, **kwargs):
                # Retain the old inode: unlink/recreate can recycle its ID on
                # Linux and fail to construct the identity change under test.
                retained = session.rename(
                    selected, "retained-selected-source", expected_identity=stat(selected).identity
                )
                replacement = session.create(selected, b"new")
                assert retained.identity == kwargs["expected_identity"]
                assert replacement.identity != retained.identity
                delete(selected, **kwargs)

            monkeypatch.setattr(session, "delete", swapped)
            with pytest.raises(fs.PrivateFSError) as err:
                rotation.sweep_audit_retention(session, cutoff_mtime_ns=2**63)
            assert err.value.reason == "unsafe"
            assert session.snapshot(name, max_bytes=3).data == b"new"
            assert session.snapshot("retained-selected-source", max_bytes=3).data == b"old"
