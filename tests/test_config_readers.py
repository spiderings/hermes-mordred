"""Snapshot parsers and Windows wrapper dispatch without spoofing the host OS."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes import _policy_io as policy
from mordred_hermes import _yaml_io as yaml
from mordred_hermes._private_fs import FileIdentity, FileMetadata, PrivateFSError


def contents(data):
    return cio.CheckedContents(data, FileMetadata(FileIdentity(1, b"file"), len(data), 1))


@pytest.mark.parametrize(
    "raw,want",
    [
        (None, "off"),
        (b"{}", "off"),
        (b'{"policy":"strict"}', "strict"),
        (b'{"policy":[]}', "strict"),
        (b"[]", "strict"),
        (b"invalid", "strict"),
        (b"\xff", "strict"),
    ],
)
def test_snapshot_policy_mode(raw, want):
    snap = cio.CanonicalSnapshot(None, contents(raw) if raw is not None else None)
    assert policy.policy_mode_from_snapshot(snap, default="off") == want


def test_snapshot_mapping_parsers_share_generation():
    snap = cio.CanonicalSnapshot(contents(b"model: {provider: local}\n"), contents(b'{"policy":"strict"}'))
    assert policy.policy_mapping_from_snapshot(snap) == {"policy": "strict"}
    assert yaml.yaml_mapping_from_snapshot(snap) == {"model": {"provider": "local"}}
    from ruamel.yaml.error import YAMLError

    for raw in (b"[]", b"bad: [", b"\xff"):
        with pytest.raises((ValueError, UnicodeError, YAMLError)):
            yaml.yaml_mapping_from_snapshot(cio.CanonicalSnapshot(contents(raw), None))
    with pytest.raises(ValueError):
        policy.policy_mapping_from_snapshot(cio.CanonicalSnapshot(None, contents(b"[]")))


def test_windows_boolean_cannot_bypass_pending(monkeypatch, tmp_path):
    monkeypatch.setattr(policy, "_platform", "nt")

    def pending(paths):
        raise cio.PolicyPendingError("pending")

    monkeypatch.setattr(cio, "read_canonical_snapshot", pending)
    path = tmp_path / "mordred" / "policy.json"
    assert policy.load_policy_mapping(path, allow_pending_transaction=True) == {}
    assert policy.read_policy_mode_fail_closed(path, default="off", log=logging.getLogger(__name__)) == "strict"


def test_windows_generic_files_are_not_canonical(monkeypatch, tmp_path):
    monkeypatch.setattr(policy, "_platform", "nt")
    monkeypatch.setattr(yaml, "_platform", "nt")

    def forbidden(paths):
        pytest.fail("generic file was treated as canonical pair")

    monkeypatch.setattr(cio, "read_canonical_snapshot", forbidden)
    auth = tmp_path / "auth.json"
    auth.write_text('{"active_provider":"local"}')
    other = tmp_path / "other.yaml"
    other.write_text("custom: true")
    assert policy.load_policy_mapping(auth) == {"active_provider": "local"}
    assert yaml.load_yaml_mapping(other) == {"custom": True}


def test_windows_config_wrapper_uses_snapshot(monkeypatch, tmp_path):
    monkeypatch.setattr(yaml, "_platform", "nt")
    monkeypatch.setattr(
        cio, "read_canonical_snapshot", lambda paths: cio.CanonicalSnapshot(contents(b"checked: true"), None)
    )
    assert yaml.load_yaml_mapping(tmp_path / "config.yaml") == {"checked": True}


def test_windows_split_policy_root_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(policy, "_platform", "nt")
    path = tmp_path / "elsewhere" / "policy.json"
    path.parent.mkdir()
    path.write_text('{"policy":"off"}')
    assert policy.read_policy_mode_fail_closed(path, default="off", log=logging.getLogger(__name__)) == "strict"
    assert policy.load_policy_mapping(path) == {}


def test_windows_marker_diagnostics_do_not_raw_read(monkeypatch, tmp_path):
    monkeypatch.setattr(policy, "_platform", "nt")
    marker = tmp_path / "mordred" / ".policy-write.pending"

    def unsafe(paths):
        raise PrivateFSError("unsafe", "marker")

    monkeypatch.setattr(cio, "read_policy_marker", unsafe)
    monkeypatch.setattr(Path, "read_text", lambda *a, **kw: pytest.fail("raw unsafe marker read"))
    assert policy.policy_transaction_pending(marker)
    warning = policy.policy_transaction_warning(marker)
    assert "configure" in warning and "delete the marker" not in warning


def test_windows_checked_marker_absence(monkeypatch, tmp_path):
    monkeypatch.setattr(policy, "_platform", "nt")
    monkeypatch.setattr(cio, "read_policy_marker", lambda paths: None)
    marker = tmp_path / "mordred" / ".policy-write.pending"
    assert not policy.policy_transaction_pending(marker)
    assert policy.policy_transaction_warning(marker) is None
