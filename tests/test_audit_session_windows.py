"""Native Windows audit validation, never inferred from POSIX mode bits."""

from __future__ import annotations

import os
import subprocess

import pytest

from mordred_hermes import _audit_io as audit
from mordred_hermes import _log_rotation as rotation
from mordred_hermes import _private_fs as fs

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows filesystem and ACLs")


@pytest.mark.parametrize("hostile", ["broad_acl", "hardlink", "junction"])
def test_hostile_rotation_refuses_without_repair_or_deletion(tmp_path, hostile):
    path = tmp_path / "private" / "audit.log"
    name = "audit.log.2026-01-01"
    with audit.audit_session(path, create=True) as session:
        session.create(name, b"preserve")
    victim = path.parent / name
    if hostile == "broad_acl":
        subprocess.run(["icacls.exe", str(victim), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    elif hostile == "hardlink":
        os.link(victim, path.parent / "alias")
    else:
        victim.unlink()
        target = tmp_path / "target"
        with fs.open_private_directory(target, create=True):
            pass
        subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(victim), str(target)], check=True, capture_output=True)
    before = subprocess.run(["icacls.exe", str(victim)], check=True, capture_output=True).stdout
    with audit.audit_session(path) as session, pytest.raises(fs.PrivateFSError) as err:
        rotation.sweep_audit_retention(session, cutoff_mtime_ns=2**63)
    assert err.value.reason == "unsafe"
    assert victim.exists()
    assert subprocess.run(["icacls.exe", str(victim)], check=True, capture_output=True).stdout == before
    if hostile != "junction":
        assert victim.read_bytes() == b"preserve"


def test_native_absence_and_case_alias_reentrancy(tmp_path):
    path = tmp_path / "PrivateAudit" / "custom.log"
    assert audit.read_audit_snapshot(path, max_bytes=100) is None
    assert not path.parent.exists()
    with audit.audit_session(path, create=True) as session:
        session.create("custom.log", b"{}\n")
        with audit.audit_session(path.with_name("CUSTOM.log")) as nested:
            assert nested.directory_identity() == session.directory_identity()
            assert nested.snapshot("CUSTOM.log", max_bytes=3).data == b"{}\n"
    assert (path.parent / ".mordred-fs.lock").exists()
