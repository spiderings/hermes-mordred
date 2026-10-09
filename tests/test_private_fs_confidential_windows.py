"""Actual NTFS inherited ACL admission without modifying the shared parent."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mordred_hermes._private_fs import (
    PrivateFSError,
    open_confidential_directory,
    open_optional_confidential_directory,
    open_private_directory,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Win32 filesystem")


def powershell(path: Path, script: str) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", "$ErrorActionPreference='Stop'; " + script],
        env={k: v for k, v in os.environ.items() if k.casefold() != "psmodulepath"}
        | {"MORDRED_ACL_FIXTURE": str(path)},
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def shared_home(tmp_path):
    root = tmp_path / "共有 home"
    root.mkdir()
    # Profile-style inheritable owner/SYSTEM/Admin grants, plus read-only access
    # to the directory itself. The sensitive child has only safe inherited ACEs.
    powershell(
        root,
        """
    $u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    $a.SetSecurityDescriptorSddlForm("O:${u}D:P(A;OICI;FA;;;${u})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FR;;;WD)");
    Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    target = root / "config.yaml"
    target.write_bytes(b"old")
    # An elevated token may default new-file ownership to Administrators.
    # Set only the fixture's owner; retain the profile-style inherited DACL.
    from mordred_hermes._private_fs._windows_api import get_api

    api = get_api()
    with api.open(str(target)) as handle:
        before = api.descriptor(handle)
    powershell(
        target,
        """
    $u=[Security.Principal.WindowsIdentity]::GetCurrent().User;
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    $a.SetOwner($u);
    Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    with api.open(str(target)) as handle:
        after = api.descriptor(handle)
    assert after.owner == api.user_sid()
    assert after.protected is before.protected is False
    assert after.aces == before.aces
    assert after.aces and all(ace.flags & 0x10 for ace in after.aces)
    return root


def descriptor(path):
    return powershell(path, "(Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE).Sddl")


def test_native_inherited_safe_update_keeps_shared_parent(shared_home):
    root = shared_home
    parent_before = descriptor(root)
    file_before = descriptor(root / "config.yaml")
    assert "ID;" in file_before
    with open_confidential_directory(root) as directory:
        identity = directory.directory_identity()
        assert directory.read_bytes("config.yaml", max_bytes=3) == b"old"
        assert descriptor(root / "config.yaml") == file_before
        with directory.transaction() as tx:
            tx.replace_bytes("config.yaml", b"new")
            tx.create_bytes("backup.yaml", b"old")
            assert tx.read_bytes("config.yaml", max_bytes=3) == b"new"
        assert directory.directory_identity() == identity
    assert descriptor(root) == parent_before
    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    for name in ("config.yaml", "backup.yaml", ".mordred-fs.lock"):
        with get_api().open(str(root / name)) as handle:
            validate_private(handle, directory=False)
    with pytest.raises(PrivateFSError), open_private_directory(root):
        pass


@pytest.mark.parametrize("acl", ["restricted", "deny_allow", "broad"])
def test_native_explicit_file_dacl_cases(shared_home, acl):
    path = shared_home / "config.yaml"
    suffix = {"restricted": "(A;;FR;;;SY)", "deny_allow": "(D;;FR;;;WD)(A;;FR;;;WD)", "broad": "(A;;FR;;;WD)"}[acl]
    powershell(
        path,
        """
    $u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    """
        + '$a.SetSecurityDescriptorSddlForm("O:${u}D:P(A;;FA;;;${u})'
        + suffix
        + '");'
        + """
    Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    before = descriptor(path)
    with open_confidential_directory(shared_home) as directory:
        if acl == "restricted":
            assert directory.read_bytes("config.yaml", max_bytes=3) == b"old"
        else:
            with pytest.raises(PrivateFSError):
                directory.read_bytes("config.yaml", max_bytes=3)
    assert descriptor(path) == before


def test_native_administrators_owned_file_is_refused_unchanged(shared_home):
    import ctypes

    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes._private_fs._windows_security import ADMINISTRATORS

    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("setting an Administrators file owner requires an elevated token")
    target = shared_home / "config.yaml"
    api = get_api()
    with api.open(str(target)) as handle:
        current_user_owned = api.descriptor(handle)
    powershell(
        target,
        """
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    $owner=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');
    $a.SetOwner($owner);
    Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    with api.open(str(target)) as handle:
        foreign_owned = api.descriptor(handle)
    assert foreign_owned.owner == ADMINISTRATORS != api.user_sid()
    assert foreign_owned.protected is current_user_owned.protected is False
    assert foreign_owned.aces == current_user_owned.aces
    parent_before = descriptor(shared_home)
    file_before = descriptor(target)
    with open_confidential_directory(shared_home) as directory:
        with pytest.raises(PrivateFSError) as read_error:
            directory.read_bytes("config.yaml", max_bytes=3)
        assert read_error.value.reason == "unsafe"
        with directory.transaction() as transaction, pytest.raises(PrivateFSError) as write_error:
            transaction.replace_bytes("config.yaml", b"wrong")
        assert write_error.value.reason == "unsafe"
        assert write_error.value.commit_state == "not_committed"
    assert target.read_bytes() == b"old"
    assert descriptor(target) == file_before
    assert descriptor(shared_home) == parent_before


@pytest.mark.parametrize("kind", ["hardlink", "junction"])
def test_native_confidential_refuses_links(shared_home, tmp_path, kind):
    if kind == "hardlink":
        os.link(shared_home / "config.yaml", shared_home / "alias")
        with open_confidential_directory(shared_home) as directory, pytest.raises(PrivateFSError):
            directory.read_bytes("config.yaml", max_bytes=3)
    else:
        junction = tmp_path / "junction"
        subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction), str(shared_home)], check=True, capture_output=True
        )
        with pytest.raises(PrivateFSError), open_optional_confidential_directory(junction):
            pass


def test_native_optional_absence_and_missing_intermediate(shared_home):
    with open_optional_confidential_directory(shared_home / "absent") as directory:
        assert directory is None
    assert not (shared_home / "absent").exists()
    with pytest.raises(PrivateFSError), open_optional_confidential_directory(shared_home / "absent" / "nested"):
        pass


@pytest.mark.integration
@pytest.mark.skipif(os.environ.get("MORDRED_WINDOWS_FS_LIVE") != "1", reason="explicit ordinary-user acceptance")
def test_ordinary_user_inherited_roundtrip(shared_home):
    import ctypes

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "Elevated run is not ordinary-user acceptance"
    test_native_inherited_safe_update_keeps_shared_parent(shared_home)


def test_native_confidential_inventory_is_bounded_and_keeps_inherited_parent(shared_home):
    from concurrent.futures import ThreadPoolExecutor

    before = descriptor(shared_home)
    with open_confidential_directory(shared_home) as directory:
        assert directory.list_names(max_entries=1) == ("config.yaml",)
        with directory.transaction() as tx:
            tx.create_bytes("memory.md", b"synthetic memory")
            assert tx.list_names(max_entries=2) == ("config.yaml", "memory.md")
            with pytest.raises(PrivateFSError) as caught:
                tx.list_names(max_entries=1)
            assert caught.value.operation == "list_limit"
            with ThreadPoolExecutor(1) as executor, pytest.raises(RuntimeError):
                executor.submit(tx.list_names, max_entries=2).result()
        with pytest.raises(RuntimeError):
            tx.list_names(max_entries=2)
    assert descriptor(shared_home) == before


def test_native_principal_matches_token_and_is_stable_across_processes(shared_home):
    import sys

    from mordred_hermes._private_fs import current_principal_id
    from mordred_hermes._private_fs._windows_api import get_api

    principal = current_principal_id()
    assert type(principal) is bytes
    assert get_api().sid_text(principal) == powershell(
        shared_home, "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from mordred_hermes._private_fs import current_principal_id; print(current_principal_id().hex())",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert bytes.fromhex(result.stdout.strip()) == principal
