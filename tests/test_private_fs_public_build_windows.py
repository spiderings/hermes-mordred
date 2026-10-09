"""Actual NTFS public Cargo-style sources and unchanged destination policy."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mordred_hermes._private_fs import (
    PrivateFSError,
    open_confidential_directory,
    open_private_directory,
    read_public_build_output,
)
from mordred_hermes.wizard import _windows_install as install

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Win32 filesystem")


@pytest.fixture
def build_source(tmp_path):
    # Copy bytes from a real PE; never hardlink or alter the running interpreter.
    content = Path(sys.executable).read_bytes()
    root = tmp_path / "Cargo 共有 build"
    with open_private_directory(root, create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("helper.exe", content)
    return root / "helper.exe", content, tmp_path / "bin"


def test_native_public_hardlinked_pe_is_read_and_published_without_source_mutation(build_source):
    source, content, target = build_source
    alias = source.with_name("deps-image.exe")
    os.link(source, alias)
    identity = (source.stat().st_ino, source.stat().st_nlink)
    digest = hashlib.sha256(content).hexdigest().upper()
    assert read_public_build_output(source, max_bytes=len(content)) == content
    installed = install.publish_helper(source, target, expected_sha256=digest)
    assert install.is_owned(installed)
    assert installed.read_bytes() == source.read_bytes() == alias.read_bytes() == content
    assert (source.stat().st_ino, source.stat().st_nlink) == identity
    assert installed.stat().st_nlink == 1
    receipt = install.receipt_path(installed).read_bytes()
    os.link(installed, installed.with_name("unsafe-stored-alias.exe"))
    with pytest.raises(PrivateFSError) as refused:
        install.publish_helper(source, target, expected_sha256=digest)
    assert refused.value.reason == "unsafe"
    assert installed.read_bytes() == content
    assert install.receipt_path(installed).read_bytes() == receipt


def test_native_readonly_foreign_grant_is_public_but_not_confidential(build_source):
    source, content, target = build_source
    subprocess.run(["icacls.exe", str(source), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    assert read_public_build_output(source, max_bytes=len(content)) == content
    assert install.is_owned(install.publish_helper(source, target))
    with open_confidential_directory(source.parent) as directory, pytest.raises(PrivateFSError) as refused:
        directory.read_bytes(source.name, max_bytes=len(content))
    assert refused.value.reason == "unsafe"


@pytest.mark.parametrize("unsafe", ["foreign_write", "junction", "malformed", "writer", "hash_mismatch"])
def test_native_public_source_failure_preserves_source_and_old_helper(build_source, tmp_path, unsafe):
    source, content, target = build_source
    installed = install.publish_helper(source, target)
    installed_content = installed.read_bytes()
    receipt = install.receipt_path(installed).read_bytes()
    selected = source
    writer = None
    junction = None
    expected = None
    if unsafe == "foreign_write":
        subprocess.run(["icacls.exe", str(source), "/grant", "*S-1-1-0:(W)"], check=True, capture_output=True)
    elif unsafe == "junction":
        junction = tmp_path / "junction"
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(source.parent)],
            check=True,
            capture_output=True,
        )
        selected = junction / source.name
    elif unsafe == "malformed":
        content = b"not a PE"
        source.write_bytes(content)
    elif unsafe == "writer":
        writer = source.open("r+b")
    else:
        expected = "0" * 64
    try:
        with pytest.raises(OSError):
            install.publish_helper(selected, target, expected_sha256=expected)
    finally:
        if writer is not None:
            writer.close()
        if junction is not None:
            junction.rmdir()  # Only the test-owned alias; never its destination.
    assert source.read_bytes() == content
    assert installed.read_bytes() == installed_content
    assert install.receipt_path(installed).read_bytes() == receipt
    assert install.is_owned(installed)


def test_native_missing_public_parent_is_classified_without_creation(tmp_path):
    source = tmp_path / "missing" / "helper.exe"
    with pytest.raises(PrivateFSError) as refused:
        read_public_build_output(source, max_bytes=10)
    assert refused.value.reason == "missing"
    assert not source.parent.exists()
