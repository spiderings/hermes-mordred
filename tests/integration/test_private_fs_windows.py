"""Explicit packaged Windows filesystem persistence acceptance, synthetic only."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

import mordred_hermes
from mordred_hermes._private_fs import open_private_directory

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "win32" or os.environ.get("MORDRED_WINDOWS_FS_LIVE") != "1",
        reason="explicit ordinary-user Windows filesystem acceptance",
    ),
]
_PAYLOAD = b"Mordred synthetic filesystem retention fixture, never a secret.\n"


def test_packaged_private_filesystem_persistence() -> None:
    import ctypes

    root_text = os.environ.get("MORDRED_WINDOWS_FS_TEST_ROOT")
    assert root_text, "Requested live run requires a synthetic fixture root"
    root = Path(root_text)
    assert root.is_absolute() and root.name.startswith("mordred-fs-validation-")
    assert not ctypes.windll.shell32.IsUserAnAdmin(), "An elevated pass is not ordinary-user acceptance"
    module = Path(mordred_hermes.__file__)
    assert "site-packages" in module.parts, "Acceptance must run the installed wheel outside its checkout"
    phase = os.environ.get("MORDRED_WINDOWS_FS_PHASE", "reopen")
    assert phase in ("provision", "reopen")
    if phase == "provision":
        assert not root.exists(), "Never overwrite a retained fixture"
    with open_private_directory(root, create=phase == "provision") as directory, directory.transaction() as tx:
        if phase == "provision":
            tx.create_bytes("retained.bin", _PAYLOAD)
        assert tx.read_bytes("retained.bin", max_bytes=1024) == _PAYLOAD
    print(
        json.dumps(
            {
                "phase": phase,
                "sha256": hashlib.sha256(_PAYLOAD).hexdigest(),
                "module": str(module),
                "python": sys.executable,
                "root": str(root),
            }
        )
    )
