"""``_open_validated_lock`` tolerates a transient ctime bump but not a persistent swap."""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage
from mordred_hermes.keyvault._storage import KeyvaultPermissionError


def _lock(tmp_path: Path) -> Path:
    path = tmp_path / ".lock"
    path.touch(mode=0o600)
    path.chmod(0o600)
    return path


def test_transient_identity_change_is_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _lock(tmp_path)
    real = _storage._open_validated_lock_once
    calls = {"n": 0}

    def flaky(p: Path, *, label: str) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyvaultPermissionError(errno.EAGAIN, f"{label} changed while it was being opened", str(p))
        return real(p, label=label)

    monkeypatch.setattr(_storage, "_open_validated_lock_once", flaky)
    fd = _storage._open_validated_lock(path, label="lock")
    import os

    os.close(fd)
    assert calls["n"] == 2


def test_persistent_identity_change_still_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _lock(tmp_path)

    def always(p: Path, *, label: str) -> int:
        raise KeyvaultPermissionError(errno.EAGAIN, f"{label} changed while it was being opened", str(p))

    monkeypatch.setattr(_storage, "_open_validated_lock_once", always)
    with pytest.raises(KeyvaultPermissionError):
        _storage._open_validated_lock(path, label="lock")


def test_other_errors_are_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _lock(tmp_path)
    calls = {"n": 0}

    def eperm(p: Path, *, label: str) -> int:
        calls["n"] += 1
        raise KeyvaultPermissionError(errno.EPERM, "bad mode", str(p))

    monkeypatch.setattr(_storage, "_open_validated_lock_once", eperm)
    with pytest.raises(KeyvaultPermissionError):
        _storage._open_validated_lock(path, label="lock")
    assert calls["n"] == 1
