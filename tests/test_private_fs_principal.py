"""Principal IDs are a Windows token capability, never account-name fallbacks."""

from __future__ import annotations

import pytest

from mordred_hermes import _private_fs as fs
from mordred_hermes._private_fs import _windows_api as api


@pytest.mark.parametrize("platform", ["posix", "unknown"])
def test_principal_refuses_unsupported_platform(monkeypatch, platform):
    monkeypatch.setattr(fs, "_platform", platform)
    with pytest.raises(fs.PrivateFSError) as caught:
        fs.current_principal_id()
    assert caught.value.reason == "unsupported"


def test_principal_token_failure_has_no_fallback(monkeypatch):
    monkeypatch.setattr(fs, "_platform", "nt")
    original = fs.PrivateFSError("access_denied", "thread_token")

    class Denied:
        def user_sid(self):
            raise original

    monkeypatch.setattr(api, "get_api", Denied)
    with pytest.raises(fs.PrivateFSError) as caught:
        fs.current_principal_id()
    assert caught.value is original
