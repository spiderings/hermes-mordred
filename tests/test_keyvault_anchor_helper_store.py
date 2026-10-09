"""The helper-owned anchor store (``HelperAnchorStore`` / ``_HelperAnchorOps``).

The vault anchor lives in a login-keychain item that ``mordred-hermes-sekey``
creates and reads, so its ACL trusts one stable binary instead of whichever
Python interpreter wrote it (see ``_anchor_keychain``'s module docstring).
These tests drive the Python half against :class:`tests._keychain_sim.SimHelperRunner`
(the helper's JSON protocol over a simulated legacy keychain).
"""

from __future__ import annotations

import os
import sys
from typing import Any

import pytest

from mordred_hermes.keyvault import _anchor_keychain, _seckey_helper, anchor
from mordred_hermes.keyvault._anchor_keychain import (
    DEFAULT_SERVICE,
    HELPER_SERVICE,
    HelperAnchorStore,
    KeychainAnchorError,
    KeychainAnchorStore,
    _HelperAnchorOps,
    default_anchor_store,
)
from mordred_hermes.keyvault._seckey_errors import _OpsError as _SeOpsError

from ._keychain_sim import SimHelperRunner, SimKeychain, SimPyobjcOps

_LABEL = "mordred-hermes.vault.0123456789abcdef"


def _store(kc: SimKeychain, *, runner: Any = None, legacy_binary: str | None = "python") -> HelperAnchorStore:
    legacy = KeychainAnchorStore(ops=SimPyobjcOps(kc, legacy_binary)) if legacy_binary else None
    return HelperAnchorStore(_HelperAnchorOps("helper", runner=runner or SimHelperRunner(kc)), legacy=legacy)


def test_service_constant_matches_the_helper_source() -> None:
    main = os.path.join(
        os.path.dirname(__file__), "..", "native", "sekey-helper", "Sources", "mordred-hermes-sekey", "main.swift"
    )
    with open(main, encoding="utf-8") as handle:
        assert f'let anchorServiceBase = "{HELPER_SERVICE}"' in handle.read()


def test_satisfies_the_anchor_store_protocol() -> None:
    assert isinstance(_store(SimKeychain()), anchor.AnchorStore)


def test_round_trip_through_the_helper() -> None:
    kc = SimKeychain()
    store = _store(kc)
    assert store.read(_LABEL) is None
    store.write(_LABEL, b"v1")
    store.write(_LABEL, b"v2")
    assert store.read(_LABEL) == b"v2"
    assert (HELPER_SERVICE, _LABEL) in kc.items
    assert (DEFAULT_SERVICE, _LABEL) not in kc.items  # never written in-process
    assert kc.items[(HELPER_SERVICE, _LABEL)].trusted == {"mordred-hermes-sekey"}
    store.delete(_LABEL)
    assert store.read(_LABEL) is None


def test_a_commit_is_one_update() -> None:
    kc = SimKeychain()
    store = _store(kc)
    store.write(_LABEL, b"v1")
    kc.reset_counts()
    store.write(_LABEL, b"v2")
    assert [op for _b, op, _s in kc.ops] == ["SecItemUpdate"]


def test_works_with_vault_anchor_helpers() -> None:
    store = _store(SimKeychain())
    anchor.write_anchor(store, _LABEL, wmk=b"w" * 40, generation=3)
    anchor.verify_anchor(store, _LABEL, wmk=b"w" * 40, generation=3)
    with pytest.raises(anchor.AnchorMismatch):
        anchor.verify_pinned(anchor.read_anchor(store, _LABEL), wmk=b"w" * 40, generation=2)


# -- migration -------------------------------------------------------------------


def test_migrates_a_legacy_item_once() -> None:
    kc = SimKeychain()
    kc.seed(DEFAULT_SERVICE, _LABEL, b"pin", creator="python")
    store = _store(kc)
    assert store.read(_LABEL) == b"pin"
    assert kc.items[(HELPER_SERVICE, _LABEL)].value == b"pin"
    assert (DEFAULT_SERVICE, _LABEL) not in kc.items  # the creator may delete silently
    assert kc.dialog_count == 0


def test_migration_never_overwrites_a_newer_helper_item() -> None:
    """A concurrent process migrated and then committed a newer pin between our
    helper miss and our add: its value wins (add-only), ours is dropped."""
    kc = SimKeychain()
    kc.seed(DEFAULT_SERVICE, _LABEL, b"old", creator="python")
    runner = SimHelperRunner(kc)
    real = runner.__call__

    def racing(binary: str, payload: dict[str, Any]) -> dict[str, Any]:
        if payload["cmd"] == "anchor_add":
            kc.seed(HELPER_SERVICE, _LABEL, b"newer", creator="mordred-hermes-sekey")
        return real(binary, payload)

    store = _store(kc, runner=racing)
    assert store.read(_LABEL) == b"newer"
    assert kc.items[(HELPER_SERVICE, _LABEL)].value == b"newer"


def test_a_concurrent_migration_is_not_reported_as_a_missing_anchor() -> None:
    kc = SimKeychain()
    runner = SimHelperRunner(kc)
    real = runner.__call__
    gets = {"n": 0}

    def racing(binary: str, payload: dict[str, Any]) -> dict[str, Any]:
        if payload["cmd"] == "anchor_get":
            gets["n"] += 1
            if gets["n"] == 2:  # after our legacy miss: the other process finished
                kc.seed(HELPER_SERVICE, _LABEL, b"pin", creator="mordred-hermes-sekey")
        return real(binary, payload)

    assert _store(kc, runner=racing).read(_LABEL) == b"pin"


def test_a_denied_legacy_read_fails_closed() -> None:
    kc = SimKeychain()
    kc.seed(DEFAULT_SERVICE, _LABEL, b"pin", creator="python")

    class _Denied(SimPyobjcOps):
        def get(self, service: str, account: str) -> bytes | None:
            raise _anchor_keychain._OpsError(-128, "user canceled")

    store = HelperAnchorStore(
        _HelperAnchorOps("helper", runner=SimHelperRunner(kc)), legacy=KeychainAnchorStore(ops=_Denied(kc, "x"))
    )
    with pytest.raises(KeychainAnchorError) as info:
        store.read(_LABEL)
    assert info.value.status == -128
    assert (HELPER_SERVICE, _LABEL) not in kc.items


def test_delete_removes_both_items() -> None:
    kc = SimKeychain()
    kc.seed(DEFAULT_SERVICE, _LABEL, b"stale", creator="python")
    kc.seed(HELPER_SERVICE, _LABEL, b"pin", creator="mordred-hermes-sekey")
    _store(kc).delete(_LABEL)
    assert kc.items == {}


# -- an older helper without the anchor commands -------------------------------------


def test_an_older_helper_falls_back_to_the_in_process_store_for_the_process() -> None:
    kc = SimKeychain()
    runner = SimHelperRunner(kc, supports_anchor=False)
    store = _store(kc, runner=runner)
    store.write(_LABEL, b"v1")
    assert store.read(_LABEL) == b"v1"
    store.delete(_LABEL)
    assert runner.calls == ["anchor_set"]  # asked once, then remembered
    assert kc.items == {}


def test_an_older_helper_without_a_fallback_fails_closed() -> None:
    store = _store(SimKeychain(), runner=SimHelperRunner(SimKeychain(), supports_anchor=False), legacy_binary=None)
    with pytest.raises(KeychainAnchorError):
        store.read(_LABEL)


# -- error translation -------------------------------------------------------------


def _failing(status: int, domain: str = "OSStatus") -> Any:
    def runner(_binary: str, _payload: dict[str, Any]) -> dict[str, Any]:
        raise _SeOpsError(status, domain, "boom")

    return runner


@pytest.mark.parametrize("method", ["read", "write", "delete"])
def test_helper_failures_fail_closed(method: str) -> None:
    store = _store(SimKeychain(), runner=_failing(-25293))
    with pytest.raises(KeychainAnchorError) as info:
        if method == "write":
            store.write(_LABEL, b"v")
        else:
            getattr(store, method)(_LABEL)
    assert info.value.status == -25293


@pytest.mark.parametrize("response", [{}, {"value_hex": 7}, {"value_hex": "zz"}])
def test_a_malformed_helper_response_fails_closed(response: dict[str, Any]) -> None:
    store = _store(SimKeychain(), runner=lambda _b, _p: response)
    with pytest.raises(KeychainAnchorError):
        store.read(_LABEL)


def test_ops_use_run_helper_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, dict[str, Any]]] = []

    def fake_run(binary: str, payload: dict[str, Any]) -> dict[str, Any]:
        seen.append((binary, payload))
        return {"value_hex": "abcd"}

    monkeypatch.setattr(_seckey_helper, "_run_helper", fake_run)
    assert _HelperAnchorOps("/bin/helper").get(_LABEL) == b"\xab\xcd"
    assert seen == [("/bin/helper", {"cmd": "anchor_get", "account": _LABEL})]


# -- store selection -----------------------------------------------------------------


def test_default_store_is_helper_owned_when_the_helper_is_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: "/x/mordred-hermes-sekey")
    assert isinstance(default_anchor_store(), HelperAnchorStore)


def test_default_store_is_in_process_without_the_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: None)
    assert type(default_anchor_store()) is KeychainAnchorStore


# -- the in-process cleanup delete never prompts ---------------------------------------


class _FakeSec:
    kSecClass = "class"
    kSecClassGenericPassword = "genp"
    kSecAttrService = "svce"
    kSecAttrAccount = "acct"
    kSecUseAuthenticationUI = "u_AuthUI"
    kSecUseAuthenticationUIFail = "u_AuthUIF"

    def __init__(self, status: int) -> None:
        self.status = status
        self.queries: list[dict[str, Any]] = []

    def SecItemDelete(self, query: dict[str, Any]) -> int:
        self.queries.append(query)
        return self.status


def test_noninteractive_delete_asks_security_framework_not_to_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    sec = _FakeSec(0)
    monkeypatch.setattr(_anchor_keychain.native, "_lazy_import_security", lambda: sec)
    _anchor_keychain._PyobjcKeychainOps().delete_noninteractive(DEFAULT_SERVICE, _LABEL)
    assert sec.queries == [
        {"class": "genp", "svce": DEFAULT_SERVICE, "acct": _LABEL, "u_AuthUI": "u_AuthUIF"},
    ]


def test_discard_swallows_a_refused_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    sec = _FakeSec(-25308)  # errSecInteractionNotAllowed
    monkeypatch.setattr(_anchor_keychain.native, "_lazy_import_security", lambda: sec)
    KeychainAnchorStore().discard(_LABEL)  # no raise
    assert len(sec.queries) == 1
