"""Phase 1 of v2-OS2 (Linux TPM 2.0 backend): platform-neutral error
taxonomy + fail-closed dispatch + split helper discovery.

These tests pin the cross-platform decoupling that lets a non-macOS
hardware helper (TPM on Linux, CNG on Windows later) drive the existing
``_SecKeyBackend`` flow without inheriting macOS ``OSStatus`` semantics:

1. ``_OpsError`` may carry a neutral ``reason`` (NOT_FOUND / EXISTS /
   UNAVAILABLE / AUTH_DENIED). When present, ``_SecKeyBackend`` dispatches
   on it and ignores the numeric ``status`` entirely. Legacy macOS ops
   leave ``reason=None`` and keep dispatching on ``errSec*`` — so the
   macOS behaviour is byte-for-byte unchanged (covered in
   ``test_keyvault_seckey_backend.py``).
2. Off macOS, ``_SecKeyBackend`` must NOT route through
   ``_SoftwareFallbackOps`` (it calls ``Security.framework`` and only
   loads on Darwin). With no software namespace (``sw_ops=None``) the
   backend fails closed: a missing key surfaces as ``WrapKeyNotFound``
   directly, never a software-Keychain lookup.
3. ``_default_ops`` is platform-aware: Darwin keeps the Secure-Enclave
   helper/pyobjc path; Linux requires a TPM helper or fails closed with
   ``WrapNativeUnavailable``; other platforms are not yet supported.
4. Helper discovery is split per backend: ``find_sekey_helper`` (macOS)
   and ``find_tpmkey_helper`` (Linux TPM), each with its own env override
   and binary name.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.keyvault import _seckey_helper
from mordred_hermes.keyvault._exceptions import (
    WrapError,
    WrapKeyNotFound,
    WrapNativeUnavailable,
)
from mordred_hermes.keyvault._seckey_backend import (
    _default_ops,
    _default_sw_ops,
    _PyobjcSecKeyOps,
    _SecKeyBackend,
    _SoftwareFallbackOps,
)
from mordred_hermes.keyvault._seckey_errors import (
    OPS_AUTH_DENIED,
    OPS_EXISTS,
    OPS_NOT_FOUND,
    OPS_UNAVAILABLE,
    _OpsError,
    _translate_error,
    errSecItemNotFound,
)
from mordred_hermes.keyvault._seckey_helper import (
    _TPM_HELPER_NAME,
    _WIN_HELPER_NAME,
    _HelperSecKeyOps,
    find_sekey_helper,
    find_tpmkey_helper,
    find_winkey_helper,
)


def _pub(priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


class _ReasonOps:
    """``_SecKeyOps`` fake that raises ``reason``-carrying ``_OpsError``.

    Holds real ``cryptography`` P-256 keys so happy-path ECDH is genuine;
    set ``*_error`` to inject a failure on the next matching call.
    """

    def __init__(self) -> None:
        self._keys: dict[bytes, ec.EllipticCurvePrivateKey] = {}
        self.calls: list[tuple[str, bytes]] = []
        self.create_error: _OpsError | None = None
        self.copy_error: _OpsError | None = None
        self.delete_error: _OpsError | None = None
        self.exchange_error: _OpsError | None = None

    def create_keypair(self, tag: bytes, label: str, *, unattended: bool = False) -> bytes:
        self.calls.append(("create", tag))
        if self.create_error is not None:
            raise self.create_error
        priv = ec.generate_private_key(ec.SECP256R1())
        self._keys[tag] = priv
        return _pub(priv)

    def copy_public_key(self, tag: bytes) -> bytes:
        self.calls.append(("copy_pub", tag))
        if self.copy_error is not None:
            raise self.copy_error
        if tag not in self._keys:
            raise _OpsError(-1, "tpm", reason=OPS_NOT_FOUND)
        return _pub(self._keys[tag])

    def delete_key(self, tag: bytes) -> None:
        self.calls.append(("delete", tag))
        if self.delete_error is not None:
            raise self.delete_error
        self._keys.pop(tag, None)

    def key_exchange(self, tag: bytes, peer_pub: bytes) -> bytes:
        self.calls.append(("ecdh", tag))
        if self.exchange_error is not None:
            raise self.exchange_error
        if tag not in self._keys:
            raise _OpsError(-1, "tpm", reason=OPS_NOT_FOUND)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self._keys[tag].exchange(ec.ECDH(), peer)


# ---------------------------------------------------------------------------
# 1. _OpsError.reason
# ---------------------------------------------------------------------------


def test_opserror_carries_reason() -> None:
    exc = _OpsError(-1, "tpm", "missing", reason=OPS_NOT_FOUND)
    assert exc.reason == OPS_NOT_FOUND
    assert exc.status == -1
    assert exc.domain == "tpm"


def test_opserror_reason_defaults_none() -> None:
    """Legacy ops construct without ``reason`` — it must default to None so
    dispatch falls back to numeric ``errSec*`` (macOS path unchanged)."""
    assert _OpsError(errSecItemNotFound).reason is None


# ---------------------------------------------------------------------------
# 2. _translate_error prefers reason, falls back to status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        (OPS_NOT_FOUND, "key_not_found"),
        (OPS_AUTH_DENIED, "auth_failed"),
        (OPS_UNAVAILABLE, "auth_failed"),
    ],
)
def test_translate_error_prefers_reason(reason: str, expected: str) -> None:
    # status=0 (errSecSuccess) proves the numeric value is ignored when a
    # reason is present.
    assert _translate_error(0, "tpm", reason) == expected


def test_translate_error_reason_none_uses_status() -> None:
    assert _translate_error(errSecItemNotFound, "OSStatus", None) == "key_not_found"


# ---------------------------------------------------------------------------
# 3. Fail-closed dispatch (sw_ops=None) on a reason-carrying backend
# ---------------------------------------------------------------------------


def test_get_public_key_not_found_reason_fail_closed() -> None:
    ops = _ReasonOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    with pytest.raises(WrapKeyNotFound):
        backend.get_enclave_public_key("absent-key")
    # No software-namespace lookup was attempted (only the primary ops ran).
    assert [c[0] for c in ops.calls] == ["copy_pub"]


def test_ecdh_not_found_reason_fail_closed() -> None:
    ops = _ReasonOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    with pytest.raises(WrapKeyNotFound):
        backend.enclave_ecdh("absent-key", _pub(ec.generate_private_key(ec.SECP256R1())))
    assert [c[0] for c in ops.calls] == ["ecdh"]


def test_ecdh_auth_denied_reason_maps_to_auth_failed() -> None:
    from mordred_hermes.keyvault.wrap import NativeBackendError

    ops = _ReasonOps()
    ops.exchange_error = _OpsError(-1, "tpm", "user refused", reason=OPS_AUTH_DENIED)
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    with pytest.raises(NativeBackendError) as ei:
        backend.enclave_ecdh("k", _pub(ec.generate_private_key(ec.SECP256R1())))
    assert ei.value.code == "auth_failed"


def test_generate_exists_reason_is_key_not_found() -> None:
    ops = _ReasonOps()
    ops.create_error = _OpsError(-1, "tpm", "already present", reason=OPS_EXISTS)
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    with pytest.raises(WrapKeyNotFound):
        backend.generate_enclave_key("dup-key")


def test_delete_fail_closed_skips_software_namespace() -> None:
    ops = _ReasonOps()
    ops.create_keypair(b"tag", "label")
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    # Must not raise and must not attempt any software-namespace delete.
    backend.delete_enclave_key("k")
    assert [c[0] for c in ops.calls].count("delete") == 1


def test_delete_propagates_reason_error() -> None:
    ops = _ReasonOps()
    ops.delete_error = _OpsError(-1, "tpm", "tpm busy", reason=OPS_UNAVAILABLE)
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    with pytest.raises(WrapError):
        backend.delete_enclave_key("k")


def test_wrap_unwrap_roundtrip_fail_closed_backend() -> None:
    """End-to-end: a reason-only backend with no software namespace still
    does a genuine ECDH/HKDF/AES-KW wrap->unwrap round-trip."""
    from mordred_hermes.keyvault import wrap

    ops = _ReasonOps()
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    backend.generate_enclave_key("wallet-key")
    blob = wrap.wrap_dek(b"\x11" * 32, "wallet-key", backend=backend)
    out = wrap.unwrap_dek(blob, "wallet-key", audit_sink=lambda _e: None, backend=backend)
    assert out == b"\x11" * 32


# ---------------------------------------------------------------------------
# 4. _default_ops platform awareness + fail-closed
# ---------------------------------------------------------------------------


def test_default_ops_linux_without_tpm_helper_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(_seckey_helper, "find_tpmkey_helper", lambda: None)
    with pytest.raises(WrapNativeUnavailable):
        _default_ops()


def test_default_ops_linux_with_tpm_helper_uses_helper_ops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "mordred-hermes-tpmkey"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(_seckey_helper, "find_tpmkey_helper", lambda: str(fake))
    ops = _default_ops()
    assert isinstance(ops, _HelperSecKeyOps)


def test_default_ops_unsupported_platform_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A platform with no hardware backend at all (not macOS/Linux/Windows).
    monkeypatch.setattr(sys, "platform", "freebsd")
    with pytest.raises(WrapNativeUnavailable):
        _default_ops()


def test_default_ops_win32_without_winkey_helper_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows fails closed (no software floor off macOS) when the CNG helper
    # is absent — same contract as Linux without the TPM helper (v2-OS2).
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)
    with pytest.raises(WrapNativeUnavailable):
        _default_ops()


def test_default_ops_win32_with_winkey_helper_uses_helper_ops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "mordred-hermes-winkey"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: str(fake))
    ops = _default_ops()
    assert isinstance(ops, _HelperSecKeyOps)


def test_default_ops_darwin_keeps_secure_enclave_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    # Patch the canonical locator (``_find_helper`` is a back-compat alias
    # that delegates to it, so this intercepts the _default_ops() call too).
    monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: None)
    assert isinstance(_default_ops(), _PyobjcSecKeyOps)


# ---------------------------------------------------------------------------
# 5. _default_sw_ops — software namespace only exists on macOS
# ---------------------------------------------------------------------------


def test_default_sw_ops_is_software_fallback_on_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert isinstance(_default_sw_ops(), _SoftwareFallbackOps)


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_default_sw_ops_is_none_off_darwin(platform: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # No software namespace off macOS (Linux TPM and Windows CNG both fail closed).
    monkeypatch.setattr(sys, "platform", platform)
    assert _default_sw_ops() is None


def test_backend_default_sw_ops_none_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_SecKeyBackend(ops=...)`` with no explicit ``sw_ops`` must NOT
    default to the macOS ``_SoftwareFallbackOps`` on Linux."""
    monkeypatch.setattr(sys, "platform", "linux")
    backend = _SecKeyBackend(ops=_ReasonOps())
    assert backend._sw_ops is None


# ---------------------------------------------------------------------------
# 6. Split helper discovery
# ---------------------------------------------------------------------------


def test_find_tpmkey_helper_env_authoritative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "tpm-helper"
    target.write_text("#!/bin/sh\n")
    monkeypatch.setenv("MORDRED_TPMKEY_HELPER", str(target))
    assert find_tpmkey_helper() == str(target)


def test_find_tpmkey_helper_env_missing_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MORDRED_TPMKEY_HELPER", str(tmp_path / "nope"))
    assert find_tpmkey_helper() is None


def test_find_tpmkey_helper_path_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MORDRED_TPMKEY_HELPER", raising=False)
    monkeypatch.setattr(Path, "home", lambda: Path("/nonexistent-home"))
    monkeypatch.setattr(_seckey_helper.shutil, "which", lambda name: "/opt/bin/" + name)
    assert find_tpmkey_helper() == "/opt/bin/" + _TPM_HELPER_NAME


def test_find_winkey_helper_env_authoritative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "win-helper.exe"
    target.write_bytes(b"MZ")
    monkeypatch.setenv("MORDRED_WINKEY_HELPER", str(target))
    assert find_winkey_helper() == str(target)


def test_find_winkey_helper_env_missing_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MORDRED_WINKEY_HELPER", str(tmp_path / "nope"))
    assert find_winkey_helper() is None


def test_find_winkey_helper_path_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _home

    monkeypatch.delenv("MORDRED_WINKEY_HELPER", raising=False)
    monkeypatch.setattr(_home, "hermes_home", lambda: tmp_path / "empty-home")
    target = tmp_path / _WIN_HELPER_NAME
    target.write_bytes(b"MZ")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert find_winkey_helper() == str(target)


def test_find_sekey_and_legacy_find_helper_agree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``_find_helper`` is preserved as the back-compat alias for
    ``find_sekey_helper`` (callers / monkeypatches still target it)."""
    target = tmp_path / "se-helper"
    target.write_text("#!/bin/sh\n")
    monkeypatch.setenv("MORDRED_SEKEY_HELPER", str(target))
    assert find_sekey_helper() == str(target) == _seckey_helper._find_helper()
