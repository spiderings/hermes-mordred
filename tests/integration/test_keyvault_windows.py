"""Explicit real-TPM tests through the compiled Windows helper and production MRKW."""

from __future__ import annotations

import os
import secrets
import shutil
import sys
import uuid
from functools import partial
from pathlib import Path

import pytest

from mordred_hermes.keyvault._exceptions import (
    WrapIntegrityError,
    WrapKeyAlreadyExists,
    WrapKeyNotFound,
    WrapNativeUnavailable,
    WrapParseError,
)
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from mordred_hermes.keyvault._seckey_helper import find_winkey_helper
from mordred_hermes.keyvault.wrap import generate_wrapping_key, unwrap_dek, wrap_dek

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "win32" or os.environ.get("MORDRED_WINKEY_TEST") != "1",
        reason="requires explicitly enabled actual Windows TPM user",
    ),
]


def test_compiled_helper_production_wrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Copy an explicitly supplied build into an isolated Hermes home, then exercise
    # real default discovery. No ctypes adapter, software ops, or native-call mocks.
    source = Path(os.environ["MORDRED_WINKEY_HELPER"])
    home = tmp_path / "Hermes 日本語"
    installed = home / "bin" / "mordred-hermes-winkey.exe"
    installed.parent.mkdir(parents=True)
    shutil.copy2(source, installed)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("MORDRED_WINKEY_HELPER")
    assert find_winkey_helper() == str(installed)
    backend = _SecKeyBackend(sw_ops=None)
    audit: list[dict[str, object]] = []
    unwrap = partial(unwrap_dek, audit_sink=audit.append)
    key_id = "windows-live.profile-a." + uuid.uuid4().hex
    generated = False
    try:
        public = generate_wrapping_key(key_id, backend=backend)
        generated = True
        with pytest.raises(WrapKeyAlreadyExists):
            generate_wrapping_key(key_id, backend=backend)
        assert backend.get_enclave_public_key(key_id) == public
        dek = secrets.token_bytes(32)
        blob = wrap_dek(dek, key_id, backend=backend)
        original = bytes(blob)
        assert len(blob) == 127 and blob[:4] == b"MRKW"
        # A new backend and a new helper process must reopen the persisted key.
        assert unwrap(blob, key_id, backend=_SecKeyBackend(sw_ops=None)) == dek
        with pytest.raises(WrapParseError):
            unwrap(blob, key_id.replace("profile-a", "profile-b"), backend=backend)
        corrupt = bytearray(blob)
        corrupt[-1] ^= 1
        with pytest.raises(WrapIntegrityError):
            unwrap(bytes(corrupt), key_id, backend=backend)
        monkeypatch.setenv("MORDRED_WINKEY_HELPER", str(home / "absent.exe"))
        with pytest.raises(WrapNativeUnavailable):
            _SecKeyBackend(sw_ops=None)
        monkeypatch.delenv("MORDRED_WINKEY_HELPER")
        assert blob == original and unwrap(blob, key_id, backend=backend) == dek
        assert audit and all(event["event"] == "keyvault.unwrap_dek" for event in audit)
        backend.delete_enclave_key(key_id)
        generated = False
        with pytest.raises(WrapKeyNotFound):
            unwrap(blob, key_id, backend=backend)
    finally:
        if generated:
            backend.delete_enclave_key(key_id)


@pytest.mark.skipif(
    not os.environ.get("MORDRED_WINKEY_INACCESSIBLE_TAG"),
    reason="requires an explicitly scoped retained key on a second TPM",
)
def test_retained_inaccessible_key_delete_refuses() -> None:
    """Run only against a disposable cloned-disk fixture; never a production key."""
    import hashlib

    from mordred_hermes.keyvault._seckey_errors import _OpsError
    from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps

    binary = find_winkey_helper()
    assert binary is not None
    ops = _HelperSecKeyOps(binary)
    tag = bytes.fromhex(os.environ["MORDRED_WINKEY_INACCESSIBLE_TAG"])
    with pytest.raises(_OpsError) as opened:
        ops.copy_public_key(tag)
    assert opened.value.status == 0x80090016
    # Establish the counterexample: this token/TPM can use newly created keys.
    ops.probe()
    store = Path(os.environ["LOCALAPPDATA"]) / "Microsoft/Crypto/PCPKSP"

    def snapshot() -> dict[str, str]:
        return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in store.rglob("*") if path.is_file()}

    before = snapshot()
    assert before
    try:
        with pytest.raises(_OpsError) as deleted:
            ops.delete_key(tag)
        assert deleted.value.status == opened.value.status
        assert deleted.value.reason == "UNAVAILABLE"
    finally:
        assert snapshot() == before, "refused deletion must preserve retained key files"
