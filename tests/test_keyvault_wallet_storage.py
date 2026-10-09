"""Public Windows wallet behavior through real checked storage on each host."""

from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import extension_sign

RAW = {"kind": "raw", "key_id": "synthetic", "envelope_id": "test-envelope", "chain_id": 1}
HD = {"kind": "hd", "key_id": "synthetic", "seed_envelope_id": "test-seed", "index": 2}


@pytest.fixture
def wallet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path.resolve() / "wallet with spaces"
    monkeypatch.setattr(extension_sign, "_WINDOWS_WALLET_STORAGE", True, raising=False)
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)
    return directory


def put(directory: Path, data: bytes, name: str = "wallet.json") -> None:
    with open_private_directory(directory, create=True) as d, d.transaction() as tx:
        tx.create_bytes(name, data)


def test_absent_read_does_not_create_state(wallet: Path) -> None:
    assert extension_sign._load_wallet_cfg() == {}
    assert not wallet.exists()


def test_public_create_replace_and_checked_lock(wallet: Path) -> None:
    extension_sign.set_wallet(RAW)
    assert extension_sign._load_wallet_cfg() == RAW
    assert (wallet / ".mordred-fs.lock").is_file()
    assert not (wallet / ".wallet.lock").exists()
    extension_sign.set_wallet(HD)
    assert extension_sign._load_wallet_cfg() == HD


@pytest.mark.parametrize(
    "payload",
    [b"{", b"[]", b"\xff", b'{"kind":"raw","kind":"hd"}', b"x" * (1048576 + 1)],
    ids=["truncated", "array", "invalid-utf8", "duplicate-member", "oversized"],
)
def test_invalid_explicit_wallet_never_discovers(wallet: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes) -> None:
    put(wallet, payload)
    monkeypatch.setattr(extension_sign.ethereum, "list_seed_envelope_ids", lambda _: pytest.fail("fallback"))
    with pytest.raises(extension_sign.WalletConfigError):
        extension_sign._resolve_account()
    assert (wallet / "wallet.json").read_bytes() == payload


@pytest.mark.parametrize("cfg", [{}, RAW | {"key_id": "x" * 1048576}])
def test_invalid_new_document_creates_nothing(wallet: Path, cfg: dict) -> None:
    with pytest.raises(extension_sign.WalletConfigError):
        extension_sign.set_wallet(cfg)
    assert not wallet.exists()


def test_oversized_existing_file_is_not_replaced(wallet: Path) -> None:
    original = b"x" * (1048576 + 1)
    put(wallet, original)
    with pytest.raises(extension_sign.WalletConfigError):
        extension_sign.set_wallet(RAW)
    assert (wallet / "wallet.json").read_bytes() == original


def test_hardlinked_wallet_is_refused_for_read_and_write(wallet: Path) -> None:
    original = json.dumps(RAW).encode()
    put(wallet, original)
    os.link(wallet / "wallet.json", wallet / "alias")
    for operation in (extension_sign._load_wallet_cfg, lambda: extension_sign.set_wallet(HD)):
        with pytest.raises(extension_sign.WalletConfigError):
            operation()
    assert (wallet / "wallet.json").read_bytes() == original
    assert (wallet / "alias").read_bytes() == original


@pytest.mark.parametrize("phase", ["acquire", "release"])
@pytest.mark.parametrize("present", [True, False])
def test_missing_lock_error_is_not_absence(
    wallet: Path, monkeypatch: pytest.MonkeyPatch, phase: str, present: bool
) -> None:
    from mordred_hermes.keyvault import _wallet_storage

    if present:
        put(wallet, json.dumps(RAW).encode())
    else:
        with open_private_directory(wallet, create=True):
            pass

    @contextlib.contextmanager
    def fail_lock(self, *, blocking=True):
        if phase == "release":
            with transaction(self, blocking=blocking) as tx:
                yield tx
        raise PrivateFSError("missing", "lock")

    with open_private_directory(wallet) as directory:
        transaction = type(directory).transaction
        monkeypatch.setattr(type(directory), "transaction", fail_lock)
    with pytest.raises(extension_sign.WalletConfigError) as error:
        _wallet_storage.read_wallet_bytes(wallet)
    assert error.value.reason == "missing"


@pytest.mark.parametrize("reason", ["io", "missing"])
def test_directory_cleanup_after_save_is_uncertain(wallet: Path, monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    from mordred_hermes.keyvault import _wallet_storage

    @contextlib.contextmanager
    def fail_cleanup(path, *, create=False):
        with open_private_directory(path, create=create) as directory:
            yield directory
        raise PrivateFSError(reason, "close", native_code=6, commit_state="uncertain")

    monkeypatch.setattr(_wallet_storage, "open_private_directory", fail_cleanup)
    with pytest.raises(extension_sign.WalletConfigError, match=r"inspect.*retry") as error:
        extension_sign.set_wallet(RAW)
    assert error.value.commit_state == "uncertain"
    assert error.value.reason == reason
    assert error.value.native_code == 6
    assert json.loads((wallet / "wallet.json").read_bytes()) == RAW
    assert "synthetic" not in str(error.value)


def test_read_cleanup_missing_is_not_absence(wallet: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.keyvault import _wallet_storage

    put(wallet, json.dumps(RAW).encode())

    @contextlib.contextmanager
    def fail_cleanup(path, *, create=False):
        with open_private_directory(path, create=create) as directory:
            yield directory
        raise PrivateFSError("missing", "close")

    monkeypatch.setattr(_wallet_storage, "open_private_directory", fail_cleanup)
    with pytest.raises(extension_sign.WalletConfigError):
        extension_sign._load_wallet_cfg()


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACLs")
@pytest.mark.parametrize("target", ["directory", "wallet", "lock"])
def test_broad_windows_acl_is_refused_without_repair(wallet: Path, target: str) -> None:
    extension_sign.set_wallet(RAW)
    path = wallet if target == "directory" else wallet / ("wallet.json" if target == "wallet" else ".mordred-fs.lock")
    subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = subprocess.check_output(["icacls.exe", str(path)])
    for operation in (extension_sign._load_wallet_cfg, lambda: extension_sign.set_wallet(HD)):
        with pytest.raises(extension_sign.WalletConfigError):
            operation()
    assert subprocess.check_output(["icacls.exe", str(path)]) == before
    assert json.loads((wallet / "wallet.json").read_bytes()) == RAW


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction")
def test_windows_junction_is_refused_without_writing_target(wallet: Path) -> None:
    extension_sign.set_wallet(RAW)
    destination = wallet.with_name("junction target")
    wallet.rename(destination)
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(wallet), str(destination)], check=True, capture_output=True)
    try:
        for operation in (extension_sign._load_wallet_cfg, lambda: extension_sign.set_wallet(HD)):
            with pytest.raises(extension_sign.WalletConfigError):
                operation()
        assert json.loads((destination / "wallet.json").read_bytes()) == RAW
    finally:
        wallet.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="native Windows publication faults")
@pytest.mark.parametrize("fail_after", [1, 2])
def test_native_save_failure_preserves_complete_selection(
    wallet: Path, monkeypatch: pytest.MonkeyPatch, fail_after: int
) -> None:
    from mordred_hermes._private_fs._windows_api import get_api

    extension_sign.set_wallet(RAW)
    api = get_api()
    flush = api.flush
    count = 0

    def fail_flush(handle):
        nonlocal count
        count += 1
        if count == fail_after:
            raise PrivateFSError("io", "flush", native_code=1117)
        flush(handle)

    monkeypatch.setattr(api, "flush", fail_flush)
    with pytest.raises(extension_sign.WalletConfigError) as error:
        extension_sign.set_wallet(HD)
    assert error.value.commit_state == ("uncertain" if fail_after == 2 else "not_committed")
    assert json.loads((wallet / "wallet.json").read_bytes()) == (HD if fail_after == 2 else RAW)


_CHILD = """
import json, sys
from pathlib import Path
from mordred_hermes.keyvault import extension_sign as signer
signer._WINDOWS_WALLET_STORAGE = True
signer._ext_dir = lambda: Path(sys.argv[1])
print('ready', flush=True)
if sys.argv[2] == 'write':
    signer.set_wallet(json.loads(sys.argv[3]))
else:
    assert signer._load_wallet_cfg() == json.loads(sys.argv[3])
print('done', flush=True)
"""


@pytest.mark.parametrize("mode", ["read", "write"])
def test_fresh_process_waits_for_shared_transaction(wallet: Path, mode: str) -> None:
    extension_sign.set_wallet(RAW)
    lines: queue.Queue[str] = queue.Queue()
    with open_private_directory(wallet) as directory, contextlib.ExitStack() as held:
        held.enter_context(directory.transaction())
        child = subprocess.Popen(
            [sys.executable, "-u", "-c", _CHILD, str(wallet), mode, json.dumps(RAW)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert child.stdout is not None

        def collect():
            for line in child.stdout:
                lines.put(line.strip())

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            assert lines.get(timeout=15) == "ready"
            with pytest.raises(queue.Empty):
                lines.get(timeout=0.3)
            held.close()
            assert lines.get(timeout=15) == "done"
            child.wait(timeout=15)
            assert child.returncode == 0
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=15)
            reader.join(timeout=5)
            child.stdout.close()
            assert child.stderr is not None
            child.stderr.close()
    assert extension_sign._load_wallet_cfg() == RAW


def test_unsafe_lock_is_never_replaced(wallet: Path) -> None:
    put(wallet, json.dumps(RAW).encode())
    lock = wallet / ".mordred-fs.lock"
    lock.unlink()
    lock.mkdir()
    for operation in (extension_sign._load_wallet_cfg, lambda: extension_sign.set_wallet(HD)):
        with pytest.raises(extension_sign.WalletConfigError):
            operation()
    assert lock.is_dir()


@pytest.mark.parametrize("operation", ["close", "file_identity", "security_info"])
def test_missing_from_file_inspection_is_not_absence(
    wallet: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    put(wallet, json.dumps(RAW).encode())

    def fail_read(self, name, *, max_bytes):
        raise PrivateFSError("missing", operation)

    with open_private_directory(wallet) as directory:
        monkeypatch.setattr(type(directory), "read_bytes", fail_read)
    with pytest.raises(extension_sign.WalletConfigError):
        extension_sign._load_wallet_cfg()
