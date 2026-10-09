"""Fail-closed persistence tests for the extension wallet selection."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _storage, extension_sign
from mordred_hermes.keyvault import ethereum as wallet_ethereum

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX test host
    _fcntl = None  # type: ignore[assignment]

VALID_HD: dict[str, Any] = {
    "kind": "hd",
    "key_id": "default",
    "seed_envelope_id": "seed-envelope",
    "index": 2,
    "account": 1,
    "change": 0,
    "chain_id": "0x1",
    "rpc": {"1": "https://rpc.example.com/v1/project?token=private"},
}
VALID_RAW: dict[str, Any] = {
    "kind": "raw",
    "key_id": "funds",
    "envelope_id": "raw-envelope",
    "chain_id": 11155111,
    "rpc_url": "https://rpc.example.com/sepolia",
}


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o600)


@pytest.fixture
def wallet_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = _private_dir(tmp_path / "extension")
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)
    return directory


def test_missing_wallet_is_the_only_automatic_discovery_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "extension"
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)
    monkeypatch.setattr(
        wallet_ethereum,
        "list_seed_envelope_ids",
        lambda key_id: ["only-seed"] if key_id == "default" else [],
    )

    assert extension_sign._resolve_account() == {
        "kind": "hd",
        "key_id": "default",
        "seed_envelope_id": "only-seed",
        "index": 0,
        "account": 0,
        "change": 0,
    }
    assert not directory.exists(), "a discovery-only read need not create extension state"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"kind":"hd","key_id":"default","seed_envelope_id":',
        b"[]",
        (b'{"kind":"hd","key_id":"first","key_id":"second","seed_envelope_id":"seed-envelope"}'),
        b"\xff\xfe\x00",
    ],
)
def test_malformed_existing_wallet_fails_closed_without_seed_discovery(
    wallet_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    _write_private(wallet_dir / "wallet.json", payload)
    monkeypatch.setattr(
        wallet_ethereum,
        "list_seed_envelope_ids",
        lambda _key_id: pytest.fail("an invalid explicit wallet must not discover a fallback"),
    )

    with pytest.raises(extension_sign.WalletConfigError) as raised:
        extension_sign._resolve_account()

    assert "first" not in str(raised.value)
    assert "second" not in str(raised.value)
    assert "seed-envelope" not in str(raised.value)


def test_unreadable_existing_wallet_fails_closed(
    wallet_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wallet = wallet_dir / "wallet.json"
    _write_private(wallet, json.dumps(VALID_HD).encode("utf-8"))
    os.chmod(wallet, 0o000)
    monkeypatch.setattr(
        wallet_ethereum,
        "list_seed_envelope_ids",
        lambda _key_id: pytest.fail("an unreadable explicit wallet must not discover a fallback"),
    )

    with pytest.raises(extension_sign.WalletConfigError, match="refusing automatic wallet fallback"):
        extension_sign._resolve_account()


@pytest.mark.parametrize("kind", ["directory", "symlink"])
def test_nonregular_existing_wallet_fails_closed(
    wallet_dir: Path,
    tmp_path: Path,
    kind: str,
) -> None:
    wallet = wallet_dir / "wallet.json"
    if kind == "directory":
        wallet.mkdir()
    else:
        target = tmp_path / "outside-wallet.json"
        _write_private(target, json.dumps(VALID_HD).encode("utf-8"))
        wallet.symlink_to(target)

    with pytest.raises(extension_sign.WalletConfigError):
        extension_sign._load_wallet_cfg()


@pytest.mark.parametrize(
    "cfg",
    [
        {},
        {"kind": "hd", "key_id": "default"},
        {"kind": "hd", "key_id": "", "seed_envelope_id": "seed"},
        {"kind": "hd", "key_id": "default", "seed_envelope_id": "seed", "index": True},
        {"kind": "hd", "key_id": "default", "seed_envelope_id": "seed", "account": -1},
        {
            "kind": "hd",
            "key_id": "default",
            "seed_envelope_id": "seed",
            "index": 1 << 31,
        },
        {
            "kind": "hd",
            "key_id": "default",
            "seed_envelope_id": "seed",
            "account": 1 << 31,
        },
        {
            "kind": "hd",
            "key_id": "default",
            "seed_envelope_id": "seed",
            "change": 1 << 31,
        },
        {"kind": "raw", "key_id": "default"},
        {"kind": "raw", "key_id": "default", "envelope_id": "raw", "index": 0},
        {"kind": "future", "key_id": "default", "envelope_id": "raw"},
        {"kind": "raw", "key_id": "default", "envelope_id": "raw", "chain_id": 0},
        {"kind": "raw", "key_id": "default", "envelope_id": "raw", "chain_id": "0x01"},
        {"kind": "raw", "key_id": "default", "envelope_id": "raw", "chain_id": True},
        {"kind": "raw", "key_id": "default", "envelope_id": "raw", "rpc": []},
        {
            "kind": "raw",
            "key_id": "default",
            "envelope_id": "raw",
            "rpc": {"01": "https://rpc.example.com"},
        },
        {
            "kind": "raw",
            "key_id": "default",
            "envelope_id": "raw",
            "rpc": {
                "1": "https://rpc-a.example.com",
                "0x1": "https://rpc-b.example.com",
            },
        },
        {
            "kind": "raw",
            "key_id": "default",
            "envelope_id": "raw",
            "rpc_url": "http://127.0.0.1/private-wallet-secret",
        },
        {"kind": "raw", "key_id": "default", "envelope_id": "raw", "chainid": 1},
    ],
)
def test_set_wallet_rejects_schema_errors_before_creating_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cfg: dict[str, Any],
) -> None:
    directory = tmp_path / "extension"
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)

    with pytest.raises(extension_sign.WalletConfigError) as raised:
        extension_sign.set_wallet(cfg)

    assert "private-wallet-secret" not in str(raised.value)
    assert not directory.exists()


@pytest.mark.parametrize("cfg", [VALID_HD, VALID_RAW])
def test_set_wallet_round_trips_private_valid_config(
    wallet_dir: Path,
    cfg: dict[str, Any],
) -> None:
    extension_sign.set_wallet(cfg)

    wallet = wallet_dir / "wallet.json"
    assert extension_sign._load_wallet_cfg() == cfg
    assert wallet.stat().st_mode & 0o777 == 0o600
    assert wallet_dir.stat().st_mode & 0o777 == 0o700
    assert (wallet_dir / ".wallet.lock").stat().st_mode & 0o777 == 0o600


def test_wallet_normalization_detaches_nested_caller_state() -> None:
    cfg: dict[str, Any] = {
        **VALID_HD,
        "rpc": dict(VALID_HD["rpc"]),
    }

    normalized = extension_sign._normalize_wallet_cfg(cfg)
    cfg["rpc"]["1"] = "https://changed.example.com"

    assert normalized["rpc"]["1"] == "https://rpc.example.com/v1/project?token=private"


def test_set_wallet_accepts_largest_bip32_child_index(wallet_dir: Path) -> None:
    cfg = {
        **VALID_HD,
        "index": (1 << 31) - 1,
        "account": (1 << 31) - 1,
        "change": (1 << 31) - 1,
    }

    extension_sign.set_wallet(cfg)

    assert extension_sign._load_wallet_cfg() == cfg


def test_set_wallet_rejects_oversized_config_before_creating_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "extension"
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)
    cfg = {
        **VALID_RAW,
        "rpc_url": "https://rpc.example.com/" + "a" * extension_sign._WALLET_CONFIG_MAX_BYTES,
    }

    with pytest.raises(extension_sign.WalletConfigError):
        extension_sign.set_wallet(cfg)

    assert not directory.exists()


def test_wallet_helpers_use_validated_chain_and_rpc(wallet_dir: Path) -> None:
    extension_sign.set_wallet(VALID_HD)

    assert extension_sign.chain_id_int() == 1
    assert extension_sign.rpc_url_for(1) == "https://rpc.example.com/v1/project?token=private"


def test_wallet_chain_display_propagates_invalid_explicit_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken wallet config must not silently advertise mainnet.

    Asserted against the live ``accounts`` surface: the old
    ``_wallet_chain_id_hex`` helper had no production caller left once
    ``api.py`` moved to the single-read snapshot.
    """
    from mordred_hermes.extension import wallet as extension_wallet

    def invalid_snapshot() -> tuple[str, int]:
        raise extension_sign.WalletConfigError("invalid wallet")

    monkeypatch.setattr(extension_sign, "account_snapshot", invalid_snapshot)

    with pytest.raises(extension_sign.WalletConfigError, match="invalid wallet"):
        extension_wallet._get_account_snapshot()


def test_account_snapshot_uses_one_wallet_config_read(monkeypatch: pytest.MonkeyPatch) -> None:
    loads = 0

    def load_wallet() -> dict[str, Any]:
        nonlocal loads
        loads += 1
        if loads > 1:
            pytest.fail("address and chain must come from one config snapshot")
        return dict(VALID_HD)

    monkeypatch.setattr(extension_sign, "_load_wallet_cfg", load_wallet)
    monkeypatch.setattr(
        extension_sign,
        "_address_for_account",
        lambda account: f"address-for-{account['seed_envelope_id']}",
    )

    assert extension_sign.account_snapshot() == ("address-for-seed-envelope", 1)
    assert loads == 1


def test_set_wallet_repairs_legacy_real_directory_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "extension"
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)

    extension_sign.set_wallet(VALID_RAW)

    assert directory.stat().st_mode & 0o777 == 0o700


def test_set_wallet_refuses_symlinked_extension_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _private_dir(tmp_path / "actual-extension")
    directory = tmp_path / "extension"
    directory.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)

    with pytest.raises(extension_sign.WalletConfigError, match="directory is unsafe"):
        extension_sign.set_wallet(VALID_HD)

    assert not (target / "wallet.json").exists()


def test_validate_extension_dir_rejects_symlink_before_repairing_target_mode(
    tmp_path: Path,
) -> None:
    """The symlink check in ``_validate_extension_dir`` must run before the
    mode-repair chmod: if a reorder let the mode check run first, a
    world-writable symlink target would get silently chmod'd through the
    link instead of being rejected untouched."""
    target = tmp_path / "world-writable"
    target.mkdir(mode=0o777)
    os.chmod(target, 0o777)
    link = tmp_path / "extension"
    link.symlink_to(target, target_is_directory=True)
    before_mode = target.stat().st_mode & 0o777

    with pytest.raises(extension_sign.WalletConfigError, match="directory is unsafe"):
        extension_sign._validate_extension_dir(link, create=True)

    assert target.stat().st_mode & 0o777 == before_mode


def test_wallet_cfg_chain_id_checked_before_rpc_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_validate_rpc_cfg`` checks ``chain_id`` before ``rpc_url``: if a
    reorder made ``rpc_url`` run first, the RPC-url validator this test
    forbids would run. The facade re-export cannot see that internal call
    (see ``extension_sign``'s "Module layout" docstring), so the spy patches
    ``_extension_config`` directly."""
    from mordred_hermes.keyvault import _extension_config

    directory = tmp_path / "extension"
    monkeypatch.setattr(extension_sign, "_ext_dir", lambda: directory)

    def fail_if_called(value: object) -> None:
        pytest.fail("rpc_url must not be validated once chain_id already failed")

    monkeypatch.setattr(_extension_config, "_validate_rpc_url", fail_if_called)

    cfg = {**VALID_RAW, "chain_id": 0, "rpc_url": "https://127.0.0.1/"}

    with pytest.raises(extension_sign.WalletConfigError) as raised:
        extension_sign.set_wallet(cfg)

    assert str(raised.value) == extension_sign._WALLET_CONFIG_ERROR
    assert not directory.exists()


def test_partial_atomic_write_preserves_previous_wallet_and_cleans_stage(
    wallet_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_sign.set_wallet(VALID_HD)
    real_write = os.write
    writes = 0

    def partial_then_fail(fd: int, data: bytes | memoryview) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(fd, data[:5])
        raise OSError("injected partial wallet write")

    monkeypatch.setattr(os, "write", partial_then_fail)

    with pytest.raises(extension_sign.WalletConfigError, match="could not be saved safely"):
        extension_sign.set_wallet(VALID_RAW)

    assert extension_sign._load_wallet_cfg() == VALID_HD
    assert not list(wallet_dir.glob("wallet.json.*.tmp"))


def test_same_process_reader_waits_for_wallet_commit(
    wallet_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_sign.set_wallet(VALID_HD)
    real_atomic_write = _storage.atomic_write
    writer_entered = threading.Event()
    release_writer = threading.Event()
    reader_done = threading.Event()
    failures: list[BaseException] = []
    observed: list[dict[str, Any]] = []

    def delayed_write(path: Path, data: bytes) -> None:
        writer_entered.set()
        if not release_writer.wait(timeout=5):
            raise RuntimeError("test writer release timed out")
        real_atomic_write(path, data)

    def write_wallet() -> None:
        try:
            extension_sign.set_wallet(VALID_RAW)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def read_wallet() -> None:
        try:
            observed.append(extension_sign._load_wallet_cfg())
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            reader_done.set()

    monkeypatch.setattr("mordred_hermes.keyvault.extension_sign.atomic_write", delayed_write)
    writer = threading.Thread(target=write_wallet)
    reader = threading.Thread(target=read_wallet)
    writer.start()
    assert writer_entered.wait(timeout=5)
    reader.start()
    assert not reader_done.wait(timeout=0.1), "reader bypassed the in-process config lock"
    release_writer.set()
    writer.join(timeout=5)
    reader.join(timeout=5)

    assert not writer.is_alive() and not reader.is_alive()
    assert failures == []
    assert observed == [VALID_RAW]


@pytest.mark.skipif(_fcntl is None, reason="fcntl is unavailable")
def test_wallet_lock_excludes_a_second_process(wallet_dir: Path) -> None:
    script = """
import fcntl
import os
import sys

fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit(0)
raise SystemExit(1)
"""
    with extension_sign._wallet_file_lock(wallet_dir):
        result = subprocess.run(
            [sys.executable, "-c", script, str(wallet_dir / ".wallet.lock")],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

    assert result.returncode == 0, result.stderr
