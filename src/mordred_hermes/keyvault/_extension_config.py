"""mordred_hermes.keyvault._extension_config — extension wallet config layer.

Extracted from :mod:`extension_sign` (the public facade) to keep that module
under the repo's 800-line guideline. What lives here is the whole
``~/.hermes/extension/wallet.json`` *document* layer — everything that decides
whether a config is safe to act on, plus the private-directory and
cross-process lock primitives that guard it:

- the wallet-config constants and the two config exception types
  (:exc:`WalletNotConfigured` / :exc:`WalletConfigError`),
- :func:`_validate_extension_dir` and :func:`_wallet_file_lock` — the
  ``~/.hermes/extension/`` directory-safety and locking primitives,
- the config schema validators (:func:`_validate_wallet_cfg` and its
  account/chain/RPC halves) and :func:`_normalize_wallet_cfg`.

What deliberately stays in ``extension_sign`` is *signing and keyvault
resolution* — :func:`extension_sign._ext_dir`, :func:`extension_sign._load_wallet_cfg`,
:func:`extension_sign.set_wallet`, ``chain_id_int`` / ``rpc_url_for`` and the
account resolvers — because those are the module's live monkeypatch seams
(``monkeypatch.setattr(extension_sign, "_ext_dir", ...)`` /
``"_load_wallet_cfg"`` / ``"mordred_hermes.keyvault.extension_sign.atomic_write"``)
and a facade alias would no longer intercept a call made through a local name.

The dependency runs one way (``extension_sign`` -> this module); nothing here
imports ``extension_sign``, so there is no load cycle to break.
``extension_sign`` re-exports every name below, preserving each one's import
path and object identity — not, on its own, interception. A moved name that
also has a caller inside this module (or ``_extension_tx``) resolves that
call locally, so ``monkeypatch.setattr(extension_sign, "<name>", ...)`` no
longer reaches it; only callers that still go through
``extension_sign.<name>`` (e.g. ``extension_sign._normalize_wallet_cfg``,
``extension_sign._wallet_file_lock``, ``extension_sign._WALLET_CONFIG_MAX_BYTES``,
``extension_sign.WalletConfigError``, ...) remain interceptable there. See the
``extension_sign`` module docstring's "Module layout" section for the
concrete example.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn

from .._file_lock import private_flock

_WALLET_FILE = "wallet.json"
_WALLET_LOCK_FILE = ".wallet.lock"
_WALLET_CONFIG_MAX_BYTES = 1024 * 1024
_WALLET_CONFIG_ERROR = "extension wallet configuration is unreadable or invalid; refusing automatic wallet fallback"
_WALLET_DIRECTORY_ERROR = "extension wallet directory is unsafe; refusing wallet access"
# Nothing in this module reads these any more: ``_wallet_file_lock``'s open
# flags are assembled inside ``mordred_hermes._file_lock.private_flock``, so
# changing them here has no effect on the lock. They survive only because
# ``extension_sign`` re-exports them by name (a #137 facade guarantee).
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_CANONICAL_CHAIN_HEX = re.compile(r"0x[1-9a-f][0-9a-f]*\Z")
_CANONICAL_CHAIN_DECIMAL = re.compile(r"[1-9][0-9]*\Z")
_BIP32_CHILD_INDEX_LIMIT = 1 << 31
_WALLET_FIELDS = frozenset(
    {
        "kind",
        "key_id",
        "seed_envelope_id",
        "envelope_id",
        "index",
        "account",
        "change",
        "chain_id",
        "rpc",
        "rpc_url",
    }
)


class WalletNotConfigured(Exception):
    """No Ethereum account is configured/discoverable for the extension."""


class WalletConfigError(WalletNotConfigured):
    """An explicit wallet config exists but cannot safely select an account."""


def _raise_wallet_config_error(message: str = _WALLET_CONFIG_ERROR) -> NoReturn:
    """Raise a content-free config error suitable for extension responses."""
    raise WalletConfigError(message)


def _create_extension_dir(path: Path) -> os.stat_result:
    """Create the absent private extension directory and re-stat it.

    Split out of :func:`_validate_extension_dir` for cyclomatic headroom only;
    the ``mkdir`` -> ``lstat`` order and both failure branches are unchanged, so
    the same hostile input still trips the same error.
    """
    try:
        path.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        pass
    except OSError:
        _raise_wallet_config_error(_WALLET_DIRECTORY_ERROR)
    try:
        return path.lstat()
    except OSError:
        _raise_wallet_config_error(_WALLET_DIRECTORY_ERROR)


def _repair_extension_dir_mode(path: Path) -> int:
    """Chmod a legacy umask-created directory back to ``0o700``, re-reading it.

    Split out of :func:`_validate_extension_dir` for cyclomatic headroom only.
    The returned mode is re-read from the filesystem, never assumed from the
    chmod call, exactly as the inlined version did.
    """
    # Older set_wallet releases created this real directory using the
    # process umask. Repair that legacy state, but never chmod a symlink.
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
        return stat.S_IMODE(path.lstat().st_mode)
    except (NotImplementedError, OSError):
        _raise_wallet_config_error(_WALLET_DIRECTORY_ERROR)


def _validate_extension_dir(path: Path, *, create: bool) -> bool:
    """Validate the private extension directory, creating it for writes.

    ``False`` is returned only when the directory is genuinely absent during a
    read. A symlink, non-directory, or overly broad mode is never interpreted as
    a missing wallet configuration.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            return False
        info = _create_extension_dir(path)

    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _raise_wallet_config_error(_WALLET_DIRECTORY_ERROR)

    mode = stat.S_IMODE(info.st_mode)
    if mode != 0o700 and create:
        mode = _repair_extension_dir_mode(path)
    if mode != 0o700:
        _raise_wallet_config_error(_WALLET_DIRECTORY_ERROR)
    return True


def _reject_unsafe_wallet_lock(_lock_path: Path, _exc: OSError | None = None) -> NoReturn:
    """Fail closed on any wallet-lock descriptor problem.

    One handler covers all three failure points (``os.open``, the mode
    assertion, ``flock``) because this module deliberately answers every one of
    them with the same content-free :exc:`WalletConfigError` — an extension
    response must not disclose which part of the operator's filesystem was
    wrong. Raising here rather than inside ``private_flock`` also keeps the
    implicit ``__context__`` chaining the original ``except OSError:`` blocks
    produced (never ``raise ... from``).
    """
    _raise_wallet_config_error(_WALLET_DIRECTORY_ERROR)


@contextmanager
def _wallet_file_lock(directory: Path) -> Iterator[None]:
    """Exclusive cross-process lock for wallet config reads and writes.

    The descriptor lifecycle is
    :func:`mordred_hermes._file_lock.private_flock`. Three things stay specific
    to this call site and are passed in rather than defaulted: there is no
    in-process thread lock (the caller's ``_validate_extension_dir`` plus the
    flock are the whole contract), the open flags omit ``O_NONBLOCK`` exactly
    as before, and the unlock swallows :exc:`OSError` so a teardown failure
    cannot mask whatever the body was already raising.
    """
    with private_flock(
        directory / _WALLET_LOCK_FILE,
        nonblock=False,
        on_unsafe=_reject_unsafe_wallet_lock,
        on_open_error=_reject_unsafe_wallet_lock,
        on_lock_error=_reject_unsafe_wallet_lock,
        suppress_unlock_errors=True,
    ):
        yield


def _required_nonempty_string(cfg: dict[str, Any], field: str) -> None:
    value = cfg.get(field)
    if not isinstance(value, str) or not value.strip():
        _raise_wallet_config_error()


def _canonical_chain_id(value: object) -> int:
    if isinstance(value, bool):
        _raise_wallet_config_error()
    if isinstance(value, int):
        if value <= 0:
            _raise_wallet_config_error()
        return value
    if isinstance(value, str) and _CANONICAL_CHAIN_HEX.fullmatch(value):
        return int(value, 16)
    _raise_wallet_config_error()


def _validate_rpc_url(value: object) -> None:
    if not isinstance(value, str):
        _raise_wallet_config_error()
    try:
        # Reuse the exact structural/public-HTTPS boundary enforced before the
        # extension makes an RPC request. It deliberately permits path/query
        # API keys while rejecting userinfo and local/private literal targets.
        from ..extension import rpc as extension_rpc

        extension_rpc._validate_rpc_url(value)
    except Exception:
        _raise_wallet_config_error()


def _validate_account_cfg(cfg: dict[str, Any]) -> None:
    """Validate the key-selection half of a wallet config."""
    kind = cfg.get("kind")
    if kind not in {"hd", "raw"}:
        _raise_wallet_config_error()
    _required_nonempty_string(cfg, "key_id")
    if kind == "hd":
        _required_nonempty_string(cfg, "seed_envelope_id")
        if "envelope_id" in cfg:
            _raise_wallet_config_error()
        for field in ("index", "account", "change"):
            value = cfg.get(field, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= _BIP32_CHILD_INDEX_LIMIT:
                _raise_wallet_config_error()
    else:
        _required_nonempty_string(cfg, "envelope_id")
        if any(field in cfg for field in ("seed_envelope_id", "index", "account", "change")):
            _raise_wallet_config_error()


def _normalized_rpc_chain(chain: object) -> int:
    """Normalize one ``rpc`` map key (hex or decimal) to its canonical chain id.

    Split out of :func:`_validate_rpc_cfg` for cyclomatic headroom only. The
    non-string / hex / decimal / reject order is byte-for-byte the original
    ``if / elif / elif / else`` chain.
    """
    if not isinstance(chain, str):
        _raise_wallet_config_error()
    if _CANONICAL_CHAIN_HEX.fullmatch(chain):
        return _canonical_chain_id(chain)
    if _CANONICAL_CHAIN_DECIMAL.fullmatch(chain):
        return _canonical_chain_id(int(chain))
    _raise_wallet_config_error()


def _validate_rpc_map(rpc: object) -> None:
    """Validate the ``rpc`` chain -> endpoint map, rejecting duplicate chains.

    Two spellings of the same chain (``"1"`` and ``"0x1"``) are ambiguous, so
    the normalized ids must stay unique. Per entry the original order is kept:
    normalize the key, reject a duplicate, record it, then validate the URL.
    """
    if not isinstance(rpc, dict):
        _raise_wallet_config_error()
    normalized_chains: set[int] = set()
    for chain, url in rpc.items():
        normalized_chain = _normalized_rpc_chain(chain)
        if normalized_chain in normalized_chains:
            _raise_wallet_config_error()
        normalized_chains.add(normalized_chain)
        _validate_rpc_url(url)


def _validate_rpc_cfg(cfg: dict[str, Any]) -> None:
    """Validate chain and endpoint selections without performing network I/O."""
    if "chain_id" in cfg:
        _canonical_chain_id(cfg["chain_id"])
    if "rpc_url" in cfg:
        _validate_rpc_url(cfg["rpc_url"])
    if "rpc" in cfg:
        _validate_rpc_map(cfg["rpc"])


def _validate_wallet_cfg(data: object) -> dict[str, Any]:
    """Validate the fields that can select a key, chain, or RPC endpoint."""
    if not isinstance(data, dict) or any(not isinstance(key, str) for key in data):
        _raise_wallet_config_error()
    cfg = data
    if set(cfg).difference(_WALLET_FIELDS):
        _raise_wallet_config_error()
    _validate_account_cfg(cfg)
    _validate_rpc_cfg(cfg)
    return cfg


class _DuplicateWalletKey(ValueError):
    """Internal signal used to reject ambiguous duplicate JSON members."""


def _wallet_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateWalletKey
        obj[key] = value
    return obj


def _normalize_wallet_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    """Return an independent, JSON-native config snapshot for persistence.

    The public ``set_wallet`` input remains owned by its caller. Serializing it
    before validation both detaches nested mappings and closes the
    validate-then-serialize window in which another thread could otherwise
    mutate the already-approved object.
    """
    try:
        encoded = json.dumps(cfg, sort_keys=True, separators=(",", ":"))
        data = json.loads(encoded, object_pairs_hook=_wallet_json_object)
    except (TypeError, ValueError, RuntimeError):
        _raise_wallet_config_error()
    return _validate_wallet_cfg(data)
