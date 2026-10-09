"""Extension signing API — sign_only surface for the Mordred Extension.

The browser extension never holds an Ethereum private key; it forwards
``personal_sign`` / ``eth_signTypedData_v4`` / ``eth_sendTransaction`` requests
over the gateway WebSocket and Hermes signs them here. The private scalar stays
inside the keyvault (Secure Enclave on macOS Apple Silicon): we use
``eth_account`` only to compute the 32-byte signing hash and to assemble the
result, then sign the hash via :mod:`mordred_hermes.keyvault.ethereum`.

Account selection: ``~/.hermes/extension/wallet.json`` may pin an account; if
absent and exactly one HD seed is stored, account ``m/44'/60'/0'/0/0`` is used.

See ``Mordred-Extension/SPEC.ja.md`` §5.5.

Module layout
-------------

This module grew past the repo's 800-line guideline and was split into two
cohesive siblings; it remains the single public facade and re-exports every
moved name below, so every ``mordred_hermes.keyvault.extension_sign.<name>``
import path keeps resolving to the same object (``is``-identical) it did
before the split:

- :mod:`._extension_config` — the ``wallet.json`` document layer: the
  wallet-config constants and exceptions, the private-directory/lock
  primitives, and the config schema validators.
- :mod:`._extension_tx` — the pure transaction layer:
  :func:`validate_transaction_request` and :func:`canonicalize_transaction`
  with their quantity/address/data parsers.

A re-export only guarantees the import path and object identity, not
*interception*. 23 of the moved names now have callers that live inside
``_extension_config`` / ``_extension_tx`` themselves and resolve the callee by
local name rather than through this module's attribute, so
``monkeypatch.setattr`` here no longer reaches those calls. For example,
patching ``extension_sign.validate_transaction_request`` still intercepts the
call from ``extension/rpc.py`` (which goes through this facade), but no
longer the call :func:`canonicalize_transaction` makes to it inside
``_extension_tx`` on the way from :func:`sign_transaction`. A test that needs
to intercept a moved name must patch it on the module it now lives in.

What stays here is the *live* half — the keyvault backend and audit sink, the
wallet-config I/O and account resolution, and the signing flow itself. That is
also where every monkeypatch seam lives (``_ext_dir``, ``_load_wallet_cfg``,
``atomic_write``, ``_backend``, ``_resolve_account``, ``_address_for_account``,
``_sign_hash``, ``_audit_writer``): a moved function calling one of these
through a local name would no longer be interceptable by patching this module,
so those call sites deliberately did not move.
"""

from __future__ import annotations

import functools
import json
import logging
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import ethereum

# Facade re-exports. The redundant ``as`` alias is the form mypy's
# ``no_implicit_reexport`` (implied by ``--strict``) recognizes as an explicit
# re-export for the leading-underscore names ``__all__`` cannot cover; the
# public names are additionally listed in ``__all__`` below. Every name that
# existed on this module before the split *and still belongs to it* is
# re-exported below, preserving its import path and object identity (see the
# "Module layout" section above for what that re-export does and does not
# guarantee). Five names this module used to expose only as import side
# effects — the stdlib modules ``os``, ``re``, ``stat``, ``contextlib`` and
# ``fcntl`` — are NOT re-exported: nothing in this package referenced them as
# ``extension_sign.<stdlib-name>``, so a stray reference now fails loudly with
# ``AttributeError`` instead of silently continuing to resolve.
from ._extension_config import _BIP32_CHILD_INDEX_LIMIT as _BIP32_CHILD_INDEX_LIMIT
from ._extension_config import _CANONICAL_CHAIN_DECIMAL as _CANONICAL_CHAIN_DECIMAL
from ._extension_config import _CANONICAL_CHAIN_HEX as _CANONICAL_CHAIN_HEX
from ._extension_config import _O_CLOEXEC as _O_CLOEXEC
from ._extension_config import _O_NOFOLLOW as _O_NOFOLLOW
from ._extension_config import _WALLET_CONFIG_ERROR as _WALLET_CONFIG_ERROR
from ._extension_config import _WALLET_CONFIG_MAX_BYTES as _WALLET_CONFIG_MAX_BYTES
from ._extension_config import _WALLET_DIRECTORY_ERROR as _WALLET_DIRECTORY_ERROR
from ._extension_config import _WALLET_FIELDS as _WALLET_FIELDS
from ._extension_config import _WALLET_FILE as _WALLET_FILE
from ._extension_config import _WALLET_LOCK_FILE as _WALLET_LOCK_FILE
from ._extension_config import WalletConfigError as WalletConfigError
from ._extension_config import WalletNotConfigured as WalletNotConfigured
from ._extension_config import _canonical_chain_id as _canonical_chain_id
from ._extension_config import _DuplicateWalletKey as _DuplicateWalletKey
from ._extension_config import _normalize_wallet_cfg as _normalize_wallet_cfg
from ._extension_config import _raise_wallet_config_error as _raise_wallet_config_error
from ._extension_config import _required_nonempty_string as _required_nonempty_string
from ._extension_config import _validate_account_cfg as _validate_account_cfg
from ._extension_config import _validate_extension_dir as _validate_extension_dir
from ._extension_config import _validate_rpc_cfg as _validate_rpc_cfg
from ._extension_config import _validate_rpc_url as _validate_rpc_url
from ._extension_config import _validate_wallet_cfg as _validate_wallet_cfg
from ._extension_config import _wallet_file_lock as _wallet_file_lock
from ._extension_config import _wallet_json_object as _wallet_json_object
from ._extension_tx import _HEX_DIGITS as _HEX_DIGITS
from ._extension_tx import _MAX_TRANSACTION_QUANTITY as _MAX_TRANSACTION_QUANTITY
from ._extension_tx import _TRANSACTION_FIELDS as _TRANSACTION_FIELDS
from ._extension_tx import TransactionFieldsMissing as TransactionFieldsMissing
from ._extension_tx import _canonical_address as _canonical_address
from ._extension_tx import _canonical_data as _canonical_data
from ._extension_tx import _canonical_fee_fields as _canonical_fee_fields
from ._extension_tx import _transaction_fee_mode as _transaction_fee_mode
from ._extension_tx import _transaction_quantity as _transaction_quantity
from ._extension_tx import _validate_present_transaction_values as _validate_present_transaction_values
from ._extension_tx import _validate_transaction_shape as _validate_transaction_shape
from ._extension_tx import _validated_transaction_chain_id as _validated_transaction_chain_id
from ._extension_tx import canonicalize_transaction as canonicalize_transaction
from ._extension_tx import validate_transaction_request as validate_transaction_request
from ._storage import atomic_write, safe_read

if TYPE_CHECKING:
    from ..privacy_check.audit import Writer

__all__ = [
    "TransactionFieldsMissing",
    "WalletConfigError",
    "WalletNotConfigured",
    "account_snapshot",
    "canonicalize_transaction",
    "chain_id_int",
    "get_address",
    "personal_sign",
    "rpc_url_for",
    "se_available",
    "set_wallet",
    "sign_transaction",
    "sign_typed_data_v4",
    "validate_transaction_request",
]

_log = logging.getLogger(__name__)
_KEY_ID_DEFAULT = "default"
_WALLET_THREAD_LOCK = threading.RLock()
_WINDOWS_WALLET_STORAGE = sys.platform == "win32"

# Public fallback RPC endpoints; users should set their own via wallet.json.
_DEFAULT_RPC: dict[int, str] = {
    1: "https://cloudflare-eth.com",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
}


# --------------------------------------------------------------------------- #
# Backend / config
# --------------------------------------------------------------------------- #


def se_available() -> bool:
    try:
        from . import native

        return bool(native.is_secure_enclave_available())
    except Exception:
        return False


def _backend() -> Any:
    from ._seckey_backend import _SecKeyBackend

    return _SecKeyBackend()


def _ext_dir() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / "extension"


def _audit_log_path() -> Path:
    """``<HERMES_BASE>/mordred/audit.log`` — the same file ``network`` /
    ``llm_guard`` / ``privacy_check`` append to.

    Resolved the same way :func:`_ext_dir` already resolves the hermes home
    (a fresh ``hermes_constants.get_hermes_home()`` call, not the
    import-time-frozen :data:`mordred_hermes._home.HERMES_BASE`) so this
    module keeps its existing import-cheapness contract: no package-root
    import pulls in the profile-aware home resolution at module-import time.
    ``.parent.parent`` of this path is ``<HERMES_BASE>``, matching
    :func:`mordred_hermes._audit_support.build_audit_writer`'s
    ``keyvault_home = path.parent.parent`` contract.
    """
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / "mordred" / "audit.log"


@functools.lru_cache(maxsize=1)
def _audit_writer() -> Writer:
    """Module-local reference to the shared extension-sign audit writer.

    Zero-arg (unlike ``network`` / ``llm_guard``'s ``_build_audit_writer(path)``)
    because this module deliberately never freezes ``HERMES_BASE`` at import
    time (see :func:`_audit_log_path`); the path is recomputed on the first
    call. The local cache preserves the test ``cache_clear()`` API, while
    :mod:`mordred_hermes._audit_support` owns the normalized-path singleton so
    clearing this cache never closes a writer another plugin is using. The
    :mod:`mordred_hermes._audit_support` import happens here, at first call,
    not at module scope, so plugin discovery stays cheap.
    """
    from .._audit_support import build_audit_writer

    return build_audit_writer(_audit_log_path())


def _audit_sink(entry: dict[str, Any]) -> None:
    """Best-effort audit for extension-driven Enclave key use.

    The extension is the one path where a remote DApp — over the gateway
    WebSocket — drives Secure-Enclave key use directly: ``personal_sign`` /
    ``eth_signTypedData_v4`` / ``eth_sendTransaction`` all route through
    :func:`_sign_hash` / :func:`get_address`, which pass this sink to the wrap
    layer as ``audit_sink``. Without this, the ``keyvault.unwrap_authorized`` /
    ``keyvault.unwrap_denied`` events that same wrap layer emits for every
    other Enclave use (and that :func:`...keyvault.log_encryption.decrypt_log_file`
    records durably) were silently dropped for the extension path, leaving no
    tamper-evident trail for fund-moving operations. Now appended to the same
    encryption-aware ``audit.log`` writer ``network`` / ``llm_guard`` /
    ``privacy_check`` use (see :func:`_audit_writer`).

    A signing operation must NEVER fail because the audit write failed — the
    same contract every other ``audit_sink`` call site in this package
    honors (``wrap.unwrap_dek``, ``recovery``, ``seed_display``) — so this
    catches broadly, including a possible failure to construct the writer
    itself. The DEBUG log line stays unconditional: it is cheap and aids live
    debugging even when the durable write fails.
    """
    _log.debug("extension_sign audit: %s", entry.get("event", "?"))
    try:
        from .._audit_support import safe_audit_append

        safe_audit_append(_audit_writer(), entry, logger=_log)
    except Exception as exc:  # best-effort: never fail a sign over an audit issue
        _log.error("extension_sign audit writer unavailable: %s", exc)


def _load_wallet_cfg() -> dict[str, Any]:
    """Load an explicit wallet, allowing discovery only when it is absent."""
    with _WALLET_THREAD_LOCK:
        directory = _ext_dir()
        if _WINDOWS_WALLET_STORAGE:
            from ._wallet_storage import read_wallet_bytes

            raw = read_wallet_bytes(directory)
            return {} if raw is None else _decode_wallet_cfg(raw)
        if not _validate_extension_dir(directory, create=False):
            return {}
        with _wallet_file_lock(directory):
            try:
                raw = safe_read(directory / _WALLET_FILE)
            except FileNotFoundError:
                return {}
            except OSError:
                _raise_wallet_config_error()
            return _decode_wallet_cfg(raw)


def _decode_wallet_cfg(raw: bytes) -> dict[str, Any]:
    if len(raw) > _WALLET_CONFIG_MAX_BYTES:
        _raise_wallet_config_error()
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_wallet_json_object)
    except (UnicodeDecodeError, ValueError):
        _raise_wallet_config_error()
    return _validate_wallet_cfg(data)


def set_wallet(cfg: dict[str, Any]) -> None:
    """Validate and durably persist the extension wallet config."""
    validated = _normalize_wallet_cfg(cfg)
    payload = json.dumps(validated, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > _WALLET_CONFIG_MAX_BYTES:
        _raise_wallet_config_error()
    with _WALLET_THREAD_LOCK:
        directory = _ext_dir()
        if _WINDOWS_WALLET_STORAGE:
            from ._wallet_storage import write_wallet_bytes

            write_wallet_bytes(directory, payload)
            return
        _validate_extension_dir(directory, create=True)
        with _wallet_file_lock(directory):
            try:
                atomic_write(directory / _WALLET_FILE, payload)
            except OSError:
                _raise_wallet_config_error("extension wallet configuration could not be saved safely")


def chain_id_int() -> int:
    cfg = _load_wallet_cfg()
    cid = cfg.get("chain_id", 1)
    return _canonical_chain_id(cid)


def rpc_url_for(chain_id: int) -> str | None:
    """Resolve the JSON-RPC URL for a chain from wallet.json (`rpc` map or
    `rpc_url`), falling back to the built-in public endpoints."""
    cfg = _load_wallet_cfg()
    rpc_map = cfg.get("rpc") or {}
    url = rpc_map.get(str(chain_id)) or rpc_map.get(hex(chain_id)) or cfg.get("rpc_url")
    if url:
        return str(url)
    return _DEFAULT_RPC.get(chain_id)


def _resolve_account_from_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    if cfg.get("kind"):
        return cfg
    key_id = cfg.get("key_id", _KEY_ID_DEFAULT)
    seeds = ethereum.list_seed_envelope_ids(key_id)
    if len(seeds) == 1:
        return {
            "kind": "hd",
            "key_id": key_id,
            "seed_envelope_id": seeds[0],
            "index": 0,
            "account": 0,
            "change": 0,
        }
    raise WalletNotConfigured(
        "No extension wallet configured. Run `hermes-mordred keyvault eth ...` to "
        "create a key, then pin it in ~/.hermes/extension/wallet.json."
        if not seeds
        else "Multiple HD seeds stored; pin one in ~/.hermes/extension/wallet.json."
    )


def _resolve_account() -> dict[str, Any]:
    return _resolve_account_from_cfg(_load_wallet_cfg())


# --------------------------------------------------------------------------- #
# Hash signing (delegates to the SE-backed keyvault)
# --------------------------------------------------------------------------- #


def _sign_hash(message_hash: bytes) -> ethereum.EthereumSignature:
    acct = _resolve_account()
    backend, sink = _backend(), _audit_sink
    if acct["kind"] == "hd":
        return ethereum.sign_hash_hd(
            acct["key_id"],
            acct["seed_envelope_id"],
            int(acct.get("index", 0)),
            message_hash,
            backend=backend,
            audit_sink=sink,
            account=int(acct.get("account", 0)),
            change=int(acct.get("change", 0)),
        )
    return ethereum.sign_hash(
        acct["key_id"],
        acct["envelope_id"],
        message_hash,
        backend=backend,
        audit_sink=sink,
    )


def _address_for_account(acct: dict[str, Any]) -> str:
    backend, sink = _backend(), _audit_sink
    if acct["kind"] == "hd":
        address, _path = ethereum.derive_ethereum_key(
            acct["key_id"],
            acct["seed_envelope_id"],
            int(acct.get("index", 0)),
            backend=backend,
            audit_sink=sink,
            account=int(acct.get("account", 0)),
            change=int(acct.get("change", 0)),
        )
        return address
    return ethereum.get_ethereum_address(acct["key_id"], acct["envelope_id"], backend=backend, audit_sink=sink)


def get_address() -> str:
    return _address_for_account(_resolve_account())


def account_snapshot() -> tuple[str, int]:
    """Resolve one internally consistent address/chain pair.

    ``accounts_request`` must not read ``wallet.json`` twice: an atomic config
    replacement between those reads could otherwise advertise account A on
    chain B (or silently advertise mainnet after a corrupt replacement).
    """
    cfg = _load_wallet_cfg()
    account = _resolve_account_from_cfg(cfg)
    return _address_for_account(account), _canonical_chain_id(cfg.get("chain_id", 1))


# --------------------------------------------------------------------------- #
# EIP-191 / EIP-712 message signing
# --------------------------------------------------------------------------- #


def _eip191_hash(signable: Any) -> bytes:
    """32-byte EIP-191 signing hash of an ``eth_account`` ``SignableMessage``.

    Reconstructed from the message's public fields rather than eth_account's
    private ``_hash_eip191_message``: that underscore-prefixed helper is not part
    of the package's public API and has moved across releases, so a routine
    dependency bump could silently break all extension message signing (and,
    because CI does not install the ``ethereum`` extra, the break would not
    surface until runtime on a user's machine). ``SignableMessage`` is a public
    ``NamedTuple`` and the ``0x19 ‖ version ‖ header ‖ body`` layout is the
    EIP-191 spec itself, so this is stable. Verified byte-identical to
    ``_hash_eip191_message`` for both ``encode_defunct`` and ``encode_typed_data``.
    """
    from eth_hash.auto import keccak

    # bytes(...): eth-hash is untyped in the CI env (the ``ethereum`` extra isn't
    # installed there), so keccak(...) is ``Any`` and returning it directly trips
    # mypy --strict's no-any-return. keccak already yields bytes at runtime.
    return bytes(keccak(b"\x19" + signable.version + signable.header + signable.body))


def personal_sign(message: str) -> str:
    """EIP-191 ``personal_sign``. ``message`` is the DApp param (hex or text)."""
    from eth_account.messages import encode_defunct

    signable = encode_defunct(hexstr=message) if message.startswith("0x") else encode_defunct(text=message)
    sig = _sign_hash(_eip191_hash(signable))
    return "0x" + sig.hex


def sign_typed_data_v4(typed_data: str | dict[str, Any]) -> str:
    """EIP-712 ``eth_signTypedData_v4``. Accepts the JSON string or dict."""
    from eth_account.messages import encode_typed_data

    data = json.loads(typed_data) if isinstance(typed_data, str) else typed_data
    sig = _sign_hash(_eip191_hash(encode_typed_data(full_message=data)))
    return "0x" + sig.hex


# --------------------------------------------------------------------------- #
# Transaction signing (raw signed tx; broadcasting is out of scope in v1)
#
# The validation/canonicalization half lives in ``_extension_tx``; what stays
# here is the RLP assembly around the ``_sign_hash`` monkeypatch seam.
# --------------------------------------------------------------------------- #


def _rlp_int(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative_transaction_quantity")
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def sign_transaction(tx: dict[str, Any], *, chain_id: int = 1) -> dict[str, str]:
    """Sign a transaction, returning ``{"raw": "0x..", "hash": "0x.."}``.

    All nonce/gas/fee fields must already be present. The extension wallet fills
    and freezes them through its configured RPC before user approval, then
    broadcasts the returned bytes only after rechecking the chain. Direct
    callers remain responsible for filling those fields. EIP-1559
    (``maxFeePerGas``) and legacy (``gasPrice``) are both supported.
    """
    import rlp
    from eth_hash.auto import keccak

    canonical = canonicalize_transaction(tx, chain_id=chain_id)
    is_1559 = canonical["type"] == "0x2"
    signing_chain_id = int(canonical["chainId"], 16)
    nonce = int(canonical["nonce"], 16)
    gas = int(canonical["gas"], 16)
    to_value = canonical["to"]
    to = b"" if to_value is None else bytes.fromhex(to_value[2:])
    value = int(canonical["value"], 16)
    data = bytes.fromhex(canonical["data"][2:])

    if is_1559:
        max_prio = int(canonical["maxPriorityFeePerGas"], 16)
        max_fee = int(canonical["maxFeePerGas"], 16)
        unsigned = [
            _rlp_int(signing_chain_id),
            _rlp_int(nonce),
            _rlp_int(max_prio),
            _rlp_int(max_fee),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            canonical["accessList"],
        ]
        sighash = keccak(b"\x02" + rlp.encode(unsigned))
        sig = _sign_hash(sighash)
        y = sig.v - 27
        r = int.from_bytes(sig.r, "big")
        s_int = int.from_bytes(sig.s, "big")
        signed = [*unsigned, _rlp_int(y), _rlp_int(r), _rlp_int(s_int)]
        raw = b"\x02" + rlp.encode(signed)
    else:
        gas_price = int(canonical["gasPrice"], 16)
        unsigned = [
            _rlp_int(nonce),
            _rlp_int(gas_price),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            _rlp_int(signing_chain_id),
            b"",
            b"",
        ]
        sighash = keccak(rlp.encode(unsigned))
        sig = _sign_hash(sighash)
        v = (sig.v - 27) + 35 + 2 * signing_chain_id
        signed = [
            _rlp_int(nonce),
            _rlp_int(gas_price),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            _rlp_int(v),
            _rlp_int(int.from_bytes(sig.r, "big")),
            _rlp_int(int.from_bytes(sig.s, "big")),
        ]
        raw = rlp.encode(signed)

    return {"raw": "0x" + raw.hex(), "hash": "0x" + keccak(raw).hex()}
