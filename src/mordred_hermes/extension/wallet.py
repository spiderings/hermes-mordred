"""Wallet signer helpers and sign-request analysis for the Mordred Extension
API (:mod:`mordred_hermes.extension.api`).

Split out of ``api.py`` (which stayed over the repo's 800-line cap) — these
members are module-level and state-free: the keyvault wallet signer helpers
(run in an executor since Touch ID can block) and the deterministic
sign-request risk/decode analysis. ``api.py`` imports them by name so
``_Connection`` keeps calling them as bare names resolved through its own
module globals.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# Sign helpers (run in executor — keyvault calls may block on Touch ID)
# --------------------------------------------------------------------------- #

_ACCOUNT_BOUND_METHODS = frozenset({"personal_sign", "eth_signTypedData_v4"})

# Resolving the account snapshot is not free: it derives the address through the
# keyvault backend, which on a Secure-Enclave host means one authorization
# (Touch ID prompt) and one audit row per call. ``accounts_request`` is reachable
# by the *page* principal — a lower-privilege browser document — so without a
# bound anything holding the page token can drive prompts and audit growth at
# frame rate.
#
# The snapshot is public data (the address the extension already hands to dapps
# plus the configured chain id), so the bound is a short-lived cache rather than
# a refusal: caching is precisely what stops the repeated prompts, and it leaks
# nothing across principals because every principal that reaches this handler is
# entitled to the same value. The window mirrors
# ``gateway_plugin._NEEDS_KEY_RATE_LIMIT_SECONDS`` (PR #93).
_ACCOUNT_SNAPSHOT_TTL_SECONDS = 60.0
_clock: Callable[[], float] = time.monotonic
_account_snapshot_lock = threading.Lock()


class _CachedSnapshotFailure(RuntimeError):
    """A previous resolution failure, replayed within the cooldown window.

    Only the message and the original class name are kept. Caching the original
    exception would pin its traceback — and every frame local it references,
    which on a failure inside the keyvault can include key material — alive for
    the whole window.

    A FRESH instance is raised per replay. Re-raising one cached instance made
    Python append the raise site to its ``__traceback__`` every time, so a
    client polling ``accounts_request`` grew both the object and every logged
    traceback without bound (quadratic in the number of replays).
    """

    def __init__(self, message: str, original_type_name: str) -> None:
        super().__init__(message)
        self.original_type_name = original_type_name


@dataclass(frozen=True, slots=True)
class _AccountSnapshotEntry:
    """One resolved (or failed) snapshot, valid until ``expires_at``.

    A failure is stored as plain text (message + class name), never as the
    exception object, so nothing about the failing call survives the window.
    """

    fingerprint: tuple[object, ...]
    expires_at: float
    value: tuple[str, str] | None
    error_message: str | None = None
    error_type_name: str | None = None


_account_snapshot_cache: _AccountSnapshotEntry | None = None


@dataclass(frozen=True, slots=True)
class _PreparedSign:
    """Approval-time snapshot passed from preparation to signing."""

    params: list[Any]
    chain_id: str | None
    rpc_url: str | None
    rpc_endpoint: str | None
    expected_signer: str | None


def _get_address() -> str:
    from mordred_hermes.keyvault import extension_sign

    return extension_sign.get_address()


def _load_account_snapshot() -> tuple[str, str]:
    """Resolve ``(address, chain_id_hex)`` through the keyvault (uncached)."""
    from mordred_hermes.keyvault import extension_sign

    address, chain_id = extension_sign.account_snapshot()
    return address, hex(chain_id)


def _wallet_config_fingerprint() -> tuple[object, ...]:
    """Identity of the wallet config a cached snapshot was resolved from.

    Reconfiguring the wallet (``set_wallet``, an operator editing
    ``wallet.json``) rewrites the file, so stat identity is the invalidation
    hook. The path itself is part of the fingerprint: a different
    ``HERMES_HOME`` — profile switch, isolated test — is a different wallet.

    KNOWN GAP: with no ``wallet.json`` the account is discovered from the
    stored HD seeds (``_resolve_account_from_cfg``), and storing a seed does
    not touch this path. Such a change is therefore visible only after the TTL
    (≤60 s) — bounded and never silent (0→1 seed turns a cached
    ``WalletNotConfigured`` into an address; 1→2 turns it into an explicit
    "pin one" error). Enumerating the seed directory here would reach into the
    keyvault's on-disk layout on every request to close a one-minute window.
    """
    from mordred_hermes.keyvault import extension_sign

    try:
        path = extension_sign._ext_dir() / extension_sign._WALLET_FILE
    except Exception:  # pragma: no cover - only if the home cannot be resolved
        return ("unresolved-wallet-path",)
    try:
        stat_result = path.stat()
    except OSError:
        # No explicit config: the account is discovered from the stored seeds.
        return (str(path), None)
    return (str(path), stat_result.st_mtime_ns, stat_result.st_size, stat_result.st_ino)


def reset_account_snapshot_cache() -> None:
    """Forget the cached snapshot (tests, and any explicit reconfiguration)."""
    global _account_snapshot_cache
    with _account_snapshot_lock:
        _account_snapshot_cache = None


def _get_account_snapshot() -> tuple[str, str]:
    """Return ``(address, chain_id_hex)``, at most one resolution per window.

    Failures are cached for the same window as successes: a bound that only
    covers the happy path is bypassable by whatever made the resolution fail
    (a denied Touch ID prompt re-prompts on the next frame otherwise).

    The resolution runs under the lock so a burst of concurrent requests
    collapses into one keyvault call instead of racing to authorize N times.
    """
    global _account_snapshot_cache
    fingerprint = _wallet_config_fingerprint()
    with _account_snapshot_lock:
        now = _clock()
        entry = _account_snapshot_cache
        if entry is not None and now < entry.expires_at and entry.fingerprint == fingerprint:
            if entry.value is not None:
                return entry.value
            # ``from None``: the replay carries no chained context, so its
            # traceback is exactly this raise site every time.
            raise _CachedSnapshotFailure(
                entry.error_message or "wallet_snapshot_unavailable",
                entry.error_type_name or "RuntimeError",
            ) from None
        expires_at = now + _ACCOUNT_SNAPSHOT_TTL_SECONDS
        try:
            value = _load_account_snapshot()
        except Exception as exc:
            _account_snapshot_cache = _AccountSnapshotEntry(fingerprint, expires_at, None, str(exc), type(exc).__name__)
            raise
        _account_snapshot_cache = _AccountSnapshotEntry(fingerprint, expires_at, value)
        return value


def _addresses_match(left: str, right: str) -> bool:
    """Compare Ethereum addresses without changing the canonical display form."""
    return left.casefold() == right.casefold()


def _validated_account_bound_params(
    method: str,
    params: list[Any],
) -> tuple[int, str, str | dict[str, Any]]:
    """Return ``(account_index, requested_account, payload)`` for RPC methods."""
    if method == "personal_sign":
        if len(params) != 2 or not isinstance(params[0], str) or not isinstance(params[1], str):
            raise ValueError("invalid_personal_sign_params")
        return 1, params[1], params[0]
    if method == "eth_signTypedData_v4":
        if len(params) != 2 or not isinstance(params[0], str) or not isinstance(params[1], (str, dict)):
            raise ValueError("invalid_eth_signTypedData_v4_params")
        return 0, params[0], params[1]
    raise ValueError(f"unsupported_method:{method}")


def _assert_current_signer(expected_signer: str) -> None:
    from mordred_hermes.keyvault import extension_sign

    if not _addresses_match(extension_sign.get_address(), expected_signer):
        raise RuntimeError("wallet_signer_changed")


def _recover_personal_signer(message: str, signature: str) -> str:
    from eth_account import Account
    from eth_account.messages import encode_defunct

    signable = encode_defunct(hexstr=message) if message.startswith("0x") else encode_defunct(text=message)
    return str(Account.recover_message(signable, signature=signature))


def _recover_typed_data_signer(typed_data: str | dict[str, Any], signature: str) -> str:
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    data = json.loads(typed_data) if isinstance(typed_data, str) else typed_data
    return str(Account.recover_message(encode_typed_data(full_message=data), signature=signature))


def _recover_transaction_signer(raw_transaction: str) -> str:
    from eth_account import Account

    return str(Account.recover_transaction(raw_transaction))


def _assert_recovered_signer(actual_signer: str, expected_signer: str) -> None:
    if not _addresses_match(actual_signer, expected_signer):
        raise RuntimeError("wallet_signer_changed")


def _freeze_transaction_signer(tx: dict[str, Any], expected_signer: str) -> None:
    supplied_from = tx.get("from")
    if supplied_from not in (None, "") and not _addresses_match(str(supplied_from), expected_signer):
        raise ValueError("transaction_from_mismatch")
    tx["from"] = expected_signer


def _do_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
    expected_signer: str | None = None,
) -> str:
    from mordred_hermes.keyvault import extension_sign

    if method in _ACCOUNT_BOUND_METHODS:
        if expected_signer is None:
            raise ValueError("missing_expected_signer")
        _account_index, requested_signer, payload = _validated_account_bound_params(method, params)
        if not _addresses_match(requested_signer, expected_signer):
            raise RuntimeError("signer_snapshot_mismatch")
        _assert_current_signer(expected_signer)
        if method == "personal_sign":
            if not isinstance(payload, str):
                raise ValueError("invalid_personal_sign_params")
            signature = extension_sign.personal_sign(payload)
            try:
                actual_signer = _recover_personal_signer(payload, signature)
            except Exception as exc:
                raise RuntimeError("signature_signer_verification_failed") from exc
        else:
            signature = extension_sign.sign_typed_data_v4(payload)
            try:
                actual_signer = _recover_typed_data_signer(payload, signature)
            except Exception as exc:
                raise RuntimeError("signature_signer_verification_failed") from exc
        _assert_recovered_signer(actual_signer, expected_signer)
        return signature
    if method == "eth_sendTransaction":
        if expected_signer is None:
            raise ValueError("missing_expected_signer")
        return _send_prepared_transaction(
            params[0] if params else {},
            chain_id_hex,
            rpc_url,
            expected_signer=expected_signer,
        )
    raise ValueError(f"unsupported_method:{method}")


def _resolve_chain_id(chain_id_hex: str | None) -> int:
    from mordred_hermes.keyvault import extension_sign

    try:
        chain_id = int(chain_id_hex, 16) if chain_id_hex else extension_sign.chain_id_int()
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_chain_id") from exc
    if chain_id <= 0:
        raise ValueError("invalid_chain_id")
    return chain_id


def _prepare_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
) -> _PreparedSign:
    """Freeze all signer- and transaction-affecting fields before approval.

    Account-bound message methods validate their standard parameter order and
    canonicalize the requested account to the exact keyvault address.
    ``eth_sendTransaction`` additionally freezes nonce, gas, fees, chain and RPC
    URL. The signer is retained separately for an approval-time recheck.
    """
    if method in _ACCOUNT_BOUND_METHODS:
        return _prepare_account_bound_sign(method, params, chain_id_hex, rpc_url)
    if method == "eth_sendTransaction":
        return _prepare_transaction_sign(params, chain_id_hex, rpc_url)
    return _PreparedSign(params, chain_id_hex, rpc_url, None, None)


def _prepare_account_bound_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None,
    rpc_url: str | None,
) -> _PreparedSign:
    account_index, requested_signer, _payload = _validated_account_bound_params(method, params)

    from mordred_hermes.keyvault import extension_sign

    expected_signer = extension_sign.get_address()
    if not _addresses_match(requested_signer, expected_signer):
        raise ValueError(f"{method}_account_mismatch")
    frozen_params = list(params)
    frozen_params[account_index] = expected_signer
    return _PreparedSign(frozen_params, chain_id_hex, rpc_url, None, expected_signer)


def _prepare_transaction_sign(
    params: list[Any],
    chain_id_hex: str | None,
    rpc_url: str | None,
) -> _PreparedSign:
    if not params or not isinstance(params[0], dict):
        raise ValueError("invalid_transaction_params")

    from mordred_hermes.keyvault import extension_sign

    from . import rpc as extension_rpc

    configured_chain_id = extension_sign.chain_id_int()
    chain_id = _resolve_chain_id(chain_id_hex)
    if chain_id != configured_chain_id:
        raise ValueError("transaction_chain_id_not_allowed")
    tx = dict(params[0])
    supplied_chain = tx.get("chainId")
    if supplied_chain not in (None, ""):
        supplied_chain_text = str(supplied_chain)
        try:
            supplied_chain_id = (
                int(supplied_chain_text, 16) if supplied_chain_text.startswith("0x") else int(supplied_chain_text)
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_transaction_chain_id") from exc
        if supplied_chain_id != chain_id:
            raise ValueError("transaction_chain_id_mismatch")

    # Reject unsupported transaction types/fields and conflicting fee models
    # before a malformed request can trigger any configured-RPC traffic.
    preflight_tx = dict(tx)
    # ``from`` is compared case-insensitively with the keyvault address and
    # replaced by that canonical address below; validate the frozen value, not
    # a harmless alternate spelling supplied by the extension.
    preflight_tx.pop("from", None)
    extension_sign.validate_transaction_request(preflight_tx, chain_id=chain_id)
    configured_rpc = extension_sign.rpc_url_for(chain_id)
    if rpc_url:
        # A paired extension may report the dapp's selected RPC, but it cannot
        # make the host contact an arbitrary endpoint before approval. Only an
        # exact operator-selected wallet endpoint is eligible.
        extension_rpc._rpc_endpoint_display(rpc_url)
        if configured_rpc is None or not secrets.compare_digest(rpc_url, configured_rpc):
            raise ValueError("rpc_endpoint_not_allowed")
    resolved_rpc = configured_rpc
    if resolved_rpc is None:
        # ``eth_sendTransaction`` promises a broadcast transaction hash. A raw
        # signed RLP blob is not a compatible success result; sign-only needs a
        # separate protocol method.
        raise ValueError("transaction_rpc_required")
    rpc_endpoint = extension_rpc._rpc_endpoint_display(resolved_rpc)
    expected_signer = extension_sign.get_address()
    _freeze_transaction_signer(tx, expected_signer)
    tx = extension_rpc.fill_transaction(resolved_rpc, tx, expected_signer, chain_id)
    # The RPC filler currently preserves all caller fields. Canonicalize again
    # at the boundary so even a future implementation cannot replace the signer
    # that the user is about to approve.
    tx["from"] = expected_signer

    # sign_transaction takes chain_id separately and verifies tx["chainId"].
    # Include the canonical value in the approved snapshot for the user, then
    # run the same canonicalizer sign_transaction uses.  This removes fields
    # the signer cannot represent only by rejecting them — never by silently
    # dropping or coercing them after the approval prompt.
    frozen_chain_id = hex(chain_id)
    tx["chainId"] = frozen_chain_id
    tx = extension_sign.canonicalize_transaction(tx, chain_id=chain_id)
    return _PreparedSign([tx], frozen_chain_id, resolved_rpc, rpc_endpoint, expected_signer)


def _send_prepared_transaction(
    tx: dict[str, Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
    *,
    expected_signer: str,
) -> str:
    """Sign an already-approved transaction and broadcast it.

    Missing nonce/gas/fee fields are never filled here: doing so after the
    approval prompt would sign content the user did not review. The keyvault
    address is re-resolved immediately before signing so changing wallet.json
    or its selected account cannot turn approval for one signer into a signature
    from another. ``eth_sendTransaction`` has no raw-transaction success mode:
    the frozen RPC must still serve the approved chain immediately before send.
    """
    from mordred_hermes.keyvault import extension_sign

    chain_id = _resolve_chain_id(chain_id_hex)
    if not rpc_url:
        raise RuntimeError("transaction_rpc_required")
    tx_signer = tx.get("from")
    if not isinstance(tx_signer, str) or not _addresses_match(tx_signer, expected_signer):
        raise RuntimeError("transaction_signer_mismatch")
    _assert_current_signer(expected_signer)
    canonical_tx = extension_sign.canonicalize_transaction(tx, chain_id=chain_id)
    if canonical_tx != tx:
        raise RuntimeError("transaction_snapshot_not_canonical")
    signed = extension_sign.sign_transaction(canonical_tx, chain_id=chain_id)
    try:
        actual_signer = _recover_transaction_signer(signed["raw"])
    except Exception as exc:
        raise RuntimeError("signature_signer_verification_failed") from exc
    _assert_recovered_signer(actual_signer, expected_signer)
    from . import rpc as extension_rpc

    try:
        remote_hash = extension_rpc.send_raw_transaction(
            rpc_url,
            signed["raw"],
            expected_chain_id=chain_id,
        )
    except Exception as exc:
        raise RuntimeError(f"broadcast_failed: {exc}") from exc
    if remote_hash.casefold() != signed["hash"].casefold():
        raise RuntimeError("broadcast_failed: RPC returned a mismatched transaction hash")
    return remote_hash


# --------------------------------------------------------------------------- #
# Deterministic sign-request analysis (risk + decode). An LLM pass can replace
# this later; keeping it deterministic makes it testable and offline-safe.
# --------------------------------------------------------------------------- #

# A bare 32-byte personal_sign payload is the shape of a Safe transaction hash
# or a meta-transaction digest — signable authority the operator cannot inspect.
_OPAQUE_HASH_BYTES = 32
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_MESSAGE_PREVIEW_CHARS = 512
_OPAQUE_PAYLOAD_WARNING = (
    "内容を検証できない不透明なデータです。Safe やメタトランザクションのダイジェストである場合、"
    "この署名だけでコントラクト操作や資産の移動がオフチェーンで承認される可能性があります。"
)

_ERC20_TRANSFER = "a9059cbb"
_ERC20_APPROVE = "095ea7b3"
_ERC20_CALLDATA_HEX_LEN = 8 + 64 + 64
_MAX_UINT = (1 << 256) - 1


def _is_canonical_erc20_call(data: str, selector: str) -> bool:
    """Recognize the exact selector/length with a canonical ABI address word."""
    return len(data) == _ERC20_CALLDATA_HEX_LEN and data[:8] == selector and data[8:32] == "0" * 24


def _is_readable_text(text: str) -> bool:
    """Whether a decoded payload is something the operator can actually read."""
    if not text.strip():
        return False
    return all(char.isprintable() or char in "\n\r\t" for char in text)


def _signer_hex_body(payload: str) -> str | None:
    """The hex body ``personal_sign`` will decode, or ``None`` if it will not.

    Mirrors ``keyvault/extension_sign.py`` ``personal_sign`` exactly:
    ``encode_defunct(hexstr=message) if message.startswith("0x")``. Three rules
    have to match byte for byte, because classifying different bytes than the
    ones being signed is how "no asset movement" ends up on a digest:

    * the prefix test is CASE-SENSITIVE — ``0X…`` is signed as literal text;
    * an odd-length body is LEFT-PADDED with one ``0``
      (``eth_utils.to_bytes(hexstr=…)``), so ``0x`` + 63 hex chars signs the
      same 32 bytes as the padded 64-char digest;
    * the decoder is ``binascii.unhexlify``, which rejects every non-hex
      character INCLUDING whitespace (``bytes.fromhex`` would accept it). Such
      a payload cannot be signed at all, so it is never described as readable.

    eth_utils is not imported here: it lives in the optional ``ethereum``
    extra, which the ``extension`` install does not guarantee.
    """
    if not payload.startswith("0x"):
        return None
    body = payload[2:]
    if any(char not in _HEX_DIGITS for char in body):
        return None
    return f"0{body}" if len(body) % 2 else body


def _classify_personal_sign_payload(payload: Any) -> tuple[str, str | None]:
    """Return ``(kind, readable_text)`` for a ``personal_sign`` message param.

    ``kind`` is ``"text"`` for an EIP-191 message the operator can read (plain
    or hex-encoded UTF-8), ``"opaque_hash"`` for a 32-byte digest — a Safe
    transaction hash, a meta-transaction digest — and ``"opaque_bytes"`` for
    anything else, including malformed params (this runs on unvalidated input).

    32 signed bytes are opaque BY RULE, not by readability: an attacker who
    wants a digest that also decodes to printable ASCII needs roughly 2**44
    keccak attempts, which is grindable. Length wins at 32 bytes; only other
    lengths may be reported as readable text.

    A hex-prefixed payload the signer cannot decode is classified opaque
    (over-warning) rather than shown as its own literal text.
    """
    if not isinstance(payload, str):
        return "opaque_bytes", None
    if not payload.startswith("0x"):
        # The signer signs the literal characters (encode_defunct(text=…)); the
        # 32-byte rule applies to those bytes too — a readable string whose
        # UTF-8 encoding is exactly 32 bytes signs the same digest-shaped input
        # as its hex spelling and must not be shown as harmless text.
        if len(payload.encode("utf-8")) == _OPAQUE_HASH_BYTES:
            return "opaque_hash", None
        return ("text", payload) if _is_readable_text(payload) else ("opaque_bytes", None)
    hex_body = _signer_hex_body(payload)
    if hex_body is None:
        return "opaque_bytes", None
    raw = bytes.fromhex(hex_body)
    if len(raw) == _OPAQUE_HASH_BYTES:
        return "opaque_hash", None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "opaque_bytes", None
    return ("text", decoded) if _is_readable_text(decoded) else ("opaque_bytes", None)


def _analyze_personal_sign(payload: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Risk/decode for ``personal_sign``.

    The old copy promised "資産移動なし" (no asset movement) for *every*
    payload. That is only true for a message the operator can read: an opaque
    digest may be a Safe transaction hash or a meta-transaction, where the
    signature alone authorizes contract actions or asset movement off-chain.
    """
    kind, text = _classify_personal_sign_payload(payload)
    if kind == "text":
        full = text or ""
        decoded: dict[str, Any] = {"payload_kind": kind, "message_preview": full[:_MESSAGE_PREVIEW_CHARS]}
        if len(full) > _MESSAGE_PREVIEW_CHARS:
            # The prompt must never look complete when it is not: an operator
            # who reads a truncated message could miss the part that matters.
            decoded["preview_truncated"] = True
        return ({"risk": "low", "summary": "メッセージ署名(資産移動なし)", "warnings": []}, decoded)
    warnings = [_OPAQUE_PAYLOAD_WARNING]
    if kind == "opaque_hash":
        summary = "不透明な32バイトハッシュへの署名(内容を検証できません)"
        warnings.append("32バイトのダイジェストは Safe のトランザクションハッシュ等である可能性があります。")
    else:
        summary = "不透明なバイト列への署名(内容を検証できません)"
    return ({"risk": "medium", "summary": summary, "warnings": warnings}, {"payload_kind": kind})


def analyze_sign(method: str, params: list[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if method == "personal_sign":
        return _analyze_personal_sign(params[0] if params else None)
    if method == "eth_signTypedData_v4":
        return (
            {"risk": "medium", "summary": "EIP-712 typed data 署名", "warnings": ["許可(permit)の可能性に注意"]},
            {"function": "eth_signTypedData_v4"},
        )
    if method == "eth_sendTransaction":
        return _analyze_tx(params[0] if params else {})
    return ({"risk": "medium", "summary": method, "warnings": []}, {})


def _analyze_tx(tx: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    data = str(tx.get("data") or "").removeprefix("0x")
    to = tx.get("to")
    value = _hex_to_int(tx.get("value"))
    warnings: list[str] = []
    decoded: dict[str, Any] = {}
    risk = "low"

    contract_context = {
        "contract": to,
        "native_value_wei": str(value),
    }
    context_summary = f"contract: {to}; native value: {value} wei"
    context_warning = f"呼び出し先コントラクト: {to} / ネイティブETH: {value} wei"

    if to is not None and _is_canonical_erc20_call(data, _ERC20_TRANSFER):
        recipient = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {
            "function": "transfer(address,uint256)",
            **contract_context,
            "args": {"to": recipient, "amount": str(amount)},
        }
        warnings.append(context_warning)
        risk = "high" if value > 0 else "medium"
        if value > 0:
            warnings.append("ERC-20呼び出しと同時にネイティブETHを送金します")
        summary = f"ERC-20 transfer: {amount} → {recipient} ({context_summary})"
    elif to is not None and _is_canonical_erc20_call(data, _ERC20_APPROVE):
        spender = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {
            "function": "approve(address,uint256)",
            **contract_context,
            "args": {"spender": spender, "amount": str(amount)},
        }
        warnings.append(context_warning)
        if amount >= _MAX_UINT:
            risk = "high"
            warnings.append("無制限の approve(残高全額を引き出せる権限)です")
        else:
            risk = "medium"
        if value > 0:
            risk = "high"
            warnings.append("ERC-20呼び出しと同時にネイティブETHを送金します")
        summary = f"ERC-20 approve: {spender} ({context_summary})"
    elif data:
        decoded = contract_context
        warnings.append(context_warning)
        risk = "high" if value > 0 else "medium"
        summary = f"コントラクト呼び出し ({context_summary})"
    elif value > 0:
        risk = "medium" if value >= 10**18 else "low"
        summary = f"ETH 送金: {value} wei → {to}"
    else:
        summary = f"トランザクション → {to}"

    return ({"risk": risk, "summary": summary, "warnings": warnings}, decoded)


def _hex_to_int(v: Any) -> int:
    if v is None or v == "":
        return 0
    if isinstance(v, int):
        return v
    s = str(v)
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return 0
