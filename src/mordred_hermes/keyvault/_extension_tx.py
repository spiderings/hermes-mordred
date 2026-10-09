"""mordred_hermes.keyvault._extension_tx — extension transaction validation.

Extracted from :mod:`extension_sign` (the public facade) to keep that module
under the repo's 800-line guideline. What lives here is the pure, side-effect
free half of ``eth_sendTransaction`` handling: parsing and bounds-checking every
caller-supplied field (:func:`validate_transaction_request`) and freezing the
exact representation Hermes signs (:func:`canonicalize_transaction`).

Nothing in this module performs I/O, touches the keyvault, or imports
``eth_account`` / ``rlp`` — the signing flow itself (``_sign_hash``,
``sign_transaction`` and its RLP encoder) deliberately stays in
``extension_sign``, which is also where the module's monkeypatch seams live.

The dependency runs one way (``extension_sign`` -> this module); nothing here
imports ``extension_sign``, so there is no load cycle to break.
``extension_sign`` re-exports every name below, preserving each one's import
path and object identity. External call sites that still go through the
facade — ``extension_sign.validate_transaction_request`` in
``extension/rpc.py``, ``extension_sign.canonicalize_transaction`` and
``extension_sign.TransactionFieldsMissing`` in ``extension/wallet.py`` and the
tests — keep resolving unchanged. But :func:`canonicalize_transaction`'s own
call to :func:`validate_transaction_request` below resolves by local name, so
``monkeypatch.setattr(extension_sign, "validate_transaction_request", ...)``
no longer reaches it; patch this module directly to intercept that internal
call.
"""

from __future__ import annotations

from typing import Any


class TransactionFieldsMissing(Exception):
    """A transaction is missing fields Hermes cannot fill without an RPC node."""

    def __init__(self, missing: list[str]) -> None:
        super().__init__("missing transaction fields: " + ", ".join(missing))
        self.missing = missing


_MAX_TRANSACTION_QUANTITY = (1 << 256) - 1
_TRANSACTION_FIELDS = frozenset(
    {
        "type",
        "chainId",
        "nonce",
        "gas",
        "gasPrice",
        "maxPriorityFeePerGas",
        "maxFeePerGas",
        "to",
        "value",
        "data",
        "accessList",
        "from",
    }
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _transaction_quantity(field: str, value: Any) -> int:
    """Parse one unsigned Ethereum JSON-RPC quantity without coercion.

    ``bool``, floats, signed strings and objects with a surprising ``__str__``
    are deliberately rejected.  The old permissive conversion made negative
    values serialize as zero and let the approval prompt describe a different
    transaction from the bytes that were ultimately signed.
    """
    if isinstance(value, bool):
        raise ValueError(f"invalid_transaction_quantity:{field}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        if value.startswith("0x"):
            digits = value[2:]
            if not digits or any(char not in _HEX_DIGITS for char in digits):
                raise ValueError(f"invalid_transaction_quantity:{field}")
            number = int(digits, 16)
        else:
            if not value or not value.isascii() or not value.isdecimal():
                raise ValueError(f"invalid_transaction_quantity:{field}")
            number = int(value, 10)
    else:
        raise ValueError(f"invalid_transaction_quantity:{field}")
    if number < 0 or number > _MAX_TRANSACTION_QUANTITY:
        raise ValueError(f"invalid_transaction_quantity:{field}")
    return number


def _canonical_address(field: str, value: Any, *, allow_empty: bool) -> str | None:
    if allow_empty and value in (None, ""):
        return None
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"invalid_transaction_address:{field}")
    digits = value[2:]
    if len(digits) != 40 or any(char not in _HEX_DIGITS for char in digits):
        raise ValueError(f"invalid_transaction_address:{field}")
    return "0x" + digits.lower()


def _canonical_data(value: Any) -> str:
    if value in (None, ""):
        return "0x"
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("invalid_transaction_data")
    digits = value[2:]
    if len(digits) % 2 or any(char not in _HEX_DIGITS for char in digits):
        raise ValueError("invalid_transaction_data")
    return "0x" + digits.lower()


def _validated_transaction_chain_id(tx: dict[str, Any], chain_id: int) -> int:
    parsed_chain_id = _transaction_quantity("chainId", chain_id)
    if parsed_chain_id == 0:
        raise ValueError("invalid_transaction_chain_id")
    supplied_chain_id = tx.get("chainId")
    if supplied_chain_id not in (None, "") and _transaction_quantity("chainId", supplied_chain_id) != parsed_chain_id:
        raise ValueError("transaction_chain_id_mismatch")
    return parsed_chain_id


def _transaction_fee_mode(tx: dict[str, Any]) -> str | None:
    """Return ``legacy`` / ``eip1559`` or ``None`` when fees are unspecified."""
    supplied_type = tx.get("type")
    explicit_type: int | None = None
    if supplied_type not in (None, ""):
        explicit_type = _transaction_quantity("type", supplied_type)
        if explicit_type not in (0, 2):
            raise ValueError("unsupported_transaction_type")

    has_legacy_fee = tx.get("gasPrice") not in (None, "")
    has_max_fee = tx.get("maxFeePerGas") not in (None, "")
    has_priority_fee = tx.get("maxPriorityFeePerGas") not in (None, "")
    has_eip1559_fee = has_max_fee or has_priority_fee
    if has_legacy_fee and has_eip1559_fee:
        raise ValueError("conflicting_transaction_fee_fields")
    if explicit_type == 0 and has_eip1559_fee:
        raise ValueError("conflicting_transaction_fee_fields")
    if explicit_type == 2 and has_legacy_fee:
        raise ValueError("conflicting_transaction_fee_fields")
    if explicit_type == 2 or (explicit_type is None and has_eip1559_fee):
        return "eip1559"
    if explicit_type == 0 or has_legacy_fee:
        return "legacy"
    return None


def _validate_present_transaction_fields(tx: dict[str, Any]) -> None:
    """Parse every caller-supplied quantity/address/data field that is present.

    Split out of :func:`_validate_present_transaction_values` for cyclomatic
    headroom only; the field order is unchanged, so a transaction carrying
    several malformed fields still reports the same first one.
    """
    for field in ("nonce", "gas", "gasPrice", "maxPriorityFeePerGas", "maxFeePerGas"):
        if tx.get(field) not in (None, ""):
            _transaction_quantity(field, tx[field])
    if "value" in tx:
        _transaction_quantity("value", tx["value"])
    if tx.get("to") not in (None, ""):
        _canonical_address("to", tx["to"], allow_empty=True)
    if tx.get("from") not in (None, ""):
        _canonical_address("from", tx["from"], allow_empty=False)
    if "data" in tx:
        _canonical_data(tx["data"])


def _validate_present_fee_bounds(tx: dict[str, Any]) -> None:
    """Reject a tip larger than the fee cap when the caller supplied both.

    Runs after :func:`_validate_present_transaction_fields`, so both values are
    already known to parse; :func:`_canonical_fee_fields` repeats the same check
    on the frozen canonical transaction.
    """
    if tx.get("maxPriorityFeePerGas") not in (None, "") and tx.get("maxFeePerGas") not in (None, ""):
        max_priority_fee = _transaction_quantity("maxPriorityFeePerGas", tx["maxPriorityFeePerGas"])
        max_fee = _transaction_quantity("maxFeePerGas", tx["maxFeePerGas"])
        if max_priority_fee > max_fee:
            raise ValueError("transaction_priority_fee_exceeds_max_fee")


def _validate_present_transaction_values(tx: dict[str, Any]) -> None:
    if "accessList" in tx and tx["accessList"] != []:
        raise ValueError("unsupported_transaction_access_list")
    _validate_present_transaction_fields(tx)
    _validate_present_fee_bounds(tx)


def validate_transaction_request(tx: dict[str, Any], *, chain_id: int) -> str | None:
    """Validate every caller-supplied field without requiring RPC-filled ones.

    This preflight is shared by the RPC filler and final canonicalizer so an
    unsupported type, conflicting fee model, malformed quantity/address/data,
    or ignored field is rejected before any request reaches the configured RPC.
    """
    if not isinstance(tx, dict):
        raise ValueError("invalid_transaction")
    unknown = sorted(field for field in tx if field not in _TRANSACTION_FIELDS)
    if unknown:
        raise ValueError("unsupported_transaction_fields:" + ",".join(unknown))

    _validated_transaction_chain_id(tx, chain_id)
    fee_mode = _transaction_fee_mode(tx)
    _validate_present_transaction_values(tx)
    if "accessList" in tx and fee_mode != "eip1559":
        raise ValueError("transaction_access_list_requires_type_2")
    return fee_mode


def _validate_transaction_shape(tx: dict[str, Any], *, is_eip1559: bool) -> None:
    required = ["nonce", "gas"]
    if is_eip1559:
        required.extend(("maxFeePerGas", "maxPriorityFeePerGas"))
    else:
        required.append("gasPrice")
    missing = [field for field in required if tx.get(field) in (None, "")]
    if missing:
        raise TransactionFieldsMissing(missing)


def _canonical_fee_fields(tx: dict[str, Any], *, is_eip1559: bool) -> dict[str, str]:
    if not is_eip1559:
        return {"gasPrice": hex(_transaction_quantity("gasPrice", tx["gasPrice"]))}
    max_priority_fee = _transaction_quantity("maxPriorityFeePerGas", tx["maxPriorityFeePerGas"])
    max_fee = _transaction_quantity("maxFeePerGas", tx["maxFeePerGas"])
    if max_priority_fee > max_fee:
        raise ValueError("transaction_priority_fee_exceeds_max_fee")
    return {
        "maxPriorityFeePerGas": hex(max_priority_fee),
        "maxFeePerGas": hex(max_fee),
    }


def canonicalize_transaction(tx: dict[str, Any], *, chain_id: int = 1) -> dict[str, Any]:
    """Validate and freeze the exact transaction representation Hermes signs.

    Only legacy EIP-155 transactions and type-2 EIP-1559 transactions with an
    empty access list are supported.  Returning a JSON-friendly canonical dict
    gives the approval UI and :func:`sign_transaction` one shared source of
    truth: unsupported or ignored fields can no longer appear in the prompt and
    then disappear from the signed bytes.
    """
    fee_mode = validate_transaction_request(tx, chain_id=chain_id)
    parsed_chain_id = _transaction_quantity("chainId", chain_id)
    is_eip1559 = fee_mode == "eip1559"
    _validate_transaction_shape(tx, is_eip1559=is_eip1559)

    canonical: dict[str, Any] = {
        "type": "0x2" if is_eip1559 else "0x0",
        "chainId": hex(parsed_chain_id),
        "nonce": hex(_transaction_quantity("nonce", tx["nonce"])),
        **_canonical_fee_fields(tx, is_eip1559=is_eip1559),
    }
    canonical.update(
        {
            "gas": hex(_transaction_quantity("gas", tx["gas"])),
            "to": _canonical_address("to", tx.get("to"), allow_empty=True),
            "value": hex(_transaction_quantity("value", tx.get("value", 0))),
            "data": _canonical_data(tx.get("data")),
        }
    )
    if is_eip1559:
        canonical["accessList"] = []
    supplied_from = tx.get("from")
    if supplied_from not in (None, ""):
        canonical["from"] = _canonical_address("from", supplied_from, allow_empty=False)
    return canonical
