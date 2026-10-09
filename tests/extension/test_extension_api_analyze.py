"""Deterministic sign-request analysis (risk + ABI decode)."""

from __future__ import annotations

import pytest

from mordred_hermes.extension.api import analyze_sign

_ADDR = "0x" + "ab" * 20


def _transfer_data(to_hex_no0x: str, amount: int) -> str:
    return "0xa9059cbb" + "00" * 12 + to_hex_no0x + amount.to_bytes(32, "big").hex()


def test_personal_sign_readable_text_is_low_risk():
    analysis, decoded = analyze_sign("personal_sign", ["0x" + b"gm wagmi".hex(), _ADDR])
    assert analysis["risk"] == "low"
    assert decoded == {"payload_kind": "text", "message_preview": "gm wagmi"}


def test_personal_sign_opaque_payload_is_not_low_risk():
    """0xdeadbeef is not a message anyone can read, so the approval copy may
    not promise "no asset movement" (see test_extension_wallet.py)."""
    analysis, decoded = analyze_sign("personal_sign", ["0xdeadbeef", _ADDR])
    assert analysis["risk"] == "medium"
    assert decoded == {"payload_kind": "opaque_bytes"}


def test_erc20_transfer_decoded():
    data = _transfer_data("11" * 20, 100)
    analysis, decoded = analyze_sign("eth_sendTransaction", [{"to": _ADDR, "data": data, "value": "0x0"}])
    assert decoded["function"] == "transfer(address,uint256)"
    assert decoded["args"]["amount"] == "100"
    assert decoded["contract"] == _ADDR
    assert decoded["native_value_wei"] == "0"
    assert _ADDR in analysis["summary"]
    assert "0 wei" in analysis["summary"]
    assert any(_ADDR in warning and "0 wei" in warning for warning in analysis["warnings"])
    assert analysis["risk"] == "medium"


def test_erc20_transfer_with_native_value_is_high_risk_and_fully_disclosed():
    data = _transfer_data("11" * 20, 1)
    native_value = 100 * 10**18

    analysis, decoded = analyze_sign(
        "eth_sendTransaction",
        [{"to": _ADDR, "data": data, "value": hex(native_value)}],
    )

    assert analysis["risk"] == "high"
    assert str(native_value) in analysis["summary"]
    assert _ADDR in analysis["summary"]
    assert decoded["contract"] == _ADDR
    assert decoded["native_value_wei"] == str(native_value)
    assert any(str(native_value) in warning for warning in analysis["warnings"])
    assert any("同時" in warning for warning in analysis["warnings"])


def test_erc20_selector_with_trailing_calldata_is_not_presented_as_verified_abi():
    data = _transfer_data("11" * 20, 1) + "00"

    analysis, decoded = analyze_sign(
        "eth_sendTransaction",
        [{"to": _ADDR, "data": data, "value": "0x0"}],
    )

    assert "function" not in decoded
    assert "コントラクト呼び出し" in analysis["summary"]
    assert decoded == {"contract": _ADDR, "native_value_wei": "0"}


@pytest.mark.parametrize("selector", ["a9059cbb", "095ea7b3"])
def test_erc20_selector_with_dirty_address_padding_is_generic_contract_call(selector):
    data = "0x" + selector + "ff" * 12 + "22" * 20 + (1).to_bytes(32, "big").hex()

    analysis, decoded = analyze_sign(
        "eth_sendTransaction",
        [{"to": _ADDR, "data": data, "value": "0x0"}],
    )

    assert "function" not in decoded
    assert "コントラクト呼び出し" in analysis["summary"]
    assert decoded == {"contract": _ADDR, "native_value_wei": "0"}


def test_unlimited_approve_high_risk():
    max_uint = (1 << 256) - 1
    data = "0x095ea7b3" + "00" * 12 + "22" * 20 + max_uint.to_bytes(32, "big").hex()
    analysis, decoded = analyze_sign("eth_sendTransaction", [{"to": _ADDR, "data": data}])
    assert decoded["function"] == "approve(address,uint256)"
    assert decoded["contract"] == _ADDR
    assert decoded["native_value_wei"] == "0"
    assert analysis["risk"] == "high"
    assert any("無制限" in w for w in analysis["warnings"])


def test_erc20_approve_with_native_value_is_high_risk():
    data = "0x095ea7b3" + "00" * 12 + "22" * 20 + (1).to_bytes(32, "big").hex()

    analysis, decoded = analyze_sign(
        "eth_sendTransaction",
        [{"to": _ADDR, "data": data, "value": "0x1"}],
    )

    assert analysis["risk"] == "high"
    assert decoded["native_value_wei"] == "1"
    assert any("同時" in warning for warning in analysis["warnings"])


def test_plain_eth_transfer():
    analysis, _ = analyze_sign("eth_sendTransaction", [{"to": _ADDR, "value": hex(2 * 10**18)}])
    assert analysis["risk"] == "medium"  # >= 1 ETH
    assert "ETH" in analysis["summary"]
