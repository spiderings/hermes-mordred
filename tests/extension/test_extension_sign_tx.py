"""Transaction signing correctness — assemble the raw tx via the keyvault hash
signer, then recover the sender with eth_account as an independent oracle."""

from __future__ import annotations

import pytest

# Web3 signing is an optional feature (hermes-mordred[ethereum] + eth-account).
# Skip the whole module when those deps aren't installed (e.g. base CI env).
eth_keys = pytest.importorskip("eth_keys")
pytest.importorskip("eth_account")
pytest.importorskip("rlp")
from eth_account import Account  # noqa: E402

from mordred_hermes.extension import wallet as extension_wallet  # noqa: E402
from mordred_hermes.keyvault import extension_sign  # noqa: E402
from mordred_hermes.keyvault.ethereum import EthereumSignature  # noqa: E402

_PRIV = eth_keys.keys.PrivateKey(b"\x42" * 32)
_ADDR = _PRIV.public_key.to_checksum_address()


@pytest.fixture(autouse=True)
def _stub_signer(monkeypatch):
    def fake_sign_hash(message_hash: bytes) -> EthereumSignature:
        sig = _PRIV.sign_msg_hash(message_hash)
        return EthereumSignature(
            v=sig.v + 27,
            r=sig.r.to_bytes(32, "big"),
            s=sig.s.to_bytes(32, "big"),
        )

    monkeypatch.setattr(extension_sign, "_sign_hash", fake_sign_hash)


def test_legacy_tx_recovers_sender():
    tx = {
        "nonce": "0x0",
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x1111111111111111111111111111111111111111",
        "value": "0xde0b6b3a7640000",  # 1 ETH
        "data": "0x",
    }
    out = extension_sign.sign_transaction(tx, chain_id=1)
    assert out["raw"].startswith("0x")
    assert Account.recover_transaction(out["raw"]) == _ADDR
    assert extension_wallet._recover_transaction_signer(out["raw"]) == _ADDR


def test_eip1559_tx_recovers_sender():
    tx = {
        "type": "0x2",
        "nonce": 5,
        "maxPriorityFeePerGas": "0x3b9aca00",
        "maxFeePerGas": "0x77359400",
        "gas": "0x5208",
        "to": "0x2222222222222222222222222222222222222222",
        "value": "0x0",
        "data": "0xa9059cbb",
    }
    out = extension_sign.sign_transaction(tx, chain_id=11155111)
    assert Account.recover_transaction(out["raw"]) == _ADDR


def test_transaction_canonicalization_is_the_signed_representation():
    tx = {
        "nonce": 0,
        "gasPrice": "1000000000",
        "gas": "0x05208",
        "to": "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD",
        "from": _ADDR,
    }

    assert extension_sign.canonicalize_transaction(tx, chain_id=1) == {
        "type": "0x0",
        "chainId": "0x1",
        "nonce": "0x0",
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "value": "0x0",
        "data": "0x",
        "from": _ADDR.lower(),
    }


@pytest.mark.parametrize("tx_type", ["0x1", 1, "0x3", 3])
def test_unsupported_transaction_types_are_rejected(tx_type):
    tx = {
        "type": tx_type,
        "nonce": "0x0",
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x" + "11" * 20,
    }

    with pytest.raises(ValueError, match="unsupported_transaction_type"):
        extension_sign.sign_transaction(tx, chain_id=1)


def test_nonempty_access_list_is_rejected_instead_of_silently_dropped():
    tx = {
        "type": "0x2",
        "nonce": "0x0",
        "maxPriorityFeePerGas": "0x3b9aca00",
        "maxFeePerGas": "0x77359400",
        "gas": "0x5208",
        "to": "0x" + "11" * 20,
        "accessList": [{"address": "0x" + "22" * 20, "storageKeys": []}],
    }

    with pytest.raises(ValueError, match="unsupported_transaction_access_list"):
        extension_sign.sign_transaction(tx, chain_id=1)


def test_negative_nonce_is_rejected_instead_of_becoming_zero():
    tx = {
        "nonce": -1,
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x" + "11" * 20,
    }

    with pytest.raises(ValueError, match="invalid_transaction_quantity:nonce"):
        extension_sign.sign_transaction(tx, chain_id=1)


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"nonce": "0xnot-hex"}, "invalid_transaction_quantity:nonce"),
        ({"value": 1 << 256}, "invalid_transaction_quantity:value"),
        ({"to": "0x1234"}, "invalid_transaction_address:to"),
        ({"data": "0x123"}, "invalid_transaction_data"),
        ({"blobVersionedHashes": []}, "unsupported_transaction_fields:blobVersionedHashes"),
        ({"maxFeePerGas": "0x2", "maxPriorityFeePerGas": "0x1"}, "conflicting_transaction_fee_fields"),
    ],
)
def test_malformed_or_unrepresentable_transactions_are_rejected(updates, error):
    tx = {
        "nonce": "0x0",
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x" + "11" * 20,
        **updates,
    }

    with pytest.raises(ValueError, match=error):
        extension_sign.sign_transaction(tx, chain_id=1)


@pytest.mark.parametrize(
    ("tx", "error"),
    [
        ({"to": "0xzz", "from": "0xzz"}, "invalid_transaction_address:to"),
        ({"accessList": [1], "nonce": "bad"}, "unsupported_transaction_access_list"),
        ({"maxPriorityFeePerGas": 100, "maxFeePerGas": 1, "to": "0xzz"}, "invalid_transaction_address:to"),
        ({"gasPrice": "0x1", "maxFeePerGas": "0x2", "bogus": "x"}, "unsupported_transaction_fields:bogus"),
    ],
)
def test_validate_transaction_request_reports_first_error_in_field_order(tx, error):
    """A transaction that fails several checks at once must always report the
    same first one, so a reorder inside ``_extension_tx``'s split-out
    validators (``_validate_present_transaction_fields``,
    ``_validate_present_transaction_values``, ``validate_transaction_request``)
    fails this test. Order pinned: ``to`` before ``from``; ``accessList``
    before per-field values; per-field values (``to``) before fee bounds;
    unknown fields before the fee-mode conflict check."""
    with pytest.raises(ValueError, match=error):
        extension_sign.validate_transaction_request(tx, chain_id=1)


def test_missing_fields_raises():
    with pytest.raises(extension_sign.TransactionFieldsMissing) as ei:
        extension_sign.sign_transaction({"to": "0x" + "00" * 20, "value": "0x1"}, chain_id=1)
    assert "gas" in ei.value.missing


def test_personal_sign_recovers_signer(monkeypatch):
    msg = "Login to Mordred"
    out = extension_sign.personal_sign(msg)
    assert Account.recover_message(__import__("eth_account").messages.encode_defunct(text=msg), signature=out) == _ADDR
    assert extension_wallet._recover_personal_signer(msg, out) == _ADDR


def test_typed_data_sign_recovers_signer():
    typed = {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}],
            "Mail": [{"name": "contents", "type": "string"}],
        },
        "primaryType": "Mail",
        "domain": {"name": "Mordred"},
        "message": {"contents": "hi"},
    }
    out = extension_sign.sign_typed_data_v4(typed)
    from eth_account.messages import encode_typed_data

    assert Account.recover_message(encode_typed_data(full_message=typed), signature=out) == _ADDR
    assert extension_wallet._recover_typed_data_signer(typed, out) == _ADDR


def test_eip191_hash_matches_eth_account_private_helper():
    """``_eip191_hash`` reconstructs the EIP-191 hash from SignableMessage's
    public fields; it MUST stay byte-identical to eth_account's private
    ``_hash_eip191_message`` (which we no longer import) for both message forms,
    so a future eth_account bump that moves the private helper can't silently
    change the hash we sign."""
    from eth_account.messages import _hash_eip191_message, encode_defunct, encode_typed_data

    defunct = encode_defunct(text="hello world")
    assert extension_sign._eip191_hash(defunct) == _hash_eip191_message(defunct)

    typed = {
        "types": {"EIP712Domain": [{"name": "name", "type": "string"}], "M": [{"name": "a", "type": "uint256"}]},
        "primaryType": "M",
        "domain": {"name": "x"},
        "message": {"a": 1},
    }
    signable = encode_typed_data(full_message=typed)
    assert extension_sign._eip191_hash(signable) == _hash_eip191_message(signable)
