"""Wallet-side bounds and copy for the extension API.

Two independent concerns live here because both are owned by
``mordred_hermes.extension.wallet``:

* the bounded account-snapshot resolution that keeps a page principal from
  driving unbounded Secure-Enclave use (one Touch ID prompt per request), and
* the ``personal_sign`` payload classification that decides whether the
  approval copy may promise "no asset movement".
"""

from __future__ import annotations

import logging
import os
import traceback
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.extension import wallet as extension_wallet
from mordred_hermes.extension.errors import wire_error_code

_ADDRESS = "0x" + "ab" * 20


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    extension_wallet.reset_account_snapshot_cache()
    yield
    extension_wallet.reset_account_snapshot_cache()


def _stub_backend(monkeypatch: pytest.MonkeyPatch, outcomes: list[Any]) -> list[int]:
    """Stub ``extension_sign.account_snapshot``; return its call counter."""
    from mordred_hermes.keyvault import extension_sign

    calls: list[int] = []

    def _snapshot() -> tuple[str, int]:
        calls.append(1)
        outcome = outcomes[min(len(calls) - 1, len(outcomes) - 1)]
        if isinstance(outcome, Exception):
            raise outcome
        value: tuple[str, int] = outcome
        return value

    monkeypatch.setattr(extension_sign, "account_snapshot", _snapshot)
    return calls


def test_repeated_accounts_requests_resolve_the_snapshot_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A burst of requests must cost exactly one keyvault/SE resolution."""
    calls = _stub_backend(monkeypatch, [(_ADDRESS, 1)])

    results = [extension_wallet._get_account_snapshot() for _ in range(5)]

    assert results == [(_ADDRESS, "0x1")] * 5
    assert len(calls) == 1


def test_snapshot_cache_expires_after_its_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _stub_backend(monkeypatch, [(_ADDRESS, 1)])
    now = [1000.0]
    monkeypatch.setattr(extension_wallet, "_clock", lambda: now[0])

    assert extension_wallet._get_account_snapshot() == (_ADDRESS, "0x1")
    now[0] += extension_wallet._ACCOUNT_SNAPSHOT_TTL_SECONDS - 0.01
    assert extension_wallet._get_account_snapshot() == (_ADDRESS, "0x1")
    assert len(calls) == 1

    now[0] += 0.02
    assert extension_wallet._get_account_snapshot() == (_ADDRESS, "0x1")
    assert len(calls) == 2


def test_snapshot_cache_is_invalidated_by_a_wallet_config_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rewritten wallet.json must not be served from a stale cache entry."""
    wallet_json = tmp_path / "extension" / "wallet.json"
    wallet_json.parent.mkdir(parents=True, exist_ok=True)
    wallet_json.write_text('{"chain_id": 1}', encoding="utf-8")
    os.utime(wallet_json, (1_000_000, 1_000_000))
    calls = _stub_backend(monkeypatch, [(_ADDRESS, 1), ("0x" + "cd" * 20, 5)])

    assert extension_wallet._get_account_snapshot() == (_ADDRESS, "0x1")

    wallet_json.write_text('{"chain_id": 5, "key_id": "other"}', encoding="utf-8")
    os.utime(wallet_json, (2_000_000, 2_000_000))

    assert extension_wallet._get_account_snapshot() == ("0x" + "cd" * 20, "0x5")
    assert len(calls) == 2


def test_failed_snapshot_is_not_retried_within_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing resolution is bounded too — otherwise the bound is bypassable,
    and the replay must classify to the same wire code as the first failure."""
    from mordred_hermes.extension.errors import wire_error_code
    from mordred_hermes.keyvault.extension_sign import WalletNotConfigured

    calls = _stub_backend(monkeypatch, [WalletNotConfigured("No extension wallet configured. Run ...")])

    with pytest.raises(WalletNotConfigured) as first:
        extension_wallet._get_account_snapshot()
    with pytest.raises(RuntimeError) as replayed:
        extension_wallet._get_account_snapshot()

    assert len(calls) == 1
    assert wire_error_code(replayed.value, fallback="x", context="t") == wire_error_code(
        first.value, fallback="x", context="t"
    )
    # The replay must not pin the original traceback (and its frame locals).
    assert replayed.value.__traceback__ is not None  # its own raise site only
    assert type(replayed.value) is extension_wallet._CachedSnapshotFailure


# --------------------------------------------------------------------------- #
# personal_sign payload classification
# --------------------------------------------------------------------------- #

_NO_ASSET_MOVEMENT = "資産移動なし"


@pytest.mark.parametrize(
    "payload",
    [
        "0x" + b"gm wagmi, please sign in".hex(),
        "Sign in to Example\nNonce: 12345",
        # Uppercase "0X" is NOT the signer's prefix (case-sensitive
        # ``message.startswith("0x")``), so these 66 characters are signed as
        # literal text — and are readable as such.
        "0X" + "9a" * 32,
    ],
)
def test_readable_personal_sign_keeps_the_no_asset_movement_copy(payload: str) -> None:
    analysis, decoded = extension_wallet.analyze_sign("personal_sign", [payload, _ADDRESS])

    assert analysis["risk"] == "low"
    assert _NO_ASSET_MOVEMENT in analysis["summary"]
    assert decoded["payload_kind"] == "text"


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ("0x" + "9a" * 32, "the plain 32-byte digest"),
        # eth_utils left-pads an odd-length body with one "0", so 63 hex chars
        # sign the SAME 32 bytes as the 64-char digest above.
        ("0x" + ("9a" * 32)[1:], "odd-length hex padded to 32 bytes"),
        # 32 bytes that also happen to decode to printable ASCII: length wins,
        # because printability is grindable (~2**44 keccak attempts).
        ("0x" + (b"A" * 32).hex(), "printable-by-accident digest"),
    ],
)
def test_thirty_two_signed_bytes_are_always_an_opaque_hash(payload: str, reason: str) -> None:
    analysis, decoded = extension_wallet.analyze_sign("personal_sign", [payload, _ADDRESS])

    assert decoded["payload_kind"] == "opaque_hash", reason
    assert analysis["risk"] == "medium"
    assert _NO_ASSET_MOVEMENT not in analysis["summary"]


@pytest.mark.parametrize(
    "payload",
    [
        "0x9a9a 9a9a",  # bytes.fromhex tolerates the space; the signer does not
        "0xnot-hex-at-all",
        "0x9a9a\n",
        "0x9a9aé",
    ],
)
def test_hex_the_signer_cannot_decode_is_opaque_not_text(payload: str) -> None:
    """These payloads make ``personal_sign`` raise. Never call them readable."""
    analysis, decoded = extension_wallet.analyze_sign("personal_sign", [payload, _ADDRESS])

    assert decoded["payload_kind"] == "opaque_bytes"
    assert _NO_ASSET_MOVEMENT not in analysis["summary"]


def test_classification_matches_the_installed_signer_bytes() -> None:
    """Cross-check the local mirror against eth_utils itself where available.

    The ``ethereum`` extra is not installed in CI, so this skips there; locally
    it is the guard that the padding/prefix rules did not drift.
    """
    to_bytes = pytest.importorskip("eth_utils").to_bytes

    for payload in ("0x" + "9a" * 32, "0x" + ("9a" * 32)[1:], "0x" + (b"A" * 32).hex(), "0x" + b"gm".hex()):
        body = extension_wallet._signer_hex_body(payload)
        assert body is not None
        assert bytes.fromhex(body) == to_bytes(hexstr=payload)


def test_opaque_32_byte_hash_warns_about_safe_and_meta_transactions() -> None:
    """A Safe/meta-tx digest is unreadable — the copy must say so."""
    analysis, decoded = extension_wallet.analyze_sign("personal_sign", ["0x" + "9a" * 32, _ADDRESS])

    assert _NO_ASSET_MOVEMENT not in analysis["summary"]
    assert analysis["risk"] == "medium"
    assert decoded["payload_kind"] == "opaque_hash"
    warnings = " ".join(analysis["warnings"])
    assert "Safe" in warnings
    assert _NO_ASSET_MOVEMENT not in warnings


def test_opaque_bytes_payload_never_claims_no_asset_movement() -> None:
    analysis, decoded = extension_wallet.analyze_sign("personal_sign", ["0x" + "ff" * 12, _ADDRESS])

    assert _NO_ASSET_MOVEMENT not in analysis["summary"]
    assert analysis["risk"] == "medium"
    assert decoded["payload_kind"] == "opaque_bytes"
    assert analysis["warnings"]


def test_readable_text_of_exactly_thirty_two_utf8_bytes_is_opaque_by_rule() -> None:
    """The literal-text branch signs the same 32 bytes as its hex spelling; length wins there too."""

    text = "Approve login to example.com!!!!"
    assert len(text.encode("utf-8")) == 32
    risk_text, decoded_text = extension_wallet._analyze_personal_sign(text)
    risk_hex, decoded_hex = extension_wallet._analyze_personal_sign("0x" + text.encode("utf-8").hex())
    assert decoded_text["payload_kind"] == decoded_hex["payload_kind"] == "opaque_hash"
    assert risk_text["risk"] == risk_hex["risk"] == "medium"
    # One byte shorter is ordinary readable text again.
    risk_short, decoded_short = extension_wallet._analyze_personal_sign(text[:-1])
    assert decoded_short["payload_kind"] == "text"
    assert risk_short["risk"] == "low"


def test_long_readable_message_preview_is_flagged_as_truncated() -> None:
    long_message = "harmless preamble " * 40 + ">>> AND I AUTHORIZE TRANSFER OF ALL FUNDS <<<"
    assert len(long_message) > extension_wallet._MESSAGE_PREVIEW_CHARS
    _risk, decoded = extension_wallet._analyze_personal_sign(long_message)
    assert decoded["payload_kind"] == "text"
    assert len(decoded["message_preview"]) == extension_wallet._MESSAGE_PREVIEW_CHARS
    assert decoded["preview_truncated"] is True
    _risk, short = extension_wallet._analyze_personal_sign("short message")
    assert "preview_truncated" not in short


@pytest.mark.parametrize("params", [[], [None, _ADDRESS], [{"a": 1}, _ADDRESS]])
def test_unreadable_personal_sign_params_are_classified_opaque(params: list[Any]) -> None:
    """analyze_sign runs on unvalidated input and must never raise or promise."""
    analysis, decoded = extension_wallet.analyze_sign("personal_sign", params)

    assert _NO_ASSET_MOVEMENT not in analysis["summary"]
    assert decoded["payload_kind"] == "opaque_bytes"


def test_cached_failure_replay_is_bounded_in_traceback_and_log(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Replaying one cached failure must stay O(1) per request.

    Re-raising a single cached instance made Python append the raise site to
    its ``__traceback__`` every time, and the error classifier logged that
    growing traceback on every call — quadratic work and an unbounded log for a
    client that just keeps polling ``accounts_request``.
    """
    calls = _stub_backend(monkeypatch, [RuntimeError("vault unavailable")])
    depths: list[int] = []
    codes: set[str] = set()

    with caplog.at_level(logging.WARNING, logger="mordred_hermes.extension.errors"):
        for _ in range(200):
            try:
                extension_wallet._get_account_snapshot()
            except Exception as exc:
                depths.append(len(traceback.extract_tb(exc.__traceback__)))
                codes.add(wire_error_code(exc, fallback="wallet_unavailable", context="accounts_request"))

    assert len(calls) == 1
    assert len(depths) == 200
    # Every replay's traceback is exactly its own raise site: constant depth.
    assert len(set(depths[1:])) == 1, depths[:5]
    assert depths[-1] == depths[1]
    # The traceback is logged once, when the call really failed.
    assert len([record for record in caplog.records if record.exc_info is not None]) == 1
    assert max(len(record.getMessage()) for record in caplog.records) < 200
    assert codes == {"wallet_unavailable"}  # same wire code on every replay


@pytest.mark.parametrize(
    ("context", "expected"),
    [("sign_approve", "wallet_signer_changed"), ("chat", "agent_error"), ("accounts_request", "agent_error")],
)
def test_wire_codes_are_scoped_to_the_call_site(context: str, expected: str) -> None:
    """A message-prefix match must not let one surface answer with another's
    code — an injected chat handler's text is agent-influenced."""
    exc = RuntimeError("wallet_signer_changed: injected by the agent")

    assert wire_error_code(exc, fallback="agent_error", context=context) == expected
