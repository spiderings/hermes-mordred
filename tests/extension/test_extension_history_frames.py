"""Bounded server frames for projected extension conversation history."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes.extension import extension_api, extension_history, extension_pairing
from mordred_hermes.extension import extension_crypto as xc


@pytest.fixture(autouse=True)
def _paired_home(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    code, _ = extension_pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    extension_pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))


def _frame(payload: dict[str, Any]) -> str:
    return extension_api._serialize_frame(payload)


def test_history_at_exact_frame_limit_is_complete() -> None:
    turns = [
        {"role": "user", "content": "old"},
        {"role": "assistant", "content": "new"},
    ]
    complete = {
        "id": "history-1",
        "type": "history_result",
        "status": "ok",
        "turns": turns,
        "truncated": False,
    }

    result = extension_api._bounded_history_result(
        "history-1",
        turns,
        max_chars=len(_frame(complete)),
    )

    assert result == complete


def test_history_returns_the_longest_complete_newest_suffix() -> None:
    turns = [
        {"role": "user", "content": "old" * 40},
        {"role": "assistant", "content": "middle"},
        {"role": "user", "content": "newest"},
    ]
    expected = {
        "id": "history-2",
        "type": "history_result",
        "status": "ok",
        "turns": turns[-2:],
        "truncated": True,
    }

    result = extension_api._bounded_history_result(
        "history-2",
        turns,
        max_chars=len(_frame(expected)),
    )

    assert result == expected
    assert len(_frame(result)) <= len(_frame(expected))


def test_unicode_uses_the_same_ascii_count_as_the_wire_frame() -> None:
    turns = [{"role": "user", "content": "履歴🙂"}]
    complete = {
        "id": "unicode",
        "type": "history_result",
        "status": "ok",
        "turns": turns,
        "truncated": False,
    }
    encoded = _frame(complete)

    assert encoded.isascii()
    assert len(encoded) == len(encoded.encode("ascii"))
    assert (
        extension_api._bounded_history_result(
            "unicode",
            turns,
            max_chars=len(encoded),
        )
        == complete
    )


def test_single_oversized_newest_turn_yields_an_empty_suffix() -> None:
    turns = [{"role": "assistant", "content": "x" * 1000}]
    empty = {
        "id": "huge",
        "type": "history_result",
        "status": "ok",
        "turns": [],
        "truncated": True,
    }
    limit = len(_frame(empty)) + 10

    result = extension_api._bounded_history_result("huge", turns, max_chars=limit)

    assert result == empty
    assert len(_frame(result)) <= limit


class _FakeWS:
    closed = False

    def __init__(self) -> None:
        self.raw: list[str] = []

    async def send_str(self, data: str) -> None:
        self.raw.append(data)


def test_serving_a_suffix_does_not_modify_encrypted_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    messages = [
        {"role": "user", "content": "old" * 80},
        {"role": "assistant", "content": "newest"},
    ]
    extension_history.save_messages(messages)
    expected_suffix = {
        "id": "persist",
        "type": "history_result",
        "status": "ok",
        "turns": [messages[-1]],
        "truncated": True,
    }
    monkeypatch.setattr(extension_api, "MAX_WS_FRAME_CHARS", len(_frame(expected_suffix)))
    ws = _FakeWS()
    connection = extension_api._Connection(ws, lambda *_: None)

    asyncio.run(connection._on_history_get({"id": "persist", "type": "history_get"}))

    assert json.loads(ws.raw[-1]) == expected_suffix
    assert len(ws.raw[-1]) <= extension_api.MAX_WS_FRAME_CHARS
    assert extension_history.load_messages() == messages


def test_undecryptable_history_is_flagged_additively() -> None:
    """``messages``/``turns`` stay a list for older clients; the outcome rides
    alongside it as an additive field."""
    result = extension_api._bounded_history_result("h", [], status="undecryptable")

    assert result == {
        "id": "h",
        "type": "history_result",
        "status": "undecryptable",
        "turns": [],
        "truncated": False,
    }
