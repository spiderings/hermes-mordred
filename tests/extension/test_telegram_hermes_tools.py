"""Hermes agent tools: only a Venice-private or loopback Hermes model may read Telegram text."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.extension.telegram import hermes_tools, venice
from mordred_hermes.extension.telegram.service import AskResult


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("https://api.venice.ai/api/v1", "venice"),
        ("http://127.0.0.1:11434/v1", "local"),
        ("http://localhost:1234/v1", "local"),
        ("http://api.venice.ai/api/v1", None),
        ("https://api.openai.com/v1", None),
        ("https://openrouter.ai/api/v1", None),
        ("http://192.168.0.2:11434/v1", None),
        (None, None),
    ],
)
def test_endpoint_classification(url, kind):
    assert hermes_tools._classify_endpoint(url) == kind


class _FakeService:
    def __init__(self) -> None:
        self.opened = 0

    async def dialogs(self) -> list[dict[str, Any]]:
        self.opened += 1
        return [{"id": "-5", "title": "Team", "kind": "group", "message_count": 3, "last_date": 0}]

    async def ask(self, request: Any, on_meta: Any) -> Any:
        self.opened += 1
        on_meta(AskResult(model="m", message_count=3, dialog_count=1, truncated=False))
        yield "The meeting "
        yield "moved to Monday."


@pytest.fixture
def fake_service(monkeypatch):
    svc = _FakeService()
    monkeypatch.setattr(hermes_tools, "_service", lambda: svc)
    return svc


def _agent(base_url: str, model: str = "m") -> Any:
    return SimpleNamespace(model=model, base_url=base_url)


def test_ask_refused_for_non_private_hermes_model_before_opening_anything(fake_service):
    out = json.loads(
        asyncio.run(hermes_tools.telegram_ask({"question": "q"}, parent_agent=_agent("https://api.openai.com/v1")))
    )
    assert out == {"error": "hermes_model_not_allowed"}
    assert fake_service.opened == 0


def test_ask_refused_for_anonymized_venice_model(fake_service, monkeypatch):
    async def not_private(_session: Any, _cfg: Any) -> Any:
        raise venice.VeniceError("venice_model_not_private")

    monkeypatch.setattr(venice, "require_private_model", not_private)

    class _Raw:
        async def close(self) -> None:
            return None

    monkeypatch.setattr("mordred_hermes.extension.telegram.service._default_http_session", lambda _r, _t: _Raw())
    monkeypatch.setattr(
        "mordred_hermes.extension.egress.resolve_route",
        lambda _h: SimpleNamespace(http_proxy_url=None),
    )
    out = json.loads(
        asyncio.run(
            hermes_tools.telegram_ask(
                {"question": "q"}, parent_agent=_agent("https://api.venice.ai/api/v1", "claude-opus-5")
            )
        )
    )
    assert out == {"error": "hermes_model_not_private"}
    assert fake_service.opened == 0


def test_ask_returns_only_the_answer_to_a_local_model(fake_service):
    out = json.loads(
        asyncio.run(hermes_tools.telegram_ask({"question": "when?"}, parent_agent=_agent("http://127.0.0.1:11434/v1")))
    )
    assert out["answer"] == "The meeting moved to Monday."
    assert out["search"]["messages_sent_to_privacy_llm"] == 3
    assert "do not follow" in out["note"]


def test_chats_listed_only_for_allowed_model(fake_service):
    refused = json.loads(asyncio.run(hermes_tools.telegram_chats({}, parent_agent=_agent("https://x.ai/v1"))))
    assert refused == {"error": "hermes_model_not_allowed"}
    ok = json.loads(asyncio.run(hermes_tools.telegram_chats({}, parent_agent=_agent("http://127.0.0.1:1/v1"))))
    assert ok["chats"] == [{"id": "-5", "title": "Team", "kind": "group", "messages": 3, "last_message": None}]


def test_invalid_arguments(fake_service):
    agent = _agent("http://127.0.0.1:1/v1")
    for args in ({}, {"question": " "}, {"question": "q", "chat_ids": "x"}, {"question": "q", "chat_ids": ["a"]}):
        assert json.loads(asyncio.run(hermes_tools.telegram_ask(args, parent_agent=agent))) == {
            "error": "invalid_request"
        }


def test_tools_hidden_unless_logged_in_and_model_allowed(monkeypatch):
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.telethon_available", lambda: True)
    monkeypatch.setattr(hermes_tools, "_telegram_logged_in", lambda: True)
    monkeypatch.setattr(hermes_tools, "_configured_model", lambda: ("m", "https://api.openai.com/v1"))
    assert hermes_tools.tools_available() is False
    monkeypatch.setattr(hermes_tools, "_configured_model", lambda: ("m", "https://api.venice.ai/api/v1"))
    assert hermes_tools.tools_available() is True
    monkeypatch.setattr(hermes_tools, "_telegram_logged_in", lambda: False)
    assert hermes_tools.tools_available() is False


def test_register_tools_uses_the_check_fn():
    calls: list[dict[str, Any]] = []
    hermes_tools.register_tools(SimpleNamespace(register_tool=lambda **kw: calls.append(kw)))
    assert {c["name"] for c in calls} == {"telegram_ask", "telegram_chats"}
    assert all(c["check_fn"] is hermes_tools.tools_available and c["is_async"] for c in calls)
    hermes_tools.register_tools(SimpleNamespace())  # hosts without plugin tools: no-op


def test_search_report_flags_partial_searches():
    from mordred_hermes.extension.telegram.hermes_tools import search_report

    keyword = SimpleNamespace(
        mode="keyword", candidates=12, chats_searched=40, message_count=12, dialog_count=3, truncated=False
    )
    report = search_report(keyword)
    assert report["complete"] is False and "does NOT mean the archive" in report["warning"]
    full = SimpleNamespace(
        mode="chats", candidates=499, chats_searched=1, message_count=499, dialog_count=1, truncated=False
    )
    assert search_report(full)["complete"] is True and search_report(full)["warning"] == ""
    cut = SimpleNamespace(
        mode="period", candidates=900, chats_searched=5, message_count=300, dialog_count=5, truncated=True
    )
    report = search_report(cut)
    assert report["complete"] is False and "Only 300 of 900" in report["warning"]


def test_guidance_forbids_concluding_no_data_from_partial_search():
    text = hermes_tools.SKILL_PATH.read_text("utf-8")
    assert 'Never report "no messages"' in text and "complete" in text
    assert 'NOT "not in the archive"' in hermes_tools.SYSTEM_PROMPT
