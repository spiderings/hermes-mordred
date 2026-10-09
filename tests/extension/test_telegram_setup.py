"""telegram setup / doctor and the Hermes guidance (skill + prompt section)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.extension.telegram import hermes_tools
from mordred_hermes.wizard import telegram_setup_cli as setup_cli


def test_skill_file_ships_and_forbids_other_paths():
    text = hermes_tools.SKILL_PATH.read_text("utf-8")
    assert text.startswith("---\nname: mordred-telegram")
    for rule in ("telegram_ask", "Telegram.app", "tool_search", "keyvault init", "Touch ID"):
        assert rule in text
    assert len(hermes_tools.SYSTEM_PROMPT) <= 4000


def test_prompt_section_only_when_tools_available(monkeypatch):
    monkeypatch.setattr(hermes_tools, "tools_available", lambda: False)
    assert hermes_tools.system_prompt_section({}) == ""
    monkeypatch.setattr(hermes_tools, "tools_available", lambda: True)
    assert "NEVER open, screenshot, or operate Telegram.app" in hermes_tools.system_prompt_section({})


def test_register_tools_registers_skill_and_section():
    seen: dict[str, Any] = {}
    ctx = SimpleNamespace(
        register_tool=lambda **kw: seen.setdefault("tools", []).append(kw["name"]),
        register_skill=lambda name, path, description="": seen.update(skill=(name, path)),
        register_system_prompt_section=lambda sid, content, **kw: seen.update(section=(sid, content)),
    )
    hermes_tools.register_tools(ctx)
    assert seen["skill"] == ("mordred-telegram", hermes_tools.SKILL_PATH)
    assert seen["section"] == ("mordred.telegram", hermes_tools.system_prompt_section)
    assert sorted(seen["tools"]) == ["telegram_ask", "telegram_chats"]


def _patch_checks(monkeypatch, *, enclave=True, flags=None, archive=True, hermes=True):
    monkeypatch.setattr(setup_cli, "_check_telethon", lambda: setup_cli.Check("telethon", True, "installed"))
    monkeypatch.setattr(
        setup_cli, "_check_enclave", lambda: setup_cli.Check("secure_enclave", enclave, "x", "" if enclave else "fix")
    )
    monkeypatch.setattr(
        setup_cli, "_check_archive", lambda: setup_cli.Check("archive", archive, "x", "" if archive else "fix")
    )
    monkeypatch.setattr(setup_cli, "_check_hermes", lambda: setup_cli.Check("hermes_integration", hermes, "x"))
    monkeypatch.setattr("mordred_hermes.extension.telegram.tee.TeeSecretStore.flags", lambda self: flags)


def test_doctor_reports_metadata_only(monkeypatch, capsys):
    _patch_checks(monkeypatch, flags={"logged_in": True, "llm_backend": "venice", "llm_model": "m"})
    assert setup_cli.telegram_doctor(as_json=True) == 0
    report = json.loads(capsys.readouterr().out)
    assert {c["name"] for c in report} == {
        "telethon",
        "secure_enclave",
        "hardware",
        "memory_encryption",
        "login",
        "privacy_llm",
        "archive",
        "hermes_integration",
    }


def test_doctor_fails_with_fixes(monkeypatch, capsys):
    _patch_checks(monkeypatch, flags=None, archive=False)
    assert setup_cli.telegram_doctor() == 1
    out = capsys.readouterr().out
    assert "hermes-mordred telegram setup" in out and "!! archive" in out


def test_archive_check_never_decrypts(tmp_path, monkeypatch):
    monkeypatch.setattr("mordred_hermes.extension.telegram.store.telegram_dir", lambda: tmp_path)
    assert setup_cli._check_archive().ok is False
    (tmp_path / "dialogs").mkdir()
    (tmp_path / "index.enc").write_bytes(b"MTG1 not decryptable")
    (tmp_path / "dialogs" / "a.enc").write_bytes(b"x" * 2048)
    (tmp_path / ".gitignore").write_text("*\n")
    check = setup_cli._check_archive()
    assert check.ok and "1 encrypted segment" in check.detail and "git-ignored: yes" in check.detail


def test_setup_skips_done_steps_and_runs_recommended_sync(monkeypatch):
    calls: list[Any] = []
    monkeypatch.setattr(setup_cli, "_ensure_enclave", lambda _i: True)
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.tee.TeeSecretStore.flags",
        lambda self: {"logged_in": True, "llm_backend": "venice", "llm_model": "m"},
    )
    monkeypatch.setattr("mordred_hermes.wizard.telegram_cli.telegram_login", lambda **kw: calls.append("login") or 0)
    monkeypatch.setattr(
        "mordred_hermes.wizard.telegram_cli.telegram_sync", lambda **kw: calls.append(("sync", kw)) or 0
    )
    saved: list[Any] = []
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.tee.TeeSecretStore.save_sync_scope", lambda self, scope: saved.append(scope)
    )
    assert setup_cli.telegram_setup(input_fn=lambda _p: "", secret_fn=lambda _p: "") == 0
    assert saved == [
        {
            "include_channels": False,
            "include_archived": False,
            "since_days": setup_cli.DEFAULT_SINCE_DAYS,
            "limit_per_dialog": setup_cli.RECOMMENDED_LIMIT,
        }
    ]
    assert calls == [("sync", {})]  # sync then uses the saved scope


def test_setup_stops_without_enclave(monkeypatch):
    monkeypatch.setattr(setup_cli, "_ensure_enclave", lambda _i: False)
    assert setup_cli.telegram_setup(input_fn=lambda _p: "n", secret_fn=lambda _p: "") == 1


@pytest.mark.parametrize(("answer", "expected"), [("", True), ("y", True), ("n", False), ("no", False)])
def test_yes_prompt(answer, expected):
    assert setup_cli._yes(lambda _p: answer, "?") is expected


def test_linux_cli_remediation_uses_tpm_and_memory_only(monkeypatch, capsys):
    from mordred_hermes.wizard import telegram_cli

    monkeypatch.setattr(telegram_cli, "sys", SimpleNamespace(platform="linux", stderr=__import__("sys").stderr))
    telegram_cli._report("tee_unavailable")
    telegram_cli._report("memory_encryption_required")
    text = capsys.readouterr().err
    assert "enable-tpm" in text
    assert "enable memory" in text
    assert "enable-se" not in text and "enable env" not in text
