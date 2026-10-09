"""Telegram refuses to run while agent memory is plaintext."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from mordred_hermes.extension.telegram import memory_guard, service
from mordred_hermes.extension.telegram.ask import AskRequest
from mordred_hermes.wizard import telegram_cli, telegram_setup_cli

pytestmark = pytest.mark.memory_plain


def _status(active: bool, drift: bool = False):
    return lambda home, platform: SimpleNamespace(active=active, drift=drift)


@pytest.mark.parametrize(("active", "drift", "ok"), [(True, False, True), (False, False, False), (True, True, False)])
def test_memory_encryption_active(monkeypatch, active, drift, ok):
    monkeypatch.setattr("mordred_hermes.wizard.encryption_cli.memory_status", _status(active, drift))
    assert memory_guard.memory_encryption_active() is ok


def test_service_entry_points_refuse_plaintext_memory(monkeypatch):
    monkeypatch.setattr("mordred_hermes.wizard.encryption_cli.memory_status", _status(False))
    # The guard must hold whether or not the optional Telethon extra is installed.
    svc = service.TelegramService(
        secret_store=SimpleNamespace(load=lambda fresh=True: None, flags=lambda: None), installed=lambda: True
    )

    async def ask() -> None:
        async for _ in svc.ask(AskRequest(question="q"), lambda _m: None):
            pass

    for call in (svc.start_sync(), svc.dialogs(), ask()):
        with pytest.raises(memory_guard.MemoryEncryptionRequired):
            asyncio.run(call)
    assert service.error_code(memory_guard.MemoryEncryptionRequired(), "x") == "memory_encryption_required"


def test_login_refuses_before_contacting_telegram(monkeypatch):
    monkeypatch.setattr("mordred_hermes.wizard.encryption_cli.memory_status", _status(False))
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.telethon_available", lambda: True)
    assert telegram_cli._login_preflight(lambda: True) == "memory_encryption_required"


def test_doctor_reports_memory_encryption(monkeypatch):
    monkeypatch.setattr("mordred_hermes.wizard.encryption_cli.memory_status", _status(False))
    check = telegram_setup_cli._check_memory()
    assert not check.ok and "encryption enable memory" in check.fix


def test_setup_stops_when_memory_encryption_declined(monkeypatch):
    monkeypatch.setattr("mordred_hermes.wizard.encryption_cli.memory_status", _status(False))
    monkeypatch.setattr(telegram_setup_cli, "_ensure_enclave", lambda _i: True)
    assert telegram_setup_cli.telegram_setup(input_fn=lambda _p: "n", secret_fn=lambda _p: "") == 1
