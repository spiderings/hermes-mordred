"""Desktop setup must not offer macOS-only Telegram setup on other hosts."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from mordred_hermes.desktop import api
from mordred_hermes.wizard import keyvault_native_cli, telegram_setup_cli


@pytest.mark.parametrize("platform", ["win32", "freebsd14"])
def test_unsupported_status_reports_platform_without_probing_setup(monkeypatch, platform):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform=platform))

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported setup must not probe hardware, credentials, or a provider")

    monkeypatch.setattr(telegram_setup_cli, "run_checks", unexpected)
    monkeypatch.setattr(api, "hermes_model_check", unexpected)
    monkeypatch.setattr(api, "_store", unexpected)
    monkeypatch.setattr(api, "_hermes_venice_key", unexpected)

    result = asyncio.run(api.status())

    assert result["ok"] is True
    assert result["platform"] == platform
    assert result["telegram_supported"] is False
    assert result["checks"] == {}


def test_macos_status_keeps_setup_progress(monkeypatch):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(
        telegram_setup_cli,
        "run_checks",
        lambda: [telegram_setup_cli.Check("secure_enclave", True, "helper ready")],
    )

    async def model():
        return {"ok": True, "kind": "local", "model": "local-test"}

    monkeypatch.setattr(api, "hermes_model_check", model)
    monkeypatch.setattr(api, "_store", lambda: SimpleNamespace(flags=lambda: {"api_configured": True}))
    monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)

    result = asyncio.run(api.status())

    assert result["platform"] == "darwin"
    assert result["telegram_supported"] is True
    assert result["checks"]["secure_enclave"] == {"ok": True, "detail": "helper ready"}
    assert result["hermes_model"]["ok"] is True
    assert result["telegram_api"] is True


@pytest.mark.parametrize("platform", ["win32", "freebsd14"])
@pytest.mark.parametrize("handler", [api.enclave_build, api.memory_enable])
def test_unsupported_setup_refuses_before_starting_work(monkeypatch, platform, handler):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform=platform))

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported setup must not start a build or access the vault")

    monkeypatch.setattr(api, "_start_job", unexpected)
    monkeypatch.setattr(api, "generate_recovery_passphrase", unexpected)
    monkeypatch.setattr("mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", unexpected)

    response = asyncio.run(handler())

    assert response.status_code == 200
    assert json.loads(response.body) == {"ok": False, "error": "telegram_platform_unsupported"}


@pytest.mark.parametrize("return_code, state, error", [(0, "done", None), (1, "failed", "enclave_build_failed")])
def test_macos_enclave_build_still_reports_job_result(monkeypatch, return_code, state, error):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(api, "_JOBS", {})
    monkeypatch.setattr(api, "_emit", lambda *args: None)
    # The hardware builder is the only platform-dependent operation here.
    monkeypatch.setattr(keyvault_native_cli, "enable_se", lambda: return_code)

    async def run():
        started = await api.enclave_build()
        async with asyncio.timeout(5):
            while api._JOBS[started["job_id"]].state == "running":
                await asyncio.sleep(0.01)
        return await api.job_status(started["job_id"])

    result = asyncio.run(run())

    assert result["state"] == state
    assert result["error"] == error


def test_linux_status_separates_support_from_readiness(monkeypatch):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        telegram_setup_cli, "run_checks", lambda: [telegram_setup_cli.Check("hardware", False, "missing")]
    )

    async def model():
        return {"ok": False}

    monkeypatch.setattr(api, "hermes_model_check", model)
    monkeypatch.setattr(api, "_store", lambda: SimpleNamespace(flags=lambda: {}))
    monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)
    result = asyncio.run(api.status(client_version=2))
    assert result["telegram_supported"] is True
    assert result["hardware_kind"] == "tpm"
    assert result["user_presence_supported"] is False
    assert result["checks"]["hardware"]["ok"] is False


def test_linux_memory_enable_does_not_create_vault_passphrase(monkeypatch, tmp_path):
    from mordred_hermes.extension.telegram import memory_guard
    from mordred_hermes.wizard import env_decrypt_cli, memory_cli

    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(api, "_home", lambda: tmp_path)
    armed = []
    monkeypatch.setattr(memory_guard, "memory_encryption_active", lambda: bool(armed))

    def enable(**kwargs):
        assert kwargs["platform"] == "linux"
        armed.append(True)
        return 0

    def forbidden(*a, **kw):
        pytest.fail("Linux must not provision env vault or passphrase")

    monkeypatch.setattr(memory_cli, "enable", enable)
    monkeypatch.setattr(env_decrypt_cli, "enable", forbidden)
    monkeypatch.setattr(api, "generate_recovery_passphrase", forbidden)
    assert asyncio.run(api.memory_enable({"acknowledge_tpm_no_recovery": True})) == {
        "ok": True,
        "restart_required": True,
    }


def test_linux_hardware_build_dispatches_tpm(monkeypatch):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(api, "_JOBS", {})
    monkeypatch.setattr(api, "_emit", lambda *a: None)
    monkeypatch.setattr(keyvault_native_cli, "enable_tpm", lambda: 0)

    async def run():
        started = await api.hardware_build()
        async with asyncio.timeout(5):
            while api._JOBS[started["job_id"]].state == "running":
                await asyncio.sleep(0.01)
        return await api.job_status(started["job_id"])

    assert asyncio.run(run())["state"] == "done"
    assert json.loads(asyncio.run(api.enclave_build()).body)["ok"] is False


def test_old_client_cannot_offer_linux_setup(monkeypatch):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    result = asyncio.run(api.status())
    assert result["telegram_supported"] is False
    assert result["checks"] == {}
    response = asyncio.run(api.memory_enable({}))
    assert json.loads(response.body)["error"] == "telegram_platform_unsupported"
