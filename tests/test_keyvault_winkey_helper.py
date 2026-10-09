"""Portable Windows discovery tests; subprocess behavior is tested at its OS boundary."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from mordred_hermes import _home
from mordred_hermes.keyvault import _seckey_helper as helper
from mordred_hermes.keyvault._seckey_errors import _OpsError


@pytest.fixture(autouse=True)
def isolated_search(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MORDRED_WINKEY_HELPER", raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(_home, "hermes_home", lambda: tmp_path / "Hermes 日本語")


def executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ")
    return path


def test_winkey_installed_home_precedes_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = executable(_home.hermes_home() / "bin" / "mordred-hermes-winkey.exe")
    other = executable(tmp_path / "other" / target.name)
    monkeypatch.setenv("PATH", str(other.parent))
    assert helper.find_winkey_helper() == str(target)


def test_winkey_explicit_unicode_exe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = executable(tmp_path / "Windows 日本語" / "helper.EXE")
    monkeypatch.setenv("MORDRED_WINKEY_HELPER", str(target))
    assert helper.find_winkey_helper() == str(target)


@pytest.mark.parametrize("override", ["missing.exe", "script.ps1", "relative.exe", ""])
def test_winkey_invalid_override_is_authoritative(
    override: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable(_home.hermes_home() / "bin" / "mordred-hermes-winkey.exe")
    monkeypatch.chdir(tmp_path)
    if override in {"script.ps1", "relative.exe"}:
        executable(tmp_path / override)
    value = str(tmp_path / override) if override in {"missing.exe", "script.ps1"} else override
    monkeypatch.setenv("MORDRED_WINKEY_HELPER", value)
    assert helper.find_winkey_helper() is None


def test_winkey_only_explicit_absolute_path_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    executable(tmp_path / "mordred-hermes-winkey.exe")
    executable(tmp_path / "relative" / "mordred-hermes-winkey.exe")
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "relative"]))
    assert helper.find_winkey_helper() is None
    target = executable(tmp_path / "trusted 日本語" / "mordred-hermes-winkey.exe")
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(target.parent)]))
    assert helper.find_winkey_helper() == str(target)


@pytest.mark.parametrize(
    "reason,status",
    [("NOT_FOUND", 0x80090016), ("EXISTS", 0x8009000F), ("AUTH_DENIED", 0x80090010), ("UNAVAILABLE", 0x80090029)],
)
def test_winkey_cng_error_transport(reason: str, status: int) -> None:
    response = {"error": {"domain": "cng", "status": status, "reason": reason, "message": "native refusal"}}
    with (
        patch.object(
            helper.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, json.dumps(response).encode(), b""),
        ),
        pytest.raises(_OpsError) as caught,
    ):
        helper._run_helper("C:/test/helper.exe", {"cmd": "probe"})
    assert (caught.value.status, caught.value.domain, caught.value.reason) == (status, "cng", reason)


@pytest.mark.parametrize("stdout,code", [(b"not json", 0), (b"{}", 1)])
def test_winkey_malformed_or_failed_process(stdout: bytes, code: int) -> None:
    with (
        patch.object(helper.subprocess, "run", return_value=subprocess.CompletedProcess([], code, stdout, b"")),
        pytest.raises(_OpsError),
    ):
        helper._run_helper("C:/test/helper.exe", {"cmd": "probe"})


def test_winkey_process_timeout() -> None:
    with (
        patch.object(helper.subprocess, "run", side_effect=subprocess.TimeoutExpired("helper.exe", 120)),
        pytest.raises(_OpsError, match="timed out"),
    ):
        helper._run_helper("C:/test/helper.exe", {"cmd": "probe"})


@pytest.mark.parametrize(
    "response", [{}, {"ok": False}, {"ok": 1}, {"ok": "true"}, {"error": "failure"}, {"error": None}]
)
@pytest.mark.parametrize("command", ["probe", "delete"])
def test_winkey_requires_boolean_success(response: dict[str, object], command: str) -> None:
    with (
        patch.object(
            helper.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(response).encode(), b""),
        ),
        pytest.raises(_OpsError),
    ):
        ops = helper._HelperSecKeyOps("C:/test/helper.exe")
        if command == "probe":
            ops.probe()
        else:
            ops.delete_key(b"synthetic-key")


@pytest.mark.parametrize("status", ["bad", None, [], {}, True, 1.5])
def test_winkey_invalid_status_is_classified(status: object) -> None:
    response = {"error": {"status": status, "reason": "UNAVAILABLE"}}
    with (
        patch.object(
            helper.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, json.dumps(response).encode(), b""),
        ),
        pytest.raises(_OpsError) as caught,
    ):
        helper._run_helper("C:/test/helper.exe", {"cmd": "probe"})
    assert caught.value.domain == "helper" and caught.value.status == -1
