"""Hermes Desktop's managed launcher: the runtime venv comes from ``--run-module site``."""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _runtime_probe


def _launcher(home: Path, site_line: str) -> None:
    launcher = home / "hermes-agent" / ".hermes" / "bin" / "hermes"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(f'#!/bin/sh\n[ "$1" = --run-module ] && printf \'%s\\n\' "{site_line}"\nexit 0\n')
    launcher.chmod(0o755)


def test_desktop_launcher_yields_the_install_venv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_runtime_probe.RUNTIME_PYTHON_ENV, raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    venv = tmp_path / "installs" / "a" / "environments" / "b" / "venv"
    python = venv / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_text("")
    _launcher(tmp_path, f"    '{venv}/lib/python3.14/site-packages',")

    assert _runtime_probe.discover_runtime_python(home=tmp_path) == python


def test_managed_venv_still_wins_and_missing_launcher_is_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_runtime_probe.RUNTIME_PYTHON_ENV, raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    assert _runtime_probe.discover_runtime_python(home=tmp_path) is None
    managed = tmp_path / "hermes-agent" / "venv" / "bin" / "python3"
    managed.parent.mkdir(parents=True)
    managed.write_text("")
    _launcher(tmp_path, "'/nowhere/venv/lib/python3.14/site-packages'")
    assert _runtime_probe.discover_runtime_python(home=tmp_path) == managed
