from __future__ import annotations

import json
import subprocess

import pytest

from mordred_hermes import _windows_runtime as runtime


def fixture_python(root, *, conda=False):
    root.mkdir(parents=True, exist_ok=True)
    if conda:
        (root / "conda-meta").mkdir()
        exe = root / "python.exe"
    else:
        (root / "pyvenv.cfg").write_text("home = base")
        (root / "Scripts").mkdir()
        exe = root / "Scripts/python.exe"
    exe.write_bytes(b"MZ")
    return exe


def runner_for(python, *, valid=True):
    def run(argv):
        if argv[1:3] == ["--run-module", "site"]:
            return subprocess.CompletedProcess(argv, 0, repr(str(python.parent.parent / "Lib/site-packages")), "")
        assert argv[0] == str(python)
        value = {
            "executable": str(python),
            "prefix": str(runtime.environment_root(python)),
            "hermes": valid,
            "environment": True,
        }
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    return run


@pytest.mark.parametrize("conda", [False, True])
def test_authoritative_selected_interpreter(tmp_path, conda):
    exe = fixture_python(tmp_path / "Hermes 日本 & space", conda=conda)
    assert runtime.resolve_windows_python(tmp_path, override=str(exe), runner=runner_for(exe)) == exe
    assert runtime.resolve_windows_python(tmp_path, override=str(exe), runner=runner_for(exe, valid=False)) is None


def test_invalid_override_never_falls_back(tmp_path):
    fixture_python(tmp_path / "hermes-agent/venv")
    assert runtime.resolve_windows_python(tmp_path, override="missing.exe") is None


def test_desktop_environment_from_actual_launcher(tmp_path):
    exe = fixture_python(tmp_path / "Desktop env space")
    launcher = tmp_path / "hermes.exe"
    launcher.touch()
    assert runtime.resolve_windows_python(tmp_path, launcher=launcher, runner=runner_for(exe)) == exe


def test_system_python_is_rejected(tmp_path):
    exe = tmp_path / "python.exe"
    exe.touch()
    assert runtime.environment_root(exe) is None


def test_scrubbed_env_keeps_profile_but_removes_uv_redirects():
    result = runtime.scrubbed_environment({"HERMES_HOME": "profile", "PYTHONPATH": "bad", "UV_INDEX_URL": "bad"})
    assert result == {"HERMES_HOME": "profile", "UV_NO_CONFIG": "1"}


def test_wizard_windows_environment_uses_shared_resolver(monkeypatch, tmp_path):
    from mordred_hermes.wizard import _uninstall_hermes_env as env

    exe = fixture_python(tmp_path / "hermes-agent/venv")
    monkeypatch.setattr("sys.platform", "win32")
    assert env.find_hermes_python(tmp_path, None, runner=runner_for(exe)) == exe
    detected = env.HermesEnv(None, exe, None, ())
    assert detected.console_script == exe.parent / "hermes-mordred.exe"


def test_wizard_preserves_unknown_windows_helper(tmp_path):
    from mordred_hermes.wizard import _uninstall_hermes_env as env

    directory = tmp_path / "bin"
    directory.mkdir()
    binary = directory / "mordred-hermes-winkey.exe"
    binary.write_bytes(b"MZ unknown")
    findings = env.classify_helpers(user_home=tmp_path, hermes_home=tmp_path, platform="win32")
    assert len(findings) == 1 and not findings[0].mordred_built


def test_desktop_site_repr_handles_doubled_native_backslashes(tmp_path):
    from pathlib import Path

    def run(argv):
        return subprocess.CompletedProcess(argv, 0, repr(r"C:\Hermes 日本 & space\venv\Lib\site-packages"), "")

    candidates = runtime._managed_candidates(tmp_path / "hermes.exe", run)
    assert candidates == [
        Path(r"C:\Hermes 日本 & space\venv") / "Scripts/python.exe",
        Path(r"C:\Hermes 日本 & space\venv") / "python.exe",
    ]


def test_wizard_runtime_guidance_uses_selected_windows_interpreter(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _runtime_probe
    from mordred_hermes.wizard import _runtime_gate, _uninstall_hermes_env

    monkeypatch.setattr(_runtime_probe, "discover_runtime_python", lambda **kw: None)
    selected = tmp_path / "selected env/Scripts/python.exe"
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr(_uninstall_hermes_env, "find_hermes_launcher", lambda home: None)
    monkeypatch.setattr(runtime, "resolve_windows_python", lambda *args, **kwargs: selected)
    assert _runtime_gate._expected_runtime_python(tmp_path) == selected


def test_resolver_requires_runtime_environment_not_only_directory_markers(tmp_path):
    exe = fixture_python(tmp_path / "looks like venv")

    def run(argv):
        data = {"executable": str(exe), "prefix": str(exe.parent.parent), "hermes": True, "environment": False}
        return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")

    assert not runtime.validate_windows_python(exe, runner=run)


def test_windows_uninstall_honors_selected_uv_and_interpreter(monkeypatch, tmp_path):
    from mordred_hermes.wizard import _uninstall_hermes_env as env

    selected = fixture_python(tmp_path / "selected A")
    ambient = fixture_python(tmp_path / "ambient B")
    uv_a = tmp_path / "uv A.exe"
    uv_b = tmp_path / "uv B.exe"
    uv_a.touch()
    uv_b.touch()
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setenv("MORDRED_HERMES_PYTHON", str(selected))
    monkeypatch.setenv("MORDRED_HERMES_UV", str(uv_a))
    calls = []

    def run(argv):
        calls.append(list(argv))
        if argv[0] == str(selected):
            return runner_for(selected)(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    found = env.detect_hermes_env(tmp_path, which=lambda name: str(uv_b) if name == "uv.exe" else None, runner=run)
    assert found.python == selected and found.uv == uv_a
    ok, _output = env.uninstall_packages(found, runner=run)
    assert ok
    assert calls[-1][:5] == [str(uv_a), "pip", "uninstall", "--python", str(selected)]
    assert all(str(ambient) not in command for command in calls)


@pytest.mark.parametrize("which_runner", ["runtime", "uninstall"])
def test_windows_runner_matches_utf8_child_output_and_capture(monkeypatch, which_runner):
    from mordred_hermes.wizard import _uninstall_hermes_env as env

    def run(argv, **kw):
        assert kw["env"]["PYTHONUTF8"] == "1"
        assert kw["env"]["PYTHONIOENCODING"] == "utf-8"
        assert kw["encoding"] == "utf-8"
        return subprocess.CompletedProcess(argv, 0, "Hermes 日本", "")

    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setenv("PYTHONIOENCODING", "cp1252")
    monkeypatch.setattr("subprocess.run", run)
    runner = runtime.default_runner if which_runner == "runtime" else env.default_runner
    assert runner(["python.exe"]).stdout == "Hermes 日本"
