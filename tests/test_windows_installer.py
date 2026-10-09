"""Native installer seams; real PowerShell acceptance is Windows-only."""

from __future__ import annotations

import subprocess

import pytest

from mordred_hermes.wizard import cli, setup_cli, status_cli
from mordred_hermes.wizard import keyvault_native_cli as native


def test_winkey_parser_dispatch(monkeypatch, tmp_path):
    monkeypatch.setattr(
        native, "enable_winkey", lambda **kw: 47 if kw["install_dir"] == tmp_path else 99, raising=False
    )
    assert cli.main(["keyvault", "enable-winkey", "--install-dir", str(tmp_path)]) == 47


def test_winkey_unsupported_host(monkeypatch, capsys):
    monkeypatch.setattr("sys.platform", "darwin")
    assert native.enable_winkey() == 1
    assert "Windows" in capsys.readouterr().err


def test_winkey_uses_exact_custom_probe(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr(native, "_missing_winkey_build_tools", lambda: [], raising=False)
    monkeypatch.setattr(native, "_locate_winkey_source", lambda: tmp_path, raising=False)
    monkeypatch.setattr(native, "_run_winkey_build", lambda src, **kw: (0, ""), raising=False)
    binary = tmp_path / "mordred-hermes-winkey.exe"
    binary.write_bytes(b"MZ")
    from mordred_hermes.keyvault import _seckey_helper

    class Probe:
        def __init__(self, selected):
            assert selected == str(binary)

        def probe(self):
            raise RuntimeError("TPM unavailable: native reason 0x1234")

    monkeypatch.setattr(_seckey_helper, "_HelperSecKeyOps", Probe)
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: pytest.fail("ambient lookup"))
    assert native.enable_winkey(install_dir=tmp_path) == 1
    assert "native reason 0x1234" in capsys.readouterr().err


def test_winkey_missing_custom_binary_never_probes_ambient(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: pytest.fail("ambient lookup"))
    assert native._verify_winkey_helper(install_dir=tmp_path)[0] is False


@pytest.mark.parametrize("failure", ["tools", "source", "build"])
def test_winkey_preflight_and_build_failure(monkeypatch, tmp_path, failure, capsys):
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr(
        native, "_missing_winkey_build_tools", lambda: ["cargo"] if failure == "tools" else [], raising=False
    )
    monkeypatch.setattr(
        native, "_locate_winkey_source", lambda: None if failure == "source" else tmp_path, raising=False
    )
    monkeypatch.setattr(native, "_run_winkey_build", lambda src, **kw: (9, "native build failed"), raising=False)
    assert native.enable_winkey(home=tmp_path) == 1
    assert "succeeded" not in capsys.readouterr().out


def test_build_argv_preserves_literal_paths_and_python(monkeypatch, tmp_path):
    import sys

    source = tmp_path / "日本 & $ source"
    target = tmp_path / "target ; space"

    def run(argv, **kw):
        assert argv[-4:] == ["-InstallDir", str(target), "-Python", sys.executable]
        assert str(source / "build.ps1") in argv
        assert not kw.get("shell")
        raise subprocess.TimeoutExpired(argv, 600)

    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr("shutil.which", lambda name: "/trusted/powershell.exe")
    rc, reason = native._run_winkey_build(source, install_dir=target)
    assert rc != 0 and "timed out" in reason


def test_winkey_status_finder(monkeypatch):
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: "winkey.exe")
    assert status_cli._default_helper_finder("win32") == "winkey.exe"


def test_winkey_setup_only_claims_helper(monkeypatch, tmp_path):
    monkeypatch.setattr(setup_cli, "_probe_winkey_helper", lambda **kw: False, raising=False)
    monkeypatch.setattr(native, "enable_winkey", lambda **kw: 0, raising=False)
    result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="win32")
    assert result.action == "ran"
    assert "memory" not in result.detail.lower()


def test_winkey_source_is_bound_to_current_package():
    source = native._locate_winkey_source()
    assert source is not None
    assert (source / "build.ps1").is_file()
    assert (source / "Cargo.toml").is_file()


def test_winkey_source_never_searches_arbitrary_ancestors(monkeypatch, tmp_path):
    import importlib.resources

    unrelated = tmp_path / "native/winkey-helper"
    (unrelated / "src").mkdir(parents=True)
    for name in ("build.ps1", "Cargo.toml", "Cargo.lock", "src/main.rs"):
        (unrelated / name).touch()
    monkeypatch.setattr(importlib.resources, "files", lambda name: tmp_path / "missing-package")
    monkeypatch.setattr(native, "__file__", str(tmp_path / "unrelated/module/wizard/native.py"))
    assert native._locate_winkey_source() is None


def test_winkey_build_has_process_only_policy_for_bound_script(monkeypatch, tmp_path):
    def run(argv, **kw):
        assert argv[argv.index("-ExecutionPolicy") + 1] == "Bypass"
        assert argv[argv.index("-File") + 1] == str(tmp_path / "build.ps1")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr("shutil.which", lambda name: "/trusted/powershell.exe")
    assert native._run_winkey_build(tmp_path, install_dir=tmp_path)[0] == 0


def test_winkey_build_uses_matching_utf8_child_and_capture(monkeypatch, tmp_path):
    def run(argv, **kw):
        assert kw["env"]["PYTHONIOENCODING"] == "utf-8"
        assert kw["env"]["PYTHONUTF8"] == "1"
        assert kw["encoding"] == "utf-8"
        return subprocess.CompletedProcess(argv, 0, "Installed: 日本", "")

    monkeypatch.setenv("PYTHONIOENCODING", "cp1252")
    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr("shutil.which", lambda name: "/trusted/powershell.exe")
    assert native._run_winkey_build(tmp_path, install_dir=tmp_path) == (0, "Installed: 日本")
