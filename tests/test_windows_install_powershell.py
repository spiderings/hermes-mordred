"""Real Windows PowerShell argument/exit tests, without package/network installs.

A disposable interpreter sees the current test package via a test-owned .pth.
The uv executable is a compiled fixture that logs argv and never uses network.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows PowerShell fixture gate")
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=["powershell.exe", "pwsh.exe"])
def ps(request):
    executable = shutil.which(request.param)
    if executable is None:
        pytest.skip(f"{request.param} not installed")
    return executable


@pytest.fixture
def native_fixture(ps, tmp_path):
    root = tmp_path / "env 日本 & $ user's"
    # Pip is unused: metadata/dependencies come from the explicit read-only
    # test-site .pth, and uv is a compiled logging fixture. Avoid ensurepip's
    # unrelated nested-path failure while retaining native Unicode paths.
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root)], check=True, timeout=60)
    python = root / "Scripts/python.exe"
    site = root / "Lib/site-packages"
    (site / "fixture.pth").write_text(
        f"import site; site.addsitedir({sysconfig.get_path('purelib')!r})\n", encoding="utf-8"
    )
    shutil.copy2(python, python.parent / "hermes-mordred.exe")
    uv = tmp_path / "uv fixture.exe"
    code = r"""
using System;
using System.IO;
using System.Text;
public class Fixture {
 public static int Main(string[] args) {
  File.AppendAllText(Environment.GetEnvironmentVariable("UV_FIXTURE_LOG"),
                     Environment.GetCommandLineArgs()[0] + "\t" + String.Join("\t", args) + "\n", Encoding.UTF8);
  if (args.Length > 1 && args[1] == "freeze") { Console.WriteLine("hermes-agent==0.19.0"); return 0; }
  string failure = Environment.GetEnvironmentVariable("UV_FIXTURE_FAIL");
  if (Array.IndexOf(args, "--dry-run") >= 0 && failure == "dry-run") return 37;
  if (args.Length > 1 && args[1] == "install" && Array.IndexOf(args, "--dry-run") < 0 && failure == "install")
   return 41;
  if (Environment.GetEnvironmentVariable("PYTHONPATH") != null ||
      Environment.GetEnvironmentVariable("UV_INDEX_URL") != null) return 51;
  return 0;
 }
}
"""
    # Framework compiler output runs under both PS5.1 and PS7. Add-Type's
    # ConsoleApplication output is unavailable on PS7/.NET Core.
    compilers = sorted(Path(os.environ["WINDIR"]).glob("Microsoft.NET/Framework*/v4.*/csc.exe"))
    assert compilers, "native fixtures require the Windows .NET Framework C# compiler"
    fixture_source = tmp_path / "fixture.cs"
    fixture_source.write_text(code, encoding="utf-8")
    result = subprocess.run(
        [str(compilers[-1]), "/nologo", "/target:exe", f"/out:{uv}", str(fixture_source)],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    source = tmp_path / "unreleased 日本 & $ source.whl"
    source.touch()
    home = tmp_path / "profile 日本 & $"
    home.mkdir()
    log = tmp_path / "uv.log"
    env = dict(
        os.environ,
        HERMES_HOME=str(home),
        UV_FIXTURE_LOG=str(log),
        PYTHONPATH="invalid redirect",
        UV_INDEX_URL="https://invalid.invalid",
    )
    argv = [
        ps,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(ROOT / "scripts/install.ps1"),
        "-Python",
        str(python),
        "-Uv",
        str(uv),
        "-Source",
        str(source),
    ]
    return argv, env, home, log, python, source


def test_installer_literal_paths_selected_runtime_and_owned_upgrade(native_fixture):
    from mordred_hermes.wizard import _windows_install

    try:
        _windows_install._confidential_opener()
    except OSError:
        pytest.skip("native successful publication pending shared C1b ACL capability")
    argv, env, home, log, python, source = native_fixture
    for _ in range(2):
        result = subprocess.run(
            [*argv, "-InstallOnly"], env=env, capture_output=True, encoding="utf-8", errors="replace", timeout=120
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Installation-only validation completed" in result.stdout
        assert str(python) in result.stdout
    recorded = log.read_text(encoding="utf-8-sig")
    assert str(source) in recorded and str(python) in recorded
    assert (home / "bin/hermes-mordred.ps1.mordred-owner.json").is_file()
    assert not (home / "config.yaml").exists()


@pytest.mark.parametrize("stage", ["dry-run", "install"])
def test_installer_nonzero_native_exit_never_claims_success(native_fixture, stage):
    argv, env, home, _log, _python, _source = native_fixture
    result = subprocess.run(
        [*argv, "-InstallOnly"],
        env={**env, "UV_FIXTURE_FAIL": stage},
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode != 0
    assert "completed" not in result.stdout
    assert not (home / "bin/hermes-mordred.ps1").exists()


def test_installer_unknown_launcher_preserved(native_fixture):
    argv, env, home, _log, _python, _source = native_fixture
    (home / "bin").mkdir()
    path = home / "bin/hermes-mordred.ps1"
    path.write_text("unknown launcher", encoding="utf-8")
    result = subprocess.run(
        [*argv, "-InstallOnly"], env=env, capture_output=True, encoding="utf-8", errors="replace", timeout=120
    )
    assert result.returncode != 0
    assert path.read_text() == "unknown launcher"
    assert "completed" not in result.stdout


def test_installer_configure_dispatch_nonzero_is_failure(native_fixture):
    from mordred_hermes.wizard import _windows_install

    try:
        _windows_install._confidential_opener()
    except OSError:
        pytest.skip("canonical dispatch follows native publication; pending shared C1b ACL capability")
    argv, env, _home, _log, _python, _source = native_fixture
    # Invalid configure flag must reach canonical parser and propagate rc2.
    result = subprocess.run(
        [*argv, "-Action", "configure", "-CommandArgs", "--unknown-fixture-flag"],
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode != 0
    assert "configure completed" not in result.stdout


def test_exposed_launcher_executes_cli_and_propagates_exit(native_fixture, ps, tmp_path):
    from mordred_hermes.wizard import _windows_install

    argv, env, _home, _log, python, _source = native_fixture
    launcher = tmp_path / "literal launcher 日本 & $.ps1"
    # Test-owned launcher fixture tests invocation before C1b publication lands.
    launcher.write_bytes(_windows_install._launcher_content(python))
    help_result = subprocess.run(
        [ps, "-NoProfile", "-File", str(launcher), "--help"],
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert help_result.returncode == 0
    assert "hermes-mordred" in help_result.stdout
    invalid = subprocess.run(
        [ps, "-NoProfile", "-File", str(launcher), "--unknown-fixture-flag"],
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert invalid.returncode == 2
    plan_env = {**env, "MORDRED_HERMES_PYTHON": str(python), "MORDRED_HERMES_UV": argv[argv.index("-Uv") + 1]}
    plan = subprocess.run(
        [ps, "-NoProfile", "-File", str(launcher), "uninstall", "--dry-run"],
        env=plan_env,
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        timeout=60,
    )
    assert plan.returncode == 0, plan.stdout + plan.stderr
    assert str(python.parent.parent) in plan.stdout


def test_installer_explicit_uninstall_targets_environment_and_uv_a(native_fixture, tmp_path):
    argv, env, home, log, python_a, _source = native_fixture
    root_b = home / "hermes-agent/venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root_b)], check=True, timeout=60)
    python_b = root_b / "Scripts/python.exe"
    (root_b / "Lib/site-packages/fixture.pth").write_text(
        f"import site; site.addsitedir({sysconfig.get_path('purelib')!r})\n", encoding="utf-8"
    )
    uv_a = Path(argv[argv.index("-Uv") + 1])
    uv_b = root_b / "Scripts/uv.exe"
    shutil.copy2(uv_a, uv_b)
    env = {
        **env,
        "MORDRED_HERMES_PYTHON": str(python_b),
        "MORDRED_HERMES_UV": str(uv_b),
        "PATH": str(uv_b.parent) + os.pathsep + env["PATH"],
    }
    result = subprocess.run(
        [*argv, "-Action", "uninstall", "-CommandArgs", "--yes"],
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert str(python_a.parent.parent) in result.stdout
    lines = [line.split("\t") for line in log.read_text(encoding="utf-8-sig").splitlines()]
    uninstalls = [line for line in lines if line[1:3] == ["pip", "uninstall"]]
    assert uninstalls
    assert all(line[0] == str(uv_a) for line in uninstalls)
    assert all(line[line.index("--python") + 1] == str(python_a) for line in uninstalls)
    assert all(str(python_b) not in line for line in lines)


def test_winkey_bound_build_runs_from_fresh_restricted_parent(ps, native_fixture, tmp_path):
    _argv, env, _home, _log, python, _source = native_fixture
    source = tmp_path / "bound helper 日本 & $"
    source.mkdir()
    target = tmp_path / "probe target"
    target.mkdir()
    (source / "build.ps1").write_text(
        "param([string]$InstallDir, [string]$Python, [switch]$OwnedInstall)\n"
        "[IO.File]::WriteAllText((Join-Path $InstallDir 'entered.txt'), $env:PSExecutionPolicyPreference)\n",
        encoding="utf-8-sig",
    )
    code = (
        "import os, sys; assert os.environ.get('PSExecutionPolicyPreference') == 'Restricted'; "
        "os.environ.pop('PSExecutionPolicyPreference'); "
        "assert 'PSExecutionPolicyPreference' not in os.environ; "
        "from mordred_hermes.wizard import keyvault_native_cli as n; "
        "from pathlib import Path; "
        "import shutil; shutil.which = lambda name: os.environ['MORDRED_FIXTURE_PS']; "
        "rc, output = n._run_winkey_build(Path(sys.argv[1]), install_dir=Path(sys.argv[2])); "
        "print(output); raise SystemExit(rc)"
    )
    env = {
        **env,
        "MORDRED_FIXTURE_PYTHON": str(python),
        "MORDRED_FIXTURE_CODE": code,
        "MORDRED_FIXTURE_SOURCE": str(source),
        "MORDRED_FIXTURE_TARGET": str(target),
        "MORDRED_FIXTURE_PS": ps,
    }
    env.pop("PSExecutionPolicyPreference", None)
    command = (
        "[Console]::WriteLine('PARENT=' + $env:PSExecutionPolicyPreference); & $env:MORDRED_FIXTURE_PYTHON -c "
        "$env:MORDRED_FIXTURE_CODE $env:MORDRED_FIXTURE_SOURCE $env:MORDRED_FIXTURE_TARGET; exit $LASTEXITCODE"
    )
    result = subprocess.run(
        [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Restricted", "-Command", command],
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PARENT=Restricted" in result.stdout
    assert (target / "entered.txt").read_text() == "Bypass"


def test_installer_removes_scrubbed_keys_from_native_python_environment(native_fixture, tmp_path):
    from mordred_hermes._windows_runtime import SCRUBBED_ENV

    argv, env, _home, _log, python, _source = native_fixture
    observed = tmp_path / "child environment keys.jsonl"
    spy = python.parent.parent / "Lib/site-packages/fixture_env_probe.py"
    spy.write_text(
        "import json, os\n"
        "from pathlib import Path\n"
        f"keys = {SCRUBBED_ENV!r}\n"
        "present = sorted(set(keys).intersection(os.environ))\n"
        "with Path(os.environ['MORDRED_FIXTURE_ENV_LOG']).open('a', encoding='utf-8') as stream:\n"
        " stream.write(json.dumps(present) + '\\n')\n",
        encoding="utf-8",
    )
    (spy.parent / "env-probe.pth").write_text("import fixture_env_probe\n", encoding="utf-8")
    result = subprocess.run(
        [*argv, "-InstallOnly"],
        env={**env, "MORDRED_FIXTURE_ENV_LOG": str(observed), "UV_SYSTEM_PYTHON": "1"},
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    import json

    records = [json.loads(line) for line in observed.read_text(encoding="utf-8").splitlines()]
    assert records
    assert all(record == [] for record in records), records
