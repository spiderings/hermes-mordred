"""Real PowerShell installer acceptance; no TPM is needed for build tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("MORDRED_WINKEY_BUILD_TEST") != "1",
    reason="requires explicit Windows build-tool test environment",
)


@pytest.fixture(scope="module")
def source() -> Path:
    return Path(os.environ.get("MORDRED_WINKEY_SOURCE", Path(__file__).resolve().parents[1] / "native/winkey-helper"))


@pytest.fixture(scope="module")
def owned_build_source(source: Path):
    from mordred_hermes._private_fs import open_private_directory

    # Hosted CI checkouts (D:\a) grant foreign mutation rights. Exercise owned
    # publication under the real trusted profile instead of weakening admission.
    root = Path(os.environ["USERPROFILE"]) / ("mordred-ci-" + uuid.uuid4().hex)
    with open_private_directory(root, create=True):
        pass
    try:
        copied = root / "source"
        with open_private_directory(copied, create=True):
            pass
        shutil.copytree(source, copied, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target"))
        yield copied
    finally:
        shutil.rmtree(root)  # Only this fixture's newly created private namespace.


def install(
    source: Path, destination: Path, *, powershell: str = "powershell.exe", owned: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(source / "build.ps1"),
            "-InstallDir",
            str(destination),
            "-Python",
            sys.executable,
            *(["-OwnedInstall"] if owned else []),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )


@pytest.mark.parametrize("powershell", ["powershell.exe", "pwsh.exe"])
def test_windows_real_build_owned_publication(owned_build_source: Path, powershell: str) -> None:
    if shutil.which(powershell) is None:
        pytest.skip(f"{powershell} unavailable")
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.wizard._windows_install import is_owned

    destination = owned_build_source.parent / f"owned {powershell} 日本語 bin"
    with open_private_directory(destination, create=True):
        pass
    result = install(owned_build_source, destination, powershell=powershell, owned=True)
    assert result.returncode == 0, result.stdout + result.stderr
    binary = destination / "mordred-hermes-winkey.exe"
    assert binary.read_bytes().startswith(b"MZ")
    assert binary.stat().st_nlink == 1 and is_owned(binary)
    result = install(owned_build_source, destination, powershell=powershell, owned=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert is_owned(binary)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def installed(source: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("winkey-install") / "Hermes 日本語 bin"
    result = install(source, destination)
    assert result.returncode == 0, result.stdout + result.stderr
    binary = destination / "mordred-hermes-winkey.exe"
    assert binary.read_bytes()[:2] == b"MZ"
    result = subprocess.run([str(binary)], input=b'{"cmd":"unknown"}', capture_output=True, timeout=15)
    assert result.returncode != 0 and b'"error"' in result.stdout
    return binary


def test_windows_build_install_unicode_and_replace(source: Path, installed: Path) -> None:
    before = digest(installed)
    result = install(source, installed.parent)
    assert result.returncode == 0, result.stdout + result.stderr
    assert digest(installed) == before
    assert list(installed.parent.iterdir()) == [installed]


def test_windows_failed_build_retains_existing(source: Path, installed: Path, tmp_path: Path) -> None:
    broken = tmp_path / "broken source"
    shutil.copytree(source, broken, ignore=shutil.ignore_patterns("target"))
    (broken / "Cargo.toml").write_text("not valid TOML", encoding="utf-8")
    before = digest(installed)
    result = install(broken, installed.parent)
    assert result.returncode != 0
    assert digest(installed) == before
    assert list(installed.parent.iterdir()) == [installed]


def test_windows_running_destination_retains_existing(source: Path, installed: Path) -> None:
    before = digest(installed)
    # The actual helper waits for bounded stdin while Windows maps its image.
    child = subprocess.Popen([str(installed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert child.poll() is None
        result = install(source, installed.parent)
        assert result.returncode != 0, result.stdout + result.stderr
        assert digest(installed) == before
        assert list(installed.parent.iterdir()) == [installed]
    finally:
        child.communicate(b'{"cmd":"unknown"}', timeout=15)


def test_windows_default_home_unicode_independent_of_codepage(source: Path, tmp_path: Path) -> None:
    home = tmp_path / "default Hermes 日本語"
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(source / "build.ps1"),
            "-Python",
            sys.executable,
        ],
        env={**os.environ, "HERMES_HOME": str(home), "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (home / "bin/mordred-hermes-winkey.exe").read_bytes()[:2] == b"MZ"


@pytest.mark.parametrize("destination", ["relative-bin", "C:relative-bin", "C:", r"\relative-bin", "/relative-bin"])
def test_windows_relative_destination_refused_before_build(source: Path, tmp_path: Path, destination: str) -> None:
    # Deliberately omit Cargo.toml: even the unfixed installer cannot install
    # outside this test's home. Path validation must precede build-tool use.
    isolated = tmp_path / "installer only"
    isolated.mkdir()
    shutil.copy2(source / "build.ps1", isolated / "build.ps1")
    result = install(isolated, Path(destination))
    assert result.returncode != 0
    assert "InstallDir must be an absolute path." in result.stdout + result.stderr


@pytest.mark.parametrize("destination", [r"C:\absolute-bin", r"\\server.invalid\share\absolute-bin"])
def test_windows_absolute_destination_reaches_build(source: Path, tmp_path: Path, destination: str) -> None:
    # Missing manifest stops before filesystem installation (including UNC I/O).
    # Both supported absolute forms must pass validation and reach that failure.
    isolated = tmp_path / "installer only"
    isolated.mkdir()
    shutil.copy2(source / "build.ps1", isolated / "build.ps1")
    result = install(isolated, Path(destination))
    assert result.returncode != 0
    assert "Cargo build failed" in result.stdout + result.stderr
    assert "InstallDir must be an absolute path." not in result.stdout + result.stderr
