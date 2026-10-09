"""Guard that the built wheel bundles the ``sekey-helper`` Swift sources.

``hermes mordred keyvault enable-se`` builds the Secure Enclave helper from
``native/sekey-helper/`` at runtime. A source checkout has those sources, but
a ``pip install``-ed wheel only ships what the build config includes. This
test builds the wheel and asserts the helper sources land under the package
(``mordred_hermes/_native/sekey-helper/``) so ``_locate_helper_source`` can
find them post-install — while the Swift ``.build/`` artifacts stay out.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

#: ``mordred-hermes/`` — the directory holding the real package pyproject.
_PKG_ROOT = Path(__file__).resolve().parent.parent

#: Destination prefix the wheel must expose for the helper sources.
_WHEEL_PREFIX = "mordred_hermes/_native/sekey-helper/"


def _build_wheel(out_dir: Path, *, uv_cache_dir: Path) -> Path:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not available to build the wheel")
    proc = subprocess.run(
        [uv, "build", "--out-dir", str(out_dir)],
        cwd=_PKG_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "UV_CACHE_DIR": str(uv_cache_dir)},
    )
    assert proc.returncode == 0, f"wheel build failed:\n{proc.stdout}\n{proc.stderr}"
    wheels = list(out_dir.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    return wheels[0]


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the wheel from the sdist once with a test-owned cache."""
    root = tmp_path_factory.mktemp("native-wheel")
    return _build_wheel(root / "dist", uv_cache_dir=root / "uv-cache")


@pytest.fixture(scope="module")
def wheel_names(built_wheel: Path) -> frozenset[str]:
    with zipfile.ZipFile(built_wheel) as archive:
        return frozenset(archive.namelist())


def test_wheel_bundles_sekey_helper_sources(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert _WHEEL_PREFIX + "build.sh" in names
    assert _WHEEL_PREFIX + "Package.swift" in names
    assert any(n.startswith(_WHEEL_PREFIX + "Sources/") and n.endswith("main.swift") for n in names)


def test_wheel_excludes_swift_build_artifacts(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert not any(".build/" in n for n in names), "Swift .build/ artifacts must not ship in the wheel"
    assert not any(n.endswith(".o") for n in names), "object files must not ship in the wheel"


#: Destination prefix the wheel must expose for the TPM helper sources (v2-OS2 2c).
_TPMKEY_WHEEL_PREFIX = "mordred_hermes/_native/tpmkey-helper/"


def test_wheel_bundles_tpmkey_helper_sources(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert _TPMKEY_WHEEL_PREFIX + "build.sh" in names
    assert _TPMKEY_WHEEL_PREFIX + "Cargo.toml" in names
    assert any(n.startswith(_TPMKEY_WHEEL_PREFIX + "src/") and n.endswith("main.rs") for n in names)


def test_wheel_excludes_rust_target_artifacts(wheel_names: frozenset[str]) -> None:
    names = wheel_names
    assert not any("tpmkey-helper/target/" in n for n in names), "Rust target/ artifacts must not ship in the wheel"


def test_wheel_bundles_winkey_helper_sources(wheel_names: frozenset[str]) -> None:
    prefix = "mordred_hermes/_native/winkey-helper/"
    for name in (
        "Cargo.toml",
        "Cargo.lock",
        "build.ps1",
        "README.md",
        "src/main.rs",
        "src/cng.rs",
        "src/key_lock.rs",
        "tests/protocol.rs",
        "tests/live_cng.rs",
    ):
        assert prefix + name in wheel_names
    assert not any("winkey-helper/target/" in name for name in wheel_names)


def test_sdist_bundles_winkey_sources_without_build_artifacts(built_wheel: Path) -> None:
    archives = list(built_wheel.parent.glob("*.tar.gz"))
    assert len(archives) == 1
    with tarfile.open(archives[0]) as archive:
        names = {name.partition("/")[2] for name in archive.getnames()}
    for name in ("Cargo.toml", "Cargo.lock", "build.ps1", "README.md", "src/cng.rs", "tests/live_cng.rs"):
        assert "native/winkey-helper/" + name in names
    assert not any("/target/" in name for name in names)


def test_sdist_ships_native_installer(built_wheel: Path) -> None:
    with tarfile.open(next(built_wheel.parent.glob("*.tar.gz"))) as archive:
        names = {name.partition("/")[2] for name in archive.getnames()}
    assert "scripts/install.ps1" in names
