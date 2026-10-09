"""Tests guarding the PyPI release version invariants.

Four invariants are pinned here:

1. **Name-reservation ordering.** The original reservation package claimed the
   ``mordred-hermes`` distribution name on TestPyPI/PyPI by uploading an
   intentionally empty stub *before* the real implementation ships. The stub
   lives at ``packaging/name-reservation/pyproject.toml``. After the rename,
   that project is continued by the metadata-only compatibility shim.

2. **Rename reservation (2026-08-12).** The canonical
   ``hermes-mordred`` distribution has its own empty ``0.0.0.dev0`` stub. It
   shares its project name with the real root package after cutover.

3. **Compatibility ownership.** The ``mordred-hermes`` shim matches the real
   version, depends on that exact ``hermes-mordred`` release, forwards every
   extra, and is configured to build a metadata-only wheel.

4. **Single-source version consistency.** The real package no
   longer hardcodes its version in pyproject. It is sourced dynamically from
   ``src/mordred_hermes/__about__.py`` (Hatch ``[tool.hatch.version] path``),
   which lives inside the importable package so sdist->wheel builds resolve it
   without the docs tree. The docs marker (``docs/dev/VERSION``) and the
   copy-paste ``--reinstall`` pin in
   ``docs/dev/setup.md`` must all match that single source — otherwise a release
   bump that touches only some of them ships an inconsistent version.
   ``tools/bump_version.py`` rewrites all of them in lockstep; these tests are
   the net that catches a hand-edit that forgets one. The top-level README is
   intentionally version-agnostic and relies on the PyPI badge.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import pytest
from packaging.version import Version

#: Repository root — holds the real package pyproject and the docs tree.
_PKG_ROOT = Path(__file__).resolve().parent.parent

#: The empty stub uploaded first to claim the name (M7).
_STUB_PYPROJECT = _PKG_ROOT / "packaging" / "name-reservation" / "pyproject.toml"

#: The historical stub that reserved the target distribution name before the
#: root package adopted it. It now deliberately shares the canonical name while
#: remaining permanently below every real release.
_RENAME_STUB_PYPROJECT = _PKG_ROOT / "packaging" / "hermes-mordred-reservation" / "pyproject.toml"

#: Metadata-only continuation of the old distribution name.
_COMPAT_PYPROJECT = _PKG_ROOT / "packaging" / "mordred-hermes-compat" / "pyproject.toml"

#: Release mode routing consumed directly by release.yml.
_RELEASE_PROJECTS = _PKG_ROOT / "packaging" / "release-projects.toml"

#: The real Mordred plugin bundle.
_REAL_PYPROJECT = _PKG_ROOT / "pyproject.toml"

#: The importable package's single source of version truth (Hatch reads this).
_ABOUT = _PKG_ROOT / "src" / "mordred_hermes" / "__about__.py"

#: Human-facing version marker in the docs tree (a mirror of ``_ABOUT``).
_DOC_VERSION = _PKG_ROOT / "docs" / "dev" / "VERSION"

#: Dev-setup doc with a version-pinned ``--reinstall`` example. Absent from
#: the installed-package context (docs tree not shipped), same as
#: ``_DOC_VERSION``.
_SETUP_MD = _PKG_ROOT / "docs" / "dev" / "setup.md"

#: Matches ``hermes-mordred[extra1,extra2]==<version>`` install pins and
#: captures the version.
_INSTALL_PIN_RE = re.compile(r"hermes-mordred\[[^\]]*\]==([0-9][^\s\"'#]*)")


def _read(pyproject: Path) -> dict[str, object]:
    """Return the ``[project]`` table of ``pyproject``."""
    with pyproject.open("rb") as fh:
        return dict(tomllib.load(fh)["project"])


def _real_version() -> str:
    """Resolve the real package version from its dynamic source.

    The real pyproject declares ``dynamic = ["version"]`` and sources the value
    from ``__about__.py`` via Hatch's ``path`` version source, so there is no
    static ``[project].version`` to read. Parse the assignment with ``ast`` so
    we read exactly what Hatch reads — no import side effects.
    """
    tree = ast.parse(_ABOUT.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return value
    raise AssertionError(f"__version__ assignment not found in {_ABOUT}")


def _plugin_manifests() -> list[Path]:
    """Every plugin manifest shipped in the package (expected: none)."""
    return sorted(_PKG_ROOT.glob("src/mordred_hermes/**/plugin.yaml"))


def test_distribution_names_follow_the_cutover_contract() -> None:
    """Reservation sources stay attached to the project they originally claimed."""
    assert _read(_STUB_PYPROJECT)["name"] == _read(_COMPAT_PYPROJECT)["name"] == "mordred-hermes"
    assert _read(_RENAME_STUB_PYPROJECT)["name"] == _read(_REAL_PYPROJECT)["name"] == "hermes-mordred"


def test_real_pyproject_sources_version_dynamically() -> None:
    """The real package must source its version from ``__about__.py``, not inline.

    Guards against someone re-introducing a hardcoded ``version`` (which would
    silently diverge from the single source and defeat ``bump_version.py``).
    """
    project = _read(_REAL_PYPROJECT)
    assert "version" not in project, "real version must be dynamic, not hardcoded in [project]"
    assert "version" in project.get("dynamic", []), "real pyproject must declare dynamic version"


def test_legacy_stub_version_is_strictly_below_compat_version() -> None:
    """The stub must sort below the compatibility release per PEP 440 ordering.

    Otherwise the real ``release.yml`` publish would be rejected by PyPI as an
    older-or-equal version of an already-claimed name.
    """
    stub = Version(str(_read(_STUB_PYPROJECT)["version"]))
    compat = Version(str(_read(_COMPAT_PYPROJECT)["version"]))
    assert stub < compat, f"stub {stub} must be < compatibility release {compat}"


def test_stub_version_is_a_dev_release() -> None:
    """The reservation stub is a ``.devN`` release — never a real version."""
    assert Version(str(_read(_STUB_PYPROJECT)["version"])).is_devrelease


def test_rename_stub_version_is_a_dev_release_below_the_real_version() -> None:
    """The reservation must never sort as a real release."""
    stub = Version(str(_read(_RENAME_STUB_PYPROJECT)["version"]))
    assert stub.is_devrelease
    assert stub < Version(_real_version())


def test_compatibility_shim_matches_and_forwards_the_real_release() -> None:
    real = _read(_REAL_PYPROJECT)
    compat = _read(_COMPAT_PYPROJECT)
    version = _real_version()

    assert compat["version"] == version
    assert compat["dependencies"] == [f"hermes-mordred=={version}"]
    real_extras = real["optional-dependencies"]
    compat_extras = compat["optional-dependencies"]
    assert isinstance(real_extras, dict)
    assert isinstance(compat_extras, dict)
    assert set(compat_extras) == set(real_extras)
    assert compat_extras == {extra: [f"hermes-mordred[{extra}]=={version}"] for extra in real_extras}


def test_compatibility_shim_declares_no_runtime_files_or_entry_points() -> None:
    with _COMPAT_PYPROJECT.open("rb") as stream:
        metadata = tomllib.load(stream)

    project = metadata["project"]
    assert "scripts" not in project
    assert "entry-points" not in project
    assert metadata["tool"]["hatch"]["build"]["targets"]["wheel"] == {"bypass-selection": True}


def test_release_project_contract_matches_package_metadata() -> None:
    """Every publish mode must resolve to the intended on-disk project."""
    with _RELEASE_PROJECTS.open("rb") as stream:
        modes = tomllib.load(stream)["mode"]

    assert modes == {
        "reserve": {
            "directory": "packaging/name-reservation",
            "name": "mordred-hermes",
            "reservation": True,
        },
        "reserve-rename": {
            "directory": "packaging/hermes-mordred-reservation",
            "name": "hermes-mordred",
            "reservation": True,
        },
        "release": {
            "directory": ".",
            "name": "hermes-mordred",
            "reservation": False,
        },
        "compat": {
            "directory": "packaging/mordred-hermes-compat",
            "name": "mordred-hermes",
            "reservation": False,
        },
    }
    for project in modes.values():
        pyproject = _PKG_ROOT / project["directory"] / "pyproject.toml"
        assert _read(pyproject)["name"] == project["name"]


def test_doc_version_marker_matches_package_version() -> None:
    """The docs-tree VERSION marker must mirror the package's single source."""
    if not _DOC_VERSION.exists():
        pytest.skip("docs tree absent (installed-package context, not a source checkout)")
    marker = _DOC_VERSION.read_text(encoding="utf-8").strip()
    assert marker == _real_version(), (
        f"docs VERSION {marker!r} != package {_real_version()!r}; run tools/bump_version.py to sync"
    )


def test_no_plugin_yaml_manifests_ship() -> None:
    """Mordred is one entry-point plugin; Hermes never reads plugin.yaml for it.

    Per-component manifests used to carry a hand-synced ``version:`` that
    nothing consumed. A new one would drift silently, so none may return.
    """
    assert _plugin_manifests() == []


def test_setup_install_pin_matches_package_version() -> None:
    """The version-pinned development reinstall command tracks the package."""
    version = _real_version()
    if not _SETUP_MD.exists():
        pytest.skip("docs tree absent (installed-package context, not a source checkout)")
    setup_pins = _INSTALL_PIN_RE.findall(_SETUP_MD.read_text(encoding="utf-8"))
    assert len(setup_pins) >= 1, f"expected >=1 install pin in docs/dev/setup.md, found {len(setup_pins)}"
    mismatched_setup = [p for p in setup_pins if p != version]
    assert not mismatched_setup, (
        f"docs/dev/setup.md install pin out of sync with package version {version!r}: {mismatched_setup}; "
        "run tools/bump_version.py to sync"
    )
