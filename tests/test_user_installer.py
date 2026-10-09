"""Hermetic tests for the public ``scripts/install.sh`` entry point."""

from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install.sh"

#: Stand-in for uv. Records every invocation, reports a fixed hermes-agent
#: version, and materialises the console script `pip install` would create.
#: ``pip check`` answers differently before and after the install so a test can
#: drive the "Mordred broke Hermes's dependency graph" path.
_FAKE_UV = """#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$UV_LOG"
# Cheap visibility probe for MORDRED_INSTALL_EXTRAS: the installer must unset
# it before invoking uv, so every call should log "<unset>" here.
printf 'MORDRED_INSTALL_EXTRAS=%s\\n' "${MORDRED_INSTALL_EXTRAS-<unset>}" >> "$UV_LOG"
if [ "$1" = pip ] && [ "$2" = show ]; then
  case " $* " in
    *' hermes-agent '*)
      printf 'Name: hermes-agent\\nVersion: %s\\n' "$HERMES_VERSION"
      exit 0
      ;;
    *' mordred-hermes '*)
      if [ -n "${UV_LEGACY_VERSION:-}" ] && [ ! -f "$UV_STATE/legacy-removed" ]; then
        printf 'Name: mordred-hermes\\nVersion: %s\\n' "$UV_LEGACY_VERSION"
        exit 0
      fi
      exit 1
      ;;
  esac
  exit 64
fi
if [ "$1" = pip ] && [ "$2" = check ]; then
  if [ -f "$UV_STATE/installed" ]; then
    exit "${UV_CHECK_AFTER:-0}"
  fi
  exit "${UV_CHECK_BEFORE:-0}"
fi
if [ "$1" = pip ] && [ "$2" = uninstall ]; then
  if [ "${UV_UNINSTALL_FAIL:-0}" = 1 ]; then
    exit 1
  fi
  : > "$UV_STATE/legacy-removed"
  exit 0
fi
if [ "$1" = pip ] && [ "$2" = freeze ]; then
  printf '%s\n' ${UV_FREEZE:-}
  exit 0
fi
if [ "$1" = pip ] && [ "$2" = install ]; then
  prev=''
  for arg in "$@"; do
    if [ "$prev" = --constraint ]; then cp "$arg" "$UV_STATE/constraints"; fi
    prev="$arg"
  done
  case " $* " in
    *' --dry-run '*) exit "${UV_DRY_RUN_FAIL:-0}" ;;
  esac
  case " $* " in
    *' hermes-mordred'*)
      if [ "${UV_CANONICAL_INSTALL_FAIL:-0}" = 1 ]; then
        exit 1
      fi
      ;;
    *' mordred-hermes'*)
      if [ "${UV_RESTORE_FAIL:-0}" = 1 ]; then
        exit 1
      fi
      ;;
  esac
  shift 2
  python_path=''
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --python ]; then
      python_path="$2"
      shift 2
    else
      shift
    fi
  done
  cli="$(dirname "$python_path")/hermes-mordred"
  printf '#!/bin/sh\\nexit 0\\n' > "$cli"
  chmod 755 "$cli"
  : > "$UV_STATE/installed"
  exit 0
fi
exit 64
"""

#: Verbatim shape of the launcher Hermes's official installer writes to
#: ~/.local/bin/hermes: a bash wrapper whose shebang names bash, not Python.
_HERMES_WRAPPER = """#!/usr/bin/env bash
unset PYTHONPATH
unset PYTHONHOME
exec "{python}" "{agent}" "$@"
"""


# eq=False: `env` is a dict, so the auto-generated __hash__ from frozen+eq
# would raise TypeError, and the field stays mutable regardless of `frozen`.
@dataclass(frozen=True, eq=False)
class InstallFixture:
    home: Path
    bin_dir: Path
    hermes_python: Path
    uv_log: Path
    env: dict[str, str]

    @property
    def installed_cli(self) -> Path:
        return self.hermes_python.parent / "hermes-mordred"

    @property
    def launcher(self) -> Path:
        return self.bin_dir / "hermes-mordred"

    def uv_calls(self) -> str:
        return self.uv_log.read_text(encoding="utf-8") if self.uv_log.exists() else ""


def _write_executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _make_env(root: Path, *, is_venv: bool = True) -> Path:
    """Create a virtualenv-shaped tree and return its ``bin/python3``."""
    python = root / "bin" / "python3"
    _write_executable(python, "#!/bin/sh\nexit 0\n")
    if is_venv:
        (root / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    return python


def _fixture(
    tmp_path: Path,
    *,
    platform_name: str = "Darwin",
    hermes_version: str = "0.19.0",
    launcher_style: str = "wrapper",
    is_venv: bool = True,
    shadow_env: Path | None = None,
) -> InstallFixture:
    """Build an isolated install target.

    ``launcher_style`` picks how ``hermes`` is exposed on PATH: ``wrapper`` is
    the official installer's bash launcher, ``console`` a pip-generated console
    script, ``none`` leaves PATH without ``hermes`` at all. ``shadow_env``
    points the PATH launcher at a *different* environment than the canonical
    ``~/.hermes`` one, which is how a second Hermes install is simulated.
    """
    home = tmp_path / "home"
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    canonical_python = _make_env(home / ".hermes" / "hermes-agent" / "venv", is_venv=is_venv)
    launcher_python = _make_env(shadow_env, is_venv=is_venv) if shadow_env is not None else canonical_python

    if launcher_style == "wrapper":
        _write_executable(
            bin_dir / "hermes",
            _HERMES_WRAPPER.format(python=launcher_python, agent=launcher_python.parent.parent.parent / "hermes"),
        )
    elif launcher_style == "console":
        _write_executable(launcher_python.parent / "hermes", f"#!{launcher_python}\n")
        (bin_dir / "hermes").symlink_to(launcher_python.parent / "hermes")
    elif launcher_style != "none":  # pragma: no cover - guards test authoring
        raise ValueError(f"unknown launcher_style {launcher_style!r}")

    expected_python = canonical_python if launcher_style == "none" else launcher_python

    state = tmp_path / "state"
    state.mkdir()
    fake_uv = tmp_path / "fake-bin" / "uv"
    _write_executable(fake_uv, _FAKE_UV)
    _write_executable(fake_uv.parent / "uname", f"#!/bin/sh\nprintf '%s\\n' '{platform_name}'\n")

    env = {
        **os.environ,
        "HOME": str(home),
        "HERMES_HOME": str(home / ".hermes"),
        "HERMES_VERSION": hermes_version,
        "UV_LOG": str(tmp_path / "uv.log"),
        "UV_STATE": str(state),
        "PATH": os.pathsep.join((str(fake_uv.parent), str(bin_dir), "/usr/bin", "/bin")),
    }
    env.pop("PYTHONPATH", None)
    return InstallFixture(
        home=home,
        bin_dir=bin_dir,
        hermes_python=expected_python,
        uv_log=tmp_path / "uv.log",
        env=env,
    )


def _run(fixture: InstallFixture, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", str(INSTALLER), *args],
        check=False,
        capture_output=True,
        text=True,
        env={**fixture.env, **overrides},
    )


def _run_from_stdin(fixture: InstallFixture, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", "-s", "--", *args],
        input=INSTALLER.read_text(encoding="utf-8"),
        check=False,
        capture_output=True,
        text=True,
        env={**fixture.env, **overrides},
    )


def test_installer_has_valid_bash_syntax() -> None:
    assert INSTALLER.stat().st_mode & stat.S_IXUSR
    result = subprocess.run(["/bin/bash", "-n", str(INSTALLER)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_minimum_hermes_version_matches_pyproject() -> None:
    """The gate in the installer and ``[tool.mordred]`` must not drift apart."""
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mordred"][
        "min-hermes-version"
    ]
    match = re.search(r'^readonly MIN_HERMES_VERSION="([^"]+)"$', INSTALLER.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None, "scripts/install.sh must declare MIN_HERMES_VERSION"
    assert match.group(1) == declared


def test_mordred_floor_excludes_the_canonical_name_reservation() -> None:
    """The installer must never resolve the empty ``0.0.0.dev0`` claim stub."""
    installer = INSTALLER.read_text(encoding="utf-8")
    floor_match = re.search(r'^readonly MIN_MORDRED_VERSION="([^"]+)"$', installer, re.MULTILINE)
    name_match = re.search(r'^readonly DISTRIBUTION_NAME="([^"]+)"$', installer, re.MULTILINE)
    with (ROOT / "packaging" / "hermes-mordred-reservation" / "pyproject.toml").open("rb") as stream:
        reservation = tomllib.load(stream)["project"]

    assert floor_match is not None, "scripts/install.sh must declare MIN_MORDRED_VERSION"
    assert name_match is not None, "scripts/install.sh must declare DISTRIBUTION_NAME"
    assert name_match.group(1) == reservation["name"] == "hermes-mordred"
    assert Version(floor_match.group(1)) > Version(reservation["version"])


def test_user_optional_extras_do_not_drift_from_pyproject_or_docs(tmp_path: Path) -> None:
    """``USER_OPTIONAL_EXTRAS``, installer validation, and the Quickstart table agree.

    The extras list is hard-coded 3x in install.sh (the readonly declaration,
    the usage heredoc, and the case whitelist arm) and again in the Quickstart
    extras table. The usage heredoc is interpolated from the readonly
    declaration so those two cannot drift; this test pins the remaining two.
    """
    installer_source = INSTALLER.read_text(encoding="utf-8")
    match = re.search(r'^readonly USER_OPTIONAL_EXTRAS="([^"]+)"$', installer_source, re.MULTILINE)
    assert match is not None, "scripts/install.sh must declare USER_OPTIONAL_EXTRAS"
    extras_in_order = match.group(1).split(",")
    user_extras = set(extras_in_order)

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["optional-dependencies"]
    # macos/keyvault are platform-automatic; dev/integration are for repository
    # development and must never land in Hermes's runtime environment (see the
    # rejection messages in scripts/install.sh's add_requested_extra()).
    platform_or_dev_only = {"macos", "keyvault", "dev", "integration"}
    assert user_extras == set(declared) - platform_or_dev_only

    # The case-arm whitelist lists the same extras, in the same order, as a
    # literal `|`-joined pattern (bash 3.2 has no associative arrays to derive
    # this from USER_OPTIONAL_EXTRAS directly without complicating the script).
    case_arm = " | ".join(extras_in_order)
    assert case_arm in installer_source, "the case whitelist arm has drifted from USER_OPTIONAL_EXTRAS"

    fixture = _fixture(tmp_path)
    result = _run(fixture, "--help")
    assert result.returncode == 0, result.stderr
    # Anchor on the interpolated line itself: bare names would also match
    # `--with-extension` / `browser-extension` elsewhere in the usage text.
    feature_line = next((line for line in result.stdout.splitlines() if line.startswith("Feature extras:")), None)
    assert feature_line is not None, "--help output lost its 'Feature extras:' line"
    assert feature_line == "Feature extras: " + ", ".join(extras_in_order)

    # Scope the Quickstart check to the extras table block; the same names
    # appear in prose elsewhere and must not satisfy a stale-table assertion.
    quickstart = (ROOT / "docs" / "user" / "QUICKSTART.md").read_text(encoding="utf-8")
    assert "| Extra | Use it for |" in quickstart, "QUICKSTART.md extras table header changed"
    table = quickstart.split("| Extra | Use it for |", 1)[1].split("\n\n", 1)[0]
    for extra in user_extras:
        assert f"| `{extra}` |" in table, f"QUICKSTART.md extras table omits {extra!r}"


def test_user_docs_lead_with_the_installer_and_path_command() -> None:
    quickstart = (ROOT / "docs" / "user" / "QUICKSTART.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    install_command = (
        "curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash"
    )

    assert install_command in quickstart
    assert "hermes-mordred configure" in quickstart
    assert install_command in readme
    assert "hermes-mordred setup" in readme


def test_user_docs_describe_installer_options() -> None:
    paths = (
        ROOT / "docs" / "user" / "QUICKSTART.md",
        ROOT / "docs" / "user" / "EXTENSION.md",
    )

    for path in paths:
        document = path.read_text(encoding="utf-8")
        assert "bash -s -- --with-extension" in document, f"{path.relative_to(ROOT)} omits --with-extension"
        assert "--version VERSION" in document, f"{path.relative_to(ROOT)} omits --version"
        assert re.search(r"The `messaging` extra is not required to use the\s+browser extension\.", document), (
            f"{path.relative_to(ROOT)} does not explain that messaging is optional"
        )
        assert "terminal QR" in document, f"{path.relative_to(ROOT)} does not explain what messaging adds"

    # Keep the common path focused on --with-extension. Quickstart owns the
    # advanced installer options; the Extension guide shows the shorter
    # additive form for users who want a QR.
    quickstart = paths[0].read_text(encoding="utf-8")
    extension_guide = paths[1].read_text(encoding="utf-8")
    assert "--extras LIST" in quickstart
    assert "--all-extras" in quickstart
    assert "--with-extension --extras messaging" in extension_guide

    # A `hermes` self-update recreates ~/.hermes/hermes-agent/venv, so a bare
    # re-run of the installer only gets what that re-run itself asks for; the
    # package-upgrade section must tell the reader to repeat the same --extras /
    # --all-extras / --with-extension flags, not just "re-run the installer".
    usage = (ROOT / "docs" / "user" / "USAGE.md").read_text(encoding="utf-8")
    upgrading_section = usage.split("## 9. Package upgrades and removal", 1)[1]
    assert "--extras" in upgrading_section, "USAGE.md package-upgrade section omits --extras"
    assert "recreate" in upgrading_section, (
        "USAGE.md package-upgrade section does not explain that a recreated venv only gets what the re-run asks for"
    )


@pytest.mark.parametrize(
    "relative_path",
    ["README.md", "docs/user/QUICKSTART.md", "docs/user/USAGE.md", "docs/user/EXTENSION.md"],
)
def test_user_docs_do_not_reintroduce_the_cli_path_variable(relative_path: str) -> None:
    """The `$M` idiom outlived its first removal in the docs README/QUICKSTART link to."""
    document = (ROOT / relative_path).read_text(encoding="utf-8")

    assert not re.search(r"^M=", document, re.MULTILINE), f"{relative_path} reintroduces the `M=...` assignment"
    assert not re.search(r"\$M\b", document), f"{relative_path} reintroduces `$M`"


@pytest.mark.parametrize(
    ("platform_name", "expected_extra"),
    [
        ("Darwin", "hermes-mordred[macos]>=0.1.0a16"),
        ("Linux", "hermes-mordred[keyvault]>=0.1.0a16"),
    ],
)
def test_installs_platform_extra_and_exposes_cli(
    tmp_path: Path,
    platform_name: str,
    expected_extra: str,
) -> None:
    fixture = _fixture(tmp_path, platform_name=platform_name)

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    calls = fixture.uv_calls()
    assert f"pip show --python {fixture.hermes_python}" in calls
    assert "--upgrade-package hermes-mordred" in calls
    assert "--dry-run" in calls
    assert expected_extra in calls
    assert "pip uninstall" not in calls
    assert fixture.launcher.is_file()
    assert "Keys and policy were not changed" in result.stdout
    assert f"{fixture.launcher} configure" in result.stdout


@pytest.mark.parametrize(
    ("platform_name", "expected_spec"),
    [
        ("Darwin", "hermes-mordred[macos,extension,ethereum]==0.1.0a16,>=0.1.0a16"),
        ("Linux", "hermes-mordred[keyvault,extension,ethereum]==0.1.0a16,>=0.1.0a16"),
    ],
)
def test_with_extension_and_version_install_requested_package(
    tmp_path: Path,
    platform_name: str,
    expected_spec: str,
) -> None:
    fixture = _fixture(tmp_path, platform_name=platform_name)

    result = _run(fixture, "--with-extension", "--version", "0.1.0a16")

    assert result.returncode == 0, result.stderr
    assert expected_spec in fixture.uv_calls()


def test_version_equals_form_is_supported(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, "--version=0.1.0a16")

    assert result.returncode == 0, result.stderr
    assert "hermes-mordred[macos]==0.1.0a16,>=0.1.0a16" in fixture.uv_calls()


def test_help_does_not_probe_or_modify_the_environment(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, "--help")

    assert result.returncode == 0, result.stderr
    assert "--with-extension" in result.stdout
    assert "--version VERSION" in result.stdout
    assert not fixture.uv_log.exists()


def test_bare_h_flag_shows_usage(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, "-h")

    assert result.returncode == 0, result.stderr
    assert "--with-extension" in result.stdout
    assert not fixture.uv_log.exists()


def test_invalid_argument_before_help_still_fails(tmp_path: Path) -> None:
    """Regression: a whole-argv --help pre-scan used to make this exit 0."""
    fixture = _fixture(tmp_path)

    result = _run(fixture, "bogus", "--help")

    assert result.returncode == 1
    assert "unexpected argument: bogus" in result.stderr
    assert not fixture.uv_log.exists()


def test_unknown_option_before_h_still_fails(tmp_path: Path) -> None:
    """Regression: a whole-argv --help pre-scan used to make this exit 0."""
    fixture = _fixture(tmp_path)

    result = _run(fixture, "--unknown", "-h")

    assert result.returncode == 1
    assert "unknown option: --unknown" in result.stderr
    assert not fixture.uv_log.exists()


def test_help_after_a_valid_option_still_succeeds(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, "--extras", "extension", "--help")

    assert result.returncode == 0, result.stderr
    assert "--with-extension" in result.stdout
    assert not fixture.uv_log.exists()


@pytest.mark.parametrize(
    "args",
    [
        ("--version",),
        ("--version=",),
        ("--version", "latest"),
        ("--version", "0.1.0a16;echo"),
        ("--unknown",),
        ("unexpected",),
    ],
)
def test_invalid_installer_arguments_stop_before_environment_changes(tmp_path: Path, args: tuple[str, ...]) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, *args)

    assert result.returncode == 1
    assert "mordred: error:" in result.stderr
    assert not fixture.uv_log.exists()


def test_installs_requested_optional_extras(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="Darwin")

    result = _run(fixture, "--extras", "extension, ethereum,messaging")

    assert result.returncode == 0, result.stderr
    expected = "hermes-mordred[macos,extension,ethereum,messaging]>=0.1.0a16"
    assert fixture.uv_calls().count(expected) == 2  # preflight + install
    assert f"installing {expected} from PyPI" in result.stdout


def test_installs_optional_extras_from_pipe_friendly_environment_variable(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="Linux")

    result = _run_from_stdin(fixture, MORDRED_INSTALL_EXTRAS="extension,tor-control")

    assert result.returncode == 0, result.stderr
    expected = "hermes-mordred[keyvault,extension,tor-control]>=0.1.0a16"
    assert fixture.uv_calls().count(expected) == 2


def test_piped_installer_accepts_optional_extra_arguments(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="Linux")

    result = _run_from_stdin(fixture, "--extras", "extension,messaging")

    assert result.returncode == 0, result.stderr
    expected = "hermes-mordred[keyvault,extension,messaging]>=0.1.0a16"
    assert fixture.uv_calls().count(expected) == 2


def test_all_extras_are_deduplicated_in_stable_order(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="Darwin")

    result = _run(fixture, "--extras=extension", "--all-extras", "--extras", "messaging,extension")

    assert result.returncode == 0, result.stderr
    expected = "hermes-mordred[macos,extension,ethereum,messaging,tor-control,telegram]>=0.1.0a16"
    calls = fixture.uv_calls()
    assert calls.count(expected) == 2
    assert "extension,extension" not in calls


@pytest.mark.parametrize("args", [("--extras", "all"), ("--extras=all",), ("--all-extras",)])
def test_extras_all_matches_the_all_extras_flag(tmp_path: Path, args: tuple[str, ...]) -> None:
    fixture = _fixture(tmp_path, platform_name="Darwin")

    result = _run(fixture, *args)

    assert result.returncode == 0, result.stderr
    expected = "hermes-mordred[macos,extension,ethereum,messaging,tor-control,telegram]>=0.1.0a16"
    assert fixture.uv_calls().count(expected) == 2


def test_with_extension_combined_with_extras_dedupes_and_preserves_order(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="Darwin")

    result = _run(fixture, "--with-extension", "--extras", "ethereum,tor-control")

    assert result.returncode == 0, result.stderr
    expected = "hermes-mordred[macos,extension,ethereum,tor-control]>=0.1.0a16"
    assert fixture.uv_calls().count(expected) == 2


def test_env_extras_are_appended_after_argv_extras(tmp_path: Path) -> None:
    """Left-to-right contract: argv extras first, MORDRED_INSTALL_EXTRAS last, deduplicated."""

    fixture = _fixture(tmp_path)
    result = _run(fixture, "--with-extension", MORDRED_INSTALL_EXTRAS="tor-control,extension")
    assert result.returncode == 0, result.stderr
    expected = "hermes-mordred[macos,extension,ethereum,tor-control]>=0.1.0a16"
    assert fixture.uv_calls().count(expected) == 2


def test_mordred_install_extras_is_not_visible_to_uv(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="Darwin")

    result = _run(fixture, MORDRED_INSTALL_EXTRAS="extension,ethereum")

    assert result.returncode == 0, result.stderr
    calls = fixture.uv_calls()
    assert "MORDRED_INSTALL_EXTRAS=<unset>" in calls
    assert "MORDRED_INSTALL_EXTRAS=extension,ethereum" not in calls


def test_invalid_mordred_install_extras_env_var_names_its_source(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, MORDRED_INSTALL_EXTRAS="bogus-extra")

    assert result.returncode == 1
    assert "from MORDRED_INSTALL_EXTRAS: unknown optional extra 'bogus-extra'" in result.stderr
    assert not fixture.uv_log.exists()


def test_cmdline_extras_error_does_not_mention_the_env_var(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, "--extras", "bogus-extra")

    assert result.returncode == 1
    assert "from MORDRED_INSTALL_EXTRAS" not in result.stderr
    assert "unknown optional extra 'bogus-extra'" in result.stderr


def test_whitespace_only_mordred_install_extras_is_treated_as_unset(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="Darwin")

    result = _run(fixture, MORDRED_INSTALL_EXTRAS="   ")

    assert result.returncode == 0, result.stderr
    assert "hermes-mordred[macos]>=0.1.0a16" in fixture.uv_calls()


@pytest.mark.parametrize("args", [("--extras=",), ("--extras", ",extension"), ("--extras", "extension,")])
def test_empty_or_dangling_comma_extras_stop_before_uv(tmp_path: Path, args: tuple[str, ...]) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, *args)

    assert result.returncode == 1
    assert "empty name" in result.stderr
    assert not fixture.uv_log.exists()


@pytest.mark.parametrize(
    "extra",
    ["unknown", "dev", "integration", "macos", "keyvault", "extension,,messaging"],
)
def test_invalid_optional_extra_stops_before_uv(tmp_path: Path, extra: str) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, "--extras", extra)

    assert result.returncode == 1
    assert "mordred: error:" in result.stderr
    assert not fixture.uv_log.exists()


@pytest.mark.parametrize("args", [("--extras",), ("--extras", "--all-extras")])
def test_missing_optional_extra_value_stops_before_uv(tmp_path: Path, args: tuple[str, ...]) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, *args)

    assert result.returncode == 1
    assert "--extras requires" in result.stderr
    assert not fixture.uv_log.exists()


def test_installer_help_does_not_require_hermes_or_uv(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.hermes_python.unlink()
    (tmp_path / "fake-bin" / "uv").unlink()

    result = _run(fixture, "--help", MORDRED_INSTALL_EXTRAS="invalid-but-ignored-for-help")

    assert result.returncode == 0, result.stderr
    assert "--extras LIST" in result.stdout
    assert "extension, ethereum, messaging, tor-control" in result.stdout
    assert not fixture.uv_log.exists()


def test_detects_the_official_bash_wrapper_not_only_the_canonical_path(tmp_path: Path) -> None:
    """The real launcher's shebang names bash; the interpreter is on its exec line."""
    fixture = _fixture(tmp_path, launcher_style="wrapper", shadow_env=tmp_path / "actual" / "venv")

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert str(fixture.hermes_python) in fixture.uv_calls()


def test_detects_root_style_environment_from_hermes_shebang(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, launcher_style="console", shadow_env=tmp_path / "root-layout" / "venv")

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert str(fixture.hermes_python) in fixture.uv_calls()


@pytest.mark.parametrize("launcher_style", ["wrapper", "console"])
def test_path_hermes_wins_over_a_second_canonical_install(tmp_path: Path, launcher_style: str) -> None:
    """`hermes` and `hermes-mordred` must never end up in different environments."""
    shadow = tmp_path / "actual" / "venv"
    fixture = _fixture(tmp_path, launcher_style=launcher_style, shadow_env=shadow)
    canonical = fixture.home / ".hermes" / "hermes-agent" / "venv" / "bin" / "python3"

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert fixture.hermes_python == shadow / "bin" / "python3"
    assert str(fixture.hermes_python) in fixture.uv_calls()
    assert str(canonical) not in fixture.uv_calls()
    assert not (canonical.parent / "hermes-mordred").exists()


def test_falls_back_to_the_canonical_environment_without_a_launcher(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, launcher_style="none")

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert str(fixture.hermes_python) in fixture.uv_calls()
    assert fixture.launcher.is_file()
    # ~/.local/bin is already on PATH here, so there is nothing to advise.
    assert "to PATH" not in result.stdout


def test_launcher_directory_off_path_is_reported(tmp_path: Path) -> None:
    """Reloading the shell cannot help when ~/.local/bin is simply not on PATH."""
    fixture = _fixture(tmp_path, launcher_style="none")
    without_bin_dir = [entry for entry in fixture.env["PATH"].split(os.pathsep) if entry != str(fixture.bin_dir)]

    result = _run(fixture, PATH=os.pathsep.join(without_bin_dir))

    assert result.returncode == 0, result.stderr
    assert f"Add {fixture.bin_dir} to PATH" in result.stdout


def test_launcher_isolates_python_path_like_hermes_own_wrapper(tmp_path: Path) -> None:
    """A bare symlink would let an ambient PYTHONPATH redirect the import."""
    fixture = _fixture(tmp_path)

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    launcher = fixture.launcher.read_text(encoding="utf-8")
    assert "unset PYTHONPATH" in launcher
    assert "unset PYTHONHOME" in launcher
    assert f'exec "{fixture.installed_cli}" "$@"' in launcher

    # The wrapper must really scrub the variables, not merely mention them.
    probe = subprocess.run(
        ["/bin/bash", "-c", f'exec "{fixture.launcher}"'],
        check=False,
        capture_output=True,
        text=True,
        env={**fixture.env, "PYTHONPATH": "/somewhere/else"},
    )
    assert probe.returncode == 0, probe.stderr
    fixture.installed_cli.write_text('#!/bin/sh\nprintf "PYTHONPATH=[%s]\\n" "${PYTHONPATH-unset}"\n', encoding="utf-8")
    fixture.installed_cli.chmod(0o755)
    probe = subprocess.run(
        [str(fixture.launcher)],
        check=False,
        capture_output=True,
        text=True,
        env={**fixture.env, "PYTHONPATH": "/somewhere/else"},
    )
    assert probe.stdout.strip() == "PYTHONPATH=[unset]"


def test_rerun_refreshes_a_launcher_this_installer_wrote(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    assert _run(fixture).returncode == 0
    first = fixture.launcher.read_text(encoding="utf-8")

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert fixture.launcher.read_text(encoding="utf-8") == first
    assert f"{fixture.launcher} configure" in result.stdout


def test_rerun_refreshes_a_legacy_installer_launcher(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _write_executable(
        fixture.launcher,
        "#!/usr/bin/env bash\n# Generated by the mordred-hermes installer. Safe to delete.\nexit 9\n",
    )

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    launcher = fixture.launcher.read_text(encoding="utf-8")
    assert "# Generated by the hermes-mordred installer." in launcher
    assert "exit 9" not in launcher


def test_legacy_distribution_is_removed_only_after_canonical_preflight(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, UV_LEGACY_VERSION="0.1.0a15")

    assert result.returncode == 0, result.stderr
    calls = fixture.uv_calls().splitlines()
    preflight = next(i for i, call in enumerate(calls) if "pip install" in call and "--dry-run" in call)
    uninstall = next(i for i, call in enumerate(calls) if "pip uninstall" in call)
    install = next(
        i
        for i, call in enumerate(calls)
        if "pip install" in call and "hermes-mordred" in call and "--dry-run" not in call
    )
    assert preflight < uninstall < install
    assert "removing legacy mordred-hermes 0.1.0a15" in result.stdout


def test_failed_canonical_preflight_keeps_legacy_distribution(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, UV_LEGACY_VERSION="0.1.0a15", UV_DRY_RUN_FAIL="1")

    assert result.returncode != 0
    calls = fixture.uv_calls()
    assert "--dry-run" in calls
    assert "pip uninstall" not in calls


def test_failed_canonical_install_attempts_exact_legacy_restore(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(
        fixture,
        UV_LEGACY_VERSION="0.1.0a15",
        UV_CANONICAL_INSTALL_FAIL="1",
    )

    assert result.returncode == 1
    calls = fixture.uv_calls()
    assert "pip uninstall" in calls
    assert "mordred-hermes[macos]==0.1.0a15" in calls
    assert "attempting to restore mordred-hermes 0.1.0a15" in result.stderr


def test_failed_extension_install_restores_the_same_legacy_extras(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(
        fixture,
        "--with-extension",
        UV_LEGACY_VERSION="0.1.0a15",
        UV_CANONICAL_INSTALL_FAIL="1",
    )

    assert result.returncode == 1
    assert "mordred-hermes[macos,extension,ethereum]==0.1.0a15" in fixture.uv_calls()


def test_foreign_symlink_is_not_replaced(tmp_path: Path) -> None:
    """A link into some other venv may belong to a different profile or checkout."""
    fixture = _fixture(tmp_path)
    stranger = tmp_path / "other" / "venv" / "bin" / "hermes-mordred"
    fixture.launcher.symlink_to(stranger)

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert fixture.launcher.is_symlink()
    assert os.readlink(fixture.launcher) == str(stranger)
    assert "this installer did not create it" in result.stderr
    assert f"{fixture.installed_cli} configure" in result.stdout


def test_unrelated_existing_launcher_is_not_overwritten(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _write_executable(fixture.launcher, "#!/bin/sh\necho unrelated\n")

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert fixture.launcher.read_text(encoding="utf-8") == "#!/bin/sh\necho unrelated\n"
    assert "this installer did not create it" in result.stderr
    assert f"{fixture.installed_cli} configure" in result.stdout


def test_console_script_in_the_launcher_directory_is_not_wrapped(tmp_path: Path) -> None:
    """In a checkout, `hermes` lives in the same bin/ that receives the script."""
    fixture = _fixture(tmp_path, launcher_style="console")
    venv_bin = fixture.hermes_python.parent
    # Drop ~/.local/bin so `hermes` resolves from the venv itself, as it does
    # inside an activated development checkout.
    entries = [entry for entry in fixture.env["PATH"].split(os.pathsep) if entry != str(fixture.bin_dir)]
    entries.insert(1, str(venv_bin))

    result = _run(fixture, PATH=os.pathsep.join(entries))

    assert result.returncode == 0, result.stderr
    assert fixture.installed_cli.read_text(encoding="utf-8") == "#!/bin/sh\nexit 0\n"
    assert f"{fixture.installed_cli} configure" in result.stdout


def test_non_virtualenv_interpreter_stops_before_install(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, is_venv=False)

    result = _run(fixture)

    assert result.returncode == 1
    assert "not in a virtual environment" in result.stderr
    # The check precedes every uv call, so nothing should have been invoked at
    # all — a substring assertion alone would also pass if uv had run.
    assert not fixture.uv_log.exists()


def test_unwritable_launcher_directory_keeps_the_successful_install(tmp_path: Path) -> None:
    """`set -e` is suppressed inside the command substitution that writes the launcher.

    Without explicit checks, a failed `mktemp` ran on into `chmod`/`mv` with an
    empty path and exited 1 — reporting failure after the package had already
    installed cleanly.
    """
    if os.geteuid() == 0:
        pytest.skip("root ignores the directory write bit")
    fixture = _fixture(tmp_path)
    fixture.bin_dir.chmod(0o555)
    try:
        result = _run(fixture)
    finally:
        fixture.bin_dir.chmod(0o755)

    assert result.returncode == 0, result.stderr
    assert "could not write" in result.stderr
    assert "No such file or directory" not in result.stderr
    # The usable console script must be named, not buried.
    assert f"{fixture.installed_cli} configure" in result.stdout
    assert fixture.installed_cli.is_file()


def test_launcher_is_not_generated_for_a_path_with_shell_metacharacters(tmp_path: Path) -> None:
    """The path is interpolated into a double-quoted `exec` in the generated wrapper."""
    hostile = tmp_path / 'ho"stile' / "venv"
    fixture = _fixture(tmp_path, launcher_style="console", shadow_env=hostile)

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert "shell metacharacters" in result.stderr
    assert not fixture.launcher.exists()


def test_dependency_conflict_introduced_by_mordred_is_reported(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, UV_CHECK_BEFORE="0", UV_CHECK_AFTER="1")

    assert result.returncode == 0, result.stderr
    assert "conflicting dependencies" in result.stderr
    assert "uv pip check --python" in result.stderr


def test_preexisting_dependency_conflict_is_not_blamed_on_mordred(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, UV_CHECK_BEFORE="1", UV_CHECK_AFTER="1")

    assert result.returncode == 0, result.stderr
    assert "conflicting dependencies" not in result.stderr


@pytest.mark.parametrize("hermes_version", ["0.11.0", "0.9.0", "0.08.0"])
def test_old_hermes_stops_before_install(tmp_path: Path, hermes_version: str) -> None:
    fixture = _fixture(tmp_path, hermes_version=hermes_version)

    result = _run(fixture)

    assert result.returncode == 1
    assert "hermes update" in result.stderr
    assert "older than the required 0.13.0" in result.stderr
    assert "value too great for base" not in result.stderr
    assert "pip install" not in fixture.uv_calls()


@pytest.mark.parametrize("hermes_version", ["0.13.0", "0.19.0", "0.13.0rc1", "1.0.0"])
def test_supported_hermes_versions_proceed(tmp_path: Path, hermes_version: str) -> None:
    fixture = _fixture(tmp_path, hermes_version=hermes_version)

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert "pip install" in fixture.uv_calls()


def test_missing_hermes_prints_official_install_command(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, launcher_style="none")
    fixture.hermes_python.unlink()

    result = _run(fixture)

    assert result.returncode == 1
    assert "https://hermes-agent.nousresearch.com/install.sh" in result.stderr
    assert not fixture.uv_log.exists()


def test_missing_uv_stops_without_changing_the_environment(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    (tmp_path / "fake-bin" / "uv").unlink()

    result = _run(fixture)

    assert result.returncode == 1
    assert "uv is not on PATH" in result.stderr
    assert not fixture.uv_log.exists()
    assert not fixture.installed_cli.exists()


def test_unsupported_platform_stops_before_install(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, platform_name="FreeBSD")

    result = _run(fixture)

    assert result.returncode == 1
    assert "unsupported platform FreeBSD" in result.stderr
    assert "pip install" not in fixture.uv_calls()


@pytest.mark.integration
def test_real_uv_accepts_the_installer_flag_combination(tmp_path: Path) -> None:
    """The hermetic tests drive a fake uv; this one proves the flags are real.

    Resolution only (``--dry-run``), so no environment is modified. It needs
    network access and is therefore excluded from default runs.
    """
    uv_bin = shutil.which("uv")
    if uv_bin is None:
        pytest.skip("uv is not installed")

    venv = tmp_path / "venv"
    subprocess.run([uv_bin, "venv", str(venv)], check=True, capture_output=True)
    python = venv / "bin" / "python3"
    env = {**os.environ, "UV_NO_CONFIG": "1"}

    check = subprocess.run(
        [uv_bin, "pip", "check", "--python", str(python)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert check.returncode == 0, check.stderr

    platform_extra = "macos" if platform.system() == "Darwin" else "keyvault"
    specs = (
        f"hermes-mordred[{platform_extra}]>=0.1.0a16",
        f"hermes-mordred[{platform_extra},extension,ethereum]==0.1.0a16,>=0.1.0a16",
        f"hermes-mordred[{platform_extra},extension,ethereum,messaging,tor-control,telegram]>=0.1.0a16",
    )
    for spec in specs:
        install = subprocess.run(
            [
                uv_bin,
                "pip",
                "install",
                "--python",
                str(python),
                "--no-python-downloads",
                "--upgrade-package",
                "hermes-mordred",
                "--dry-run",
                spec,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert install.returncode == 0, install.stderr
        # Every published release is still a pre-release; both the floor and
        # exact-pin forms must resolve rather than selecting the claim stub.
        assert "hermes-mordred==" in install.stdout + install.stderr


def _source_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text('[project]\nname = "hermes-mordred"\n', encoding="utf-8")
    return checkout


def test_from_source_installs_the_local_checkout_without_pypi(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    checkout = _source_checkout(tmp_path)

    result = _run(fixture, "--from-source", str(checkout), "--with-telegram")

    assert result.returncode == 0, result.stderr
    calls = fixture.uv_calls()
    assert f"{checkout}[macos,extension,telegram]" in calls
    assert "--reinstall-package hermes-mordred" in calls
    assert "--dry-run" not in calls
    assert "from the local checkout" in result.stdout + result.stderr


def test_from_source_editable_links_the_checkout(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    checkout = _source_checkout(tmp_path)

    result = _run(fixture, f"--from-source={checkout}", "--editable")

    assert result.returncode == 0, result.stderr
    assert f"--editable {checkout}[macos]" in fixture.uv_calls()


@pytest.mark.parametrize(
    "args",
    [
        ("--editable",),
        ("--from-source",),
        ("--from-source", "/nonexistent/checkout"),
    ],
)
def test_invalid_from_source_arguments_stop_before_uv(tmp_path: Path, args: tuple[str, ...]) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, *args)

    assert result.returncode == 1
    assert "mordred: error:" in result.stderr
    assert not fixture.uv_log.exists()


def test_from_source_refuses_a_foreign_checkout_and_version_pins(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "pyproject.toml").write_text('[project]\nname = "other"\n', encoding="utf-8")
    checkout = _source_checkout(tmp_path)

    assert _run(fixture, "--from-source", str(foreign)).returncode == 1
    assert _run(fixture, "--from-source", str(checkout), "--version", "0.1.0a20").returncode == 1
    assert not fixture.uv_log.exists()


def test_finds_the_hermes_desktop_managed_environment_and_uv(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, launcher_style="none")
    hermes_home = fixture.home / ".hermes"
    managed_python = _make_env(hermes_home / "installs" / "abc" / "environments" / "def" / "venv")
    site = managed_python.parent.parent / "lib" / "python3.14" / "site-packages"
    # The managed launcher reports the active environment through `--run-module site`.
    _write_executable(
        hermes_home / "hermes-agent" / ".hermes" / "bin" / "hermes",
        f"#!/bin/sh\n[ \"$1\" = --run-module ] && printf \"sys.path = [\\n    '%s',\\n]\\n\" '{site}'\nexit 0\n",
    )
    managed_python.with_name("python").symlink_to(managed_python)
    # uv only under <home>/tools, not on PATH.
    fake_uv = Path(fixture.env["PATH"].split(os.pathsep)[0]) / "uv"
    tools_uv = hermes_home / "tools" / "uv-9.9.9-test" / "uv"
    tools_uv.parent.mkdir(parents=True)
    fake_uv.rename(tools_uv)

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert str(managed_python.with_name("python")) in fixture.uv_calls()


# -----------------------------------------------------------------------------
# --uninstall: hand over to the installed CLI's `uninstall`
# -----------------------------------------------------------------------------
def _installed_cli_recording_args(fixture: InstallFixture, tmp_path: Path) -> Path:
    """Put a `hermes-mordred` into Hermes's env that records how it was called."""
    log = tmp_path / "cli.log"
    _write_executable(fixture.installed_cli, f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nexit 0\n")
    return log


def test_uninstall_runs_the_installed_cli_with_passthrough_flags(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    log = _installed_cli_recording_args(fixture, tmp_path)

    result = _run(fixture, "--uninstall", "--yes", "--purge-data")

    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8") == "uninstall --yes --purge-data\n"
    assert fixture.uv_calls() == ""  # nothing is installed or checked


def test_uninstall_without_flags_and_from_stdin(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    log = _installed_cli_recording_args(fixture, tmp_path)

    result = _run_from_stdin(fixture, "--uninstall", "--dry-run")

    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8") == "uninstall --dry-run\n"


def test_uninstall_ignores_a_stale_extras_variable(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    log = _installed_cli_recording_args(fixture, tmp_path)

    result = _run(fixture, "--uninstall", MORDRED_INSTALL_EXTRAS="bogus")

    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8") == "uninstall\n"


def test_uninstall_finds_the_hermes_desktop_managed_environment(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, launcher_style="none")
    hermes_home = fixture.home / ".hermes"
    managed_python = _make_env(hermes_home / "installs" / "abc" / "environments" / "def" / "venv")
    site = managed_python.parent.parent / "lib" / "python3.14" / "site-packages"
    _write_executable(
        hermes_home / "hermes-agent" / ".hermes" / "bin" / "hermes",
        f"#!/bin/sh\n[ \"$1\" = --run-module ] && printf \"sys.path = [\\n    '%s',\\n]\\n\" '{site}'\nexit 0\n",
    )
    managed_python.with_name("python").symlink_to(managed_python)
    log = tmp_path / "cli.log"
    _write_executable(
        managed_python.with_name("hermes-mordred"), f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nexit 0\n"
    )

    result = _run(fixture, "--uninstall", "--yes")

    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8") == "uninstall --yes\n"


def test_uninstall_propagates_the_cli_exit_code(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _write_executable(fixture.installed_cli, "#!/bin/sh\necho 'uninstall stopped' >&2\nexit 1\n")

    result = _run(fixture, "--uninstall", "--yes")

    assert result.returncode == 1
    assert "uninstall stopped" in result.stderr


def test_uninstall_when_mordred_is_not_installed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    result = _run(fixture, "--uninstall")

    assert result.returncode == 1
    assert "Mordred is not installed in Hermes's environment" in result.stderr


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--uninstall", "--extras", "telegram"), "--uninstall cannot be combined with --extras"),
        (("--uninstall", "--from-source", "."), "--uninstall cannot be combined with --from-source"),
        (("--purge-data",), "--purge-data is only valid with --uninstall"),
        (("--yes",), "--yes is only valid with --uninstall"),
    ],
)
def test_uninstall_flag_misuse_stops_before_anything_runs(tmp_path: Path, args: tuple[str, ...], message: str) -> None:
    fixture = _fixture(tmp_path)
    log = _installed_cli_recording_args(fixture, tmp_path)

    result = _run(fixture, *args)

    assert result.returncode == 1
    assert message in result.stderr
    assert not log.exists()
    assert fixture.uv_calls() == ""


def test_source_hermes_version_comes_from_the_launcher(tmp_path: Path) -> None:
    # Hermes Desktop's git install reports its package as 0.0.0.
    fixture = _fixture(tmp_path, hermes_version="0.0.0", launcher_style="none")
    launcher = fixture.home / ".hermes" / "hermes-agent" / ".hermes" / "bin" / "hermes"
    _write_executable(
        launcher,
        "#!/bin/sh\n[ \"$1\" = --version ] && echo 'Hermes Agent v0.21.5+3640.ge5050a0 (2026.9.24)'\nexit 0\n",
    )

    result = _run(fixture)

    assert result.returncode == 0, result.stderr
    assert "Hermes Agent 0.21.5" in result.stdout + result.stderr


def test_install_never_resolves_hermes_and_pins_what_hermes_has(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    # The fake Hermes python answers the requirements query with two packages.
    _write_executable(fixture.hermes_python, "#!/bin/sh\nprintf 'telethon>=1.36\\nruamel.yaml>=0.18\\n'\n")

    result = _run(fixture, UV_FREEZE="ruamel.yaml==0.18.16 hermes-mordred==0.1.0a19 cryptography==46.0.7")

    assert result.returncode == 0, result.stderr
    calls = [
        line for line in fixture.uv_calls().splitlines() if line.startswith("pip install") and "--dry-run" not in line
    ]
    package_install, deps_install = calls[0], calls[1]
    assert "--no-deps" in package_install and "hermes-mordred[macos]" in package_install
    assert "--constraint" in deps_install and "telethon>=1.36" in deps_install and "hermes-mordred" not in deps_install
    constraints = (tmp_path / "state" / "constraints").read_text(encoding="utf-8").split()
    assert constraints == ["ruamel.yaml==0.18.16", "cryptography==46.0.7"]
