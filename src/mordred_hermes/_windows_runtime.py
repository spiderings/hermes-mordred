"""Reusable Windows Hermes interpreter selection, without importing native APIs.

Overrides are authoritative. Every candidate must be a real venv/conda Python
and must confirm Hermes's console registration in that exact interpreter.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
SCRUBBED_ENV = (
    "PYTHONHOME",
    "PYTHONPATH",
    "UV_PYTHON",
    "UV_PROJECT_ENVIRONMENT",
    "UV_INDEX",
    "UV_INDEX_URL",
    "UV_DEFAULT_INDEX",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
    "UV_INDEX_STRATEGY",
    "UV_NO_SOURCES",
    "UV_OFFLINE",
    "UV_CONFIG_FILE",
    "UV_INSECURE_HOST",
    "UV_NO_VERIFY_HASHES",
    "UV_SYSTEM_CERTS",
    "UV_PRERELEASE",
    "UV_EXCLUDE_NEWER",
    "UV_SYSTEM_PYTHON",
    "UV_BREAK_SYSTEM_PACKAGES",
)


def scrubbed_environment(environ: Mapping[str, str]) -> dict[str, str]:
    result = {key: value for key, value in environ.items() if key.upper() not in SCRUBBED_ENV}
    result["UV_NO_CONFIG"] = "1"
    return result


def default_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    env = scrubbed_environment(os.environ)
    env.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    try:
        return subprocess.run(
            list(argv), capture_output=True, encoding="utf-8", errors="replace", timeout=30, env=env, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(list(argv), 127, "", str(exc))


def environment_root(python: Path) -> Path | None:
    if python.name.lower() != "python.exe" or not python.is_file():
        return None
    root = python.parent.parent if python.parent.name.lower() == "scripts" else python.parent
    return root if (root / "pyvenv.cfg").is_file() or (root / "conda-meta").is_dir() else None


_VALIDATE = """import importlib.metadata as m, json, os, sys
import hermes_cli
root = sys.prefix
registered = any(e.group == 'console_scripts' and e.name == 'hermes'
                 for e in m.distribution('hermes-agent').entry_points)
environment = sys.prefix != sys.base_prefix or os.path.isdir(os.path.join(root, 'conda-meta'))
print(json.dumps(dict(executable=sys.executable, prefix=root, hermes=registered, environment=environment)))
"""


def _same_path(a: str | Path, b: str | Path) -> bool:
    return os.path.normpath(str(a)).casefold() == os.path.normpath(str(b)).casefold()


def validate_windows_python(python: Path, *, runner: Runner = default_runner) -> bool:
    root = environment_root(python)
    if root is None or not python.is_absolute():
        return False
    result = runner([str(python), "-c", _VALIDATE])
    if result.returncode:
        return False
    try:
        data = json.loads(result.stdout)
        return (
            data.get("hermes") is True
            and data.get("environment") is True
            and _same_path(data["executable"], python)
            and _same_path(data["prefix"], root)
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def _managed_candidates(launcher: Path, runner: Runner) -> list[Path]:
    result = runner([str(launcher), "--run-module", "site"])
    if result.returncode:
        return []
    candidates: list[Path] = []
    # site prints repr strings (doubled Windows backslashes), not shell argv.
    for line in result.stdout.splitlines()[:80]:
        match = re.search(r"['\"](.+?)[\\/]+Lib[\\/]+site-packages['\"]", line, re.IGNORECASE)
        if match:
            root = Path(match.group(1).replace("\\\\", "\\"))
            candidates.extend((root / "Scripts" / "python.exe", root / "python.exe"))
    return candidates


def resolve_windows_python(
    home: Path,
    launcher: Path | None = None,
    *,
    override: str | None = None,
    runner: Runner = default_runner,
) -> Path | None:
    """Resolve Windows Hermes; explicit override refuses rather than falls back.

    A supplied launcher is authoritative too: its neighboring Python or actual
    Desktop managed environment must validate. No unrelated home venv replaces
    a mismatched launcher. Callers pass MORDRED_HERMES_PYTHON when configured.
    """
    if override is not None:
        candidate = Path(override).expanduser()
        return candidate if validate_windows_python(candidate, runner=runner) else None
    if launcher is not None:
        candidates = [launcher.parent / "python.exe", launcher.parent.parent / "python.exe"]
        for candidate in candidates:
            if validate_windows_python(candidate, runner=runner):
                return candidate
        candidates = _managed_candidates(launcher, runner)
    else:
        root = home / "hermes-agent" / "venv"
        candidates = [root / "Scripts" / "python.exe", root / "python.exe"]
    return next((path for path in candidates if validate_windows_python(path, runner=runner)), None)
