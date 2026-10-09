"""Tests for guards installed before Hermes plugin/model initialization."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes import _pth_bootstrap, _runtime_bootstrap
from mordred_hermes._proxy_bypass import ensure_loopback_proxy_bypass
from mordred_hermes.privacy_check._exceptions import MordredIntegrityRefused

_REPO_ROOT = Path(__file__).resolve().parent.parent
_RUNTIME_PTH = _REPO_ROOT / "packaging" / "pth" / "mordred_hermes_runtime.pth"
_PTH_PREFIX = "import os, sys; "
_PTH_SUFFIX = " and __import__('mordred_hermes._runtime_bootstrap', fromlist=['run']).run()"


def _pth_engage_expr() -> str:
    line = _RUNTIME_PTH.read_text(encoding="utf-8").strip()
    assert line.startswith(_PTH_PREFIX)
    assert line.endswith(_PTH_SUFFIX)
    return line[len(_PTH_PREFIX) : -len(_PTH_SUFFIX)]


def _eval_pth_engages(argv0: str) -> bool:
    fake_os = SimpleNamespace(path=os.path)
    fake_sys = SimpleNamespace(argv=[argv0])
    return bool(eval(_pth_engage_expr(), {"os": fake_os, "sys": fake_sys}))


@pytest.mark.parametrize(
    "argv0,expected",
    [
        ("/opt/venv/bin/hermes", True),
        ("/opt/venv/bin/hermes-agent", True),
        ("/opt/venv/bin/hermes-acp", True),
        ("/opt/venv/bin/hermes-mordred", True),
        (r"C:\venv\Scripts\hermes.EXE", True),
        (r"C:\venv\Scripts\HERMES.Exe", True),
        (r"C:\venv\Scripts\HERMES.PY", True),
        ("/x/site-packages/hermes_cli/cli.py", True),
        ("/x/site-packages/hermes_cli", True),
        ("/opt/venv/bin/hermes.backup", False),
        ("/opt/venv/bin/hermes.test.py", False),
        (r"C:\venv\Scripts\hermes.backup.EXE", False),
        ("/x/hermes-venv/bin/pytest", False),
        ("/usr/bin/python", False),
    ],
)
def test_runtime_pth_gate_matches_existing_hermes_matcher(argv0: str, expected: bool) -> None:
    engaged = _eval_pth_engages(argv0)
    assert engaged is expected
    assert engaged == _pth_bootstrap._looks_like_hermes([argv0])


_FAKE_MEMORY_TOOL_SRC = '''\
"""A shape-C ``tools.memory_tool`` stand-in, imported through the real machinery."""

from pathlib import Path

ENTRY_DELIMITER = "\\n\\u00a7\\n"


class MemoryStore:
    @staticmethod
    def _write_file(path, entries):
        Path(path).write_text(ENTRY_DELIMITER.join(entries) if entries else "", encoding="utf-8")

    @staticmethod
    def _read_file(path):
        target = Path(path)
        if not target.exists():
            return []
        return [e.strip() for e in target.read_text(encoding="utf-8").split(ENTRY_DELIMITER) if e.strip()]
'''


def test_install_registers_the_memory_import_hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The keyvault plugin's ``register()`` is not reached in every Hermes process
    (discovery can be skipped or fail), so the memory seam is armed from the
    ``.pth`` bootstrap too — via a finder, never an eager import.

    Behavioural on purpose: counting finders on ``sys.meta_path`` proves only that
    an object was inserted, not that importing the seam actually wraps the class.
    """
    import importlib

    from mordred_hermes.keyvault import _memory_hook

    site = tmp_path / "site"
    (site / "tools").mkdir(parents=True)
    (site / "tools" / "__init__.py").write_text("", encoding="utf-8")
    (site / "tools" / "memory_tool.py").write_text(_FAKE_MEMORY_TOOL_SRC, encoding="utf-8")
    saved = {name: mod for name, mod in sys.modules.items() if name.split(".")[0] == "tools"}
    for name in saved:
        del sys.modules[name]
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    importlib.invalidate_caches()

    calls: list[str] = []
    monkeypatch.setattr(_runtime_bootstrap, "ensure_loopback_proxy_bypass", lambda: calls.append("proxy"))
    monkeypatch.setattr(_runtime_bootstrap, "_install_plugin_discovery_wrapper", lambda: calls.append("discovery"))
    try:
        _runtime_bootstrap.install()
        assert calls == ["proxy", "discovery"]

        memory_tool = importlib.import_module("tools.memory_tool")

        assert _memory_hook.memory_hook_installed(memory_tool) is True
    finally:
        for name in [n for n in sys.modules if n.split(".")[0] == "tools"]:
            del sys.modules[name]
        sys.modules.update(saved)
        sys.meta_path[:] = [f for f in sys.meta_path if not isinstance(f, _memory_hook._PostImportFinder)]
        _memory_hook._IMPORT_HOOK = None


def test_runtime_bootstrap_failure_aborts_startup() -> None:
    def fail() -> None:
        raise RuntimeError("synthetic bootstrap failure")

    with pytest.raises(SystemExit) as exc_info:
        _runtime_bootstrap.run(installer=fail)
    assert exc_info.value.code == 1


def test_loopback_bypass_preserves_effective_lowercase_no_proxy() -> None:
    """Synchronizing spellings must not resurrect a stale uppercase bypass."""
    environ = {
        "HTTPS_PROXY": "http://proxy.example:8080",
        "NO_PROXY": "api.openai.com",
        "no_proxy": "localhost",
    }

    ensure_loopback_proxy_bypass(environ)

    expected = "localhost,127.0.0.1,::1"
    assert environ["NO_PROXY"] == expected
    assert environ["no_proxy"] == expected
    assert "api.openai.com" not in expected


@pytest.mark.parametrize(
    ("uppercase", "lowercase"),
    [
        ("HTTPS_PROXY", "https_proxy"),
        ("HTTP_PROXY", "http_proxy"),
        ("ALL_PROXY", "all_proxy"),
    ],
)
def test_loopback_bypass_detects_hermes_uppercase_proxy_when_lowercase_is_empty(
    uppercase: str,
    lowercase: str,
) -> None:
    """Hermes scans uppercase proxy spellings before lowercase spellings."""
    environ = {
        uppercase: "http://proxy.example:8080",
        lowercase: "",
        "NO_PROXY": "api.openai.com",
        "no_proxy": "",
    }

    ensure_loopback_proxy_bypass(environ)

    expected = "localhost,127.0.0.1,::1"
    assert environ["NO_PROXY"] == expected
    assert environ["no_proxy"] == expected
    assert "api.openai.com" not in expected


def test_mandatory_integrity_evaluation_error_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mordred_hermes.privacy_check import hooks

    def fail(**_kwargs: object) -> None:
        raise RuntimeError("synthetic integrity failure")

    monkeypatch.setattr(hooks, "check_plugin_integrity", fail)

    with pytest.raises(SystemExit) as exc_info:
        _runtime_bootstrap._mandatory_integrity_hook()
    assert exc_info.value.code == 1


def test_mandatory_integrity_policy_refusal_propagates_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A policy decision is not converted into an ordinary CLI exit."""
    from mordred_hermes.privacy_check import hooks

    refusal = MordredIntegrityRefused("synthetic strict-policy refusal")

    def refuse(**_kwargs: object) -> None:
        raise refusal

    monkeypatch.setattr(hooks, "check_plugin_integrity", refuse)

    with pytest.raises(MordredIntegrityRefused) as exc_info:
        _runtime_bootstrap._mandatory_integrity_hook()
    assert exc_info.value is refusal
    assert not isinstance(exc_info.value, SystemExit)


def test_concurrent_manager_installations_keep_their_own_integrity_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each bridge inspects its own manager, independent of discovery order."""
    from mordred_hermes.privacy_check import hooks

    monkeypatch.delenv("HERMES_SAFE_MODE", raising=False)
    managers = [SimpleNamespace(_hooks={}), SimpleNamespace(_hooks={})]
    barrier = threading.Barrier(len(managers) + 1)
    errors: list[BaseException] = []

    def install_bridge(manager: SimpleNamespace) -> None:
        try:
            barrier.wait()
            _runtime_bootstrap._ensure_integrity_callback(manager)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=install_bridge, args=(manager,)) for manager in managers]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert not errors

    inspected: list[object] = []

    def record_manager(**kwargs: object) -> None:
        inspected.append(kwargs["plugin_manager"])

    monkeypatch.setattr(hooks, "check_plugin_integrity", record_manager)
    for manager in managers:
        callbacks = manager._hooks["on_session_start"]
        assert len(callbacks) == 1
        callbacks[0](plugin_manager=object())

    assert inspected == managers


_PLUGIN_MANAGER_PROBE = r"""
import json

from mordred_hermes._runtime_bootstrap import (
    _ensure_integrity_callback,
    _is_integrity_callback,
    _is_mandatory_integrity_bridge,
    install,
)
from mordred_hermes.privacy_check import _runtime
from mordred_hermes.privacy_check._exceptions import MordredIntegrityRefused

install()
install()

from hermes_cli.plugins import PluginManager

manager = PluginManager()
manager.discover_and_load(force=True)
first_count = sum(
    1 for callback in manager._hooks.get("on_session_start", [])
    if _is_integrity_callback(callback)
)
manager.discover_and_load(force=True)
second_count = sum(
    1 for callback in manager._hooks.get("on_session_start", [])
    if _is_integrity_callback(callback)
)

side_effects = []
def third_party(**_kwargs):
    side_effects.append("ran")

manager._hooks["on_session_start"].insert(0, third_party)
_ensure_integrity_callback(manager)
bridge_first = _is_mandatory_integrity_bridge(manager._hooks["on_session_start"][0])
bridge_count = sum(
    1 for callback in manager._hooks["on_session_start"]
    if _is_mandatory_integrity_bridge(callback)
)

blocked = False
try:
    manager.invoke_hook("on_session_start")
except MordredIntegrityRefused:
    blocked = True

print(json.dumps({
    "first_count": first_count,
    "second_count": second_count,
    "bridge_first": bridge_first,
    "bridge_count": bridge_count,
    "third_party_ran_before_refusal": bool(side_effects),
    "blocked": blocked,
    "poisoned": _runtime.is_poisoned(),
}))
"""


@pytest.mark.parametrize(
    "config_body",
    [
        """\
plugins:
  enabled:
    - mordred_wizard
  mordred_privacy_check:
    policy: strict
""",
        """\
plugins:
  mordred_privacy_check:
    policy: strict
""",
        """\
plugins:
  enabled: mordred_wizard
  mordred_privacy_check:
    policy: strict
""",
    ],
    ids=["wizard-only", "enabled-missing", "enabled-malformed"],
)
def test_real_plugin_manager_always_gets_fail_closed_integrity_hook(
    tmp_path: Path,
    config_body: str,
) -> None:
    """Exercise the installed Hermes manager, including its real opt-in rules."""
    (tmp_path / "config.yaml").write_text(config_body, encoding="utf-8")
    env = os.environ.copy()
    env["HERMES_HOME"] = str(tmp_path)
    env.pop("HERMES_SAFE_MODE", None)
    source_path = str(_REPO_ROOT / "src")
    prior_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source_path if not prior_pythonpath else source_path + os.pathsep + prior_pythonpath

    completed = subprocess.run(
        [sys.executable, "-c", _PLUGIN_MANAGER_PROBE],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout.splitlines()[-1])
    assert result == {
        "first_count": 1,
        "second_count": 1,
        "bridge_first": True,
        "bridge_count": 1,
        "third_party_ran_before_refusal": False,
        "blocked": True,
        "poisoned": True,
    }


_SAFE_MODE_PROBE = r"""
import json

from mordred_hermes._runtime_bootstrap import _is_mandatory_integrity_bridge, install
from hermes_cli.plugins import PluginManager

install()
manager = PluginManager()
manager.discover_and_load(force=True)
callbacks = manager._hooks.get("on_session_start", [])
print(json.dumps({
    "bridge_count": sum(1 for callback in callbacks if _is_mandatory_integrity_bridge(callback)),
    "callback_count": len(callbacks),
}))
"""


def test_real_plugin_manager_safe_mode_remains_a_recovery_escape_hatch(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        """\
plugins:
  enabled: []
  mordred_privacy_check:
    policy: strict
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["HERMES_HOME"] = str(tmp_path)
    env["HERMES_SAFE_MODE"] = "1"
    source_path = str(_REPO_ROOT / "src")
    prior_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source_path if not prior_pythonpath else source_path + os.pathsep + prior_pythonpath

    completed = subprocess.run(
        [sys.executable, "-c", _SAFE_MODE_PROBE],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout.splitlines()[-1]) == {
        "bridge_count": 0,
        "callback_count": 0,
    }


_DISCOVERY_DRIFT_PROBE = r"""
import json

import mordred_hermes._runtime_bootstrap as bootstrap
from hermes_cli.plugins import PluginManager

bootstrap.install()
def fail(_manager):
    raise RuntimeError("synthetic host shape drift")
bootstrap._ensure_integrity_callback = fail

manager = PluginManager()
raised = None
try:
    manager.discover_and_load(force=True)
except BaseException as exc:
    raised = type(exc).__name__
print(json.dumps({"raised": raised, "hooks": manager._hooks}))
"""


def test_discovery_wrapper_converts_host_drift_to_fail_closed_refusal(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("plugins:\n  enabled: []\n", encoding="utf-8")
    env = os.environ.copy()
    env["HERMES_HOME"] = str(tmp_path)
    env.pop("HERMES_SAFE_MODE", None)
    source_path = str(_REPO_ROOT / "src")
    prior_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source_path if not prior_pythonpath else source_path + os.pathsep + prior_pythonpath

    completed = subprocess.run(
        [sys.executable, "-c", _DISCOVERY_DRIFT_PROBE],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout.splitlines()[-1])
    assert result == {"raised": "SystemExit", "hooks": {}}
