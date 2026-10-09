"""Tests for the runtime-interpreter probe (:mod:`...keyvault._runtime_probe`).

The probe answers one question before ``encryption enable env`` deletes the
plaintext on macOS: can the interpreter that actually runs ``hermes`` run the
env-injection shim? Discovery must prefer the deterministic managed runtime venv
over a ``$PATH`` lookup (an activated dev venv can shadow it), and the capability
check must fail closed on any launch error, timeout, or non-zero exit.

Pure unit tests: launcher files are synthesized under ``tmp_path`` and the probe
subprocess is monkeypatched, so nothing depends on a real interpreter's install
state.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mordred_hermes.keyvault._runtime_probe import (
    RUNTIME_PYTHON_ENV,
    discover_runtime_python,
    runtime_config_decrypt_available,
    runtime_env_injection_available,
    runtime_memory_encryption_available,
)


def _make_managed_venv(home: Path, *, python_name: str = "python3") -> Path:
    """Create ``<home>/hermes-agent/venv/bin/<python_name>`` and return it."""
    bindir = home / "hermes-agent" / "venv" / "bin"
    bindir.mkdir(parents=True)
    py = bindir / python_name
    py.write_text("")
    return py


# -----------------------------------------------------------------------------
# discover_runtime_python
# -----------------------------------------------------------------------------
class TestDiscoverRuntimePython:
    def test_explicit_override_returned_when_it_exists(self, tmp_path: Path) -> None:
        py = tmp_path / "python"
        py.write_text("")
        assert discover_runtime_python(home=tmp_path, explicit=py) == py

    def test_explicit_override_missing_is_none(self, tmp_path: Path) -> None:
        assert discover_runtime_python(home=tmp_path, explicit=tmp_path / "nope") is None

    def test_env_var_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        py = tmp_path / "python"
        py.write_text("")
        monkeypatch.setenv(RUNTIME_PYTHON_ENV, str(py))
        assert discover_runtime_python(home=tmp_path) == py

    def test_prefers_managed_venv_over_path_lookup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        managed = _make_managed_venv(tmp_path)
        # `which hermes` would resolve to some *other* (dev-venv) hermes — the
        # managed venv must win so a shadowing dev venv cannot pose as the runtime.
        monkeypatch.setattr(shutil, "which", lambda _name: "/somewhere/else/bin/hermes")
        assert discover_runtime_python(home=tmp_path) == managed

    def test_falls_back_to_path_launcher_when_no_managed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        venvbin = tmp_path / "rt" / "bin"
        venvbin.mkdir(parents=True)
        py = venvbin / "python3"
        py.write_text("")
        hermes = venvbin / "hermes"
        hermes.write_text(f"#!{py}\nprint('hi')\n")  # console script: python shebang
        monkeypatch.setattr(shutil, "which", lambda _name: str(hermes))
        assert discover_runtime_python(home=tmp_path) == py

    def test_none_when_no_managed_and_no_hermes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        assert discover_runtime_python(home=tmp_path) is None


# -----------------------------------------------------------------------------
# launcher resolution (bash wrapper -> console script -> python)
# -----------------------------------------------------------------------------
class TestLauncherResolution:
    def test_bash_wrapper_execs_to_console_script(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        venvbin = tmp_path / "rt" / "bin"
        venvbin.mkdir(parents=True)
        py = venvbin / "python3"
        py.write_text("")
        real = venvbin / "hermes"
        real.write_text(f"#!{py}\n")
        wrapper = tmp_path / "bin" / "hermes"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text(f'#!/usr/bin/env bash\nunset PYTHONPATH\nunset PYTHONHOME\nexec "{real}" "$@"\n')
        monkeypatch.setattr(shutil, "which", lambda _name: str(wrapper))
        assert discover_runtime_python(home=tmp_path) == py

    def test_console_script_python_shebang_resolves_directly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        venvbin = tmp_path / "rt" / "bin"
        venvbin.mkdir(parents=True)
        py = venvbin / "python"
        py.write_text("")
        hermes = venvbin / "hermes"
        hermes.write_text(f"#!{py}\n")
        monkeypatch.setattr(shutil, "which", lambda _name: str(hermes))
        assert discover_runtime_python(home=tmp_path) == py

    def test_unparseable_wrapper_without_sibling_python_is_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        wrapper = tmp_path / "bin" / "hermes"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text("#!/usr/bin/env bash\necho nothing-useful\n")  # no exec, no sibling python
        monkeypatch.setattr(shutil, "which", lambda _name: str(wrapper))
        assert discover_runtime_python(home=tmp_path) is None

    def test_sibling_fallback_resolves_when_outside_current_prefix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        rtbin = tmp_path / "rt" / "bin"
        rtbin.mkdir(parents=True)
        py = rtbin / "python3"
        py.write_text("")
        wrapper = rtbin / "hermes"
        wrapper.write_text("#!/bin/sh\necho unrecognized\n")  # not python, no exec target
        monkeypatch.setattr(shutil, "which", lambda _name: str(wrapper))
        assert discover_runtime_python(home=tmp_path) == py

    def test_sibling_fallback_skipped_inside_current_prefix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A dev venv whose `hermes` shadows the host one must not validate itself
        # through the guess fallback — that is the false-pass the guard prevents.
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        monkeypatch.setattr(sys, "prefix", str(tmp_path))
        venvbin = tmp_path / "bin"
        venvbin.mkdir(parents=True)
        (venvbin / "python3").write_text("")
        wrapper = venvbin / "hermes"
        wrapper.write_text("#!/bin/sh\necho unrecognized\n")
        monkeypatch.setattr(shutil, "which", lambda _name: str(wrapper))
        assert discover_runtime_python(home=tmp_path) is None


# -----------------------------------------------------------------------------
# runtime_env_injection_available
# -----------------------------------------------------------------------------
class TestRuntimeInjectionAvailable:
    def test_none_python_is_unavailable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        ok, detail = runtime_env_injection_available(home=tmp_path)
        assert ok is False
        assert "could not locate" in detail

    def test_oserror_when_interpreter_missing(self, tmp_path: Path) -> None:
        ok, detail = runtime_env_injection_available(home=tmp_path, runtime_python=tmp_path / "ghost-python")
        assert ok is False
        assert "could not run" in detail

    def test_returncode_zero_maps_to_available(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_env_injection_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is True
        assert "can inject" in detail

    def test_nonzero_returncode_reports_stderr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=11, stdout="", stderr="plugin not registered")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_env_injection_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is False
        assert "plugin not registered" in detail

    def test_timeout_is_unavailable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd="python", timeout=1.0)

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_env_injection_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is False
        assert "timed out" in detail

    def test_strips_pythonpath_and_neutralizes_the_config_hook(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A stray PYTHONPATH must not let the runtime import a mordred it would not
        # see under the real `hermes` wrapper (which unsets both). MORDRED_CONFIG_DECRYPT=0
        # matters just as much: with it exported as "1" the config-decrypt .pth hook
        # force-engages inside the probe process and would open the vault / prompt
        # Touch ID — including from the read-only `encryption status` path.
        monkeypatch.setenv("PYTHONPATH", "/leak/src")
        monkeypatch.setenv("PYTHONHOME", "/leak/home")
        monkeypatch.setenv("MORDRED_CONFIG_DECRYPT", "1")
        captured: dict[str, dict[str, str]] = {}

        def _fake_run(*_a: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            captured["env"] = dict(kwargs["env"])  # type: ignore[arg-type]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        runtime_env_injection_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert "PYTHONPATH" not in captured["env"]
        assert "PYTHONHOME" not in captured["env"]
        assert captured["env"].get("MORDRED_CONFIG_DECRYPT") == "0"


# -----------------------------------------------------------------------------
# runtime_config_decrypt_available — the config.yaml analogue of the env probe
# -----------------------------------------------------------------------------
class TestRuntimeConfigDecryptAvailable:
    def test_none_python_is_unavailable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(RUNTIME_PYTHON_ENV, raising=False)
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        ok, detail = runtime_config_decrypt_available(home=tmp_path)
        assert ok is False
        assert "could not locate" in detail

    def test_oserror_when_interpreter_missing(self, tmp_path: Path) -> None:
        ok, detail = runtime_config_decrypt_available(home=tmp_path, runtime_python=tmp_path / "ghost-python")
        assert ok is False
        assert "could not run" in detail

    def test_returncode_zero_maps_to_available(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_config_decrypt_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is True
        assert "can decrypt a sealed config.yaml" in detail

    def test_nonzero_returncode_reports_stderr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=21, stdout="", stderr=".pth hook not installed")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_config_decrypt_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is False
        assert ".pth hook not installed" in detail

    def test_timeout_is_unavailable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd="python", timeout=1.0)

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_config_decrypt_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is False
        assert "timed out" in detail

    def test_neutralizes_hook_and_strips_pythonpath(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The probe must (a) strip a stray PYTHONPATH/PYTHONHOME like the env probe
        # and (b) set MORDRED_CONFIG_DECRYPT=0 so the .pth startup hook cannot fire
        # a vault open / Touch ID prompt while we are merely probing capability.
        monkeypatch.setenv("PYTHONPATH", "/leak/src")
        monkeypatch.setenv("PYTHONHOME", "/leak/home")
        captured: dict[str, dict[str, str]] = {}

        def _fake_run(*_a: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            captured["env"] = dict(kwargs["env"])  # type: ignore[arg-type]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        runtime_config_decrypt_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert "PYTHONPATH" not in captured["env"]
        assert "PYTHONHOME" not in captured["env"]
        assert captured["env"].get("MORDRED_CONFIG_DECRYPT") == "0"


# -----------------------------------------------------------------------------
# runtime_memory_encryption_available — the memories/*.md analogue
# -----------------------------------------------------------------------------
class TestRuntimeMemoryEncryptionAvailable:
    def test_returncode_zero_reports_the_shape(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="A", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_memory_encryption_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is True
        assert "seam A" in detail

    def test_nonzero_returncode_reports_stderr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=31, stdout="", stderr="ENTRY_DELIMITER missing")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        ok, detail = runtime_memory_encryption_available(home=tmp_path, runtime_python=Path("/any/python"))
        assert ok is False
        assert "ENTRY_DELIMITER missing" in detail

    def test_never_hands_the_memory_key_to_the_child(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """No probe needs HERMES_MEMORY_KEY, so it must not reach a child process
        from here — the probed interpreter is chosen from another process's argv."""
        monkeypatch.setenv("HERMES_MEMORY_KEY", "c2VjcmV0LW1lbW9yeS1rZXktdmFsdWUtaGVyZQ==")
        monkeypatch.setenv("PYTHONPATH", "/leak/src")
        captured: dict[str, dict[str, str]] = {}

        def _fake_run(*_a: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            captured["env"] = dict(kwargs["env"])  # type: ignore[arg-type]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="A", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        runtime_memory_encryption_available(home=tmp_path, runtime_python=Path("/any/python"))

        assert "HERMES_MEMORY_KEY" not in captured["env"]
        assert "PYTHONPATH" not in captured["env"]
        assert captured["env"].get("MORDRED_CONFIG_DECRYPT") == "0"

    def test_the_env_probe_also_drops_the_memory_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HERMES_MEMORY_KEY", "c2VjcmV0LW1lbW9yeS1rZXktdmFsdWUtaGVyZQ==")
        captured: dict[str, dict[str, str]] = {}

        def _fake_run(*_a: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            captured["env"] = dict(kwargs["env"])  # type: ignore[arg-type]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        runtime_env_injection_available(home=tmp_path, runtime_python=Path("/any/python"))

        assert "HERMES_MEMORY_KEY" not in captured["env"]


def test_key_probe_uses_hermes_startup_and_sanitizes_failure(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _runtime_probe as probe

    def run(args, **kwargs):
        assert args[0] == "/runtime/python"
        script = Path(args[1])
        assert script.name == "hermes"
        assert script.is_file()
        assert "HERMES_MEMORY_KEY" not in kwargs["env"]
        assert kwargs["env"]["HERMES_HOME"] == str(tmp_path)
        return subprocess.CompletedProcess(args, 35, "synthetic-secret", "synthetic-secret")

    monkeypatch.setenv("HERMES_MEMORY_KEY", "synthetic-secret")
    monkeypatch.setattr(subprocess, "run", run)
    ok, reason = probe.runtime_memory_key_available(home=tmp_path, runtime_python=Path("/runtime/python"))
    assert not ok
    assert "synthetic-secret" not in reason
