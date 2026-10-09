"""Tests for running-gateway discovery (``...keyvault._runtime_probe``).

``discover_runtime_python`` answers "which interpreter *should* run hermes"
(override → managed venv → ``hermes`` on ``$PATH``). This module covers the
complementary question the 2026-06-25 incident exposed: **which interpreter is
running the gateway right now**. There, ``hermes gateway run`` had been started
from a repo ``.venv`` that had no ``mordred_hermes``, while the managed venv (the
one the probe checked, and the one named by ``gateway_state.json``'s recorded
``argv``) did — so the seal passed its check and the live gateway could not
unseal the files.

Everything here is a pure unit test: ``ps`` is monkeypatched with realistic
output and candidate interpreters are synthesized under ``tmp_path``, so no test
depends on what is actually running on the host (the one exception is an explicit
smoke test that only asserts the real call returns a list).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _runtime_probe
from mordred_hermes.keyvault._runtime_probe import (
    GatewayRuntime,
    discover_running_gateway_pythons,
    discover_running_gateway_runtimes,
    environment_key,
)

_UID = os.getuid()

# The incident's two interpreters, in `ps args=` form.
_MANAGED_ARGV = "{py} -m hermes_cli.main gateway run --replace"
_REPO_ARGV = "{py} -m hermes_cli.main gateway run --replace"


def _make_python(bindir: Path, name: str = "python") -> Path:
    """A regular, non-world-writable, executable file standing in for an interpreter."""
    bindir.mkdir(parents=True, exist_ok=True)
    py = bindir / name
    py.write_text("#!/bin/sh\nexit 0\n")
    py.chmod(0o755)
    return py


def _scan_row(pid: int, args: str, *, uid: int = _UID) -> str:
    """One ``ps -axo pid=,uid=,args=`` row (right-aligned numeric columns)."""
    return f"{pid:>6} {uid:>5} {args}"


def _pid_row(args: str, *, uid: int = _UID) -> str:
    """One ``ps -p <pid> -o uid=,args=`` row."""
    return f"{uid:>5} {args}"


class _FakePs:
    """Monkeypatched ``subprocess.run`` serving canned ``ps`` output.

    Records every invocation so tests can assert *which* ``ps`` calls were made
    (e.g. that a dead state-file pid is never queried).
    """

    def __init__(self, *, scan: str = "", per_pid: dict[int, str] | None = None) -> None:
        self.scan = scan
        self.per_pid = per_pid or {}
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if "-p" in cmd:
            pid = int(cmd[cmd.index("-p") + 1])
            out = self.per_pid.get(pid, "")
            return subprocess.CompletedProcess(args=cmd, returncode=0 if out else 1, stdout=out, stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=self.scan, stderr="")


@pytest.fixture
def macos(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the platform so the Linux-only ``/proc`` branch stays out of the way."""
    monkeypatch.setattr(sys, "platform", "darwin")


def _install_ps(monkeypatch: pytest.MonkeyPatch, fake: _FakePs) -> _FakePs:
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def _write_state(home: Path, payload: object) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "gateway_state.json").write_text(
        payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8"
    )


# -----------------------------------------------------------------------------
# ps scan — argv shapes we must (and must not) match
# -----------------------------------------------------------------------------
class TestScanMatching:
    def test_managed_venv_gateway_is_discovered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        py = _make_python(tmp_path / "home" / "hermes-agent" / "venv" / "bin", "python3")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(4242, _MANAGED_ARGV.format(py=py))))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [py]

    def test_repo_venv_gateway_incident_shape_is_discovered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        # The live incident: the gateway ran from a repo checkout's .venv, which
        # had no mordred_hermes, while the managed venv (probed, passing) did.
        py = _make_python(tmp_path / "Mordred-Hermes" / ".venv" / "bin", "python")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(9111, _REPO_ARGV.format(py=py))))
        runtimes = discover_running_gateway_runtimes(home=tmp_path / "home")
        assert runtimes == [GatewayRuntime(pid=9111, python=py)]

    def test_launcher_form_resolves_through_its_shebang(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        bindir = tmp_path / "rt" / "bin"
        py = _make_python(bindir, "python3")
        launcher = bindir / "hermes"
        launcher.write_text(f"#!{py}\n")
        launcher.chmod(0o755)
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(77, f"{launcher} gateway run --replace")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [py]

    def test_console_script_shape_python_then_launcher(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        # How a `#!` console script REALLY appears in ps: the kernel rewrites the
        # exec to [interpreter, script, ...], so `hermes gateway run` shows up as
        # `<venv>/bin/python <venv>/bin/hermes gateway run`. Missing this shape
        # made the whole check fail open for the standard launch path.
        bindir = tmp_path / "rt" / "bin"
        py = _make_python(bindir, "python3")
        launcher = bindir / "hermes"
        launcher.write_text("#!/does/not/matter\n")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(4242, f"{py} {launcher} gateway run --replace")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [py]

    def test_shell_wrapper_shape_resolves_the_launcher(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        # A `#!/usr/bin/env bash` wrapper appears as `bash /path/hermes gateway run`.
        bindir = tmp_path / "rt" / "bin"
        py = _make_python(bindir, "python3")
        launcher = bindir / "hermes"
        launcher.write_text(f"#!{py}\n")
        launcher.chmod(0o755)
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(77, f"/bin/bash {launcher} gateway run --replace")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [py]

    def test_python_running_an_unrelated_script_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        py = _make_python(tmp_path / "rt" / "bin", "python3")
        other = tmp_path / "rt" / "bin" / "something-else"
        other.write_text("")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(5, f"{py} {other} gateway run")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_unrelated_processes_are_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        py = _make_python(tmp_path / "rt" / "bin", "python3")
        scan = "\n".join(
            [
                _scan_row(1, f"{py} -m http.server 8000"),  # python, not hermes
                _scan_row(2, f"{py} -m hermes_cli.main status"),  # hermes, not `gateway run`
                _scan_row(3, "/bin/zsh -c 'hermes gateway run'"),  # a shell mentioning it
                _scan_row(4, f"grep gateway run {py}"),  # coincidental words
                _scan_row(5, f"{py} -m hermes_cli.main gateway status"),  # gateway, not run
            ]
        )
        _install_ps(monkeypatch, _FakePs(scan=scan))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_other_uid_rows_are_ignored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        py = _make_python(tmp_path / "rt" / "bin", "python3")
        scan = _scan_row(31, _MANAGED_ARGV.format(py=py), uid=_UID + 1)
        _install_ps(monkeypatch, _FakePs(scan=scan))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_malformed_rows_are_ignored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        py = _make_python(tmp_path / "rt" / "bin", "python3")
        good = _scan_row(12, _MANAGED_ARGV.format(py=py))
        scan = "\n".join(
            [
                "",  # blank
                "   ",  # whitespace only
                "12345",  # pid only
                "12345 501",  # no args
                f"notapid 501 {_MANAGED_ARGV.format(py=py)}",  # non-numeric pid
                f"999 root {_MANAGED_ARGV.format(py=py)}",  # non-numeric uid
                good,
            ]
        )
        _install_ps(monkeypatch, _FakePs(scan=scan))
        assert discover_running_gateway_runtimes(home=tmp_path / "home") == [GatewayRuntime(pid=12, python=py)]

    def test_empty_output_is_empty_list(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        _install_ps(monkeypatch, _FakePs(scan=""))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_relative_argv0_is_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        _make_python(tmp_path / "rt" / "bin", "python3")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(8, "python3 -m hermes_cli.main gateway run")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []


# -----------------------------------------------------------------------------
# ps unavailability — discovery is best-effort and must never raise
# -----------------------------------------------------------------------------
class TestPsUnavailable:
    def test_missing_ps_binary_is_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        def _boom(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("ps")

        monkeypatch.setattr(subprocess, "run", _boom)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_timeout_is_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        def _slow(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd="ps", timeout=1.0)

        monkeypatch.setattr(subprocess, "run", _slow)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_nonzero_returncode_is_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        def _fail(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="ps: illegal option")

        monkeypatch.setattr(subprocess, "run", _fail)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_unexpected_error_never_escapes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        # Any surprise (here: an OS refusing getuid) must degrade to "no gateway
        # found" rather than raise into the CLI mid-seal.
        def _boom() -> int:
            raise RuntimeError("no uid here")

        monkeypatch.setattr(os, "getuid", _boom)
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(1, "/bin/python3 -m hermes_cli.main gateway run")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_windows_known_empty_inventory_without_running_ps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        from mordred_hermes.keyvault import _windows_processes

        monkeypatch.setattr(
            _windows_processes,
            "inspect_windows_gateway_runtimes",
            lambda home: _windows_processes.GatewayInventory("known", (), ()),
        )

        def _never(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise AssertionError("ps must not run on Windows")

        monkeypatch.setattr(subprocess, "run", _never)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []


# -----------------------------------------------------------------------------
# Candidate acceptance — we are about to *execute* whatever we return
# -----------------------------------------------------------------------------
class TestCandidateAcceptance:
    def _scan_for(self, py: Path) -> str:
        return _scan_row(55, _MANAGED_ARGV.format(py=py))

    def test_missing_file_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        _install_ps(monkeypatch, _FakePs(scan=self._scan_for(tmp_path / "ghost" / "python3")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_directory_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        d = tmp_path / "bin" / "python3"
        d.mkdir(parents=True)
        _install_ps(monkeypatch, _FakePs(scan=self._scan_for(d)))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_non_executable_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        py = _make_python(tmp_path / "bin", "python3")
        py.chmod(0o644)
        _install_ps(monkeypatch, _FakePs(scan=self._scan_for(py)))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_group_writable_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        py = _make_python(tmp_path / "bin", "python3")
        py.chmod(0o775)
        _install_ps(monkeypatch, _FakePs(scan=self._scan_for(py)))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_world_writable_parent_directory_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        py = _make_python(tmp_path / "bin", "python3")
        py.parent.chmod(0o777)
        _install_ps(monkeypatch, _FakePs(scan=self._scan_for(py)))
        try:
            assert discover_running_gateway_pythons(home=tmp_path / "home") == []
        finally:
            py.parent.chmod(0o755)

    def test_world_writable_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        py = _make_python(tmp_path / "bin", "python3")
        py.chmod(0o777)
        _install_ps(monkeypatch, _FakePs(scan=self._scan_for(py)))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []


class TestLauncherPathHardening:
    """A launcher path comes from ANOTHER process's argv — never trust it blindly."""

    def test_relative_launcher_token_is_never_resolved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        # `hermes gateway run` with a `hermes` file in the CLI's cwd used to
        # resolve against that cwd and hand back `<cwd>/python3` — which we then
        # EXECUTE with the operator's environment.
        cwd = tmp_path / "cwd"
        _make_python(cwd, "python3")
        (cwd / "hermes").write_text("#!/bin/sh\necho planted\n")
        (cwd / "hermes").chmod(0o755)
        monkeypatch.chdir(cwd)
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(6, "hermes gateway run --replace")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []

    def test_fifo_launcher_does_not_hang(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        # Opening a FIFO for reading blocks until a writer appears. A regression
        # here would hang the CLI forever, so bound the test with SIGALRM.
        fifo = tmp_path / "bin" / "hermes"
        fifo.parent.mkdir(parents=True)
        os.mkfifo(fifo)
        _make_python(tmp_path / "bin", "python3")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(7, f"/bin/bash {fifo} gateway run")))

        def _timeout(_signum: int, _frame: object) -> None:
            raise AssertionError("reading a FIFO launcher blocked")

        previous = signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(5)
        try:
            assert discover_running_gateway_pythons(home=tmp_path / "home") == []
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_oversized_launcher_is_read_only_up_to_the_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        # The `exec` line sits past the 64 KiB cap, and the launcher's own
        # directory holds no python, so an uncapped read would report
        # `<elsewhere>/bin/python3` while a capped one finds nothing at all.
        target = _make_python(tmp_path / "elsewhere" / "bin", "python3")
        bindir = tmp_path / "bin"
        bindir.mkdir(parents=True)
        launcher = bindir / "hermes"
        launcher.write_text("#!/bin/sh\n" + ("# padding\n" * 40_000) + f'exec "{target}" "$@"\n')
        launcher.chmod(0o755)
        assert launcher.stat().st_size > _runtime_probe._LAUNCHER_READ_LIMIT
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(8, f"{launcher} gateway run")))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == []


# -----------------------------------------------------------------------------
# /proc/<pid>/exe — authoritative on Linux, never consulted on macOS
# -----------------------------------------------------------------------------
class TestProcExe:
    def test_absolute_argv0_is_preferred_over_proc_exe(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # /proc/<pid>/exe resolves symlinks, so a gateway running a venv's
        # bin/python reports the BASE interpreter — whose site-packages is not the
        # venv's. A usable argv[0] must win, or Linux would probe the wrong env.
        monkeypatch.setattr(sys, "platform", "linux")
        base = _make_python(tmp_path / "base" / "bin", "python3.13")
        venv_py = tmp_path / "repo" / ".venv" / "bin" / "python3"
        venv_py.parent.mkdir(parents=True)
        venv_py.symlink_to(base)
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(4242, _MANAGED_ARGV.format(py=venv_py))))

        def _readlink(path: str, *_a: object, **_k: object) -> str:
            if str(path) == "/proc/4242/exe":
                return str(base)
            raise OSError(22, "not a symlink")  # os.path.realpath probes components this way

        monkeypatch.setattr(os, "readlink", _readlink)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [venv_py]

    def test_proc_exe_used_when_argv0_is_unusable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # A relative argv[0] is never trusted (it would resolve against OUR cwd),
        # so on Linux the kernel's answer is the remaining source.
        monkeypatch.setattr(sys, "platform", "linux")
        real_py = _make_python(tmp_path / "real" / "bin", "python3")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(4242, "python3 -m hermes_cli.main gateway run --replace")))

        def _readlink(path: str, *_a: object, **_k: object) -> str:
            if str(path) == "/proc/4242/exe":
                return str(real_py)
            raise OSError(22, "not a symlink")

        monkeypatch.setattr(os, "readlink", _readlink)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [real_py]

    def test_falls_back_to_argv_when_proc_unreadable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        argv_py = _make_python(tmp_path / "argv" / "bin", "python3")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(4242, _MANAGED_ARGV.format(py=argv_py))))

        def _denied(_path: str, *_a: object, **_k: object) -> str:
            raise PermissionError("/proc is not readable here")

        monkeypatch.setattr(os, "readlink", _denied)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [argv_py]

    def test_proc_not_consulted_on_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        argv_py = _make_python(tmp_path / "argv" / "bin", "python3")
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(4242, _MANAGED_ARGV.format(py=argv_py))))

        seen: list[str] = []

        def _spy(path: str, *_a: object, **_k: object) -> str:
            seen.append(str(path))
            raise OSError(22, "not a symlink")

        monkeypatch.setattr(os, "readlink", _spy)
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [argv_py]
        assert not any(p.startswith("/proc") for p in seen)  # macOS has no /proc


# -----------------------------------------------------------------------------
# gateway_state.json pid — a *locator*, never the source of the interpreter
# -----------------------------------------------------------------------------
class TestStateFilePid:
    def test_alive_pid_is_queried_and_reports_the_live_interpreter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        home = tmp_path / "home"
        managed = _make_python(home / "hermes-agent" / "venv" / "bin", "python3")
        live = _make_python(tmp_path / "repo" / ".venv" / "bin", "python")
        # The recorded argv names the managed venv (as it did in the incident) —
        # the process table says otherwise, and the process table wins.
        _write_state(home, {"pid": 4242, "argv": [str(managed), "-m", "hermes_cli.main", "gateway", "run"]})
        monkeypatch.setattr(os, "kill", lambda _pid, _sig: None)
        fake = _install_ps(monkeypatch, _FakePs(per_pid={4242: _pid_row(_REPO_ARGV.format(py=live))}))
        assert discover_running_gateway_runtimes(home=home) == [GatewayRuntime(pid=4242, python=live)]
        assert ["ps", "-p", "4242", "-o", "uid=,args="] in fake.calls

    def test_dead_pid_is_not_queried(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None) -> None:
        home = tmp_path / "home"
        _write_state(home, {"pid": 4242})

        def _dead(_pid: int, _sig: int) -> None:
            raise ProcessLookupError

        monkeypatch.setattr(os, "kill", _dead)
        fake = _install_ps(monkeypatch, _FakePs(scan=""))
        assert discover_running_gateway_pythons(home=home) == []
        assert all("-p" not in call for call in fake.calls)

    @pytest.mark.parametrize(
        "payload",
        ["{not json", {"argv": ["x"]}, {"pid": "4242"}, {"pid": -1}, {"pid": True}, ["not", "a", "dict"]],
        ids=["malformed", "no-pid", "string-pid", "negative-pid", "bool-pid", "not-a-dict"],
    )
    def test_malformed_state_file_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None, payload: object
    ) -> None:
        home = tmp_path / "home"
        _write_state(home, payload)
        fake = _install_ps(monkeypatch, _FakePs(scan=""))
        assert discover_running_gateway_pythons(home=home) == []
        assert all("-p" not in call for call in fake.calls)

    def test_oversized_state_file_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        # Reading is capped, so a giant file truncates to invalid JSON -> no pid.
        home = tmp_path / "home"
        _write_state(home, {"pad": "x" * (70 * 1024), "pid": 4242})
        fake = _install_ps(monkeypatch, _FakePs(scan=""))
        assert discover_running_gateway_pythons(home=home) == []
        assert all("-p" not in call for call in fake.calls)

    def test_same_interpreter_from_both_sources_is_deduped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        home = tmp_path / "home"
        py = _make_python(tmp_path / "repo" / ".venv" / "bin", "python")
        _write_state(home, {"pid": 4242})
        monkeypatch.setattr(os, "kill", lambda _pid, _sig: None)
        args = _REPO_ARGV.format(py=py)
        _install_ps(monkeypatch, _FakePs(scan=_scan_row(4242, args), per_pid={4242: _pid_row(args)}))
        assert discover_running_gateway_runtimes(home=home) == [GatewayRuntime(pid=4242, python=py)]

    def test_two_processes_from_one_venv_collapse_to_one_candidate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        py = _make_python(tmp_path / "repo" / ".venv" / "bin", "python")
        scan = "\n".join([_scan_row(1, _REPO_ARGV.format(py=py)), _scan_row(2, _REPO_ARGV.format(py=py))])
        _install_ps(monkeypatch, _FakePs(scan=scan))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [py]

    def test_two_distinct_environments_are_both_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: None
    ) -> None:
        a = _make_python(tmp_path / "a" / "bin", "python3")
        b = _make_python(tmp_path / "b" / "bin", "python3")
        scan = "\n".join([_scan_row(1, _REPO_ARGV.format(py=a)), _scan_row(2, _REPO_ARGV.format(py=b))])
        _install_ps(monkeypatch, _FakePs(scan=scan))
        assert discover_running_gateway_pythons(home=tmp_path / "home") == [a, b]


# -----------------------------------------------------------------------------
# environment_key — venv identity, NOT the fully resolved interpreter
# -----------------------------------------------------------------------------
class TestEnvironmentKey:
    def test_two_venvs_sharing_a_base_interpreter_are_different(self, tmp_path: Path) -> None:
        base = _make_python(tmp_path / "base" / "bin", "python3.13")
        managed = tmp_path / "managed" / "bin" / "python3"
        repo = tmp_path / "repo" / ".venv" / "bin" / "python3"
        for link in (managed, repo):
            link.parent.mkdir(parents=True)
            link.symlink_to(base)  # exactly how a venv's bin/python is built
        assert managed.resolve() == repo.resolve() == base.resolve()  # resolve() would collapse them
        assert environment_key(managed) != environment_key(repo)

    def test_interpreters_in_one_bin_dir_share_a_key(self, tmp_path: Path) -> None:
        bindir = tmp_path / "venv" / "bin"
        assert environment_key(_make_python(bindir, "python")) == environment_key(_make_python(bindir, "python3"))


# -----------------------------------------------------------------------------
# Host smoke test — the real call must not raise on this machine
# -----------------------------------------------------------------------------
def test_real_discovery_returns_a_list_without_raising(tmp_path: Path) -> None:
    found = discover_running_gateway_pythons(home=tmp_path)
    assert isinstance(found, list)
    assert all(isinstance(p, Path) for p in found)
    assert _runtime_probe.discover_running_gateway_runtimes.__doc__  # public, documented API


def test_launcher_with_unbalanced_shebang_quote_is_ignored(tmp_path: Path) -> None:
    """A hostile shebang must not raise out of launcher resolution (mirrors _exec_target's guard)."""

    launcher = tmp_path / "hermes"
    launcher.write_text("#!/usr/bin/python3 'unterminated\nprint(1)\n", encoding="utf-8")
    launcher.chmod(0o755)
    assert _runtime_probe._python_for_launcher(launcher) is None
