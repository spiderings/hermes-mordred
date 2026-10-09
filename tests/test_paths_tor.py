"""Tests for ``mordred_hermes.network.paths.tor``.

Subprocess is fully mocked — no real ``tor`` binary touched. Tests cover:

- torrc rendering (SOCKSPort / ControlPort / DataDirectory / CookieAuthentication)
- Port shift from 9050 → 9150 on collision
- All candidate ports busy → ``BringupFailed``
- Successful bootstrap (stdout streams "Bootstrapped 100%")
- Bootstrap timeout → ``BringupFailed``
- ``stop()`` calls ``terminate()``, waits grace, then ``kill()``
- ``health()`` reports ``False`` once the subprocess has exited

The shallow `health()` process check and the richer optional ControlPort
circuit-status probe are tested separately.
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TextIO
from unittest.mock import MagicMock

import pytest

# --------------------------------------------------------------------------- #
# Fake subprocess plumbing                                                    #
# --------------------------------------------------------------------------- #


class _FakePopen:
    """Mimics the subset of ``subprocess.Popen`` we touch."""

    def __init__(self, stdout_lines: list[str], *, exit_after_terminate: bool = True) -> None:
        self._stdout_lines = list(stdout_lines)
        self._exit_after_terminate = exit_after_terminate
        self.terminate_called = False
        self.kill_called = False
        self.wait_called = False
        self._returncode: int | None = None
        self.pid = 4242

    @property
    def stdout(self) -> list[str]:
        return self._stdout_lines

    def terminate(self) -> None:
        self.terminate_called = True
        if self._exit_after_terminate:
            self._returncode = 0

    def kill(self) -> None:
        self.kill_called = True
        self._returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.wait_called = True
        if self._returncode is None:
            # Match the real ``subprocess.Popen.wait`` contract — it raises
            # ``subprocess.TimeoutExpired`` (NOT ``TimeoutError``) when the
            # grace window elapses with the process still running. Codex
            # review P1 (HIGH-1) found ``tor.stop`` was catching the wrong
            # exception type, so this fake now exercises the production
            # path.
            raise subprocess.TimeoutExpired(cmd=["tor"], timeout=timeout or 0.0)
        return self._returncode

    def poll(self) -> int | None:
        return self._returncode


def _make_busy_socket_factory(busy_ports: set[int]) -> Any:
    """Return a fake socket factory whose ``bind`` errors on busy ports."""

    def factory(*_args: Any, **_kwargs: Any) -> Any:
        sock = MagicMock()

        def bind(addr: tuple[str, int]) -> None:
            _, port = addr
            if port in busy_ports:
                raise OSError(48, "Address already in use")

        sock.bind.side_effect = bind
        sock.close.return_value = None
        return sock

    return factory


class _FakeClock:
    """Monotonic-like clock that advances by a fixed step on each call."""

    def __init__(self, *, start: float, step: float) -> None:
        self._t = start
        self._step = step

    def __call__(self) -> float:
        cur = self._t
        self._t += self._step
        return cur


# --------------------------------------------------------------------------- #
# torrc rendering                                                             #
# --------------------------------------------------------------------------- #


class TestTorrcRender:
    def test_includes_socks_port(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "SOCKSPort 127.0.0.1:9050" in content

    def test_includes_control_port(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "ControlPort 127.0.0.1:9051" in content

    def test_includes_cookie_auth(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "CookieAuthentication 1" in content

    def test_includes_data_directory(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert f"DataDirectory {tmp_path}" in content

    def test_includes_isolate_socks_auth(self, tmp_path: Path) -> None:
        """v2-N1: make ``IsolateSOCKSAuth`` explicit on the SOCKSPort line so
        per-credential circuit isolation does not rely on Tor's silent
        default-on behaviour (a future Tor release could change the default)."""
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "SOCKSPort 127.0.0.1:9050 IsolateSOCKSAuth" in content


class TestTorrcRenderDisableIpv6:
    """``disable_ipv6`` was resolved into ``RuntimeConfig`` from
    ``policy.json`` and then never threaded into ``render_torrc`` — every
    torrc was rendered identically regardless of policy, so the advertised
    strict-mode IPv6-leak defence (``ClientUseIPv6 0``) was a silent no-op.
    """

    def test_disable_ipv6_true_emits_client_use_ipv6_0(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path, disable_ipv6=True)
        assert "ClientUseIPv6 0" in content

    def test_disable_ipv6_default_omits_client_use_ipv6_0(self, tmp_path: Path) -> None:
        """The parameter is purely additive: omitting it must not change any
        existing caller's rendered torrc."""
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path)
        assert "ClientUseIPv6" not in content

    def test_disable_ipv6_false_omits_client_use_ipv6_0(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        content = tor.render_torrc(socks_port=9050, control_port=9051, data_dir=tmp_path, disable_ipv6=False)
        assert "ClientUseIPv6" not in content


# --------------------------------------------------------------------------- #
# Port collision handling                                                     #
# --------------------------------------------------------------------------- #


class TestPortShift:
    def test_picks_first_free_port(self) -> None:
        from mordred_hermes.network.paths import tor

        chosen = tor.pick_free_port(
            candidates=(9050, 9150),
            socket_factory=_make_busy_socket_factory(set()),
        )
        assert chosen == 9050

    def test_shifts_to_9150_when_9050_busy(self) -> None:
        from mordred_hermes.network.paths import tor

        chosen = tor.pick_free_port(
            candidates=(9050, 9150),
            socket_factory=_make_busy_socket_factory({9050}),
        )
        assert chosen == 9150

    def test_shifts_when_adjacent_control_port_is_busy(self) -> None:
        from mordred_hermes.network.paths import tor

        chosen = tor.pick_free_port(
            candidates=(9050, 9150),
            socket_factory=_make_busy_socket_factory({9051}),
        )
        assert chosen == 9150

    def test_rejects_65535_because_control_port_would_overflow(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        with pytest.raises(BringupFailed, match="pairs busy or invalid"):
            tor.pick_free_port(
                candidates=(65535,),
                socket_factory=_make_busy_socket_factory(set()),
            )

    def test_all_busy_raises_bringup_failed(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        with pytest.raises(BringupFailed):
            tor.pick_free_port(
                candidates=(9050, 9150),
                socket_factory=_make_busy_socket_factory({9050, 9150}),
            )


# --------------------------------------------------------------------------- #
# Bootstrap wait                                                              #
# --------------------------------------------------------------------------- #


class TestBootstrap:
    def test_returns_when_bootstrapped_100(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Tor 0.4.x", "Bootstrapped 5%", "Bootstrapped 100% (done)"])
        tor.wait_for_bootstrap(proc, timeout=1.0, clock=_FakeClock(start=0.0, step=0.01))

    def test_timeout_raises_bringup_failed(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 5%", "Bootstrapped 50%"])
        with pytest.raises(BringupFailed):
            tor.wait_for_bootstrap(proc, timeout=0.1, clock=_FakeClock(start=0.0, step=0.5))

    def test_idle_stdout_does_not_hang(self) -> None:
        """Codex P1 / HIGH-2 (2026-05-13): when the real ``tor`` daemon
        emits a couple of bootstrap lines then stalls without closing
        stdout, the blocking ``for line in stdout`` iterator never wakes
        to check the timeout. The fix makes ``wait_for_bootstrap`` consult
        the deadline between reads; this test injects a ``read_line`` that
        always reports "readiness timeout" (``""``) so the loop's only
        exit path is the deadline raising :class:`BringupFailed`.
        """
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        proc = _FakePopen([])  # stdout never produces lines

        def always_idle(_deadline: float) -> str:
            return ""  # readiness timeout — no line within budget

        with pytest.raises(BringupFailed):
            tor.wait_for_bootstrap(
                proc,
                timeout=0.05,
                clock=_FakeClock(start=0.0, step=0.1),
                read_line=always_idle,
            )

    def test_stdout_closed_before_token(self) -> None:
        """``read_line`` returning ``None`` signals stdout EOF before bootstrap."""
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import tor

        proc = _FakePopen([])
        eof_calls: list[float] = []

        def returns_eof(deadline: float) -> None:
            eof_calls.append(deadline)
            return None

        with pytest.raises(BringupFailed):
            tor.wait_for_bootstrap(
                proc,
                timeout=1.0,
                clock=_FakeClock(start=0.0, step=0.01),
                read_line=returns_eof,
            )
        assert eof_calls, "read_line should have been called at least once"

    def test_stdout_is_continuously_drained_after_bootstrap(self) -> None:
        """A live Tor daemon must not block when its stdout pipe fills later."""
        from mordred_hermes.network.paths import tor

        script = (
            "import sys,time\n"
            "print('Bootstrapped 100% (done)', flush=True)\n"
            "time.sleep(0.2)\n"
            "for _ in range(1024):\n"
            "    print('x' * 1024)\n"
            "sys.stdout.flush()\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            tor.wait_for_bootstrap(proc, timeout=2.0)
            assert proc.wait(timeout=5.0) == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2.0)


# --------------------------------------------------------------------------- #
# Stop semantics                                                              #
# --------------------------------------------------------------------------- #


class TestStop:
    def test_terminate_then_wait(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 100%"])
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        tor.stop(handle)
        assert proc.terminate_called
        assert proc.wait_called

    def test_kill_on_grace_timeout(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 100%"], exit_after_terminate=False)
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        tor.stop(handle, grace_seconds=0.0)
        assert proc.terminate_called
        assert proc.kill_called


# --------------------------------------------------------------------------- #
# Health probe                                                                #
# --------------------------------------------------------------------------- #


class TestHealth:
    def test_alive_process_is_healthy(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 100%"])
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        assert tor.health(handle) is True

    def test_dead_process_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen([])
        proc._returncode = 1
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=Path("/tmp/x"))
        assert tor.health(handle) is False


# --------------------------------------------------------------------------- #
# start_process — Popen decode-error hardening                                #
# --------------------------------------------------------------------------- #


class TestStartProcess:
    """``start_process`` must pass ``errors="replace"`` to ``Popen``. Text
    mode defaults to STRICT decoding, so a single non-UTF-8 byte in tor's
    log output (a relay nickname, a locale-encoded OS error string) would
    otherwise make ``readline()`` raise ``UnicodeDecodeError`` deep inside
    the bootstrap tail, killing an otherwise-healthy bring-up over a
    cosmetic byte.
    """

    class _FakeStartedProcess:
        """Minimal stand-in for the ``Popen`` object ``start_process`` writes
        the torrc into and returns; ``stdin=None`` skips the write/close."""

        def __init__(self) -> None:
            self.stdin = None

    def test_popen_factory_receives_errors_replace(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        captured_kwargs: dict[str, Any] = {}

        def fake_popen_factory(*args: Any, **kwargs: Any) -> Any:
            captured_kwargs.update(kwargs)
            captured_kwargs["_args"] = args
            return self._FakeStartedProcess()

        tor.start_process(binary="tor-bin", torrc="dummy torrc", popen_factory=fake_popen_factory)
        assert captured_kwargs.get("errors") == "replace"
        # Sanity: still text mode (not switched to bytes), since callers scan
        # decoded lines for the bootstrap token.
        assert captured_kwargs.get("text") is True


# --------------------------------------------------------------------------- #
# PATH_NAME constant                                                          #
# --------------------------------------------------------------------------- #


def test_path_name_constant() -> None:
    from mordred_hermes.network.paths import tor

    assert tor.PATH_NAME == "tor"


def test_default_socket_constants() -> None:
    """Sanity: pick_free_port's defaults should be the standard TCP probe."""
    assert socket.AF_INET == 2
    assert socket.SOCK_STREAM == 1


# --------------------------------------------------------------------------- #
# Phase 3 PR3a Task #5: ControlPort cookie auth + GETINFO circuit-status      #
# --------------------------------------------------------------------------- #


class _FakeController:
    """Minimal stand-in for stem's ``Controller``.

    Implements the methods ``circuit_status_health`` actually calls so
    tests don't depend on a real Tor daemon or the ``stem`` library.

    The ``authenticate`` signature mirrors stem's real API
    (Codex P1, 2026-05-14): ``Controller.authenticate`` accepts no
    cookie kwarg -- it does PROTOCOLINFO discovery and cookie reading
    itself. Earlier versions of this fake accepted ``cookie=...`` which
    masked the production API mismatch.
    """

    def __init__(
        self,
        *,
        get_info_response: str = "",
        network_liveness: str = "up",
        auth_raises: BaseException | None = None,
        get_info_raises: BaseException | None = None,
        liveness_raises: BaseException | None = None,
    ) -> None:
        self.authenticated: bool = False
        self.closed: bool = False
        self.get_info_keys: list[str] = []
        self._get_info_response = get_info_response
        self._network_liveness = network_liveness
        self._auth_raises = auth_raises
        self._get_info_raises = get_info_raises
        self._liveness_raises = liveness_raises

    def authenticate(self) -> None:
        if self._auth_raises is not None:
            raise self._auth_raises
        self.authenticated = True

    def get_info(self, key: str) -> str:
        assert self.authenticated, "controller used before authenticate()"
        self.get_info_keys.append(key)
        if key == "circuit-status":
            if self._get_info_raises is not None:
                raise self._get_info_raises
            return self._get_info_response
        if key == "network-liveness":
            if self._liveness_raises is not None:
                raise self._liveness_raises
            return self._network_liveness
        raise KeyError(key)

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> _FakeController:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class TestCircuitStatusHealth:
    """``circuit_status_health(handle, *, controller_factory=...)`` does
    the deep liveness check via control-port cookie auth + GETINFO."""

    def _make_handle(self, tmp_path: Path) -> Any:
        from mordred_hermes.network.paths import tor

        proc = _FakePopen(["Bootstrapped 100%"])
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_path.write_bytes(b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe")
        return tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=tmp_path)

    def test_built_circuit_returns_true(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="circuit-status=\n42 BUILT $abc,$def,$ghi BUILD_FLAGS=NEED_CAPACITY")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True
        assert fake.authenticated is True
        # A BUILT circuit is conclusive on its own — no liveness follow-up.
        assert "network-liveness" not in fake.get_info_keys
        # Codex P1 (2026-05-14): stem does cookie reading via PROTOCOLINFO,
        # the production code no longer reads cookie_bytes itself, so the
        # fake no longer tracks them. The cookie *file* existence is still
        # a precondition asserted by _make_handle's setUp.

    @pytest.mark.parametrize("status", ["LAUNCHED", "EXTENDED", "GUARD_WAIT", "BUILT"])
    def test_active_or_progress_circuit_returns_true(self, tmp_path: Path, status: str) -> None:
        """Healthy before/after circuit construction while liveness is up."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response=f"42 {status} $abc", network_liveness="up")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True

    def test_no_circuits_returns_true_for_healthy_idle_tor(self, tmp_path: Path) -> None:
        """Tor tears down unused preemptive circuits after a long idle period."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="", network_liveness="up")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True

    @pytest.mark.parametrize("response", ["", "42 LAUNCHED $abc", "42 LAUNCHED $abc\n43 EXTENDED $def"])
    def test_circuitless_tor_with_liveness_down_returns_false(self, tmp_path: Path, response: str) -> None:
        """Review 2026-07-29: FAILED/CLOSED circuits are pruned from the
        circuit list almost immediately, so a running-but-circuit-less Tor
        (upstream died after bring-up) shows an empty or in-progress-only
        list forever. The probe must still detect it — via Tor's own
        ``network-liveness`` verdict — or the strict-mode sticky drop can
        never fire for the exact state the deep probe exists to catch."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response=response, network_liveness="down")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is False

    def test_liveness_query_failure_returns_false(self, tmp_path: Path) -> None:
        """An inconclusive circuit list plus a failing liveness query fails
        closed, mirroring the GETINFO-failure contract above."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="", liveness_raises=RuntimeError("no such info"))

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is False

    def test_built_among_malformed_lines_returns_true(self, tmp_path: Path) -> None:
        """A proven BUILT circuit must not be vetoed by an unparseable
        sibling line (review 2026-07-29: one out-of-grammar line from an
        older/forked Tor must not sticky-drop a path that is routing)."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="!!garbage!!\n43 BUILT $def")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True

    def test_attached_echo_prefix_is_tolerated(self, tmp_path: Path) -> None:
        """Older Tor may echo the key attached to the first data line
        (``circuit-status=8 BUILT …``), not only as a standalone line."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="circuit-status=8 BUILT $abc")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True

    def test_echo_line_with_leading_whitespace_is_tolerated(self, tmp_path: Path) -> None:
        """A whitespace-indented standalone echo (`` circuit-status=``) must
        read as the tolerated echo, not as a malformed line (review
        2026-07-29: the strip-based pre-rewrite check accepted it)."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response=" circuit-status=\n42 BUILT $abc")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True

    @pytest.mark.parametrize(
        "response",
        [
            "42 FAILED $abc REASON=TIMEOUT",
            "42 CLOSED $abc REASON=FINISHED",
            "42 FAILED $abc REASON=TIMEOUT\n43 CLOSED $def REASON=FINISHED",
        ],
    )
    def test_only_terminal_circuits_return_false(self, tmp_path: Path, response: str) -> None:
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response=response)

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is False

    def test_terminal_and_healthy_circuits_return_true(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="42 FAILED $abc REASON=TIMEOUT\n43 BUILT $def")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True

    def test_future_well_formed_status_returns_true(self, tmp_path: Path) -> None:
        """A newer Tor status must not create a sticky false drop."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="42 PATH_BIAS_RECOVERY $abc")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is True

    @pytest.mark.parametrize(
        "response",
        [
            "not-a-circuit-status",
            "42 lower_case_status $abc",
            "42 INVALID-STATUS $abc",
            "circuit-status=garbage",
        ],
    )
    def test_malformed_response_returns_false(self, tmp_path: Path, response: str) -> None:
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response=response)

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        assert tor.circuit_status_health(handle, controller_factory=factory) is False

    def test_unreachable_control_port_returns_false(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)

        def factory(*, host: str, port: int) -> _FakeController:
            raise ConnectionRefusedError(f"{host}:{port}")

        assert tor.circuit_status_health(handle, controller_factory=factory) is False

    def test_missing_cookie_file_falls_back_to_shallow(self, tmp_path: Path) -> None:
        """An absent cookie file means stem can't auth; we shouldn't crash --
        fall back to the shallow ``health()`` so the strict-mode session
        gets a clear error from a separate probe, not a noisy traceback."""
        from mordred_hermes.network.paths import tor

        # Don't create the cookie file.
        proc = _FakePopen(["Bootstrapped 100%"])
        handle = tor.TorHandle(process=proc, socks_port=9050, control_port=9051, data_dir=tmp_path)

        called = False

        def factory(*, host: str, port: int) -> _FakeController:
            nonlocal called
            called = True
            return _FakeController()

        result = tor.circuit_status_health(handle, controller_factory=factory)
        assert called is False, "factory must not run when cookie missing"
        # Shallow fallback: process is alive → True
        assert result is True

    def test_authentication_failure_returns_false(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)

        def factory(*, host: str, port: int) -> _FakeController:
            return _FakeController(auth_raises=RuntimeError("cookie mismatch"))

        # Authentication failure does NOT raise to the caller; it returns
        # False so the runtime treats it as "Tor unhealthy" and surfaces a
        # clean MordredPathDropped at the next pre_tool_call.
        assert tor.circuit_status_health(handle, controller_factory=factory) is False

    def test_get_info_failure_returns_false(self, tmp_path: Path) -> None:
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)

        def factory(*, host: str, port: int) -> _FakeController:
            return _FakeController(get_info_raises=RuntimeError("control reply failed"))

        assert tor.circuit_status_health(handle, controller_factory=factory) is False

    def test_no_stem_installed_falls_back_to_shallow(self, tmp_path: Path) -> None:
        """When stem is absent, the default factory raises ImportError on
        first construction; ``circuit_status_health`` collapses to shallow."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)

        def factory(*, host: str, port: int) -> _FakeController:
            raise ImportError("stem not installed (optional [tor-control] extra)")

        # Should not raise; falls back to process.poll()
        result = tor.circuit_status_health(handle, controller_factory=factory)
        assert result is True  # _FakePopen has returncode None → alive

    def test_controller_close_invoked(self, tmp_path: Path) -> None:
        """The controller must be closed even on the success path so we don't
        leak control-port sockets across health probes (the worker runs every
        30s by default)."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        fake = _FakeController(get_info_response="42 BUILT $abc")

        def factory(*, host: str, port: int) -> _FakeController:
            return fake

        tor.circuit_status_health(handle, controller_factory=factory)
        assert fake.closed is True

    def test_default_factory_attempts_stem_lazy_import(self, tmp_path: Path) -> None:
        """When ``controller_factory`` is omitted, the function attempts to
        import stem on demand. With stem not installed in the test env, the
        helper should fall back gracefully (return shallow). We don't assert
        anything about the lazy-import internals -- only the contract."""
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)
        # Call without controller_factory; should not crash regardless of
        # whether stem is installed.
        result = tor.circuit_status_health(handle)
        assert isinstance(result, bool)

    def test_authenticate_called_without_kwargs_matches_real_stem_api(self, tmp_path: Path) -> None:
        """Codex review (2026-05-14, P1): stem's real
        ``Controller.authenticate(password=None, chroot_path=None,
        protocolinfo_response=None)`` does NOT accept a ``cookie`` kwarg.
        The previous implementation called
        ``controller.authenticate(cookie=cookie_bytes)`` -> TypeError ->
        caught silently -> circuit_status_health always returned False.
        Strict-mode deep liveness would mark an otherwise healthy Tor
        process as dropped on every probe.

        Fix: call ``authenticate()`` with no args; stem auto-discovers
        the cookie path via PROTOCOLINFO and reads it itself. This test
        uses a fake mirroring stem's real signature so the production
        code path is exercised against the actual API.
        """
        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)

        class _StemRealisticController:
            """Fake matching stem.control.Controller.authenticate's real signature.

            stem.connection.authenticate (which Controller.authenticate
            delegates to) accepts password/chroot_path/protocolinfo_response
            -- NO cookie kwarg. Calling with cookie=... raises TypeError.
            """

            def __init__(self) -> None:
                self.authenticated = False
                self.closed = False

            def authenticate(
                self,
                password: object = None,
                chroot_path: object = None,
                protocolinfo_response: object = None,
            ) -> None:
                # Reject unexpected kwargs the way real stem would.
                self.authenticated = True

            def get_info(self, key: str) -> str:
                assert self.authenticated, "controller used before authenticate()"
                return "42 BUILT $abc"

            def close(self) -> None:
                self.closed = True

        fake = _StemRealisticController()

        def factory(*, host: str, port: int) -> _StemRealisticController:
            return fake

        result = tor.circuit_status_health(handle, controller_factory=factory)
        assert result is True, (
            "P1: circuit_status_health must call authenticate() in a way "
            "stem accepts; today it passes cookie=... -> TypeError -> False "
            "-> Tor falsely marked dropped on every probe"
        )
        assert fake.authenticated, "authenticate() was not called"

    def test_no_stem_logs_warning_once(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """H5 (review 2026-05-14): the silent shallow fallback when stem
        is absent hides a real downgrade from the strict-mode operator.
        At least one WARNING must be emitted naming the optional extra so
        the operator can install ``hermes-mordred[tor-control]`` to
        recover the deep probe. The warning must NOT be emitted every
        call (the 30s liveness worker would spam logs); once per process
        is enough.
        """
        import logging

        from mordred_hermes.network.paths import tor

        handle = self._make_handle(tmp_path)

        def factory(*, host: str, port: int) -> _FakeController:
            raise ImportError("stem not installed (optional [tor-control] extra)")

        # Reset the module-level "warned once" flag if it exists so this
        # test starts from a clean slate. After GREEN it'll be a real
        # module attribute; before GREEN the setattr is harmless.
        with contextlib.suppress(AttributeError):
            tor._STEM_FALLBACK_WARNED = False  # type: ignore[attr-defined]

        with caplog.at_level(logging.WARNING, logger="mordred.network.paths.tor"):
            tor.circuit_status_health(handle, controller_factory=factory)
            tor.circuit_status_health(handle, controller_factory=factory)
            tor.circuit_status_health(handle, controller_factory=factory)

        relevant = [r for r in caplog.records if r.levelno == logging.WARNING and "tor-control" in r.getMessage()]
        assert relevant, (
            "H5: circuit_status_health must emit a WARNING when stem is "
            "absent so the operator knows the deep probe was skipped. "
            f"Got log records: {[(r.levelname, r.getMessage()) for r in caplog.records]}"
        )
        assert len(relevant) == 1, (
            f"H5: warning must fire exactly once per process; got {len(relevant)} (30s liveness worker would spam logs)"
        )


class TestPipedReadLine:
    """``_make_piped_read_line`` — the production reader for a real pipe.

    Review 2026-07-29: the thread+queue reader replacing the selectors code
    had zero unit coverage (only a live tor bring-up exercised it). These
    tests drive it with a real OS pipe through the public
    ``_make_default_read_line`` dispatch (covering the ``fileno`` branch).
    """

    @pytest.fixture
    def pipe(self) -> Iterator[tuple[TextIO, TextIO]]:
        read_fd, write_fd = os.pipe()
        reader = os.fdopen(read_fd, "r", encoding="utf-8")
        writer = os.fdopen(write_fd, "w", encoding="utf-8")
        try:
            yield reader, writer
        finally:
            with contextlib.suppress(OSError, ValueError):
                writer.close()
            with contextlib.suppress(OSError, ValueError):
                reader.close()

    def test_reads_lines_then_latches_eof(self, pipe: tuple[TextIO, TextIO]) -> None:
        from mordred_hermes.network.paths import tor

        reader, writer = pipe
        writer.write("notice\nBootstrapped 100%\n")
        writer.close()
        read_line, cleanup = tor._make_default_read_line(reader)
        try:
            assert read_line(2.0) == "notice\n"
            assert read_line(2.0) == "Bootstrapped 100%\n"
            assert read_line(2.0) is None  # EOF sentinel
            assert read_line(2.0) is None  # EOF latches without re-reading
        finally:
            cleanup()

    def test_timeout_returns_empty_string(self, pipe: tuple[TextIO, TextIO]) -> None:
        from mordred_hermes.network.paths import tor

        reader, _writer = pipe
        read_line, cleanup = tor._make_default_read_line(reader)
        try:
            assert read_line(0.05) == ""
        finally:
            cleanup()

    def test_reader_error_reaches_the_caller(self) -> None:
        """A reader-side failure must re-raise in ``read_line``, not vanish
        into the pump thread (pre-thread behavior: select/readline raised on
        the caller's thread and became ``BringupFailed`` with a cause)."""
        from mordred_hermes.network.paths import tor

        class _ExplodingStdout:
            def fileno(self) -> int:  # route into the piped branch
                return 0

            def __iter__(self) -> Iterator[str]:
                yield "one\n"
                raise OSError(9, "Bad file descriptor")

        read_line, cleanup = tor._make_default_read_line(_ExplodingStdout())
        try:
            assert read_line(2.0) == "one\n"
            with pytest.raises(OSError, match="Bad file descriptor"):
                read_line(2.0)
            assert read_line(2.0) is None  # error latches EOF
        finally:
            cleanup()

    def test_cleanup_switches_to_discarding_drain_mode(self, pipe: tuple[TextIO, TextIO]) -> None:
        """After cleanup, later lines are consumed but never queued."""
        from mordred_hermes.network.paths import tor

        reader, writer = pipe
        read_line, cleanup = tor._make_default_read_line(reader)
        writer.write("a\n")
        writer.flush()
        assert read_line(2.0) == "a\n"
        cleanup()
        writer.write("unblock\n")
        writer.flush()
        writer.close()
        # The post-cleanup line was drained/discarded; EOF is the next item.
        assert read_line(2.0) is None
