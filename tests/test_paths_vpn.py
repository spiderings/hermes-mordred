"""Tests for ``mordred_hermes.network.paths.vpn``.

Mullvad CLI is fully mocked — no real client install touched. Tests cover:

- ``detect_cli`` resolves ``mullvad`` from PATH
- ``detect_cli`` falls back to the macOS app bundle path
- ``detect_cli`` raises ``BringupFailed`` when neither is present
- ``bring_up`` issues lockdown / relay / connect in the documented order
- ``wait_connected`` polls until ``status`` reports ``Connected``
- ``wait_connected`` raises ``BringupFailed`` on timeout
- ``disconnect`` calls ``mullvad disconnect`` and preserves lockdown by default
- ``disconnect(preserve_lockdown=False)`` also clears lockdown
- ``health`` parses ``wg show`` latest-handshake-age and accepts fresh handshakes
- ``health`` rejects stale handshakes (> 180s default ceiling)

The operational contract is documented in SPEC.md §Plugin: `mordred_network`.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

import pytest

# --------------------------------------------------------------------------- #
# Subprocess runner fakes                                                     #
# --------------------------------------------------------------------------- #


class _FakeRunner:
    """Captures every ``subprocess.run``-shaped call for assertion."""

    def __init__(self, responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[float | None] = []

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del check, capture_output, text
        key = tuple(argv)
        self.calls.append(key)
        self.timeouts.append(timeout)
        try:
            return self._responses[key]
        except KeyError:
            return subprocess.CompletedProcess(args=list(key), returncode=0, stdout="", stderr="")


class _LockdownTransitionRunner(_FakeRunner):
    """Stateful runner for a successful strict OFF -> ON transition."""

    def __init__(
        self,
        responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]] | None = None,
        *,
        initial_state: str = "off",
    ) -> None:
        super().__init__(responses or {})
        self.lockdown_state = initial_state

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        key = tuple(argv)
        if key[-2:] == ("lockdown-mode", "get") and key not in self._responses:
            self.calls.append(key)
            self.timeouts.append(timeout)
            return _result(f"Network lockdown when disconnected: {self.lockdown_state}\n")
        result = super().__call__(
            argv,
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
        )
        if result.returncode == 0 and key[-3:] == ("lockdown-mode", "set", "on"):
            self.lockdown_state = "on"
        elif result.returncode == 0 and key[-3:] == ("lockdown-mode", "set", "off"):
            self.lockdown_state = "off"
        return result


def _result(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


class _FakeClock:
    def __init__(self, *, start: float, step: float) -> None:
        self._t = start
        self._step = step

    def __call__(self) -> float:
        cur = self._t
        self._t += self._step
        return cur


# --------------------------------------------------------------------------- #
# CLI detection                                                               #
# --------------------------------------------------------------------------- #


class TestDetectCli:
    def test_which_returns_path(self) -> None:
        from mordred_hermes.network.paths import vpn

        def which(name: str) -> str | None:
            assert name == "mullvad"
            return "/opt/homebrew/bin/mullvad"

        assert vpn.detect_cli(which=which) == "/opt/homebrew/bin/mullvad"

    def test_macos_app_bundle_fallback(self, monkeypatch: Any) -> None:
        from mordred_hermes.network.paths import vpn

        bundle = "/Applications/Mullvad VPN.app/Contents/Resources/mullvad"

        def exists(self: object) -> bool:
            return str(self) == bundle

        monkeypatch.setattr("pathlib.Path.exists", exists)
        result = vpn.detect_cli(which=lambda _: None)
        assert result == bundle

    def test_not_found_raises_bringup_failed(self, monkeypatch: Any) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        monkeypatch.setattr("pathlib.Path.exists", lambda _self: False)
        with pytest.raises(BringupFailed) as excinfo:
            vpn.detect_cli(which=lambda _: None)
        msg = str(excinfo.value)
        assert "Install the official Mullvad VPN app/CLI" in msg
        assert "mullvad account login" in msg
        assert "PATH" in msg


# --------------------------------------------------------------------------- #
# Bring-up sequence                                                           #
# --------------------------------------------------------------------------- #


class TestBringUp:
    def test_strict_enforces_lockdown(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _LockdownTransitionRunner()
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="strict",
            runner=runner,
        )
        assert ("/bin/mullvad", "lockdown-mode", "set", "on") in runner.calls

    def test_lenient_does_not_enforce_lockdown(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="lenient",
            runner=runner,
        )
        assert ("/bin/mullvad", "lockdown-mode", "set", "on") not in runner.calls

    def test_relay_set_with_region(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="jp",
            policy_mode="off",
            runner=runner,
        )
        assert ("/bin/mullvad", "relay", "set", "location", "jp") in runner.calls

    def test_connect_invoked(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="off",
            runner=runner,
        )
        assert ("/bin/mullvad", "connect") in runner.calls
        assert runner.timeouts
        assert all(timeout is not None and timeout > 0 for timeout in runner.timeouts)


# --------------------------------------------------------------------------- #
# wait_connected                                                              #
# --------------------------------------------------------------------------- #


class TestBringUpReturnCodes:
    """Codex round 4 P1 (2026-05-14): ``bring_up`` must reject non-zero
    returncodes from any Mullvad CLI subprocess. Previously the helper
    used ``check=False`` and ignored ``returncode``, so a failed
    ``lockdown-mode set on`` / ``connect`` could still produce a handle
    — strict mode would mark the path READY without actually being on
    the tunnel.
    """

    def test_failed_lockdown_command_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _LockdownTransitionRunner({("mullvad", "lockdown-mode", "set", "on"): _result(returncode=1)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)

    def test_failed_relay_set_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "relay", "set", "location", "jp"): _result(returncode=1)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="jp", policy_mode="off", runner=runner)

    def test_failed_connect_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "connect"): _result(returncode=3)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)

    def test_zero_returncode_does_not_raise(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})  # all responses default to returncode=0
        handle = vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)
        assert handle.cli_path == "mullvad"


class TestPreservePreExistingLockdown:
    """Codex round 8 P1-A (2026-05-14): the rollback path must not turn
    off Mullvad settings the user had enabled before Mordred ran.
    A transient bring-up failure should leave the user's pre-existing
    security posture intact (or stronger), never weaker.
    """

    def test_lockdown_already_on_is_not_disabled_on_failure(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        # Pre-existing user state: lockdown ON.
        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: on\n"),
                ("mullvad", "connect"): _result(returncode=1),  # force failure
            }
        )
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)

        # lockdown was already on → we never touched it, so it stays on.
        assert ("mullvad", "lockdown-mode", "set", "off") not in runner.calls, (
            "user's pre-existing lockdown was disabled on bring-up failure"
        )

    def test_lockdown_already_on_is_not_set_again(self) -> None:
        """Skip the redundant ``set on`` when state already matches."""
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: on\n"),
            }
        )
        vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        # No redundant set-on was issued, because lockdown was already on.
        assert ("mullvad", "lockdown-mode", "set", "on") not in runner.calls

    def test_failed_state_query_aborts_without_mutation_or_rollback(self) -> None:
        """A failed GET must not be treated as OFF and claimed as ours.

        This reproduces the dangerous sequence where the user's real state is
        ON, the GET command fails, and a later relay failure used to trigger
        ``set off`` against their pre-existing kill-switch.
        """
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="on", returncode=1),
                ("mullvad", "relay", "set", "location", "any"): _result(returncode=1),
            }
        )

        with pytest.raises(BringupFailed, match="state could not be determined"):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)

        assert ("mullvad", "lockdown-mode", "set", "on") not in runner.calls
        assert ("mullvad", "lockdown-mode", "set", "off") not in runner.calls

    def test_handle_records_what_we_applied(self) -> None:
        """The returned handle reflects whether *we* enabled lockdown
        (so runtime tear-down can decide whether to undo it).
        """
        from mordred_hermes.network.paths import vpn

        runner = _LockdownTransitionRunner()
        handle = vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        # We changed lockdown from off → on, so we should clean up on disconnect.
        assert handle.lockdown_applied_by_us is True

    def test_handle_records_what_already_was(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: on\n"),
            }
        )
        handle = vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        # User already had lockdown on; we did NOT apply it.
        assert handle.lockdown_applied_by_us is False


class TestStrictPartialFailureRollback:
    """Strict failures retain lockdown because ownership is not atomic."""

    def test_preserves_lockdown_when_connect_fails(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _LockdownTransitionRunner({("mullvad", "connect"): _result(returncode=2)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        assert ("mullvad", "lockdown-mode", "set", "off") not in runner.calls
        assert "leaving it ON" in caplog.text

    def test_concurrent_owner_barrier_never_turns_lockdown_off(self) -> None:
        """Deterministically interleave another actor after the initial GET."""
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        calls: list[tuple[str, ...]] = []
        query_count = 0
        concurrent_owner_state = "off"

        def runner(
            argv: list[str] | tuple[str, ...],
            **_kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            nonlocal query_count, concurrent_owner_state
            command = tuple(argv)
            calls.append(command)
            if command[-2:] == ("lockdown-mode", "get"):
                query_count += 1
                if query_count == 1:
                    return _result("Network lockdown when disconnected: off\n")
                return _result(f"Network lockdown when disconnected: {concurrent_owner_state}\n")
            if command[-3:] == ("lockdown-mode", "set", "on"):
                # The other actor enables and begins relying on lockdown in
                # the query/mutation window. Mordred's idempotent set also
                # returns success, but cannot claim exclusive ownership.
                concurrent_owner_state = "on"
                return _result()
            if command[-1:] == ("connect",):
                return _result(returncode=2)
            if command[-3:] == ("lockdown-mode", "set", "off"):
                concurrent_owner_state = "off"
            return _result()

        with pytest.raises(BringupFailed, match="connect"):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)

        assert ("mullvad", "lockdown-mode", "set", "off") not in calls
        assert concurrent_owner_state == "on"

    def test_unconfirmed_set_on_is_rolled_back_and_refused(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        # The CLI reports OFF both before and after a successful ``set on``.
        runner = _LockdownTransitionRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: off\n"),
            }
        )

        with pytest.raises(BringupFailed, match="did not confirm ON"):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)

        assert ("mullvad", "lockdown-mode", "set", "off") not in runner.calls

    def test_lenient_failure_does_not_alter_user_settings(self) -> None:
        """Lenient mode never sets lockdown, so no rollback fires."""
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "connect"): _result(returncode=2)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)
        # Must NOT touch lockdown at all in lenient/off.
        for call in runner.calls:
            assert call[:2] != ("mullvad", "lockdown-mode")


class TestMullvadCli2026Drift:
    """Mullvad CLI 2026.2 dropped the ``always-require-vpn`` subcommand;
    its kill-switch semantics are now subsumed by ``lockdown-mode``. The
    bring-up sequence must not invoke ``always-require-vpn`` on any
    code path or strict-mode sessions raise ``BringupFailed`` against
    every modern Mullvad install.
    """

    def test_strict_mode_does_not_invoke_removed_subcommand(self) -> None:
        from mordred_hermes.network.paths import vpn

        lockdown_state = "off"

        def runner_2026_2(
            argv: list[str] | tuple[str, ...],
            **_kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            nonlocal lockdown_state
            argv_t = tuple(argv)
            if "always-require-vpn" in argv_t:
                return subprocess.CompletedProcess(
                    args=list(argv_t),
                    returncode=2,
                    stdout="",
                    stderr="error: unrecognized subcommand 'always-require-vpn'\n",
                )
            if argv_t[-2:] == ("lockdown-mode", "get"):
                return _result(f"Network lockdown when disconnected: {lockdown_state}\n")
            if argv_t[-3:] == ("lockdown-mode", "set", "on"):
                lockdown_state = "on"
            return subprocess.CompletedProcess(args=list(argv_t), returncode=0, stdout="", stderr="")

        handle = vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="strict",
            runner=runner_2026_2,
        )
        assert handle.cli_path == "/bin/mullvad"
        assert handle.lockdown_enforced is True

    def test_strict_mode_never_emits_always_require_argv(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _LockdownTransitionRunner()
        vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        for call in runner.calls:
            assert "always-require-vpn" not in call, (
                f"bring_up must not invoke the removed Mullvad CLI subcommand; saw {call!r}"
            )


class TestRegionTranslation:
    """Codex round 6 P1 (2026-05-14): the Mullvad CLI uses ``any`` (not
    ``auto``) for automatic relay selection. Our config / wizard
    surface keeps ``auto`` for user-friendliness, but :func:`bring_up`
    must translate it before invoking the CLI; otherwise the new
    returncode check from r4-P1 turns every default-region bring-up
    into a :class:`BringupFailed`."""

    def test_auto_region_translates_to_any(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)
        # Confirm the CLI was asked for "any", not "auto".
        relay_call = next(call for call in runner.calls if call[:3] == ("mullvad", "relay", "set"))
        assert relay_call == ("mullvad", "relay", "set", "location", "any"), (
            f"Expected 'any' translation; got {relay_call!r}"
        )

    def test_explicit_country_code_passes_through(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(cli_path="mullvad", region="jp", policy_mode="off", runner=runner)
        relay_call = next(call for call in runner.calls if call[:3] == ("mullvad", "relay", "set"))
        assert relay_call == ("mullvad", "relay", "set", "location", "jp")


class TestWaitConnected:
    def test_succeeds_when_status_reports_connected(self) -> None:
        from mordred_hermes.network.paths import vpn

        status_cmd = ("/bin/mullvad", "status")
        runner = _FakeRunner({status_cmd: _result(stdout="Tunnel status: Connected to wg-jp-1\n")})
        vpn.wait_connected(
            cli_path="/bin/mullvad",
            runner=runner,
            timeout=2.0,
            clock=_FakeClock(start=0.0, step=0.01),
        )
        assert runner.timeouts == [2.0]

    def test_timeout_raises_bringup_failed(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        status_cmd = ("/bin/mullvad", "status")
        runner = _FakeRunner({status_cmd: _result(stdout="Tunnel status: Disconnected\n")})
        with pytest.raises(BringupFailed):
            vpn.wait_connected(
                cli_path="/bin/mullvad",
                runner=runner,
                timeout=0.05,
                clock=_FakeClock(start=0.0, step=0.1),
            )

    def test_nonzero_status_refuses_even_if_stdout_says_connected(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        status_cmd = ("/bin/mullvad", "status")
        runner = _FakeRunner(
            {
                status_cmd: _result(
                    stdout="Tunnel status: Connected\n",
                    returncode=1,
                )
            }
        )
        with pytest.raises(BringupFailed, match="status failed"):
            vpn.wait_connected(cli_path="/bin/mullvad", runner=runner)

    def test_not_connected_diagnostic_never_marks_ready(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("/bin/mullvad", "status"): _result(stdout="Not Connected (last state: Connected)\n")})
        with pytest.raises(BringupFailed, match="did not reach Connected"):
            vpn.wait_connected(
                cli_path="/bin/mullvad",
                runner=runner,
                timeout=0.05,
                clock=_FakeClock(start=0.0, step=0.1),
            )


# --------------------------------------------------------------------------- #
# Disconnect                                                                  #
# --------------------------------------------------------------------------- #


class TestDisconnect:
    def test_calls_mullvad_disconnect(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        vpn.disconnect(handle, runner=runner)
        assert ("/bin/mullvad", "disconnect") in runner.calls
        assert runner.timeouts == [vpn.DEFAULT_COMMAND_TIMEOUT]

    def test_preserve_lockdown_default(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        vpn.disconnect(handle, runner=runner)
        assert ("/bin/mullvad", "lockdown-mode", "set", "off") not in runner.calls

    def test_preserve_lockdown_false_clears_it(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        vpn.disconnect(handle, runner=runner, preserve_lockdown=False)
        assert ("/bin/mullvad", "lockdown-mode", "set", "off") in runner.calls

    @pytest.mark.parametrize(
        "failed_command",
        [
            ("/bin/mullvad", "disconnect"),
            ("/bin/mullvad", "lockdown-mode", "set", "off"),
        ],
    )
    def test_nonzero_cleanup_command_is_reported(
        self,
        failed_command: tuple[str, ...],
    ) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({failed_command: _result(returncode=9)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)

        with pytest.raises(BringupFailed, match="rc=9"):
            vpn.disconnect(handle, runner=runner, preserve_lockdown=False)


# --------------------------------------------------------------------------- #
# Health (mullvad status Connected — Mullvad-scoped, fix 2026-07-13)          #
# --------------------------------------------------------------------------- #


class TestHealth:
    """The Mullvad-path health probe uses the daemon's own Connected state.

    FIX 2026-07-13: it used to run an UNSCOPED ``wg show`` and take the
    freshest handshake across ALL WireGuard interfaces, so a sibling tunnel
    could mask a dead Mullvad tunnel (strict-mode fail-open). ``mullvad
    status`` is inherently Mullvad-scoped and cannot be fooled that way.
    """

    _CONNECTED = "Connected to jp-tyo-wg-001 in Tokyo, Japan\n"
    _DISCONNECTED = "Disconnected\n"
    _CONNECTING = "Connecting to jp-tyo-wg-001...\n"

    def test_connected_status_is_healthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("/bin/mullvad", "status"): _result(stdout=self._CONNECTED)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is True

    def test_disconnected_status_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("/bin/mullvad", "status"): _result(stdout=self._DISCONNECTED)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        # "Connected" (capital C) must NOT match inside "Disconnected".
        assert vpn.health(handle, runner=runner) is False

    def test_connecting_status_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("/bin/mullvad", "status"): _result(stdout=self._CONNECTING)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is False

    def test_not_connected_diagnostic_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("/bin/mullvad", "status"): _result(stdout="Not Connected (last state: Connected)\n")})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is False

    def test_probe_is_mullvad_scoped_not_freshest_wg_interface(self) -> None:
        """Regression proof for the fix. The OLD unscoped probe ran
        ``wg show`` and returned the FRESHEST handshake across every
        interface: given a stale Mullvad interface (5 min) beside a fresh
        SIBLING interface (60 s < 180 s ceiling) it reported healthy even
        though Mullvad's own tunnel was dead. The new probe never runs
        ``wg show`` — it asks the daemon, which reports Disconnected — so
        this scenario is correctly unhealthy. This assertion FAILS if the
        fix is reverted to the freshest-of-all-interfaces logic.
        """
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner(
            {
                ("/bin/mullvad", "status"): _result(stdout=self._DISCONNECTED),
                # The exact multi-interface output that fooled the old probe:
                # Mullvad's iface stale, an unrelated sibling fresh.
                ("wg", "show"): _result(
                    stdout=(
                        "interface: wg0-mullvad\n"
                        "peer: AAA\n  latest handshake: 5 minutes ago\n"
                        "interface: wg1-other\n"
                        "peer: BBB\n  latest handshake: 1 minute ago\n"
                    )
                ),
            }
        )
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is False
        # It must have consulted the Mullvad daemon, never the unscoped wg show.
        assert ("/bin/mullvad", "status") in runner.calls
        assert ("wg", "show") not in runner.calls

    def test_mullvad_binary_missing_is_unhealthy(self) -> None:
        """On hosts where the ``mullvad`` CLI is not on PATH,
        ``subprocess.run`` raises :class:`FileNotFoundError`. ``health`` must
        catch it and return ``False`` so the PR2 liveness worker records the
        path as unhealthy instead of crashing the thread (fail-closed, Codex
        P2 / HIGH-3 2026-05-13)."""
        from mordred_hermes.network.paths import vpn

        def missing(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("[Errno 2] No such file or directory: 'mullvad'")

        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=missing) is False

    def test_status_command_timeout_is_unhealthy(self) -> None:
        """If the liveness worker passes a ``timeout=`` to the runner,
        :class:`subprocess.TimeoutExpired` must also be coerced into
        ``unhealthy`` rather than propagating."""
        from mordred_hermes.network.paths import vpn

        def slow(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=["mullvad", "status"], timeout=1.0)

        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=slow) is False

    def test_status_nonzero_returncode_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("/bin/mullvad", "status"): _result(stdout="Connected", returncode=1)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is False


# --------------------------------------------------------------------------- #
# Module constants                                                            #
# --------------------------------------------------------------------------- #


def test_path_name_constant() -> None:
    from mordred_hermes.network.paths import vpn

    assert vpn.PATH_NAME == "vpn"


def test_default_runner_is_callable() -> None:
    """Production default must be a runnable subprocess wrapper."""
    from mordred_hermes.network.paths import vpn

    assert callable(vpn.DEFAULT_RUNNER)


def test_default_handshake_ceiling() -> None:
    from mordred_hermes.network.paths import vpn

    assert vpn.DEFAULT_MAX_HANDSHAKE_AGE_SECONDS == 180.0


def _detect_cli_signature_sanity() -> None:
    """Type-checker sanity: detect_cli is a Callable returning str."""
    from mordred_hermes.network.paths import vpn

    cli: Callable[..., str] = vpn.detect_cli
    del cli


# --------------------------------------------------------------------------- #
# parse_handshake_age — multi-peer safety (audit #6)                          #
# --------------------------------------------------------------------------- #


class TestParseHandshakeAge:
    def test_compound_age_is_summed_within_one_line(self) -> None:
        from mordred_hermes.network.paths import vpn

        out = "peer: AAA\n  latest handshake: 1 minute, 30 seconds ago\n"
        assert vpn.parse_handshake_age(out) == 90.0

    def test_multiple_peers_return_the_freshest_not_the_sum(self) -> None:
        # Regression #6: an unrelated second WireGuard tunnel must not inflate
        # the age. ``wg show`` (unscoped) lists both; the freshest handshake
        # wins. The old code summed 60s + 150s = 210s > 180s ceiling and
        # false-dropped the path even though Mullvad was healthy.
        from mordred_hermes.network.paths import vpn

        out = (
            "interface: wg0-mullvad\n"
            "peer: AAA\n  latest handshake: 1 minute ago\n"
            "interface: wg1-other\n"
            "peer: BBB\n  latest handshake: 2 minutes, 30 seconds ago\n"
        )
        assert vpn.parse_handshake_age(out) == 60.0

    def test_none_handshake_does_not_poison_a_fresh_peer(self) -> None:
        from mordred_hermes.network.paths import vpn

        out = "peer: AAA\n  latest handshake: (none)\npeer: BBB\n  latest handshake: 45 seconds ago\n"
        assert vpn.parse_handshake_age(out) == 45.0

    def test_all_none_or_absent_returns_none(self) -> None:
        from mordred_hermes.network.paths import vpn

        assert vpn.parse_handshake_age("peer: AAA\n  latest handshake: (none)\n") is None
        assert vpn.parse_handshake_age("no handshake lines here at all") is None


# --------------------------------------------------------------------------- #
# _get_setting_state — tri-state parsing and ownership safety                 #
# --------------------------------------------------------------------------- #


class TestGetSettingState:
    def test_labeled_on_reads_on(self) -> None:
        from mordred_hermes.network.paths import vpn

        def runner(_argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            return _result("Network lockdown when disconnected: on\n")

        assert vpn._get_setting_state(runner, "/fake/mullvad", "lockdown-mode") == "on"

    def test_labeled_off_reads_off(self) -> None:
        from mordred_hermes.network.paths import vpn

        def runner(_argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            return _result("Network lockdown when disconnected: off\n")

        assert vpn._get_setting_state(runner, "/fake/mullvad", "lockdown-mode") == "off"

    def test_word_ending_in_on_is_unknown(self) -> None:
        # Regression #7: an OFF status whose last word merely ends in "on"
        # (e.g. "...connection") must NOT read as ON — that would fail OPEN
        # in strict (bring_up would skip enabling the kill-switch, believing
        # it is already active).
        from mordred_hermes.network.paths import vpn

        def runner(_argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            return _result("Tunnel status: no active connection\n")

        assert vpn._get_setting_state(runner, "/fake/mullvad", "lockdown-mode") == "unknown"

    def test_nonzero_returncode_reads_unknown(self) -> None:
        from mordred_hermes.network.paths import vpn

        def runner(_argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            return _result("on", returncode=1)

        assert vpn._get_setting_state(runner, "/fake/mullvad", "lockdown-mode") == "unknown"
