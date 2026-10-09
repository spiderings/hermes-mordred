"""Live-gated Mullvad integration tests.

Gated by ``MORDRED_LIVE_VPN_TEST=1`` and a real Mullvad account number
in ``MORDRED_MULLVAD_ACCOUNT``. Skipped by default so ``pytest -q`` on
CI and dev machines remains hermetic.

.. code-block:: bash

   MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=XXXX-YYYY-ZZZZ \\
     pytest tests/integration/test_vpn.py -v

These tests are workflow_dispatch-only in CI — never run on every PR
because (a) the account number is a paid resource and (b) the bring-up
mutates real network state. See ``.github/workflows/integration-vpn.yml``.

Scope (Phase 3 PR3b, TODO §3.3):

1. ``bring_up`` → ``wait_connected`` → ``health`` → ``disconnect``
   roundtrip succeeds against a real ``mullvad`` daemon.
2. After ``disconnect(preserve_lockdown=False)``, the kill-switch
   actually returns to ``off`` when WE flipped it on (the
   ``MullvadHandle.lockdown_applied_by_us`` flag).
3. ``parse_handshake_age`` agrees with reality — the value returned
   immediately after connect is below the strict-mode 180s threshold.

The PR1 unit tests (``test_paths_vpn.py``) cover the parse / rollback
contract with fake runners; this file ensures the parse format we
expect actually matches what shipping ``mullvad`` / ``wg show`` emit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator

import pytest

from mordred_hermes.network.paths import vpn

# Codex P2-1 (2026-05-14): tag the suite ``integration`` so the default
# unit-test run skips it. ``MORDRED_LIVE_VPN_TEST`` is the runtime opt-
# in; the marker is the static (config-level) opt-in. Both must agree.
pytestmark = pytest.mark.integration

_LIVE_GATE_ENV = "MORDRED_LIVE_VPN_TEST"
_ACCOUNT_ENV = "MORDRED_MULLVAD_ACCOUNT"


def _live_or_skip() -> tuple[str, str]:
    """Return ``(cli_path, account)`` or skip the test if gates are off."""
    if os.environ.get(_LIVE_GATE_ENV) != "1":
        pytest.skip(f"set {_LIVE_GATE_ENV}=1 to run live Mullvad integration tests")
    account = os.environ.get(_ACCOUNT_ENV)
    if not account:
        pytest.skip(f"{_ACCOUNT_ENV} env var must hold a Mullvad account number")
    try:
        cli_path = vpn.detect_cli()
    except vpn.BringupFailed as e:
        pytest.skip(f"mullvad CLI not installed: {e}")
    return cli_path, account


@pytest.fixture
def authenticated_cli() -> Iterator[str]:
    """Login the mullvad CLI for the duration of one test, logout on teardown.

    Each test that mutates connection state pays the login cost so a
    failure in test N doesn't poison test N+1's account session.
    """
    cli_path, account = _live_or_skip()

    subprocess.run(
        [cli_path, "account", "login", account],
        check=True,
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    try:
        yield cli_path
    finally:
        subprocess.run(
            [cli_path, "disconnect"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15.0,
        )
        subprocess.run(
            [cli_path, "account", "logout"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15.0,
        )


class TestMullvadConnectionRoundtrip:
    """Live Mullvad connection and teardown verification."""

    def test_bring_up_wait_connected_disconnect(self, authenticated_cli: str) -> None:
        """Connect, wait for handshake, disconnect — full happy path."""
        handle = vpn.bring_up(
            cli_path=authenticated_cli,
            region="auto",
            policy_mode="lenient",
        )
        try:
            vpn.wait_connected(cli_path=authenticated_cli, timeout=30.0)
        finally:
            vpn.disconnect(handle, preserve_lockdown=True)


class TestMullvadLockdownRollback:
    """Codex round 7 P2-A / round 8 P1-A: only roll back kill-switch
    settings WE flipped on.
    """

    def test_lockdown_off_after_disconnect_when_we_applied_it(
        self,
        authenticated_cli: str,
    ) -> None:
        """If the user starts with lockdown off and we bring up in strict,
        ``MullvadHandle.lockdown_applied_by_us`` must be True, and
        disconnecting with ``preserve_lockdown=False`` must restore the
        pre-Mordred state.
        """
        subprocess.run(
            [authenticated_cli, "lockdown-mode", "set", "off"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10.0,
        )

        handle = vpn.bring_up(
            cli_path=authenticated_cli,
            region="auto",
            policy_mode="strict",
        )
        try:
            assert handle.lockdown_applied_by_us, "expected `bring_up` to flip lockdown-mode on (it was off pre-test)"
        finally:
            vpn.disconnect(handle, preserve_lockdown=False)

        result = subprocess.run(
            [authenticated_cli, "lockdown-mode", "get"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        assert "off" in (result.stdout or "").lower(), (
            f"lockdown not restored to off after disconnect: {result.stdout!r}"
        )


class TestMullvadHandshakeFreshness:
    """Acceptance gate row 3 — health() returns truthful state right
    after a successful connect.
    """

    def test_health_passes_immediately_after_connect(
        self,
        authenticated_cli: str,
    ) -> None:
        """Right after ``wait_connected`` returns, ``health()`` should be
        True: the Mullvad daemon reports Connected.

        Since the fix 2026-07-13, ``health()`` uses ``mullvad status`` (the
        daemon's own Connected state) rather than an unscoped ``wg show``, so
        no ``wg`` binary is needed on PATH.
        """
        handle = vpn.bring_up(
            cli_path=authenticated_cli,
            region="auto",
            policy_mode="lenient",
        )
        try:
            vpn.wait_connected(cli_path=authenticated_cli, timeout=30.0)
            assert vpn.health(handle), "mullvad status did not report Connected despite connect succeeding"
        finally:
            vpn.disconnect(handle, preserve_lockdown=True)


class TestMullvadIPv6Behaviour:
    """Live IPv6 egress gate.

    ``RuntimeConfig.disable_ipv6`` is **advisory only** in v1: on the Tor
    path it renders ``ClientUseIPv6 0``, but it does not alter host routes or
    suppress provider transport warnings. Kernel-level IPv6 firewalling is
    v2-N2 deferred. On a dual-stack host the OS may route IPv6 traffic around
    a misconfigured Mullvad tunnel regardless of this setting.

    This gate compares the host's IPv6 egress address pre-tunnel against
    during-tunnel and documents three acceptable outcomes:

    - **tunneled**: during-tunnel IPv6 differs from baseline → Mullvad is
      routing IPv6 too (no leak).
    - **blocked**: during-tunnel IPv6 unreachable → kill-switch / OS-level
      block (no leak).
    - **leaked**: during-tunnel IPv6 == baseline → IPv6 bypassed the
      tunnel; **FAIL** so the leak surfaces in CI rather than prod.

    Skips when curl is unavailable or the host has no reachable IPv6
    pre-tunnel (nothing to compare — common on IPv4-only CI runners).
    """

    _IPV6_PROBE_URL = "https://ifconfig.co"
    _IPV6_PROBE_TIMEOUT = 8.0

    @classmethod
    def _fetch_ipv6_egress(cls) -> str | None:
        """Return the host's IPv6 egress, or ``None`` if unreachable.

        Failure-to-connect is intentionally collapsed to ``None`` (not
        an exception) — "no IPv6 reachable from here" is the normal
        skip condition, not a test bug.
        """
        result = subprocess.run(
            [
                "curl",
                "-6",
                "-s",
                "--max-time",
                str(cls._IPV6_PROBE_TIMEOUT),
                cls._IPV6_PROBE_URL,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=cls._IPV6_PROBE_TIMEOUT + 2.0,
        )
        if result.returncode != 0:
            return None
        addr = (result.stdout or "").strip()
        # ifconfig.co returns a bare IP literal. Reject anything that
        # doesn't look like a v6 literal (HTML error pages, IPv4
        # fallback bugs, captive-portal responses, etc.).
        if ":" not in addr or len(addr) > 64:
            return None
        return addr

    def test_ipv6_during_tunnel_does_not_leak_baseline_address(
        self,
        authenticated_cli: str,
    ) -> None:
        """Pre-tunnel IPv6 egress must NOT remain reachable during a
        lenient VPN session — same address pre+during = leak.

        The lenient + ``disable_ipv6=false`` combination is the realistic
        worst case: v1 has no kernel firewall, so a dual-stack host
        without OS-level IPv6 blocking would expose clear IPv6 traffic
        even while WireGuard is up.
        """
        if shutil.which("curl") is None:
            pytest.skip("curl binary not on $PATH; IPv6 probe needs it")

        baseline = self._fetch_ipv6_egress()
        if baseline is None:
            pytest.skip("host has no reachable IPv6 egress pre-tunnel; nothing to compare")

        handle = vpn.bring_up(
            cli_path=authenticated_cli,
            region="auto",
            policy_mode="lenient",
        )
        try:
            vpn.wait_connected(cli_path=authenticated_cli, timeout=30.0)
            during = self._fetch_ipv6_egress()
            # tunneled (different) or blocked (None) both pass; same = leak.
            assert during != baseline, (
                f"IPv6 leak: egress address {baseline!r} reachable both "
                f"before and during the Mullvad session, indicating IPv6 "
                f"traffic is bypassing the WireGuard tunnel. v1 has no "
                f"kernel-level IPv6 firewall; until that boundary exists, "
                f"set policy.json disable_ipv6=true "
                f"or use strict mode + Mullvad lockdown-mode."
            )
        finally:
            vpn.disconnect(handle, preserve_lockdown=True)
