"""Hermetic Tor integration tests via docker-compose.

PR3b scope (Phase 3 §3.3): bring up an ephemeral ``tor`` container,
expose 9050 (SOCKS) on ``127.0.0.1``, and verify three contracts:

1. The forwarded SOCKS5 port speaks the SOCKS5 protocol (handshake).
2. ``socks5h://`` URLs route DNS through Tor (no leak to the host
   resolver) — exercised by routing a real HTTPS request through the
   container and checking the response.
3. :func:`mordred_hermes.network.proxy_env.desired_env` produces a
   config string that an :mod:`httpx` client picks up via the
   ``HTTPS_PROXY`` env var when constructed AFTER the switch — the
   contract Phase 0.8 §8.1 documents (Regime A / B).

These tests run by default on Linux when ``docker`` (and the compose
plugin) is on ``$PATH``. macOS, Windows, and CI runners without Docker
auto-skip. Set ``MORDRED_SKIP_DOCKER_TESTS=1`` to force skip without
uninstalling Docker.

Deep ``circuit_status_health`` verification against a real Tor
ControlPort + stem cookie auth is **deferred to PR3c** (it requires
bind-mounting the data dir so the host can read ``control_auth_cookie``
— PR3b keeps the harness minimal and proves the SOCKS path end-to-end).
The unit tests in ``test_paths_tor.py`` already cover the parsing
layer.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network import proxy_env

from . import _docker

_COMPOSE_DIR = Path(__file__).parent / "docker" / "tor"
_SOCKS_PORT = 9050
_LOOPBACK = "127.0.0.1"
_TOR_SKILL_DIR = Path(__file__).parent.parent / "fixtures" / "tor_skill"


def _load_tor_skill_probe() -> Any:
    """Load ``tor_skill/network_probe.py`` — the fixture skill's
    executable counterpart (see :class:`TestTorSkillEndToEnd`).

    ``tests/fixtures/`` is not a package, so the probe is loaded by
    path. The hermetic response-handling tests live in
    ``tests/test_tor_skill_fixture.py``.
    """
    import importlib.util

    path = _TOR_SKILL_DIR / "network_probe.py"
    spec = importlib.util.spec_from_file_location("tor_skill_network_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Codex P2-1 (2026-05-14): tag the suite ``integration`` so the default
# ``-m "not integration"`` filter in mordred-hermes/pyproject.toml
# excludes it. The dedicated ``integration-tor`` CI job opts back in
# with ``-m integration`` (see .github/workflows/ci.yml).
# Codex P2-1 also: cache the skip-reason so the docker probe doesn't
# fire twice during module collection.
_SKIP_REASON = _docker.skip_reason_if_unavailable()
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or ""),
]


@pytest.fixture(scope="module")
def tor_container() -> Iterator[None]:
    """Module-scoped Tor container — start once, tear down even on failure.

    Bootstrap timing depends on the live Tor network; the helper waits
    for ``Bootstrapped 100%`` with a per-attempt deadline and recreates
    the container once on timeout (see :mod:`._docker`) before yielding.
    """
    with _docker.compose_up(
        project_dir=_COMPOSE_DIR,
        service="tor",
        bootstrap_token="Bootstrapped 100%",
    ):
        yield


class TestSocks5Reachable:
    """Contract 1: forwarded port speaks SOCKS5."""

    def test_socks5_handshake_returns_no_auth(self, tor_container: None) -> None:
        """Send a minimal SOCKS5 greeting; assert the server offers
        method 0x00 (no auth). Anything else means we're not actually
        talking to Tor (could be a firewall, wrong port, or container
        misconfig).

        Spec: RFC 1928 §3 — client sends ``05 NMETHODS METHODS``, server
        replies ``05 METHOD``. Tor with default torrc replies ``05 00``.
        """
        with socket.create_connection((_LOOPBACK, _SOCKS_PORT), timeout=5.0) as sock:
            # VER=5, NMETHODS=1, METHOD=0x00 (NO AUTHENTICATION REQUIRED)
            sock.sendall(b"\x05\x01\x00")
            reply = sock.recv(2)
        assert reply == b"\x05\x00", f"unexpected SOCKS5 handshake reply: {reply!r}"


class TestSocks5hDnsRemoteResolution:
    """Contract 2: socks5h:// routes DNS through Tor, not the host
    resolver. Verified by hitting ``check.torproject.org`` which echoes
    whether the request appeared to come from a Tor exit node.

    External-network dependent — skipped (not failed) when the request
    itself errors so an upstream outage doesn't block CI. The SOCKS
    handshake test above is the primary guarantee.
    """

    def test_isTor_true_via_socks5h(self, tor_container: None) -> None:
        httpx = pytest.importorskip("httpx", reason="httpx[socks] required for SOCKS5h tests")
        try:
            with httpx.Client(
                proxy=f"socks5h://{_LOOPBACK}:{_SOCKS_PORT}",
                timeout=30.0,
            ) as client:
                response = client.get("https://check.torproject.org/api/ip")
        except Exception as e:
            pytest.skip(f"check.torproject.org unreachable: {e!r}")

        if response.status_code != 200:
            pytest.skip(f"check.torproject.org returned {response.status_code}; treating as flake")
        body: dict[str, Any] = response.json()
        assert body.get("IsTor") is True, f"request did not exit via Tor: {body!r}"


class TestProxyEnvRoundTrip:
    """Contract 3: ``proxy_env.desired_env(path="tor")`` produces an
    HTTPS_PROXY value that an httpx client constructed AFTER applying
    the env vars actually uses to route through the container.

    Documents the Regime A pattern from Phase 0.8 §8.1 — child
    processes spawned after ``Runtime.use("tor")`` inherit the proxy.
    """

    def test_httpx_constructed_after_env_apply_routes_through_tor(
        self,
        tor_container: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Codex P2-2 (2026-05-14): the prior assertion ``status_code <
        400`` passed even when ``HTTPS_PROXY`` was ignored — direct
        clearnet still returns 200. Hit ``/api/ip`` and assert
        ``IsTor=True`` so the test fails closed if the env-var contract
        regresses.
        """
        httpx = pytest.importorskip("httpx", reason="httpx[socks] required")
        env = proxy_env.desired_env(path="tor", tor_socks_port=_SOCKS_PORT)
        for key, value in env.items():
            monkeypatch.setenv(key, value)

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get("https://check.torproject.org/api/ip")
        except Exception as e:
            pytest.skip(f"upstream probe flaked: {e!r}")

        if response.status_code != 200:
            pytest.skip(f"check.torproject.org returned {response.status_code}; treating as flake")
        body: dict[str, Any] = response.json()
        assert body.get("IsTor") is True, (
            f"httpx via HTTPS_PROXY did not exit via Tor (proxy ignored or env regressed?): {body!r}"
        )


class TestTorSkillEndToEnd:
    """A skill that declares
    ``network_requirements: tor`` routes its *own* traffic through Tor
    once the ``tor`` path is active.

    Method C — Hermes has no ``skill invoke`` API (a skill is a Markdown
    instruction sheet, not callable code), so the ``tor_skill`` fixture
    ships ``network_probe.py`` as the executable counterpart to its
    ``SKILL.md``. This test applies the env that
    ``hermes mordred network use tor`` installs, then runs the fixture
    probe and asserts it exited via Tor — closing the install-to-runtime
    loop that ``test_install_dispatch.py`` opens at install time.

    Scope: the CLI/runtime switch mechanism itself
    (``network_cli.handle_use`` -> ``Runtime.use("tor")`` -> ``os.environ``
    mutation) is covered by ``test_wizard_network_cli.py`` and
    ``test_network_runtime.py``. This test takes the resulting proxy env
    as its starting point and verifies the *skill* side.

    External-network dependent: only genuine transport flakes are
    skipped. A ``network_probe.py`` API regression surfaces as
    ``AttributeError`` / ``TypeError`` and fails the test.
    """

    def test_tor_skill_probe_exits_via_tor(
        self,
        tor_container: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        httpx = pytest.importorskip("httpx", reason="httpx[socks] required")
        # SOCKS support is an optional httpx extra; without it the probe
        # raises ImportError mid-request — skip cleanly rather than fail.
        pytest.importorskip("socksio", reason="httpx[socks] backend required")
        probe = _load_tor_skill_probe()

        # Apply the proxy env `hermes mordred network use tor` installs;
        # the probe builds its httpx client afterwards (Phase 0.8 §8.1
        # Regime A — a child process spawned after Runtime.use("tor")).
        env = proxy_env.desired_env(path="tor", tor_socks_port=_SOCKS_PORT)
        for key, value in env.items():
            monkeypatch.setenv(key, value)

        # Skip only on genuine transport flakes (check.torproject.org
        # down, Tor circuit hiccup). A network_probe.py regression raises
        # AttributeError/TypeError, which propagates and fails the test.
        try:
            body = probe.probe_exit_ip(timeout=30.0)
        except httpx.HTTPError as e:
            pytest.skip(f"upstream probe flaked: {e!r}")

        assert body.get("IsTor") is True, (
            f"tor-skill probe did not exit via Tor (network use tor env not honoured?): {body!r}"
        )
