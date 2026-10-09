"""Unit coverage for the ``tor_skill`` fixture's network probe.

Hermes has no ``skill invoke`` API: a skill is a Markdown instruction sheet,
not callable code. To verify that a
skill declaring ``network_requirements: tor`` actually routes through
Tor, the ``tor_skill`` fixture ships ``network_probe.py``: the
executable counterpart to its ``SKILL.md``.

These tests exercise the probe's response handling hermetically with an
:class:`httpx.MockTransport` — no network, no Docker. The live
Tor-routing assertion lives in
``tests/integration/test_tor.py::TestTorSkillEndToEnd``.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

httpx = pytest.importorskip("httpx", reason="httpx (integration extra) required")

_TOR_SKILL_DIR = Path(__file__).parent / "fixtures" / "tor_skill"


def _load_probe() -> ModuleType:
    """Load the fixture's ``network_probe.py`` by path.

    ``tests/fixtures/`` is not a package, so the probe is loaded with an
    explicit spec rather than ``import``. A missing file raises here, at
    collection time — the intended RED signal before the probe exists.
    """
    path = _TOR_SKILL_DIR / "network_probe.py"
    spec = importlib.util.spec_from_file_location("tor_skill_network_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = _load_probe()


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    """Build an httpx client whose transport is the given mock handler."""
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestProbeExitIp:
    """``probe_exit_ip`` decodes the check.torproject.org JSON body."""

    def test_requests_the_check_torproject_endpoint(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json={"IsTor": True})

        with _client(handler) as client:
            probe.probe_exit_ip(client=client)

        assert seen == [probe.CHECK_URL]

    def test_returns_decoded_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"IsTor": True, "IP": "10.0.0.1"})

        with _client(handler) as client:
            body = probe.probe_exit_ip(client=client)

        assert body == {"IsTor": True, "IP": "10.0.0.1"}

    def test_raises_on_http_error_status(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        with _client(handler) as client, pytest.raises(httpx.HTTPStatusError):
            probe.probe_exit_ip(client=client)


class TestExitedViaTor:
    """``exited_via_tor`` collapses the probe body to a bool."""

    def test_true_when_istor_true(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"IsTor": True})

        with _client(handler) as client:
            assert probe.exited_via_tor(client=client) is True

    def test_false_when_istor_false(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"IsTor": False})

        with _client(handler) as client:
            assert probe.exited_via_tor(client=client) is False

    def test_false_when_istor_absent(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        with _client(handler) as client:
            assert probe.exited_via_tor(client=client) is False
