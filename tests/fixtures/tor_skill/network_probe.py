"""Network probe for the ``tor-skill`` test fixture.

This module is the executable counterpart to ``SKILL.md``: the fixture
skill declares ``network_requirements: tor``, and this probe is the
network operation that declaration is *about*. It exists so the
integration test ``tests/integration/test_tor.py::TestTorSkillEndToEnd``
can prove — end to end — that a Tor-declared skill's traffic actually
exits through Tor once ``hermes-mordred network use tor`` is active.

It is a **test fixture**, not shipped Mordred code. It deliberately lets
:mod:`httpx` read proxy configuration from the process environment
(``HTTPS_PROXY`` / ``ALL_PROXY`` / ``NO_PROXY``) the way a real skill's
HTTP client would, so the test exercises the
``mordred_hermes.network.proxy_env`` contract rather than a bespoke
client config.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

# check.torproject.org echoes whether the caller appeared to arrive
# from a Tor exit node — the same endpoint the sibling SOCKS5h tests use.
CHECK_URL = "https://check.torproject.org/api/ip"


def probe_exit_ip(
    *,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
) -> dict[str, object]:
    """Issue the skill's representative HTTPS request and return the
    decoded ``check.torproject.org`` response body.

    When *client* is ``None`` a fresh :class:`httpx.Client` is built
    here, so it picks up whatever proxy env vars are currently set —
    mirroring a child process spawned after ``Runtime.use("tor")``
    (Phase 0.8 §8.1, Regime A). Tests inject a client backed by a mock
    transport to exercise the response handling without a network.

    Raises :class:`httpx.HTTPStatusError` on a non-2xx response.
    """
    import httpx

    owns_client = client is None
    active = httpx.Client(timeout=timeout) if client is None else client
    try:
        response = active.get(CHECK_URL)
        response.raise_for_status()
        body: dict[str, object] = response.json()
        return body
    finally:
        if owns_client:
            active.close()


def exited_via_tor(
    *,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
) -> bool:
    """Return ``True`` iff the probe request appeared to exit via Tor."""
    return probe_exit_ip(client=client, timeout=timeout).get("IsTor") is True
