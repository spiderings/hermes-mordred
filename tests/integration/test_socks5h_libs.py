"""SOCKS5h library compatibility verification.

Empirically proves that each HTTP client library on the Mordred /
Hermes surface honours the ``socks5h://`` URL scheme: when told to use a
``socks5h`` proxy, the library hands the destination **hostname** to the
proxy (RFC 1928 ``ATYP=0x03`` DOMAINNAME) instead of resolving DNS
locally and sending an IP literal. Local resolution is the silent
DNS-leak failure mode ``socks5h`` exists to prevent.

The verification is hermetic and deterministic — no Tor, no Docker, no
external network. The :mod:`_socks5_inspector` proxy records the ATYP
byte of every CONNECT; the :mod:`_http_target` server is the relay
destination so the round trip also yields a real ``200`` response.

Each test additionally asserts the installed library version meets the
``min_version`` pinned in
:data:`mordred_hermes.network.proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS` —
this is the evidence that backs flipping ``unverified_baseline`` to
``False`` for that entry.

Marked ``integration`` because it consumes the optional ``integration``
dependency extra (``httpx[socks]`` / ``requests[socks]`` /
``aiohttp-socks``); the default ``-m "not integration"`` run skips it.
Libraries absent from the environment ``skip`` (never fail).
"""

from __future__ import annotations

import asyncio
import importlib.metadata as importlib_metadata

import pytest
from packaging.version import Version

from mordred_hermes.network.proxy_env import SOCKS5H_LIBRARY_REQUIREMENTS

from ._http_target import http_target
from ._socks5_inspector import ATYP_DOMAINNAME, socks5_inspector

pytestmark = pytest.mark.integration


def _assert_meets_baseline(library: str) -> None:
    """Fail if the installed ``library`` is older than its pinned min_version.

    Uses :class:`packaging.version.Version` for PEP 440-correct ordering
    (``packaging`` is a hard pytest dependency, always importable here).
    """
    requirement = SOCKS5H_LIBRARY_REQUIREMENTS[library]
    installed = importlib_metadata.version(library)
    assert Version(installed) >= Version(requirement.min_version), (
        f"{library} {installed} is below the socks5h baseline {requirement.min_version}"
    )


class TestHttpx:
    """``httpx`` (anthropic / openai / mordred-local transport)."""

    def test_socks5h_sends_hostname_to_proxy(self) -> None:
        httpx = pytest.importorskip("httpx", reason="httpx[socks] not installed")
        pytest.importorskip("socksio", reason="httpx SOCKS support needs socksio")
        with http_target() as target, socks5_inspector() as inspector:
            with httpx.Client(proxy=f"socks5h://127.0.0.1:{inspector.port}", timeout=10.0) as client:
                response = client.get(target.url)
            assert response.status_code == 200
            assert response.content == target.ok_body
        capture = inspector.last_capture
        assert capture.atyp == ATYP_DOMAINNAME, f"httpx leaked DNS: ATYP={capture.atyp:#04x}"
        assert capture.dest_host == target.host
        _assert_meets_baseline("httpx")

    def test_socks5_scheme_also_defers_dns(self) -> None:
        """Empirical finding (TODO §0.8): httpx's socksio transport hands
        the hostname to the proxy for **both** ``socks5://`` and
        ``socks5h://`` — the scheme distinction is a no-op in httpx. A
        safety property: even a misconfigured plain-``socks5://`` URL
        cannot leak DNS through an httpx client."""
        httpx = pytest.importorskip("httpx", reason="httpx[socks] not installed")
        pytest.importorskip("socksio", reason="httpx SOCKS support needs socksio")
        with (
            http_target() as target,
            socks5_inspector() as inspector,
            httpx.Client(proxy=f"socks5://127.0.0.1:{inspector.port}", timeout=10.0) as client,
        ):
            client.get(target.url)
        assert inspector.last_capture.is_remote_dns is True


class TestRequests:
    """``requests`` + ``urllib3`` + PySocks (gemini baseline transport)."""

    def test_socks5h_sends_hostname_to_proxy(self) -> None:
        requests = pytest.importorskip("requests", reason="requests not installed")
        pytest.importorskip("socks", reason="requests SOCKS support needs PySocks")
        with http_target() as target, socks5_inspector() as inspector:
            proxy = f"socks5h://127.0.0.1:{inspector.port}"
            response = requests.get(target.url, proxies={"http": proxy, "https": proxy}, timeout=10.0)
            assert response.status_code == 200
            assert response.content == target.ok_body
        capture = inspector.last_capture
        assert capture.atyp == ATYP_DOMAINNAME, f"requests leaked DNS: ATYP={capture.atyp:#04x}"
        assert capture.dest_host == target.host
        _assert_meets_baseline("requests")

    def test_socks5_without_h_resolves_locally(self) -> None:
        requests = pytest.importorskip("requests", reason="requests not installed")
        pytest.importorskip("socks", reason="requests SOCKS support needs PySocks")
        with http_target() as target, socks5_inspector() as inspector:
            proxy = f"socks5://127.0.0.1:{inspector.port}"
            requests.get(target.url, proxies={"http": proxy, "https": proxy}, timeout=10.0)
        assert inspector.last_capture.is_remote_dns is False


class TestUrllib3:
    """``urllib3`` SOCKS support via ``urllib3.contrib.socks`` + PySocks.

    Exercised directly (not only through ``requests``) because the
    allowlist pins ``urllib3`` as its own entry — ``requests[socks]``
    delegates the actual SOCKS handling here.
    """

    def test_socks5h_sends_hostname_to_proxy(self) -> None:
        pytest.importorskip("urllib3", reason="urllib3 not installed")
        pytest.importorskip("socks", reason="urllib3 SOCKS support needs PySocks")
        from urllib3.contrib.socks import SOCKSProxyManager

        with http_target() as target, socks5_inspector() as inspector:
            manager = SOCKSProxyManager(f"socks5h://127.0.0.1:{inspector.port}")
            try:
                response = manager.request("GET", target.url, timeout=10.0)
                assert response.status == 200
                assert response.data == target.ok_body
            finally:
                manager.clear()
        capture = inspector.last_capture
        assert capture.atyp == ATYP_DOMAINNAME, f"urllib3 leaked DNS: ATYP={capture.atyp:#04x}"
        assert capture.dest_host == target.host
        _assert_meets_baseline("urllib3")


class TestAiohttp:
    """``aiohttp`` SOCKS support via ``aiohttp-socks`` + ``python-socks``.

    Empirical finding (TODO §0.8): ``python-socks`` (the engine under
    ``aiohttp-socks``) does **not** recognise the ``socks5h://`` URL
    scheme — ``ProxyConnector.from_url`` raises ``ValueError``. Remote
    DNS is opted into with the explicit ``rdns=True`` argument on a
    ``socks5://`` connector instead. This is the documented caveat that
    backs the ``aiohttp`` allowlist entry.
    """

    def test_socks5h_url_scheme_is_rejected(self) -> None:
        """The bare ``socks5h://`` scheme is not parseable — a caller that
        forwards Mordred's ``HTTPS_PROXY`` value straight into
        ``from_url`` gets a hard ``ValueError`` (fail-loud, not a silent
        DNS leak)."""
        aiohttp_socks = pytest.importorskip("aiohttp_socks", reason="aiohttp SOCKS needs aiohttp-socks")
        with pytest.raises(ValueError, match="socks5h"):
            aiohttp_socks.ProxyConnector.from_url("socks5h://127.0.0.1:1080")

    def test_socks5_with_rdns_sends_hostname_to_proxy(self) -> None:
        """The correct usage: ``socks5://`` + ``rdns=True`` defers DNS to
        the proxy (RFC 1928 ``ATYP=DOMAINNAME``)."""
        aiohttp = pytest.importorskip("aiohttp", reason="aiohttp not installed")
        aiohttp_socks = pytest.importorskip("aiohttp_socks", reason="aiohttp SOCKS needs aiohttp-socks")

        async def _drive(inspector_port: int, url: str) -> tuple[int, bytes]:
            connector = aiohttp_socks.ProxyConnector.from_url(f"socks5://127.0.0.1:{inspector_port}", rdns=True)
            async with (
                aiohttp.ClientSession(connector=connector) as session,
                session.get(url, timeout=aiohttp.ClientTimeout(total=10.0)) as response,
            ):
                return response.status, await response.read()

        with http_target() as target, socks5_inspector() as inspector:
            status, body = asyncio.run(_drive(inspector.port, target.url))
            assert status == 200
            assert body == target.ok_body
        capture = inspector.last_capture
        assert capture.atyp == ATYP_DOMAINNAME, f"aiohttp leaked DNS: ATYP={capture.atyp:#04x}"
        assert capture.dest_host == target.host
        _assert_meets_baseline("aiohttp")


class TestInspectorSelfCheck:
    """Guards the harness itself — a broken inspector would make every
    library look compliant. Drives a raw PySocks client through the
    inspector and confirms the ATYP differential is observable."""

    def test_inspector_distinguishes_socks5h_from_socks5(self) -> None:
        socks = pytest.importorskip("socks", reason="PySocks not installed")

        def _fetch(*, rdns: bool) -> bool:
            with http_target() as target, socks5_inspector() as inspector:
                sock = socks.socksocket()
                sock.set_proxy(socks.SOCKS5, "127.0.0.1", inspector.port, rdns=rdns)
                sock.settimeout(10.0)
                try:
                    sock.connect((target.host, target.port))
                finally:
                    sock.close()
                return inspector.last_capture.is_remote_dns

        assert _fetch(rdns=True) is True
        assert _fetch(rdns=False) is False
