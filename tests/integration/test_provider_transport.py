"""Provider transport verification.

For each Hermes provider, verify empirically whether the SDK's HTTP
transport honours a ``socks5h://`` proxy supplied through the standard
proxy environment variables — the contract Mordred relies on to route
provider traffic through Tor.

Method (no real API credentials or cloud calls needed):

1. Start the :mod:`_socks5_inspector` SOCKS5 proxy and the
   :mod:`_http_target` origin server, both on loopback.
2. Point the proxy env vars at the inspector and the SDK's ``base_url``
   / ``endpoint_url`` at the origin.
3. Drive one request. The SDK fails to parse the origin's stub ``200``
   as a real API response — irrelevant; the inspector has already
   recorded (or not) the CONNECT.
4. Assert on ``inspector.captures`` (did it route through the proxy?
   with which ATYP?) and ``target.hits`` (did it reach the origin
   directly = a leak?).

Marked ``integration`` — needs the optional ``integration`` extra. Each
provider SDK is import-or-skipped, so a partial install runs what it can.
``mordred_network`` itself depends on no provider SDK; this suite only
verifies the transport assumptions baked into
``provider_transport_flagger.KNOWN_PROVIDERS``.
"""

from __future__ import annotations

import contextlib

import pytest

from mordred_hermes.network import proxy_env

from ._http_target import http_target
from ._socks5_inspector import ATYP_DOMAINNAME, socks5_inspector

pytestmark = pytest.mark.integration

_PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)
_NO_PROXY_KEYS = ("NO_PROXY", "no_proxy")


def _apply_socks_env(monkeypatch: pytest.MonkeyPatch, proxy_url: str) -> None:
    """Route every proxy env var at ``proxy_url`` and clear NO_PROXY.

    SDKs that build an env-trusting HTTP client read these at client
    construction, so callers must apply this *before* instantiating the
    SDK client.
    """
    for key in _PROXY_ENV_KEYS:
        monkeypatch.setenv(key, proxy_url)
    for key in _NO_PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)


class TestAnthropic:
    """``anthropic`` SDK — httpx transport, env-trusting by default."""

    def test_default_client_routes_socks5h(self, monkeypatch: pytest.MonkeyPatch) -> None:
        anthropic = pytest.importorskip("anthropic", reason="anthropic SDK not installed")
        with http_target() as target, socks5_inspector() as inspector:
            _apply_socks_env(monkeypatch, f"socks5h://127.0.0.1:{inspector.port}")
            client = anthropic.Anthropic(api_key="verification-stub", base_url=target.url, timeout=10.0, max_retries=0)
            with contextlib.suppress(Exception):
                list(client.models.list())
        capture = inspector.last_capture
        assert capture.atyp == ATYP_DOMAINNAME, f"anthropic leaked DNS: ATYP={capture.atyp:#04x}"
        assert capture.dest_host == target.host


class TestOpenAI:
    """``openai`` SDK — httpx transport, env-trusting by default."""

    def test_default_client_routes_socks5h(self, monkeypatch: pytest.MonkeyPatch) -> None:
        openai = pytest.importorskip("openai", reason="openai SDK not installed")
        with http_target() as target, socks5_inspector() as inspector:
            _apply_socks_env(monkeypatch, f"socks5h://127.0.0.1:{inspector.port}")
            client = openai.OpenAI(api_key="verification-stub", base_url=target.url, timeout=10.0, max_retries=0)
            with contextlib.suppress(Exception):
                list(client.models.list())
        capture = inspector.last_capture
        assert capture.atyp == ATYP_DOMAINNAME, f"openai leaked DNS: ATYP={capture.atyp:#04x}"
        assert capture.dest_host == target.host


class TestGemini:
    """``google-genai`` SDK (the current Gemini SDK; supersedes the
    ``requests``-based ``google-generativeai``)."""

    def test_default_client_routes_socks5h(self, monkeypatch: pytest.MonkeyPatch) -> None:
        genai = pytest.importorskip("google.genai", reason="google-genai SDK not installed")
        with http_target() as target, socks5_inspector() as inspector:
            _apply_socks_env(monkeypatch, f"socks5h://127.0.0.1:{inspector.port}")
            client = genai.Client(
                api_key="verification-stub",
                http_options=genai.types.HttpOptions(base_url=target.url.rstrip("/")),
            )
            with contextlib.suppress(Exception):
                list(client.models.list())
        capture = inspector.last_capture
        assert capture.atyp == ATYP_DOMAINNAME, f"gemini leaked DNS: ATYP={capture.atyp:#04x}"
        assert capture.dest_host == target.host


class TestMordredLocal:
    """``mordred-local`` — localhost-only synthetic provider.

    Drives the *real* env that ``proxy_env.desired_env(path="tor")``
    emits: ``HTTPS_PROXY=socks5h://...`` plus the ``NO_PROXY`` default
    (``localhost,127.0.0.1,::1``). A localhost endpoint must therefore
    bypass the proxy entirely — confirming the ``localhost_only`` exempt
    branch in ``provider_transport_flagger``.
    """

    def test_localhost_bypasses_proxy_via_no_proxy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        httpx = pytest.importorskip("httpx", reason="httpx not installed")
        with http_target() as target, socks5_inspector() as inspector:
            env = proxy_env.desired_env(path="tor", tor_socks_port=inspector.port)
            for key, value in env.items():
                monkeypatch.setenv(key, value)
            with httpx.Client(timeout=10.0) as client:  # trust_env=True picks up NO_PROXY
                response = client.get(target.url)
            assert response.status_code == 200
            assert response.content == target.ok_body
        assert inspector.captures == [], "localhost traffic was routed through the Tor proxy"
        assert target.hits == 1, "localhost request never reached the origin directly"


class TestBedrock:
    """``boto3`` / ``botocore`` — urllib3 transport.

    botocore's ``URLLib3Session`` only understands HTTP(S) proxies; it
    has no SOCKS support. The verification confirms a ``socks5h://``
    proxy is NOT honoured (``respects_socks5h=False``) — botocore either
    errors out or connects directly. Either way the inspector records
    no CONNECT.
    """

    def test_socks5h_proxy_is_not_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        boto3 = pytest.importorskip("boto3", reason="boto3 SDK not installed")
        botocore_config = pytest.importorskip("botocore.config", reason="botocore not installed")
        with http_target() as target, socks5_inspector() as inspector:
            _apply_socks_env(monkeypatch, f"socks5h://127.0.0.1:{inspector.port}")
            client = boto3.client(
                "bedrock",
                region_name="us-east-1",
                aws_access_key_id="verification-stub",
                aws_secret_access_key="verification-stub",  # synthetic test value, not a real secret
                endpoint_url=target.url,
                config=botocore_config.Config(
                    connect_timeout=10,
                    read_timeout=10,
                    retries={"max_attempts": 0},
                ),
            )
            with contextlib.suppress(Exception):
                client.list_foundation_models()
        assert inspector.captures == [], "botocore unexpectedly routed through the socks5h proxy"
