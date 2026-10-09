"""Outbound route resolution shared by the extension server's own clients.

The extension server talks to third parties directly (Discord's bot API, the
Telegram MTProto network, Venice.ai). None of those clients may read ambient
proxy environment variables on their own, so each resolves ONE explicit route
here and passes it to its transport. The rules:

- **Tor selected** → a loopback SOCKS proxy is mandatory. No proxy, a
  non-loopback proxy, or an HTTP proxy all fail closed.
- **VPN selected** → the live OS route can only be verified by the network
  runtime; without one, refuse rather than assume the tunnel is up.
- **Clearnet** → use whatever proxy the gateway would use (possibly none).

Every failure is the single content-free code ``routing_unavailable``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .._home import hermes_home

_PROTECTED_NETWORK_PATHS = frozenset({"tor", "vpn"})


class EgressError(RuntimeError):
    """Stable, content-free routing failure."""

    def __init__(self, code: str = "routing_unavailable") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EgressRoute:
    """One explicit route. At most one of the two proxy fields is set."""

    socks_proxy_url: str | None  # ``socks5://`` (remote DNS is the caller's job)
    http_proxy_url: str | None


@dataclass(frozen=True)
class SocksProxy:
    host: str
    port: int
    username: str | None
    password: str | None


def tor_route_required() -> bool:
    """Return whether traffic must use Tor, failing closed on bad live state.

    The registered network runtime is authoritative in a full Hermes process.
    A standalone process (``extension serve`` or a CLI command) has no plugin
    discovery, so it falls back to the persisted selection: Tor still requires
    an explicit proxy, while VPN is refused because its live OS route cannot be
    verified without a runtime.
    """

    from ..network import api as network_api
    from ..network._exceptions import MordredNetworkError

    try:
        status = network_api.status()
    except MordredNetworkError:
        try:
            from ..network.settings import read_default_path_strict

            selected_path = read_default_path_strict(hermes_home() / "config.yaml")
        except Exception as exc:
            raise EgressError() from exc
        if selected_path == "vpn":
            raise EgressError() from None
        return selected_path == "tor"
    except Exception as exc:
        raise EgressError() from exc

    if status.active_path not in {"tor", "vpn", "clearnet"}:
        raise EgressError()
    if status.active_path in _PROTECTED_NETWORK_PATHS and not status.ready:
        raise EgressError()
    try:
        if status.active_path in _PROTECTED_NETWORK_PATHS and network_api.is_dropped():
            raise EgressError()
    except EgressError:
        raise
    except Exception as exc:
        raise EgressError() from exc
    return status.active_path == "tor"


def loopback_proxy_host(url: str) -> bool:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if host is None:
        return False
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_route(target_host: str) -> EgressRoute:
    """Resolve the explicit route for traffic to *target_host*.

    ``socks5h://`` is normalized to ``socks5://``; callers must request remote
    DNS from their SOCKS client (``rdns=True``) so hostnames never resolve
    locally when Tor is in use.
    """

    tor_required = tor_route_required()
    try:
        from gateway.platforms.base import resolve_proxy_url

        proxy_url = resolve_proxy_url(target_hosts=target_host)
    except Exception as exc:
        raise EgressError() from exc

    if not proxy_url:
        if tor_required:
            raise EgressError()
        return EgressRoute(None, None)

    try:
        scheme = urlsplit(proxy_url).scheme.casefold()
    except ValueError as exc:
        raise EgressError() from exc

    if scheme in {"socks5", "socks5h"}:
        if tor_required and not loopback_proxy_host(proxy_url):
            raise EgressError()
        _scheme, separator, remainder = proxy_url.partition("://")
        if not separator or not remainder:
            raise EgressError()
        return EgressRoute(f"socks5://{remainder}", None)

    if tor_required or scheme not in {"http", "https"}:
        raise EgressError()
    return EgressRoute(None, proxy_url)


def socks_proxy(url: str) -> SocksProxy:
    """Split a ``socks5://[user:pass@]host:port`` URL for non-HTTP clients.

    The credentials matter: the Tor runtime uses them as the
    ``IsolateSOCKSAuth`` stream-isolation token.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise EgressError() from exc
    if parts.scheme != "socks5" or not parts.hostname or port is None:
        raise EgressError()
    return SocksProxy(
        host=parts.hostname,
        port=port,
        username=unquote(parts.username) if parts.username is not None else None,
        password=unquote(parts.password) if parts.password is not None else None,
    )
