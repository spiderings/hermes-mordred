"""In-process SOCKS5 inspector proxy for hermetic ``socks5h://`` verification.

A real (relaying) SOCKS5 server that records the address type (``ATYP``)
of every CONNECT request it receives. This is the empirical core of the
SOCKS5h compatibility tests:

- ``socks5h://`` clients MUST send the destination **hostname**
  (``ATYP=0x03`` DOMAINNAME) so the proxy resolves DNS server-side. No
  DNS query ever reaches the host resolver → no leak.
- A client that resolves locally and sends an IP literal
  (``ATYP=0x01`` IPV4) has already leaked the DNS query to the host
  resolver — exactly the failure mode ``socks5h`` exists to prevent.

Point each HTTP client library at the inspector with a ``socks5h://``
URL, drive one request, and assert the captured ATYP is DOMAINNAME.
The proxy actually relays bytes to the resolved destination so the
client-side request completes normally and the test can also assert on
the HTTP response.

Dependency-free: stdlib ``socket`` / ``threading`` only, loopback-bound,
fully ephemeral. RFC 1928 §3/§4/§5.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Final

# RFC 1928 §4 — address type byte.
ATYP_IPV4: Final = 0x01
ATYP_DOMAINNAME: Final = 0x03
ATYP_IPV6: Final = 0x04

# RFC 1928 §4 — reply field.
_REP_SUCCESS: Final = 0x00
_REP_GENERAL_FAILURE: Final = 0x01
_REP_CONNECTION_REFUSED: Final = 0x05
_REP_COMMAND_NOT_SUPPORTED: Final = 0x07

_CMD_CONNECT: Final = 0x01
_SOCKS_VERSION: Final = 0x05
_METHOD_NO_AUTH: Final = 0x00

_RELAY_CHUNK: Final = 65536


@dataclass(frozen=True, slots=True)
class CapturedConnect:
    """One observed SOCKS5 CONNECT request.

    ``atyp`` is the raw RFC 1928 address-type byte; ``dest_host`` is the
    decoded destination (a hostname when ``atyp == ATYP_DOMAINNAME``, an
    IP-literal string otherwise).
    """

    atyp: int
    dest_host: str
    dest_port: int

    @property
    def is_remote_dns(self) -> bool:
        """True when the client deferred DNS to the proxy (socks5h contract)."""
        return self.atyp == ATYP_DOMAINNAME


@dataclass
class Socks5Inspector:
    """Handle for a running inspector proxy.

    ``port`` is the loopback port the proxy listens on; ``captures``
    accumulates one :class:`CapturedConnect` per CONNECT, guarded by an
    internal lock so test threads read it safely.
    """

    port: int
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _captures: list[CapturedConnect] = field(default_factory=list, repr=False)

    @property
    def captures(self) -> list[CapturedConnect]:
        with self._lock:
            return list(self._captures)

    @property
    def last_capture(self) -> CapturedConnect:
        """The most recent CONNECT; raises ``AssertionError`` if none seen."""
        caps = self.captures
        assert caps, "inspector observed no SOCKS5 CONNECT request"
        return caps[-1]

    def _record(self, capture: CapturedConnect) -> None:
        with self._lock:
            self._captures.append(capture)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly ``count`` bytes or raise ``ConnectionError`` on short read."""
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(buf)}/{count} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _negotiate_no_auth(client: socket.socket) -> None:
    """RFC 1928 §3 greeting — accept the no-auth method (0x00)."""
    header = _recv_exact(client, 2)
    if header[0] != _SOCKS_VERSION:
        raise ConnectionError(f"not SOCKS5: version byte {header[0]:#04x}")
    nmethods = header[1]
    _recv_exact(client, nmethods)  # drain offered methods; we always pick no-auth
    client.sendall(bytes((_SOCKS_VERSION, _METHOD_NO_AUTH)))


def _read_request(client: socket.socket) -> tuple[int, str, int]:
    """RFC 1928 §4 request — return ``(atyp, dest_host, dest_port)``.

    Raises ``ConnectionError`` for a non-CONNECT command so the handler
    can answer with REP=0x07 and close.
    """
    head = _recv_exact(client, 4)
    version, cmd, _rsv, atyp = head
    if version != _SOCKS_VERSION:
        raise ConnectionError(f"bad request version {version:#04x}")
    if cmd != _CMD_CONNECT:
        raise ConnectionError(f"unsupported command {cmd:#04x}")
    if atyp == ATYP_IPV4:
        host = socket.inet_ntoa(_recv_exact(client, 4))
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
    elif atyp == ATYP_DOMAINNAME:
        length = _recv_exact(client, 1)[0]
        host = _recv_exact(client, length).decode("idna")
    else:
        raise ConnectionError(f"unknown ATYP {atyp:#04x}")
    port = int.from_bytes(_recv_exact(client, 2), "big")
    return atyp, host, port


def _reply(client: socket.socket, rep: int) -> None:
    """Send a SOCKS5 reply with a zeroed BND.ADDR/BND.PORT (RFC 1928 §6)."""
    client.sendall(bytes((_SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0)))


def _relay_host(host: str) -> str:
    """Normalise any loopback destination to IPv4 loopback for the relay.

    The inspector only ever serves loopback test origins (the
    :mod:`_http_target` server binds ``127.0.0.1``). Whatever loopback
    form the client encoded — the ``localhost`` hostname, ``::1``, or a
    ``127.x`` literal — the relay connects to ``127.0.0.1`` so it reaches
    the IPv4-only origin. This only affects where bytes are *relayed*;
    the recorded :class:`CapturedConnect` still carries the exact host
    and ATYP the client sent, which is what the tests assert on.
    """
    if host in {"localhost", "::1"} or host.startswith("127."):
        return "127.0.0.1"
    return host


def _pump(src: socket.socket, dst: socket.socket) -> None:
    """Copy ``src`` → ``dst`` until EOF, then half-close ``dst``."""
    try:
        while True:
            chunk = src.recv(_RELAY_CHUNK)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            dst.shutdown(socket.SHUT_WR)


def _handle(client: socket.socket, inspector: Socks5Inspector) -> None:
    """Serve one client connection: negotiate, record, relay."""
    upstream: socket.socket | None = None
    try:
        _negotiate_no_auth(client)
        try:
            atyp, host, port = _read_request(client)
        except ConnectionError:
            _reply(client, _REP_COMMAND_NOT_SUPPORTED)
            return
        inspector._record(CapturedConnect(atyp=atyp, dest_host=host, dest_port=port))
        try:
            # The capture above already recorded the true host/ATYP the
            # client sent (socks5h server-side resolution is the point).
            # Relaying normalises loopback forms to 127.0.0.1 so the
            # IPv4-only test origin is reached either way.
            upstream = socket.create_connection((_relay_host(host), port), timeout=10.0)
        except OSError:
            _reply(client, _REP_CONNECTION_REFUSED)
            return
        _reply(client, _REP_SUCCESS)
        up_thread = threading.Thread(target=_pump, args=(client, upstream), daemon=True)
        up_thread.start()
        _pump(upstream, client)
        up_thread.join(timeout=10.0)
    except (OSError, ConnectionError):
        with contextlib.suppress(OSError):
            _reply(client, _REP_GENERAL_FAILURE)
    finally:
        client.close()
        if upstream is not None:
            upstream.close()


@contextmanager
def socks5_inspector() -> Iterator[Socks5Inspector]:
    """Run an inspector proxy for the duration of the ``with`` block.

    Binds ``127.0.0.1`` on an ephemeral port; the accept loop runs on a
    daemon thread and is torn down on exit. Yields a :class:`Socks5Inspector`
    whose ``captures`` list grows as clients connect.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.5)
    inspector = Socks5Inspector(port=listener.getsockname()[1])
    stop = threading.Event()

    def _accept_loop() -> None:
        while not stop.is_set():
            try:
                client, _addr = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=_handle, args=(client, inspector), daemon=True).start()

    accept_thread = threading.Thread(target=_accept_loop, daemon=True)
    accept_thread.start()
    try:
        yield inspector
    finally:
        stop.set()
        listener.close()
        accept_thread.join(timeout=5.0)
