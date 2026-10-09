"""Minimal loopback HTTP server used as a relay target by integration tests.

The SOCKS5h and provider-verification tests need a
real HTTP endpoint so the client-side request completes with a genuine
``200`` response — proving the full
``client → socks5h → inspector → resolved host → server`` chain.

The server counts the requests it receives so a caller can tell apart
two outcomes when a SOCKS proxy is configured:

- ``inspector.captures`` non-empty, ``target.hits == 0`` → routed
  through the proxy (the request never reached the origin directly).
- ``inspector.captures`` empty, ``target.hits >= 1`` → the client
  bypassed the proxy and connected to the origin directly (a leak when
  the proxy was supposed to be the only egress).

Dependency-free: stdlib :mod:`http.server` on a daemon thread, bound to
the ``127.0.0.1`` loopback address (never all-interfaces), torn down on
``with``-block exit. The :mod:`_socks5_inspector` relay normalises every
loopback destination to ``127.0.0.1``, so an IPv4-only origin is reached
regardless of how the client encoded the (always-loopback) host.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

_OK_BODY: Final = b"mordred-ok"


@dataclass(frozen=True, slots=True)
class HttpTarget:
    """Address of a running loopback HTTP server.

    ``ok_body`` is the exact bytes the server returns for any request so
    callers can assert on a full round trip. ``hits`` reports how many
    requests the origin has served — ``0`` means every request went
    through a proxy instead.
    """

    host: str
    port: int
    _server: _CountingServer
    ok_body: bytes = _OK_BODY

    @property
    def url(self) -> str:
        """A ``GET``-able URL whose host component is a *hostname*.

        Uses the literal ``host`` (default ``"localhost"``) so ``socks5h``
        clients must hand the name to the proxy for server-side
        resolution — an IP literal would defeat the whole test.
        """
        return f"http://{self.host}:{self.port}/"

    @property
    def hits(self) -> int:
        """Number of HTTP requests this origin has served directly."""
        return self._server.hit_count


class _Handler(BaseHTTPRequestHandler):
    server: _CountingServer  # narrow the BaseHTTPRequestHandler attribute

    def _respond(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)  # drain the body so the socket can close cleanly
        self.server.record_hit()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_OK_BODY)))
        self.end_headers()
        self.wfile.write(_OK_BODY)

    do_GET = _respond
    do_POST = _respond
    do_HEAD = _respond
    do_PUT = _respond

    def log_message(self, *_args: object) -> None:
        """Silence the per-request stderr logging."""


class _CountingServer(ThreadingHTTPServer):
    """Loopback-bound HTTP server that counts the requests it serves.

    Bound to ``127.0.0.1`` (IPv4 loopback) only — never all-interfaces —
    so the origin is unreachable to anything but the local test runner.
    """

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        self._hit_lock = threading.Lock()
        self.hit_count = 0
        super().__init__(server_address, handler)

    def record_hit(self) -> None:
        with self._hit_lock:
            self.hit_count += 1


@contextmanager
def http_target(host: str = "localhost") -> Iterator[HttpTarget]:
    """Run an HTTP server on ``127.0.0.1`` for the duration of the block.

    ``host`` is the *name* callers should use when building the request
    URL (default ``"localhost"``); the socket binds the ``127.0.0.1``
    loopback address.
    """
    server = _CountingServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield HttpTarget(host=host, port=server.server_address[1], _server=server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)
