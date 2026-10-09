"""Response security headers for the localhost web app (:mod:`.api`).

The page at ``http://127.0.0.1:<port>/`` is a *token-bearing* document: the
launcher hands it the per-process page principal in the URL fragment, the
bootstrap moves it into ``sessionStorage``, and every later WebSocket session
authenticates with it. That makes the page worth protecting like a logged-in
origin even though it never leaves the loopback interface:

* ``frame-ancestors``/``X-Frame-Options`` — nothing may frame an already
  authenticated page (a local document, an Electron app, a stray localhost
  server on another port).
* ``Referrer-Policy: no-referrer`` — the principal lives in the fragment, and
  a fragment rides along in ``Referer`` for same-document navigations.
* ``script-src``/``style-src`` hashes — the served document is pinned to the
  bytes this server actually shipped, without ``'unsafe-inline'``.

The hashes are computed from the **served** bytes rather than baked in at build
time: the bundle is produced in the extension repo and copied into ``web/``, so
a bundle refresh must not silently ship a page its own policy blocks.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterable

# Matching runs against the ORIGINAL document, never a case-folded copy:
# ``str.casefold`` can change a string's length (ß → ss), which would slide
# every offset in a bundle that contains such a character and hash the wrong
# bytes. The lookahead keeps ``<scriptable>`` from parsing as a script.
_TAG_START = "(?=[\\s/>])"


def _inline_bodies(html: str, tag: str) -> list[str]:
    """Return the bodies of inline ``<tag>`` elements the browser will run.

    Scanning is strictly sequential, the way an HTML parser reads raw-text
    elements: everything between a start tag and its first closing tag is
    opaque. The shipped bundle contains the literal string ``"<script>"``
    *inside* its module body, and a naive per-tag regex would treat it as a
    second element and hash the wrong slice.

    Elements carrying ``src``/``href`` fetch a subresource instead of holding
    an inline body; those are covered by ``'self'`` and need no hash.
    """
    opening = re.compile(f"<{tag}{_TAG_START}", re.IGNORECASE)
    closing = re.compile(f"</{tag}[^>]*>", re.IGNORECASE)
    bodies: list[str] = []
    position = 0
    while (start := opening.search(html, position)) is not None:
        tag_end = html.find(">", start.end())
        if tag_end == -1:
            break
        end = closing.search(html, tag_end + 1)
        if end is None:
            break
        attributes = html[start.end() : tag_end].lower()
        body = html[tag_end + 1 : end.start()]
        position = end.end()
        if "src=" in attributes or "href=" in attributes or not body.strip():
            continue
        bodies.append(body)
    return bodies


def _inline_sources(html: str) -> tuple[list[str], list[str]]:
    """Return ``(inline script bodies, inline style bodies)``."""
    return _inline_bodies(html, "script"), _inline_bodies(html, "style")


def _hash_source(source: str) -> str:
    """CSP ``'sha256-…'`` expression for one inline source block."""
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def websocket_origins(http_origins: Iterable[str]) -> list[str]:
    """Map the server's HTTP page origins onto their WebSocket equivalents.

    The page connects to ``ws://${location.host}/ext``, so whichever loopback
    spelling the operator opened (``127.0.0.1``, ``localhost``, ``[::1]``, a
    non-canonical bind address) must be allowed. The server is plain HTTP —
    there is no ``wss:`` endpoint to allow.
    """
    return sorted({f"ws://{origin.split('://', 1)[-1]}" for origin in http_origins})


def content_security_policy(html: str, *, connect_origins: Iterable[str]) -> str:
    """Build a policy that admits exactly what *html* needs and nothing else.

    ``img-src`` additionally allows ``data:`` — self-contained image bytes are
    not an exfiltration channel, and it is the one allowance a future bundle is
    likely to need (icons, a pairing QR) without any review of this file.
    """
    scripts, styles = _inline_sources(html)
    directives = [
        "default-src 'self'",
        " ".join(["script-src", "'self'", *(_hash_source(s) for s in scripts)]),
        " ".join(["style-src", "'self'", *(_hash_source(s) for s in styles)]),
        "img-src 'self' data:",
        "font-src 'self'",
        " ".join(["connect-src", "'self'", *dict.fromkeys(connect_origins)]),
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ]
    return "; ".join(directives)


def plain_response_headers() -> dict[str, str]:
    """Baseline headers for the page route's non-HTML replies (403 / 503).

    They carry no token and no script, but they are still responses from the
    page origin: keep them unsniffable, uncached, referrer-free and unframeable
    so the route's behaviour does not depend on which branch answered.
    """
    return {
        # The fragment token is process-bound. Avoid retaining even the
        # token-free shell across restarts and keep security headers
        # deterministic for both "/" and "/app".
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        # frame-ancestors is the modern spelling; X-Frame-Options stays for
        # any embedder that predates CSP level 2.
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    }


def security_headers(html: str, *, connect_origins: Iterable[str]) -> dict[str, str]:
    """Full header set for a token-bearing page response."""
    return {
        **plain_response_headers(),
        "Content-Security-Policy": content_security_policy(html, connect_origins=connect_origins),
    }
