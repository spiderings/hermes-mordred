"""Security headers for the localhost page that carries the bearer token.

The page principal's token arrives in the URL fragment, so the response must
deny framing (clickjacking against a same-origin, already-authenticated page),
deny referrer leakage of the fragment, and pin the executable content of the
served document with hashes rather than ``'unsafe-inline'``.
"""

from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path

import pytest

from mordred_hermes.extension import page_headers

_DOC = (
    "<!doctype html><html><head>"
    "<script>const a = 1</script>"
    '<script type="module">document.body.innerHTML = "<script><\\/script>"</script>'
    "<style>body{color:red}</style>"
    "</head><body></body></html>"
)


def _sha256_source(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


def test_inline_sources_are_split_the_way_a_browser_parses_them() -> None:
    """A ``<script>`` literal inside a script body is not a second element."""
    scripts, styles = page_headers._inline_sources(_DOC)

    assert scripts == ["const a = 1", 'document.body.innerHTML = "<script><\\/script>"']
    assert styles == ["body{color:red}"]


def test_policy_pins_every_inline_source_by_hash() -> None:
    policy = page_headers.content_security_policy(_DOC, connect_origins=["ws://127.0.0.1:7799"])

    directives = {d.split(" ", 1)[0]: d for d in policy.split("; ")}
    assert "'unsafe-inline'" not in policy
    assert "'unsafe-eval'" not in policy
    for source in ("const a = 1", 'document.body.innerHTML = "<script><\\/script>"'):
        assert _sha256_source(source) in directives["script-src"]
    assert _sha256_source("body{color:red}") in directives["style-src"]


def test_policy_denies_framing_and_navigation_sinks() -> None:
    policy = page_headers.content_security_policy(_DOC, connect_origins=["ws://127.0.0.1:7799"])

    directives = {d.split(" ", 1)[0]: d for d in policy.split("; ")}
    assert directives["default-src"] == "default-src 'self'"
    assert directives["frame-ancestors"] == "frame-ancestors 'none'"
    assert directives["base-uri"] == "base-uri 'none'"
    assert directives["form-action"] == "form-action 'none'"
    assert directives["object-src"] == "object-src 'none'"
    assert "ws://127.0.0.1:7799" in directives["connect-src"]
    assert "'self'" in directives["connect-src"]


def test_security_headers_cover_the_token_bearing_page() -> None:
    headers = page_headers.security_headers(_DOC, connect_origins=["ws://127.0.0.1:7799"])

    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Security-Policy"].startswith("default-src 'self'")


@pytest.mark.skipif(
    not (Path(page_headers.__file__).parent / "web" / "index.html").exists(),
    reason="the localhost web app bundle is not built in this checkout",
)
def test_shipped_bundle_is_fully_covered_by_the_policy() -> None:
    """Every executable/styling block of the real bundle must be allowed.

    The bundle is built in the extension repo and copied in, so this is the
    guard that a bundle refresh cannot silently ship a page the policy blocks.
    """
    html = (Path(page_headers.__file__).parent / "web" / "index.html").read_text("utf-8")
    html = html.replace("%%MORDRED_PAGE_TOKEN%%", "")
    policy = page_headers.content_security_policy(html, connect_origins=["ws://127.0.0.1:7799"])

    scripts, styles = page_headers._inline_sources(html)
    assert scripts and styles
    for source in (*scripts, *styles):
        assert _sha256_source(source) in policy
    # No subresource may be pulled from a remote host by the shipped page.
    assert "<link" not in html
    assert 'src="http' not in html


class _RawTextCollector(HTMLParser):
    """Independent reference for :func:`page_headers._inline_sources`.

    ``html.parser`` implements the raw-text rules for ``script``/``style``
    itself, so agreement here means the hash inputs are the same slices a
    browser will hash — the one property the whole policy depends on.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._tag: str | None = None
        self._attrs: dict[str, str | None] = {}
        self._buffer: list[str] = []
        self.scripts: list[str] = []
        self.styles: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._tag, self._attrs, self._buffer = tag, dict(attrs), []

    def handle_data(self, data: str) -> None:
        if self._tag is not None:
            self._buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != self._tag:
            return
        body = "".join(self._buffer)
        if not (self._attrs.get("src") or self._attrs.get("href")) and body.strip():
            (self.scripts if tag == "script" else self.styles).append(body)
        self._tag = None


@pytest.mark.parametrize("document", [_DOC, None])
def test_extraction_agrees_with_an_html_parser(document: str | None) -> None:
    if document is None:
        bundle = Path(page_headers.__file__).parent / "web" / "index.html"
        if not bundle.exists():  # pragma: no cover - only when the app isn't built
            pytest.skip("the localhost web app bundle is not built in this checkout")
        document = bundle.read_text("utf-8").replace("%%MORDRED_PAGE_TOKEN%%", "")

    reference = _RawTextCollector()
    reference.feed(document)

    assert page_headers._inline_sources(document) == (reference.scripts, reference.styles)
