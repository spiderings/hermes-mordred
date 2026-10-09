"""The only two places imported Telegram text may be sent: Venice or a local model.

There is deliberately no "custom endpoint" here:

- **venice** — the base URL is the fixed constant
  :data:`.venice.DEFAULT_BASE_URL` (``https://api.venice.ai/api/v1``). It is
  not read from configuration, so no setting can point it elsewhere. Only
  models Venice labels ``private`` are used (see :mod:`.venice`).
- **local** — an OpenAI-compatible server on THIS machine. The endpoint must
  use a literal loopback address (``127.0.0.1`` or ``[::1]``; ``localhost`` is
  rewritten to ``127.0.0.1`` so a hosts-file entry cannot redirect it). It is
  reached directly, never through a proxy.

Both are called with redirects disabled, so a server cannot bounce the request
(and the messages in it) to another host.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from . import venice

Backend = Literal["venice", "local"]
BACKENDS: tuple[Backend, ...] = ("venice", "local")
DEFAULT_LOCAL_CONTEXT_TOKENS = 32_768


class LlmConfigError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class LlmTarget:
    backend: Backend
    base_url: str
    model: str
    api_key: str | None

    @property
    def config(self) -> venice.VeniceConfig:
        return venice.VeniceConfig(api_key=self.api_key or "", model=self.model, base_url=self.base_url)


def normalize_local_endpoint(url: str) -> str:
    """Return a canonical loopback base URL, or raise ``local_endpoint_invalid``.

    Accepts ``http``/``https`` with a literal loopback IP (or ``localhost``,
    rewritten to ``127.0.0.1``) and an explicit port. Userinfo, query strings
    and fragments are refused.
    """
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise LlmConfigError("local_endpoint_invalid") from exc
    host = (parts.hostname or "").casefold()
    if parts.scheme not in {"http", "https"} or port is None:
        raise LlmConfigError("local_endpoint_invalid")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise LlmConfigError("local_endpoint_invalid")
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise LlmConfigError("local_endpoint_invalid") from exc
    if not address.is_loopback:
        raise LlmConfigError("local_endpoint_invalid")
    netloc = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))


def resolve_target(
    backend: str | None,
    *,
    venice_api_key: str | None,
    venice_model: str,
    local_endpoint: str | None,
    local_model: str | None,
) -> LlmTarget:
    """Pick the configured destination; anything else is refused."""
    chosen = backend or ("venice" if venice_api_key else None)
    if chosen == "venice":
        if not venice_api_key:
            raise LlmConfigError("venice_not_configured")
        return LlmTarget("venice", venice.DEFAULT_BASE_URL, venice_model, venice_api_key)
    if chosen == "local":
        if not local_endpoint or not local_model:
            raise LlmConfigError("local_llm_not_configured")
        return LlmTarget("local", normalize_local_endpoint(local_endpoint), local_model, None)
    raise LlmConfigError("llm_not_configured")
