"""Cloud provider identity and endpoint matching for strict-mode enforcement.

Split out of ``enforce.py`` (LOC-reduction sweep): everything here answers
"which provider does this URL/id actually belong to", never "should this
call be allowed" — the allow/refuse decision and its audit trail stay in
``enforce.py``. Owns:

- ``policy_provider_id`` — canonicalizes a runtime provider id into the
  stable identity Mordred policy files key on, collapsing the handful of
  cross-registry aliases (``auth.py`` vs ``models.py`` vs the models.dev
  catalog) that :func:`.._provider_identity.canonicalize_provider` alone
  does not.
- ``safe_endpoint_for_audit`` — the bounded, credential-stripped URL
  renderer used by every audit entry and log message that mentions a
  runtime endpoint.
- The provider-owned endpoint host table (``_CLOUD_ENDPOINT_HOSTS``) plus
  the Bedrock/Vertex shape-specific matchers, ``cloud_endpoint_matches_provider``,
  ``cloud_provider_has_owned_default``, and ``infer_cloud_provider``.
- Ambient SDK ``base_url`` override detection (``ambient_base_url_override``)
  and the runtime-endpoint <-> provider binding decision
  (``_resolve_cloud_endpoint_binding``, ``_cloud_route_key``) that
  ``enforce.check_runtime_provider`` consumes.

Several private names here are re-imported and re-exported by ``enforce.py``
(listed in its ``__all__``) so existing callers that reach them as
``enforce.X`` — tests and :mod:`.auxiliary_guard` — keep working unchanged.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Final
from urllib.parse import urlsplit, urlunsplit

from .._provider_identity import canonicalize_provider

# Hermes 0.19 exposes a few different slugs for the same policy-level
# provider depending on whether a route came from auth.py, models.py, or the
# models.dev catalog. Keep the faithful models.py alias replica untouched and
# collapse only those cross-registry identities at this enforcement boundary.
_POLICY_PROVIDER_EQUIVALENTS: Final[Mapping[str, str]] = {
    "deep-infra": "deepinfra",
    "deepinfra-ai": "deepinfra",
    "kimi-for-coding": "kimi-coding",
    "minimax-oauth": "minimax",
    "openai-api": "openai",
    "solar": "upstage",
    "xai-oauth": "xai",
}

_MAX_ENDPOINT_DISPLAY_LENGTH: Final = 256

# Provider identity is not an endpoint grant. Hermes permits ``base_url``
# overrides for first-class providers, so checking only ``provider`` lets a
# process label an arbitrary collector as e.g. ``openai`` and inherit the
# allow-list entry. These are the provider-owned endpoint hosts exposed by
# Hermes 0.19's built-in profiles. A leading dot means "this DNS suffix";
# exact entries never accept a sibling/lookalike hostname.
#
# Every key must already be a ``policy_provider_id`` output. An alias key (e.g.
# ``xai-oauth``) is unreachable for lookups — callers canonicalize first — and
# would additionally let ``infer_cloud_provider`` return a non-canonical
# identity that no allow-list entry can match.
_CLOUD_ENDPOINT_HOSTS: Final[Mapping[str, tuple[str, ...]]] = {
    # Present in the hermes-agent floor registry but not in the current one, so
    # the table has to span the supported version range: a provider missing here
    # is refused outright under strict mode.
    "ai-gateway": ("ai-gateway.vercel.sh",),
    "alibaba": ("dashscope-intl.aliyuncs.com",),
    "alibaba-coding-plan": ("coding-intl.dashscope.aliyuncs.com",),
    "anthropic": ("api.anthropic.com",),
    "arcee": ("api.arcee.ai",),
    # Azure resource subdomains select an operator/tenant, so a vendor suffix
    # is not sufficient destination ownership. Strict refuses Azure Foundry
    # until policy.json has a separately persisted exact-endpoint pin.
    "azure-foundry": (),
    # Bedrock and Vertex have shape-specific matchers below. Deliberately do
    # not use broad ``.amazonaws.com`` / ``.googleapis.com`` suffixes: those
    # would grant unrelated services such as S3 or Cloud Storage.
    "bedrock": (),
    "copilot": ("api.githubcopilot.com",),
    "deepinfra": ("api.deepinfra.com",),
    "deepseek": ("api.deepseek.com",),
    "fireworks": ("api.fireworks.ai",),
    "gemini": ("generativelanguage.googleapis.com",),
    "gmi": ("api.gmi-serving.com",),
    "huggingface": ("router.huggingface.co",),
    "kilocode": ("api.kilo.ai",),
    "kimi-coding": ("api.kimi.com", "api.moonshot.ai"),
    "kimi-coding-cn": ("api.moonshot.cn",),
    "minimax": ("api.minimax.io",),
    "minimax-cn": ("api.minimaxi.com",),
    "nous": ("inference-api.nousresearch.com",),
    "novita": ("api.novita.ai",),
    "nvidia": ("integrate.api.nvidia.com",),
    "ollama-cloud": ("ollama.com",),
    "openai": ("api.openai.com",),
    "openai-codex": ("chatgpt.com",),
    "opencode-go": ("opencode.ai",),
    "opencode-zen": ("opencode.ai",),
    "openrouter": ("openrouter.ai",),
    "qwen-oauth": ("portal.qwen.ai",),
    "stepfun": ("api.stepfun.ai", "api.stepfun.com"),
    "tencent-tokenhub": ("tokenhub.tencentmaas.com",),
    "upstage": ("api.upstage.ai",),
    # Venice.ai is not a Hermes provider; the entry binds Mordred's own
    # Telegram question client (extension/telegram/venice.py), which runs
    # check_runtime_provider(active_provider="venice") before every request.
    "venice": ("api.venice.ai",),
    "vertex": (),
    "xai": ("api.x.ai",),
    "xiaomi": ("api.xiaomimimo.com",),
    # Hermes probes both the global Z.AI host and its China service
    # (``hermes_cli.auth.ZAI_ENDPOINTS``); vision resolution uses the same
    # pair directly.
    "zai": ("api.z.ai", "open.bigmodel.cn"),
}

_BEDROCK_ENDPOINT_RE: Final = re.compile(
    r"^bedrock-runtime(?:-fips)?\.[a-z0-9-]+\."
    r"(?:amazonaws\.com(?:\.cn)?|api\.aws)$"
)
_VERTEX_ENDPOINT_RE: Final = re.compile(r"^(?:[a-z0-9-]+-)?aiplatform\.googleapis\.com$")


def policy_provider_id(provider_id: str) -> str:
    """Return the stable provider identity used by Mordred policy files."""
    canonical = canonicalize_provider(provider_id)
    return _POLICY_PROVIDER_EQUIVALENTS.get(canonical, canonical)


def safe_endpoint_for_audit(endpoint: object) -> str:
    """Return a bounded URL display with all credential-bearing parts removed."""
    if not isinstance(endpoint, str) or not endpoint:
        return "<missing>"
    if endpoint != endpoint.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in endpoint):
        return "<invalid>"
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError):
        return "<invalid>"
    scheme = parsed.scheme.casefold()
    hostname = parsed.hostname
    if scheme not in {"http", "https"} or not hostname:
        return "<invalid>"
    host = hostname.rstrip(".").casefold()
    if not host:
        return "<invalid>"
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port is None else f"{rendered_host}:{port}"
    # Paths can also contain bearer/project secrets on custom or rejected
    # endpoints. Audit needs only the destination origin; internal route keys
    # retain normalized paths where provider disambiguation requires them.
    sanitized = urlunsplit((scheme, authority, "", "", ""))
    if len(sanitized) > _MAX_ENDPOINT_DISPLAY_LENGTH:
        return sanitized[: _MAX_ENDPOINT_DISPLAY_LENGTH - 3] + "..."
    return sanitized


def _normalized_cloud_endpoint(runtime_base_url: str | None) -> tuple[str, str] | None:
    """Return ``(host, normalized route id)`` for a safe cloud URL."""
    if not isinstance(runtime_base_url, str) or not runtime_base_url.strip():
        return None
    if runtime_base_url != runtime_base_url.strip() or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in runtime_base_url
    ):
        return None
    raw = runtime_base_url.strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.casefold() != "https" or parsed.username is not None or parsed.password is not None:
        return None
    if parsed.query or parsed.fragment:
        return None
    host = (parsed.hostname or "").rstrip(".").casefold()
    if not host:
        return None
    default_port = port in (None, 443)
    authority = host if default_port else f"{host}:{port}"
    path = parsed.path.rstrip("/") or "/"
    return host, f"https://{authority}{path}"


def _host_matches_constraint(host: str, constraint: str) -> bool:
    if constraint.startswith("."):
        suffix = constraint[1:]
        return host == suffix or host.endswith(constraint)
    return host == constraint


def _path_at_or_below(path: str, base: str) -> bool:
    return path == base or path.startswith(f"{base}/")


def cloud_endpoint_matches_provider(provider_id: str, runtime_base_url: str | None) -> bool:
    """Whether a runtime URL belongs to the named built-in cloud provider."""
    parsed = _normalized_cloud_endpoint(runtime_base_url)
    provider = policy_provider_id(provider_id)
    if parsed is None:
        return False
    host = parsed[0]
    path = urlsplit(parsed[1]).path
    if provider == "bedrock":
        return _BEDROCK_ENDPOINT_RE.fullmatch(host) is not None
    if provider == "vertex":
        return _VERTEX_ENDPOINT_RE.fullmatch(host) is not None
    if provider == "opencode-go":
        return host == "opencode.ai" and _path_at_or_below(path, "/zen/go/v1")
    if provider == "opencode-zen":
        return host == "opencode.ai" and _path_at_or_below(path, "/zen/v1")
    constraints = _CLOUD_ENDPOINT_HOSTS.get(provider)
    return bool(constraints and any(_host_matches_constraint(parsed[0], constraint) for constraint in constraints))


# Provider SDKs silently redirect to these when the caller passes no
# ``base_url``. Hermes then reports ``base_url=""`` while the request actually
# leaves for the override, so an absent runtime endpoint may only be trusted
# once none of these is set. Enumerated from the installed
# ``openai`` / ``anthropic`` / ``google`` clients rather than guessed.
_SDK_BASE_URL_ENV_VARS: Final[tuple[str, ...]] = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "AZURE_OPENAI_ENDPOINT",
    "GEMINI_NEXT_GEN_API_BASE_URL",
    "OPENAI_BASE_URL",
)


def ambient_base_url_override() -> str | None:
    """Return the first provider-SDK endpoint override present in the env.

    ``None`` means no ambient redirect exists, so a client constructed without
    an explicit ``base_url`` really does reach the vendor default.
    """
    for name in _SDK_BASE_URL_ENV_VARS:
        raw = os.environ.get(name)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def cloud_provider_has_owned_default(provider_id: str) -> bool:
    """Whether omitting ``base_url`` still lands on a provider-owned endpoint.

    Hermes leaves ``base_url`` unset whenever the provider SDK supplies its own
    endpoint (``agent.base_url = base_url or ""`` in ``agent/agent_init.py``);
    native Anthropic is the common case. That is NOT an unbound destination — it
    is the vendor default — so it must not be treated like an operator override
    pointing at an arbitrary collector.

    Providers whose destination selects a tenant, region, or project (Azure
    Foundry, Bedrock, Vertex) have no single owned default. They keep failing
    closed until an explicit endpoint is configured, which is exactly what their
    empty :data:`_CLOUD_ENDPOINT_HOSTS` entries encode.
    """
    provider = policy_provider_id(provider_id)
    return bool(_CLOUD_ENDPOINT_HOSTS.get(provider))


def infer_cloud_provider(runtime_base_url: str | None) -> str | None:
    """Infer a unique built-in provider from an actual endpoint."""
    parsed = _normalized_cloud_endpoint(runtime_base_url)
    if parsed is None:
        return None
    matches = [
        provider for provider in _CLOUD_ENDPOINT_HOSTS if cloud_endpoint_matches_provider(provider, runtime_base_url)
    ]
    if not matches:
        return None
    # Several Hermes aliases intentionally share one service endpoint. Prefer
    # a policy identity already canonical in the public allow-list.
    priority = ("openai", "anthropic", "gemini", "bedrock", "vertex", "openrouter")
    return next((provider for provider in priority if provider in matches), sorted(matches)[0])


def _resolve_cloud_endpoint_binding(
    provider_id: str,
    runtime_base_url: str | None,
) -> tuple[bool, str | None, bool]:
    """Decide whether the request's real destination belongs to ``provider_id``.

    Returns ``(bound, effective_base_url, overridden)``.

    Endpoint identity is a prerequisite, not an approval decision: an allow-list
    entry or a provider-only prompt must never bless
    ``provider=openai, base_url=https://collector...``.

    An absent/blank ``base_url`` is NOT an unbound destination. Hermes stores
    ``base_url or ""`` and omits it whenever the provider SDK supplies its own
    endpoint, so the request goes to the vendor default. Such a client is still
    redirectable through the SDK's own environment overrides while Hermes keeps
    reporting ``base_url=""``, so bind against the ambient value when one exists
    and otherwise require the provider to own a single default endpoint.
    """
    overridden = isinstance(runtime_base_url, str) and bool(runtime_base_url.strip())
    if not overridden:
        ambient = ambient_base_url_override()
        if ambient is not None:
            return cloud_endpoint_matches_provider(provider_id, ambient), ambient, True
        return cloud_provider_has_owned_default(provider_id), runtime_base_url, False
    return cloud_endpoint_matches_provider(provider_id, runtime_base_url), runtime_base_url, True


def _cloud_route_key(provider_id: str, runtime_base_url: str | None) -> str:
    parsed = _normalized_cloud_endpoint(runtime_base_url)
    endpoint = parsed[1] if parsed is not None else "<missing-or-invalid-endpoint>"
    return f"{provider_id}@{endpoint}"
