"""Provider-vs-transport compatibility flagger.

For each Hermes provider, decide whether the configured ``HTTPS_PROXY`` /
SOCKS5h transport actually reaches the upstream API — or whether the SDK
will bypass the proxy (DNS leak, plain TCP, etc.) and surface as silent
deanonymization.

The integration verification in
``tests/integration/test_provider_transport.py`` drives supported SDKs against
an in-process SOCKS5 inspector. It has cleared the flag on the
``anthropic`` / ``openai`` / ``gemini`` /
``mordred-local`` entries. ``bedrock`` keeps the flag — only
``respects_socks5h=False`` is empirically confirmed; the ``dns_quirk`` /
IPv6 facts still need a real AWS packet capture. ``vertex`` is untested
(heavy SDK + GCP-side proxy behaviour) and stays flagged.

Severity policy:

============ =================================== ======== ==============================================
mode          provider state                      flag     notes
============ =================================== ======== ==============================================
off           any                                 —        no flags emitted
strict        tor + respects_socks5h=False        abort    prevent the strict-mode session from starting
strict        tor + respects_ipv6_proxy=False     abort    no host-level IPv6 enforcement exists in v1
strict        tor + unknown/unverified provider   abort    absence of transport evidence is not safe
strict        clearnet + incompatible/unknown     warning  informational; no anonymity contract
lenient       any abortable flag                  warning  downgraded; user is informed but continues
============ =================================== ======== ==============================================

Localhost-only providers (``mordred-local``) are exempt — Phase 2
``proxy_env.NO_PROXY`` keeps ``localhost`` out of the proxy regardless of
path.

User overrides via ``policy.json provider_overrides`` may **add** new
providers (e.g. an internal LLM proxy) but cannot replace baseline
entries: a malicious override that flips ``anthropic.respects_socks5h``
to ``False`` would be a silent strict-mode bypass.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

from .._policy_types import ActivePath, PolicyMode
from .._provider_identity import canonicalize_provider

Severity = Literal["abort", "warning"]
TransportClass = Literal["http", "tcp", "udp", "quic", "grpc", "websocket"]


@dataclass(frozen=True, slots=True)
class ProviderEntry:
    """Empirical (or baseline) facts about one Hermes provider adapter.

    Phase 3 PR3a Task #3 added ``transport_class`` and
    ``respects_ipv6_proxy`` so the flagger can warn on non-HTTP transports
    (which never honour ``HTTPS_PROXY``) and on IPv6 leaks (SDKs that route
    around the SOCKS5h proxy when the resolved endpoint is IPv6).
    """

    name: str
    transport: str
    respects_proxy: bool | Literal["partial"]
    respects_socks5h: bool
    localhost_only: bool = False
    dns_quirk: bool = False
    unverified_baseline: bool = True
    # Phase 3 PR3a Task #3 — defaults preserve existing baseline semantics.
    transport_class: TransportClass = "http"
    respects_ipv6_proxy: bool = False


@dataclass(frozen=True, slots=True)
class Flag:
    """A single compatibility concern between active path and a provider."""

    provider: str
    severity: Severity
    reason: str


KNOWN_PROVIDERS: Final[Mapping[str, ProviderEntry]] = {
    "anthropic": ProviderEntry(
        name="anthropic",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=True,
        # Verified: the SDK's env-trusting httpx
        # client routes a socks5h:// HTTPS_PROXY (ATYP=DOMAINNAME).
        unverified_baseline=False,
    ),
    "openai": ProviderEntry(
        name="openai",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=True,
        # Verified: same env-trusting httpx path.
        unverified_baseline=False,
    ),
    "gemini": ProviderEntry(
        name="gemini",
        # The current `google-genai` SDK is
        # httpx-based. The PR1 baseline said "requests" — that was the
        # legacy `google-generativeai` SDK; corrected here.
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=True,
        # Verified — google-genai routes a socks5h:// proxy correctly.
        unverified_baseline=False,
    ),
    "mordred-local": ProviderEntry(
        name="mordred-local",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        localhost_only=True,
        transport_class="http",
        # localhost-only never reaches the proxy regardless of IPv6;
        # marking True so an override that drops `localhost_only` still
        # behaves correctly under the IPv6 check.
        respects_ipv6_proxy=True,
        # Verified: the proxy_env NO_PROXY default
        # (localhost,127.0.0.1,::1) keeps a localhost endpoint off Tor.
        unverified_baseline=False,
    ),
    "bedrock": ProviderEntry(
        name="bedrock",
        transport="boto3",
        respects_proxy=True,
        # respects_socks5h=False is verified: botocore's
        # urllib3 transport has no SOCKS support (test_provider_transport.py
        # TestBedrock). dns_quirk and respects_ipv6_proxy remain unverified
        # (a real AWS packet capture is needed), so unverified_baseline
        # stays True for the entry as a whole.
        respects_socks5h=False,
        dns_quirk=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "vertex": ProviderEntry(
        name="vertex",
        transport="google-cloud",
        respects_proxy="partial",
        respects_socks5h=False,
        transport_class="http",
        # Deferred live evidence: google-cloud-aiplatform is a heavy
        # SDK and the "partial" proxy behaviour is GCP-side; not exercised
        # by test_provider_transport.py. unverified_baseline stays True.
        respects_ipv6_proxy=False,
    ),
    # --- Hermes 0.14 cloud providers synced from CANONICAL_PROVIDERS (PR-B) ---
    # All eight are OpenAI-compatible HTTP APIs reached through the env-trusting
    # httpx / openai client, the same transport path empirically verified for
    # the ``openai`` / ``anthropic`` entries above — so ``respects_proxy`` and
    # ``respects_socks5h`` are seeded ``True`` with HIGH confidence. They are
    # NOT yet packet-capture verified, so ``unverified_baseline`` stays ``True``
    # and the lower-confidence IPv6-routing dimension is seeded conservatively
    # (``respects_ipv6_proxy=False``). ``disable_ipv6`` only configures Tor's
    # own client connections, so strict mode still refuses these providers;
    # lenient surfaces honest unverified/IPv6 warnings until a real capture
    # flips the entry (mirrors the bedrock/vertex stance). The
    # slugs match Hermes' canonical ids (asserted by the drift test).
    "openrouter": ProviderEntry(
        name="openrouter",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "nous": ProviderEntry(
        name="nous",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "deepseek": ProviderEntry(
        name="deepseek",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "xai": ProviderEntry(
        name="xai",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "zai": ProviderEntry(
        name="zai",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "novita": ProviderEntry(
        name="novita",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "minimax": ProviderEntry(
        name="minimax",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
    "alibaba": ProviderEntry(
        name="alibaba",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=False,
    ),
}


def evaluate(
    *,
    active_path: ActivePath,
    providers: Iterable[str],
    policy_mode: PolicyMode,
    overrides: Mapping[str, ProviderEntry] | None = None,
    disable_ipv6: bool = False,
) -> list[Flag]:
    """Inspect each provider and return any compatibility flags.

    See module docstring for the severity matrix. ``disable_ipv6`` is retained
    for API/config compatibility, but it only renders Tor's
    ``ClientUseIPv6 0`` option. That option does not disable host IPv6, filter
    AAAA answers, or constrain provider SDK sockets, so it never suppresses an
    IPv6 compatibility flag.
    """
    if policy_mode == "off":
        return []

    catalog = _resolve_catalog(overrides)
    flags: list[Flag] = []
    for provider in providers:
        # Resolve Hermes aliases (``claude`` → ``anthropic`` …) to the
        # canonical registry key before lookup; the original id is preserved
        # in the unknown-provider Flag below for an accurate message.
        entry = catalog.get(canonicalize_provider(provider))
        if entry is None:
            severity: Severity = "abort" if active_path == "tor" else "warning"
            flags.append(
                Flag(
                    provider=provider,
                    severity=_downgrade(severity, policy_mode),
                    reason="unknown provider; not in baseline allowlist",
                )
            )
            continue
        if entry.localhost_only:
            continue
        flags.extend(
            _flag_for_all(
                entry,
                active_path,
                policy_mode,
                disable_ipv6=disable_ipv6,
            )
        )
    return flags


def _flag_for_all(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
    *,
    disable_ipv6: bool,
) -> list[Flag]:
    """Run every flag branch and return the accumulated flags.

    Multiple independent concerns can co-exist (e.g. ``bedrock`` is both
    ``respects_socks5h=False`` and ``respects_ipv6_proxy=False``), so the
    flagger emits one ``Flag`` per concern instead of collapsing to the
    "worst" one. The CLI / hooks layer is responsible for aggregating
    them in the final user-facing message.
    """
    flags: list[Flag] = []
    socks_flag = _flag_for_socks5h(entry, active_path, policy_mode)
    if socks_flag is not None:
        flags.append(socks_flag)
    proxy_flag = _flag_for_clearnet_proxy(entry, active_path)
    if proxy_flag is not None:
        flags.append(proxy_flag)
    verification_flag = _flag_for_unverified(entry, active_path, policy_mode)
    if verification_flag is not None:
        flags.append(verification_flag)
    ipv6_flag = _flag_for_ipv6(entry, active_path, policy_mode, disable_ipv6=disable_ipv6)
    if ipv6_flag is not None:
        flags.append(ipv6_flag)
    non_http_flag = _flag_for_non_http(entry, active_path, policy_mode)
    if non_http_flag is not None:
        flags.append(non_http_flag)
    return flags


def _flag_for_socks5h(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
) -> Flag | None:
    if active_path == "tor" and not entry.respects_socks5h:
        return Flag(
            provider=entry.name,
            severity=_downgrade("abort", policy_mode),
            reason=f"{entry.name} transport {entry.transport!r} does not honor socks5h",
        )
    return None


def _flag_for_clearnet_proxy(entry: ProviderEntry, active_path: ActivePath) -> Flag | None:
    if active_path == "clearnet" and entry.respects_proxy is False:
        return Flag(
            provider=entry.name,
            severity="warning",
            reason=f"{entry.name} ignores HTTPS_PROXY entirely",
        )
    return None


def _flag_for_unverified(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
) -> Flag | None:
    """Refuse unverified transport baselines on Tor under strict policy.

    A seeded SDK assumption is useful in lenient mode, but it is not evidence
    that DNS and every socket family traverse SOCKS5h. Until packet-capture
    verification clears ``unverified_baseline``, strict Tor must fail closed.
    """
    if active_path != "tor" or not entry.unverified_baseline:
        return None
    return Flag(
        provider=entry.name,
        severity=_downgrade("abort", policy_mode),
        reason=f"{entry.name} transport baseline is not packet-capture verified",
    )


def _flag_for_ipv6(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
    *,
    disable_ipv6: bool,
) -> Flag | None:
    """Flag SDKs whose IPv6 path bypasses HTTPS_PROXY.

    Only fires on Tor (clearnet has no anonymity contract). ``disable_ipv6``
    currently maps to Tor's ``ClientUseIPv6 0`` setting, which controls Tor's
    own directory/entry connections; it does not disable host IPv6 or prevent
    a provider SDK from opening a direct IPv6 socket. Therefore the setting
    changes the explanatory text but cannot suppress this flag.
    """
    if active_path != "tor":
        return None
    if entry.respects_ipv6_proxy:
        return None
    configured_note = (
        "; disable_ipv6=True only sets Tor ClientUseIPv6 0 and does not enforce host/SDK IPv6 routing"
        if disable_ipv6
        else ""
    )
    return Flag(
        provider=entry.name,
        severity=_downgrade("abort", policy_mode),
        reason=f"{entry.name} may resolve IPv6 endpoints and bypass socks5h{configured_note}",
    )


def _flag_for_non_http(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
) -> Flag | None:
    """Flag non-HTTP transports (gRPC, raw TCP/UDP, QUIC, WebSocket).

    ``HTTPS_PROXY`` is an HTTP-layer contract; non-HTTP transports do not
    honour it. On Tor that's an abort (the tunnel is bypassed entirely);
    on clearnet it's an informational warning so the user knows the
    provider talks raw, not via HTTP. ``off`` mode skips at the call-site
    of ``evaluate`` and never reaches here.
    """
    if entry.transport_class == "http":
        return None
    severity: Severity = "abort" if active_path == "tor" else "warning"
    return Flag(
        provider=entry.name,
        severity=_downgrade(severity, policy_mode),
        reason=(f"{entry.name} uses non-HTTP transport_class={entry.transport_class!r}; HTTPS_PROXY is not honoured"),
    )


def _downgrade(severity: Severity, policy_mode: PolicyMode) -> Severity:
    if policy_mode == "lenient" and severity == "abort":
        return "warning"
    return severity


def _resolve_catalog(
    overrides: Mapping[str, ProviderEntry] | None,
) -> dict[str, ProviderEntry]:
    """Merge baseline + overrides, refusing to replace baseline entries.

    Overrides may add new entries (internal LLMs) but the baseline is
    immutable — a malicious replacement could flip a Tor-incompatible
    provider to "safe" and silently bypass strict mode.
    """
    catalog = dict(KNOWN_PROVIDERS)
    if not overrides:
        return catalog
    for name, entry in overrides.items():
        if name in KNOWN_PROVIDERS:
            raise ValueError(
                f"override {name!r} conflicts with immutable baseline entry; "
                "policy.json provider_overrides may only add new providers"
            )
        catalog[name] = entry
    return catalog
