"""Tests for ``mordred_hermes.network.provider_transport_flagger``.

``KNOWN_PROVIDERS`` records verified and conservative provider-transport
facts. Integration checks clear `unverified_baseline` only where current
evidence supports it.

Tests cover:

- Baseline dict includes the six original providers.
- Verification state matches the available integration evidence.
- Tor + ``respects_socks5h=False`` provider under strict → ``abort`` flag.
- Tor + ``respects_socks5h=True`` provider → no flag.
- Clearnet + ``respects_proxy=False`` provider → ``warning`` flag.
- Localhost-only provider is exempt from Tor flagging.
- Lenient mode downgrades ``abort`` to ``warning``.
- Off mode emits no flags regardless of path.
- Unknown/unverified providers abort on strict Tor and warn in lenient mode.
- Overrides may add new providers but must not replace baseline entries.
"""

from __future__ import annotations

import pytest


def test_known_providers_includes_v1_baseline() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    expected = {"anthropic", "openai", "gemini", "mordred-local", "bedrock", "vertex"}
    assert expected.issubset(set(KNOWN_PROVIDERS))


def test_baseline_verification_state() -> None:
    """Providers whose transport is empirically backed
    by ``tests/integration/test_provider_transport.py`` have
    ``unverified_baseline`` cleared. ``bedrock`` is only partially verified
    (``respects_socks5h=False`` confirmed; the ``dns_quirk`` / IPv6 facts
    still need a real AWS packet capture) and ``vertex`` is untested (heavy
    SDK + GCP-side behaviour) — both stay flagged."""
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    verified = {"anthropic", "openai", "gemini", "mordred-local"}
    deferred = {"bedrock", "vertex"}
    for name in verified:
        assert KNOWN_PROVIDERS[name].unverified_baseline is False, f"{name} should be verified"
    for name in deferred:
        assert KNOWN_PROVIDERS[name].unverified_baseline is True, f"{name} verify still deferred"


def test_anthropic_respects_socks5h() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["anthropic"]
    assert entry.respects_proxy is True
    assert entry.respects_socks5h is True


def test_bedrock_socks5h_false() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["bedrock"]
    assert entry.respects_socks5h is False
    assert entry.dns_quirk is True


def test_vertex_partial_proxy() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["vertex"]
    assert entry.respects_proxy == "partial"
    assert entry.respects_socks5h is False


def test_mordred_local_is_localhost_only() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["mordred-local"]
    assert entry.localhost_only is True


class TestStrictTor:
    def test_socks5h_compatible_provider_no_flag(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("anthropic",), policy_mode="strict")
        assert flags == []

    def test_bedrock_aborts(self) -> None:
        """bedrock fires both ``socks5h=False`` and ``respects_ipv6_proxy=False``
        flags after Task #3 - assert at least one abort is present and that
        the socks5h reason is mentioned. The aggregated message to the user
        is composed downstream by the CLI / hooks layer."""
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("bedrock",), policy_mode="strict")
        assert flags, "bedrock must produce at least one flag"
        assert all(f.provider == "bedrock" for f in flags)
        assert any(f.severity == "abort" for f in flags)
        assert any("socks5h" in f.reason.lower() for f in flags)

    def test_vertex_aborts(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("vertex",), policy_mode="strict")
        assert flags
        assert any(f.severity == "abort" for f in flags)

    def test_localhost_only_provider_exempt(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("mordred-local",), policy_mode="strict")
        assert flags == []


class TestStrictClearnet:
    def test_no_flags_for_proxy_compatible(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="clearnet", providers=("anthropic",), policy_mode="strict")
        assert flags == []


class TestLenientMode:
    def test_socks5h_incompatible_downgrades_to_warning(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("bedrock",), policy_mode="lenient")
        assert flags[0].severity == "warning"


class TestOffMode:
    def test_no_flags_regardless_of_path(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="tor",
            providers=("bedrock", "vertex"),
            policy_mode="off",
        )
        assert flags == []


class TestUnknown:
    def test_unknown_provider_aborts_under_strict_tor(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("custom-llm",), policy_mode="strict")
        assert len(flags) == 1
        assert flags[0].provider == "custom-llm"
        assert flags[0].severity == "abort"

    def test_unknown_provider_warns_under_lenient_tor(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("custom-llm",), policy_mode="lenient")
        assert len(flags) == 1
        assert flags[0].severity == "warning"

    def test_unknown_provider_warns_under_strict_clearnet(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="clearnet", providers=("custom-llm",), policy_mode="strict")
        assert len(flags) == 1
        assert flags[0].severity == "warning"

    def test_alias_resolves_to_canonical_entry(self) -> None:
        """An aliased provider id resolves to its canonical registry entry
        instead of being flagged as 'unknown provider' (PR-A alias norm)."""
        from mordred_hermes.network import provider_transport_flagger as ptf

        # aws → bedrock (socks5h-incompatible): real transport flag, not "unknown".
        aws_flags = ptf.evaluate(active_path="tor", providers=("aws",), policy_mode="strict")
        bedrock_flags = ptf.evaluate(active_path="tor", providers=("bedrock",), policy_mode="strict")
        assert aws_flags == bedrock_flags
        assert aws_flags  # bedrock lacks socks5h support → at least one flag
        assert all("unknown provider" not in f.reason for f in aws_flags)

        # claude → anthropic (socks5h-clean): no flag at all, and never "unknown".
        claude_flags = ptf.evaluate(active_path="tor", providers=("claude",), policy_mode="strict")
        assert claude_flags == []


class TestRegistrySync:
    """PR-B: the eight Hermes 0.14 cloud providers synced into KNOWN_PROVIDERS."""

    _NEW = ("openrouter", "nous", "deepseek", "xai", "zai", "novita", "minimax", "alibaba")

    @pytest.mark.parametrize("slug", _NEW)
    def test_entry_present_with_unverified_httpx_baseline(self, slug: str) -> None:
        from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

        entry = KNOWN_PROVIDERS[slug]
        assert entry.respects_proxy is True
        assert entry.respects_socks5h is True  # httpx env-trusting baseline
        assert entry.unverified_baseline is True  # not yet packet-capture verified

    @pytest.mark.parametrize("slug", _NEW)
    def test_new_provider_is_selectable_in_wizard(self, slug: str) -> None:
        from mordred_hermes.wizard import configure

        assert slug in configure._SELECTABLE_CLOUD_PROVIDERS

    def test_known_provider_slugs_are_real_hermes_ids(self) -> None:
        """Every non-localhost registry slug must be a provider id Hermes
        actually recognises — guarding against typos in the synced slugs and
        accidental stale entries. ``vertex`` and ``novita`` used to be
        carve-outs while absent from older bundled Hermes versions;
        hermes-agent 0.18.0 recognises both, so the registry is now checked
        without exceptions. Skips if the upstream registry can't be
        imported."""
        from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

        try:
            from hermes_cli.models import _PROVIDER_MODELS, CANONICAL_PROVIDERS
        except (ImportError, AttributeError):  # pragma: no cover - upstream moved
            pytest.skip("hermes_cli.models provider registry not importable")

        recognised = {p.slug for p in CANONICAL_PROVIDERS} | set(_PROVIDER_MODELS)
        mordred_cloud = {name for name, e in KNOWN_PROVIDERS.items() if not e.localhost_only}
        unrecognised = mordred_cloud - recognised
        assert not unrecognised, f"registry slugs not known to Hermes: {unrecognised}"


class TestOverrides:
    def test_override_can_add_new_provider(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        entry = ptf.ProviderEntry(
            name="my-internal",
            transport="httpx",
            respects_proxy=True,
            respects_socks5h=True,
            # Task #3: opt in to IPv6 proxy honouring so the new IPv6 branch
            # doesn't flag this otherwise-clean provider.
            respects_ipv6_proxy=True,
            unverified_baseline=False,
        )
        flags = ptf.evaluate(
            active_path="tor",
            providers=("my-internal",),
            policy_mode="strict",
            overrides={"my-internal": entry},
        )
        assert flags == []

    def test_override_cannot_replace_baseline(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        entry = ptf.ProviderEntry(
            name="anthropic",
            transport="httpx",
            respects_proxy=False,
            respects_socks5h=False,
            unverified_baseline=False,
        )
        with pytest.raises(ValueError):
            ptf.evaluate(
                active_path="tor",
                providers=("anthropic",),
                policy_mode="strict",
                overrides={"anthropic": entry},
            )


def test_multiple_providers_returns_one_flag_each() -> None:
    from mordred_hermes.network import provider_transport_flagger as ptf

    flags = ptf.evaluate(
        active_path="tor",
        providers=("anthropic", "bedrock", "vertex", "mordred-local"),
        policy_mode="strict",
    )
    names_flagged = {f.provider for f in flags}
    assert "bedrock" in names_flagged
    assert "vertex" in names_flagged
    assert "anthropic" not in names_flagged
    assert "mordred-local" not in names_flagged


def test_provider_entry_is_immutable() -> None:
    """``ProviderEntry`` must be frozen so user code can't smuggle a mutation."""
    import dataclasses

    from mordred_hermes.network import provider_transport_flagger as ptf

    entry = ptf.KNOWN_PROVIDERS["anthropic"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.respects_socks5h = False  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Phase 3 PR3a Task #3: IPv6 + non-HTTP transport flagging                    #
# --------------------------------------------------------------------------- #


class TestProviderEntryExtensions:
    """New fields landed in Task #3.

    - ``transport_class``: which protocol family the SDK speaks. ``"http"``
      means HTTPS_PROXY routing is well-understood; everything else needs
      careful per-protocol setup that v1 does not provide.
    - ``respects_ipv6_proxy``: does the transport honor proxy env vars when
      the resolved endpoint is IPv6? Many SDKs route IPv6 directly even
      when ``HTTPS_PROXY`` is set, causing a silent Tor leak.
    """

    def test_baseline_entries_default_to_http_transport_class(self) -> None:
        from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

        for name, entry in KNOWN_PROVIDERS.items():
            assert entry.transport_class == "http", f"{name} transport_class={entry.transport_class!r}"

    def test_bedrock_respects_ipv6_proxy_false(self) -> None:
        """boto3 historically routes IPv6 around HTTPS_PROXY; flag it."""
        from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

        assert KNOWN_PROVIDERS["bedrock"].respects_ipv6_proxy is False

    def test_anthropic_respects_ipv6_proxy_true(self) -> None:
        """httpx with ``http://`` env var honors IPv6 routing through the proxy."""
        from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

        assert KNOWN_PROVIDERS["anthropic"].respects_ipv6_proxy is True

    def test_transport_class_literal_type_pins_alphabet(self) -> None:
        """``transport_class`` is a Literal so mypy --strict catches typos."""
        from typing import get_type_hints

        from mordred_hermes.network.provider_transport_flagger import ProviderEntry

        hints = get_type_hints(ProviderEntry)
        args = getattr(hints["transport_class"], "__args__", ())
        assert set(args) == {"http", "tcp", "udp", "quic", "grpc", "websocket"}, args


class TestIPv6Flagging:
    """``respects_ipv6_proxy=False`` on Tor always produces a flag.

    ``disable_ipv6=True`` only configures Tor's own client connections; it
    does not disable host IPv6 or constrain provider SDK sockets.
    """

    def test_strict_tor_ipv6_enabled_provider_respects_ipv6_proxy_false_aborts(self) -> None:
        """strict + Tor + IPv6 allowed + provider doesn't proxy IPv6 → abort."""
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="tor",
            providers=("bedrock",),
            policy_mode="strict",
            disable_ipv6=False,
        )
        # bedrock is already flagged for socks5h=False; check that an
        # IPv6-leak flag is ALSO emitted (or that the existing reason
        # mentions ipv6 specifically). Either way the abort severity stays.
        assert any("ipv6" in f.reason.lower() for f in flags), [f.reason for f in flags]
        assert any(f.severity == "abort" for f in flags)

    def test_strict_tor_disable_ipv6_setting_does_not_suppress_flag(self) -> None:
        """Tor ``ClientUseIPv6 0`` is not host-level IPv6 enforcement."""
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="tor",
            providers=("bedrock",),
            policy_mode="strict",
            disable_ipv6=True,
        )
        ipv6_flags = [f for f in flags if "ipv6" in f.reason.lower()]
        assert ipv6_flags, "Tor-only disable_ipv6 must not suppress the SDK IPv6 flag"
        assert all(f.severity == "abort" for f in ipv6_flags)
        assert all("does not enforce host/sdk" in f.reason.lower() for f in ipv6_flags)

    def test_lenient_tor_ipv6_enabled_downgrades_to_warning(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="tor",
            providers=("anthropic",),  # anthropic respects_socks5h=True so no other flag
            policy_mode="lenient",
            disable_ipv6=False,
        )
        # anthropic respects_ipv6_proxy=True so still no flag.
        assert flags == []

    def test_strict_clearnet_no_ipv6_flag(self) -> None:
        """IPv6-leak flag only fires on Tor; clearnet has no anonymity model."""
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="clearnet",
            providers=("bedrock",),
            policy_mode="strict",
            disable_ipv6=False,
        )
        ipv6_flags = [f for f in flags if "ipv6" in f.reason.lower()]
        assert ipv6_flags == []


class TestUnverifiedBaseline:
    def test_strict_tor_unverified_provider_aborts(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="tor",
            providers=("openrouter",),
            policy_mode="strict",
            disable_ipv6=True,
        )
        verification = [f for f in flags if "not packet-capture verified" in f.reason]
        assert verification
        assert all(f.severity == "abort" for f in verification)

    def test_lenient_tor_unverified_provider_warns(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="tor",
            providers=("openrouter",),
            policy_mode="lenient",
            disable_ipv6=True,
        )
        verification = [f for f in flags if "not packet-capture verified" in f.reason]
        assert verification
        assert all(f.severity == "warning" for f in verification)

    def test_strict_clearnet_unverified_provider_not_transport_gated(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="clearnet",
            providers=("openrouter",),
            policy_mode="strict",
        )
        assert all("not packet-capture verified" not in f.reason for f in flags)


class TestNonHTTPTransportFlagging:
    """``transport_class != "http"`` providers don't honor HTTPS_PROXY.

    The v1 baseline has no non-HTTP providers, so this matrix exercises an
    override-injected fake. v2 may introduce raw-TCP / WebSocket providers.
    """

    def test_strict_tor_grpc_provider_aborts(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        grpc_provider = ptf.ProviderEntry(
            name="my-internal-grpc",
            transport="grpc-python",
            respects_proxy=False,
            respects_socks5h=False,
            transport_class="grpc",
        )
        flags = ptf.evaluate(
            active_path="tor",
            providers=("my-internal-grpc",),
            policy_mode="strict",
            overrides={"my-internal-grpc": grpc_provider},
        )
        assert any("grpc" in f.reason.lower() or "non-http" in f.reason.lower() for f in flags)
        assert any(f.severity == "abort" for f in flags)

    def test_strict_clearnet_grpc_provider_emits_warning_not_abort(self) -> None:
        """Clearnet doesn't have a proxy contract for non-HTTP either, but
        the absence of a tunnel reduces severity to warning (informational)."""
        from mordred_hermes.network import provider_transport_flagger as ptf

        grpc_provider = ptf.ProviderEntry(
            name="my-grpc",
            transport="grpc-python",
            respects_proxy=False,
            respects_socks5h=False,
            transport_class="grpc",
        )
        flags = ptf.evaluate(
            active_path="clearnet",
            providers=("my-grpc",),
            policy_mode="strict",
            overrides={"my-grpc": grpc_provider},
        )
        # Filter to non-http flags (separate from clearnet `respects_proxy=False`).
        non_http_flags = [f for f in flags if "non-http" in f.reason.lower() or "grpc" in f.reason.lower()]
        assert non_http_flags, "expected a non-http flag on clearnet"
        assert all(f.severity == "warning" for f in non_http_flags)

    def test_lenient_tor_grpc_provider_downgrades_to_warning(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        grpc_provider = ptf.ProviderEntry(
            name="my-grpc",
            transport="grpc-python",
            respects_proxy=False,
            respects_socks5h=False,
            transport_class="grpc",
        )
        flags = ptf.evaluate(
            active_path="tor",
            providers=("my-grpc",),
            policy_mode="lenient",
            overrides={"my-grpc": grpc_provider},
        )
        assert all(f.severity == "warning" for f in flags)

    def test_off_emits_no_non_http_flags(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        grpc_provider = ptf.ProviderEntry(
            name="my-grpc",
            transport="grpc-python",
            respects_proxy=False,
            respects_socks5h=False,
            transport_class="grpc",
        )
        flags = ptf.evaluate(
            active_path="tor",
            providers=("my-grpc",),
            policy_mode="off",
            overrides={"my-grpc": grpc_provider},
        )
        assert flags == []


class TestEvaluateBackwardCompat:
    """The new ``disable_ipv6`` kw-arg must default-False so existing callers
    (PR2 runtime, all other tests) keep working without modification."""

    def test_evaluate_default_disable_ipv6_false(self) -> None:
        """Calling evaluate without disable_ipv6 behaves as if it were False."""
        from mordred_hermes.network import provider_transport_flagger as ptf

        # bedrock without disable_ipv6 in strict + tor — should emit IPv6 flag
        # because the default behavior is "IPv6 not disabled at OS level".
        flags_explicit = ptf.evaluate(
            active_path="tor",
            providers=("bedrock",),
            policy_mode="strict",
            disable_ipv6=False,
        )
        flags_default = ptf.evaluate(
            active_path="tor",
            providers=("bedrock",),
            policy_mode="strict",
        )
        # Both runs flag the same set of reasons.
        assert {f.reason for f in flags_explicit} == {f.reason for f in flags_default}
