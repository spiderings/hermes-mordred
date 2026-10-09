"""Hook handlers for ``mordred_network`` (Phase 3 PR2-B).

Hermes invokes hooks via ``invoke_hook(name, **kwargs)``. Each handler
accepts arbitrary kwargs because Hermes adds payload fields without
breaking the call-site contract - the handler ignores unknown kwargs.

Return-shape contracts (HOOK_PAYLOADS.md §1, §4):

- ``on_session_start`` - return ignored. Raising
  :class:`MordredPathBringupFailed` (``BaseException``) escapes the
  ``except Exception`` wrapper inside ``hermes_cli.plugins.invoke_hook``
  so a strict-mode bring-up failure actually aborts the session.
- ``on_session_end`` - return ignored. Hermes fires this after every turn, so
  the active path is deliberately retained for the next turn.
- ``pre_api_request`` - return ignored. Strict + Tor revalidates the
  request-resolved provider and raises :class:`MordredPathBringupFailed`
  before egress when its transport is not verified compatible.
- ``pre_tool_call`` - return ``None`` to allow. Strict protected routes are
  revalidated before every tool; a missing/stale route raises
  :class:`MordredPathBringupFailed`, while a liveness drop raises
  :class:`MordredPathDropped` (both ``BaseException``) for the same escape
  reason.

The hooks delegate to :mod:`mordred_hermes.network.api` rather than to
:class:`mordred_hermes.network.runtime.Runtime` directly so the test
suite can swap in a tiny fake runtime via :func:`api.set_runtime`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Literal, NoReturn, cast

from .._audit_support import AuditWriter as _AuditWriter
from .._audit_support import safe_audit_append
from .._policy_io import load_policy_mapping
from .._policy_types import VALID_ACTIVE_PATHS, ActivePath, PolicyMode
from .._provider_resolution import (
    read_auth_active_provider,
    read_config_model_provider,
    resolve_disk_provider,
)
from . import api
from . import settings as settings_mod
from ._exceptions import (
    BringupFailed,
    MordredNetworkError,
    MordredPathBringupFailed,
    MordredPathDropped,
    PathSwitchRequiresRestart,
)
from .provider_transport_flagger import ProviderEntry, TransportClass, evaluate

_LOG = logging.getLogger("mordred.network.hooks")

_PROTECTED_NETWORK_PATHS: Final[frozenset[str]] = frozenset({"tor", "vpn"})
# Audit reason code for a provider-vs-transport compatibility flag (FIX 1,
# 2026-07-13). ``decision`` is ``block`` for an abort-severity flag (strict
# refusal) and ``warn`` for a warning-severity one (audited, session continues).
_REASON_TRANSPORT_FLAG: Final[str] = "network.transport_incompatible"
_UNRESOLVED_PROVIDER: Final[str] = "<unresolved>"
_OVERRIDE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "transport",
        "respects_proxy",
        "respects_socks5h",
        "localhost_only",
        "dns_quirk",
        "unverified_baseline",
        "transport_class",
        "respects_ipv6_proxy",
    }
)
_TRANSPORT_CLASSES: Final[frozenset[str]] = frozenset({"http", "tcp", "udp", "quic", "grpc", "websocket"})


# --------------------------------------------------------------------------- #
# Disk readers                                                                #
# --------------------------------------------------------------------------- #


def _read_policy_mode(policy_json_path: Path) -> str:
    """Read the enforcement policy mode, failing CLOSED on a damaged file.

    M1 (security review 2026-06-11): an absent file is a fresh install and
    keeps the historical ``"off"`` default — but a file that EXISTS and
    cannot be read or parsed reads as ``"strict"``. Falling back to
    ``"off"`` meant corrupting policy.json silently disabled strict
    enforcement on both hook paths (session bring-up and the per-tool
    dropped-path gate). The open-first mechanics live in the shared
    :func:`.._policy_io.read_policy_mode_fail_closed` so llm_guard's
    reader cannot drift from this one.
    """
    return settings_mod.read_policy_mode(policy_json_path, log=_LOG)


def _read_default_network_path(config_path: Path) -> str:
    """Read ``plugins.mordred_network.default_path`` from ``config.yaml``.

    Wizard PR2-C is the writer.
    """
    return settings_mod.read_default_path(config_path, log=_LOG)


def _read_default_network_path_strict(config_path: Path) -> str:
    """Read ``default_path`` without hiding damage to an existing config.

    A missing file, absent ``plugins`` key, absent ``mordred_network`` section,
    or absent ``default_path`` is a legitimate unconfigured state and resolves
    to clearnet. Existing malformed YAML, non-mapping container shapes, and an
    invalid explicit ``default_path`` raise so strict request-time enforcement
    can fail closed rather than misclassifying damaged Tor configuration as
    intentional clearnet.
    """
    return settings_mod.read_default_path_strict(config_path)


# --------------------------------------------------------------------------- #
# Hook handlers                                                               #
# --------------------------------------------------------------------------- #


def on_session_start(
    *,
    policy_json_path: Path,
    config_path: Path,
    auth_json_path: Path | None = None,
    audit: _AuditWriter | None = None,
    **_kwargs: Any,
) -> None:
    """Validate and reuse the configured process-global default path.

    - Call :func:`api.use` for the configured default in every policy mode.
      A ready same-path call is a runtime no-op; a different process-frozen
      route raises a fail-closed restart-required refusal rather than leaving
      existing provider clients on a stale transport.
      Strict-mode bring-up failure raises :class:`MordredPathBringupFailed`
      (BaseException) after emitting ``network.bringup_failed`` audit.
      Lenient-mode failure is absorbed by the runtime (fallback to
      clearnet + ``network.bringup_failed`` audit there); the hook
      itself returns normally.
    - After bring-up, resolve the active provider and run the transport gate.
      Strict + Tor fails closed for unsafe/unresolved providers, malformed
      overrides, or an internal gate error. Lenient downgrades provider flags;
      off skips them. Malformed overrides and internal errors warn and continue
      in lenient/off.
    """
    policy_mode = _read_policy_mode(policy_json_path)
    target = _read_default_network_path(config_path)
    _reuse_frozen_route(
        policy_json_path=policy_json_path,
        config_path=config_path,
        policy_mode=policy_mode,
        target=target,
        audit=audit,
    )

    # FIX 1 (2026-07-13): provider-vs-transport compatibility gate. Once the
    # path is up (or fell back to clearnet in lenient), verify the provider
    # Hermes will use can actually reach the upstream API over the active
    # transport. A strict Tor session talking to an incompatible, unknown, or
    # unverified provider is refused HERE. Internal errors are also
    # policy-sensitive: strict + Tor refuses while preserving the process route;
    # lenient/off warn and continue.
    gate_stage = "status"
    gate_active_path = cast(ActivePath, target)
    gate_providers = [_UNRESOLVED_PROVIDER]
    try:
        raw_active_path = api.status().active_path
        if raw_active_path not in VALID_ACTIVE_PATHS:
            raise ValueError(f"runtime reported invalid active path {raw_active_path!r}")
        gate_active_path = cast(ActivePath, raw_active_path)
        gate_stage = "provider_resolution"
        gate_providers = _resolve_active_providers(config_path=config_path, auth_json_path=auth_json_path)
        gate_stage = "provider_overrides"
        overrides = _read_provider_overrides(policy_json_path)
        gate_stage = "policy_config"
        disable_ipv6 = _read_disable_ipv6(policy_json_path, policy_mode)
        gate_stage = "evaluate"
        _flag_transport_compat(
            active_path=gate_active_path,
            providers=gate_providers,
            policy_mode=policy_mode,
            disable_ipv6=disable_ipv6,
            overrides=overrides,
            audit=audit,
        )
    except Exception as flag_err:
        _handle_transport_gate_error(
            error=flag_err,
            stage=gate_stage,
            target_path=cast(ActivePath, target),
            active_path=gate_active_path,
            providers=gate_providers,
            policy_mode=policy_mode,
            audit=audit,
        )


def _reuse_frozen_route(
    *,
    policy_json_path: Path,
    config_path: Path,
    policy_mode: str,
    target: str,
    audit: _AuditWriter | None,
) -> None:
    """Validate the activation fingerprint and reuse the process route."""
    try:
        # Compare every activation input before mutating the runtime's policy.
        from . import _load_runtime_config

        current_config = _load_runtime_config(
            policy_json_path=policy_json_path,
            config_path=config_path,
        )
        api.assert_route_config(current_config)
        api.update_policy_mode(policy_mode)
        api.use(target)  # type: ignore[arg-type]
    except PathSwitchRequiresRestart as error:
        _raise_route_restart_refusal(
            error=error,
            target=target,
            policy_mode=policy_mode,
            audit=audit,
        )
    except BringupFailed as error:
        _handle_route_bringup_failure(
            error=error,
            target=target,
            policy_mode=policy_mode,
            audit=audit,
        )
    except MordredNetworkError as error:
        _handle_route_runtime_error(error=error, target=target, policy_mode=policy_mode)
    except Exception as error:
        _raise_unexpected_route_validation(
            error=error,
            target=target,
            policy_mode=policy_mode,
            audit=audit,
        )


def _append_route_block(
    *,
    audit: _AuditWriter | None,
    target: str,
    policy_mode: str,
    error: Exception,
) -> None:
    if audit is None:
        return
    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": "block",
            "reason": "network.bringup_failed",
            "attempted_path": target,
            "policy_mode": policy_mode,
            "error": str(error),
        },
    )


def _raise_route_restart_refusal(
    *,
    error: PathSwitchRequiresRestart,
    target: str,
    policy_mode: str,
    audit: _AuditWriter | None,
) -> NoReturn:
    _append_route_block(
        audit=audit,
        target=target,
        policy_mode=policy_mode,
        error=error,
    )
    msg = (
        f"Mordred {policy_mode} mode: process network route {target!r} cannot be changed live ({error}); "
        "restart Hermes before continuing."
    )
    _LOG.error(msg)
    raise MordredPathBringupFailed(msg) from error


def _handle_route_bringup_failure(
    *,
    error: BringupFailed,
    target: str,
    policy_mode: str,
    audit: _AuditWriter | None,
) -> None:
    if policy_mode != "strict":
        return
    _append_route_block(
        audit=audit,
        target=target,
        policy_mode=policy_mode,
        error=error,
    )
    msg = f"Mordred strict mode: network path {target!r} failed to bring up ({error}); refusing the session."
    _LOG.error(msg)
    raise MordredPathBringupFailed(msg) from error


def _handle_route_runtime_error(*, error: MordredNetworkError, target: str, policy_mode: str) -> None:
    if policy_mode == "strict":
        msg = f"Mordred strict mode: api.use({target!r}) raised {error}; refusing the session."
        _LOG.error(msg)
        raise MordredPathBringupFailed(msg) from error
    _LOG.warning(
        "on_session_start: api.use(%r) raised %s; continuing in %s mode",
        target,
        error,
        policy_mode,
    )


def _raise_unexpected_route_validation(
    *,
    error: Exception,
    target: str,
    policy_mode: str,
    audit: _AuditWriter | None,
) -> NoReturn:
    _append_route_block(
        audit=audit,
        target=target,
        policy_mode=policy_mode,
        error=error,
    )
    msg = f"Mordred {policy_mode} mode: process route validation failed unexpectedly ({error}); refusing the session."
    _LOG.error(msg)
    raise MordredPathBringupFailed(msg) from error


def on_session_end(**_kwargs: Any) -> None:
    """Keep the active path alive across Hermes conversation turns.

    Hermes 0.13--0.19 fires ``on_session_end`` after every
    ``run_conversation`` call, not only when the logical session is over.
    Stopping here resets the runtime to clearnet, while continuation turns do
    not fire ``on_session_start`` again. Consequently a strict Tor session
    would send its second turn over clearnet.

    The Runtime is process-global and can serve multiple gateway sessions, so
    session-finalize/reset hooks cannot own teardown either. ``register()``
    installs a single process-exit callback for final cleanup.
    """


def pre_api_request(
    *,
    policy_json_path: Path,
    config_path: Path,
    audit: _AuditWriter | None = None,
    provider: Any = None,
    **_kwargs: Any,
) -> None:
    """Gate the configured protected route and resolved provider in strict mode.

    ``on_session_start`` can only inspect the provider persisted in
    ``config.yaml`` / ``auth.json``. Hermes can override that provider later
    through CLI flags, environment variables, one-shot calls, or gateway model
    switches. ``pre_api_request`` carries the provider that is actually about
    to receive the request, so strict Tor re-runs the transport evidence gate
    here immediately before egress.

    The configured path is checked again here because continuation turns do
    not fire ``on_session_start``. Under strict policy, configured Tor and VPN
    paths must both be active and ready before any provider evaluation.

    Missing provider evidence, malformed overrides, invalid runtime state, and
    internal evaluation errors all fail closed. A refusal keeps the current
    runtime state intact and raises :class:`MordredPathBringupFailed`, whose
    ``BaseException`` inheritance escapes Hermes's ``except Exception`` hook
    wrappers.
    """
    policy_mode = _read_policy_mode(policy_json_path)
    if policy_mode != "strict":
        return

    runtime_provider = (
        provider.strip().lower() if isinstance(provider, str) and provider.strip() else _UNRESOLVED_PROVIDER
    )
    # Default to Tor until config resolution succeeds. If the reader itself
    # fails under strict policy, the error path must assume the protected route
    # was Tor rather than silently allowing possible clearnet egress.
    configured_path: ActivePath = "tor"
    active_path: ActivePath = "tor"
    stage = "configured_path"
    try:
        configured_path = cast(ActivePath, _read_default_network_path_strict(config_path))
        stage = "activation_config"
        from . import _load_runtime_config

        current_config = _load_runtime_config(
            policy_json_path=policy_json_path,
            config_path=config_path,
        )
        api.assert_route_config(current_config)
        stage = "status"
        runtime_status = api.status()
        raw_active_path = runtime_status.active_path
        if raw_active_path not in VALID_ACTIVE_PATHS:
            raise ValueError(f"runtime reported invalid active path {raw_active_path!r}")
        active_path = cast(ActivePath, raw_active_path)
        if configured_path in _PROTECTED_NETWORK_PATHS and active_path != configured_path:
            stage = "required_path"
            raise RuntimeError(
                f"configured protected path {configured_path!r} is not active (runtime active_path={active_path!r})"
            )
        if active_path in _PROTECTED_NETWORK_PATHS and not runtime_status.ready:
            stage = "path_readiness"
            raise RuntimeError(f"active protected path {active_path!r} is not ready")
        if active_path in _PROTECTED_NETWORK_PATHS:
            stage = "path_readiness"
            if api.is_dropped():
                raise RuntimeError(f"active protected path {active_path!r} was dropped")
        if active_path != "tor":
            return

        stage = "provider_overrides"
        overrides = _read_provider_overrides(policy_json_path)
        stage = "policy_config"
        disable_ipv6 = _read_disable_ipv6(policy_json_path, policy_mode)
        stage = "evaluate"
        _flag_transport_compat(
            active_path=active_path,
            providers=[runtime_provider],
            policy_mode=policy_mode,
            disable_ipv6=disable_ipv6,
            overrides=overrides,
            audit=audit,
            event="pre_api_request",
            refusal_context="outbound API request",
        )
    except Exception as gate_error:
        # Under strict policy an unreadable runtime status cannot establish
        # that the request is outside a configured protected route.
        _handle_transport_gate_error(
            error=gate_error,
            stage=stage,
            target_path=configured_path,
            active_path=active_path,
            providers=[runtime_provider],
            policy_mode=policy_mode,
            audit=audit,
            event="pre_api_request",
            refusal_context="outbound API request",
        )


def pre_tool_call(
    *,
    policy_json_path: Path,
    config_path: Path,
    tool_name: str = "",
    audit: _AuditWriter | None = None,
    **_kwargs: Any,
) -> dict[str, Any] | None:
    """Revalidate the process route before every strict-mode tool call.

    Continuation turns do not reliably fire ``on_session_start`` and tool
    calls need not trigger ``pre_api_request``. Therefore strict mode repeats
    the same activation-config, configured-path, readiness, and drop checks as
    the provider request gate. Lenient/off retain the historical ``None``
    result; the liveness worker already audits their drops with
    ``decision=warn``.
    """
    policy_mode = _read_policy_mode(policy_json_path)
    if policy_mode != "strict":
        return None

    # Assume a protected route until each disk/runtime read proves otherwise.
    # That mirrors ``pre_api_request`` and prevents damaged strict config from
    # being misclassified as an intentional clearnet route.
    configured_path: ActivePath = "tor"
    active_path: ActivePath = "tor"
    stage = "configured_path"
    try:
        configured_path = cast(ActivePath, _read_default_network_path_strict(config_path))
        stage = "activation_config"
        from . import _load_runtime_config

        current_config = _load_runtime_config(
            policy_json_path=policy_json_path,
            config_path=config_path,
        )
        api.assert_route_config(current_config)
        stage = "status"
        runtime_status = api.status()
        raw_active_path = runtime_status.active_path
        if raw_active_path not in VALID_ACTIVE_PATHS:
            raise ValueError(f"runtime reported invalid active path {raw_active_path!r}")
        active_path = cast(ActivePath, raw_active_path)
        if configured_path in _PROTECTED_NETWORK_PATHS and active_path != configured_path:
            stage = "required_path"
            raise RuntimeError(
                f"configured protected path {configured_path!r} is not active (runtime active_path={active_path!r})"
            )
        if active_path in _PROTECTED_NETWORK_PATHS and not runtime_status.ready:
            stage = "path_readiness"
            raise RuntimeError(f"active protected path {active_path!r} is not ready")
        if active_path in _PROTECTED_NETWORK_PATHS:
            stage = "path_readiness"
            if api.is_dropped():
                _raise_dropped_tool_refusal(tool_name=tool_name, audit=audit)
    except Exception as gate_error:
        _handle_transport_gate_error(
            error=gate_error,
            stage=stage,
            target_path=configured_path,
            active_path=active_path,
            providers=[_UNRESOLVED_PROVIDER],
            policy_mode=policy_mode,
            audit=audit,
            event="pre_tool_call",
            refusal_context=f"tool {tool_name!r}",
        )
    return None


def _raise_dropped_tool_refusal(*, tool_name: str, audit: _AuditWriter | None) -> NoReturn:
    """Audit and raise the dedicated strict liveness-drop refusal."""
    if audit is not None:
        _safe_audit_append(
            audit,
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": "network.path_dropped",
                "tool_name": tool_name,
            },
        )
    msg = (
        f"Mordred strict mode: active network path was dropped; refusing tool {tool_name!r}. "
        "Restart Hermes so provider clients and the process route are rebuilt together."
    )
    _LOG.error(msg)
    raise MordredPathDropped(msg)


# --------------------------------------------------------------------------- #
# Bootstrap polling fallback                                                  #
# --------------------------------------------------------------------------- #


def wait_until_ready(*, timeout: float = 5.0, poll_interval: float = 0.05) -> bool:
    """Poll ``api.status().ready`` until true or timeout.

    Hermes loads bundled / user / project plugins before entry-point
    plugins (HOOK_PAYLOADS.md §1). Sibling plugins whose
    ``on_session_start`` fires earlier may issue outbound calls before
    our path is ready. Those plugins should call this helper to wait
    deterministically.

    Returns ``True`` when the runtime reports ``ready`` within the
    deadline, ``False`` otherwise. Never raises - the caller decides
    what to do with a non-ready state.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if api.status().ready:
                return True
        except MordredNetworkError:
            # No runtime registered yet, or runtime in an error state.
            pass
        time.sleep(poll_interval)
    try:
        return api.status().ready
    except MordredNetworkError:
        return False


# --------------------------------------------------------------------------- #
# Internals                                                                   #
# --------------------------------------------------------------------------- #


def _safe_audit_append(audit: _AuditWriter, entry: Mapping[str, Any]) -> None:
    """Best-effort audit append binding this module's logger.

    Thin wrapper over :func:`mordred_hermes._audit_support.safe_audit_append`
    -- a strict-mode refusal must still raise even if the audit write fails
    (disk full, permission denied, etc.).
    """
    safe_audit_append(audit, entry, logger=_LOG)


# --------------------------------------------------------------------------- #
# Provider-vs-transport compatibility gate (FIX 1)                            #
# --------------------------------------------------------------------------- #


def _read_config_model_provider(config_path: Path) -> str | None:
    """Read ``model.provider`` from ``config.yaml`` (Hermes' persistent
    provider-of-record).

    Returns ``None`` when the key is absent, non-string, empty, or the
    ``"auto"`` sentinel (Hermes' "defer to auth.json / env" marker). Mirrors
    ``llm_guard._read_config_model_provider`` — same shared ``load_yaml_mapping``
    reader — so the two plugins resolve the same provider from the same file.
    """
    return read_config_model_provider(config_path, log=_LOG)


def _read_auth_active_provider(auth_json_path: Path) -> str | None:
    """Read ``active_provider`` from ``auth.json`` (Hermes' auto-resolution
    fallback when ``model.provider`` is unset / ``auto``).

    Mirrors ``llm_guard._read_auth_active_provider`` — the shared
    ``load_policy_mapping`` reader collapses a missing / unreadable / malformed
    file to ``{}`` so this reader degrades to ``None``. The caller then sends
    the explicit unresolved-provider sentinel through the normal transport
    severity matrix (strict + Tor refuses; lenient warns).
    """
    return read_auth_active_provider(auth_json_path, log=_LOG)


def _resolve_active_providers(*, config_path: Path, auth_json_path: Path | None) -> list[str]:
    """Resolve the provider(s) Hermes will run, for the transport gate.

    Same resolution order as ``llm_guard._resolve_active_provider``:
    ``config.yaml model.provider`` wins, else ``auth.json active_provider``. A
    single active provider is enough for the transport gate. Returns the RAW
    (lower-cased) id — :func:`provider_transport_flagger.evaluate` applies
    ``canonicalize_provider`` itself and preserves the raw id in the
    unknown-provider Flag message. When neither source yields a provider, the
    explicit ``<unresolved>`` sentinel is returned. That sentinel follows the
    normal unknown-provider severity matrix: strict + Tor aborts, lenient +
    Tor warns, and clearnet remains informational.
    """
    resolved = resolve_disk_provider(
        config_path=config_path,
        auth_json_path=auth_json_path,
        config_reader=_read_config_model_provider,
        auth_reader=_read_auth_active_provider,
    )
    return [resolved if resolved is not None else _UNRESOLVED_PROVIDER]


def _read_provider_overrides(policy_json_path: Path) -> dict[str, ProviderEntry]:
    """Parse additive transport facts from ``policy.json``.

    Missing fields take conservative defaults so an incomplete entry cannot
    accidentally satisfy strict Tor: SOCKS5h/IPv6 support default false and
    ``unverified_baseline`` defaults true. Invalid types and unknown fields
    raise ``ValueError``; the caller turns that into a strict-Tor refusal or a
    lenient/off warning. Baseline replacement remains prohibited by
    :func:`provider_transport_flagger.evaluate`.
    """
    data = load_policy_mapping(policy_json_path, log=_LOG)
    if "provider_overrides" not in data:
        return {}
    raw_overrides = data["provider_overrides"]
    if not isinstance(raw_overrides, dict):
        raise ValueError("policy.json provider_overrides must be an object")

    overrides: dict[str, ProviderEntry] = {}
    for raw_name, raw_entry in raw_overrides.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("provider_overrides keys must be non-empty strings")
        name = raw_name.strip().lower()
        if name in overrides:
            raise ValueError(f"provider_overrides contains duplicate normalized provider {name!r}")
        overrides[name] = _parse_provider_override(name, raw_entry)
    return overrides


def _parse_provider_override(name: str, raw_entry: Any) -> ProviderEntry:
    if not isinstance(raw_entry, dict):
        raise ValueError(f"provider override {name!r} must be an object")
    unknown_fields = [field for field in raw_entry if field not in _OVERRIDE_FIELDS]
    if unknown_fields:
        raise ValueError(f"provider override {name!r} has unsupported field {unknown_fields[0]!r}")

    raw_transport = raw_entry.get("transport", "unknown")
    if not isinstance(raw_transport, str) or not raw_transport.strip():
        raise ValueError(f"provider override {name!r} transport must be a non-empty string")

    raw_respects_proxy = raw_entry.get("respects_proxy", False)
    if not isinstance(raw_respects_proxy, bool) and raw_respects_proxy != "partial":
        raise ValueError(f"provider override {name!r} respects_proxy must be boolean or 'partial'")
    respects_proxy = cast(bool | Literal["partial"], raw_respects_proxy)

    raw_transport_class = raw_entry.get("transport_class", "http")
    if not isinstance(raw_transport_class, str) or raw_transport_class not in _TRANSPORT_CLASSES:
        raise ValueError(f"provider override {name!r} transport_class must be one of {sorted(_TRANSPORT_CLASSES)!r}")

    return ProviderEntry(
        name=name,
        transport=raw_transport.strip(),
        respects_proxy=respects_proxy,
        respects_socks5h=_read_override_bool(raw_entry, name=name, field="respects_socks5h", default=False),
        localhost_only=_read_override_bool(raw_entry, name=name, field="localhost_only", default=False),
        dns_quirk=_read_override_bool(raw_entry, name=name, field="dns_quirk", default=False),
        unverified_baseline=_read_override_bool(
            raw_entry,
            name=name,
            field="unverified_baseline",
            default=True,
        ),
        transport_class=cast(TransportClass, raw_transport_class),
        respects_ipv6_proxy=_read_override_bool(
            raw_entry,
            name=name,
            field="respects_ipv6_proxy",
            default=False,
        ),
    )


def _read_override_bool(entry: Mapping[str, Any], *, name: str, field: str, default: bool) -> bool:
    value = entry.get(field, default)
    if not isinstance(value, bool):
        raise ValueError(f"provider override {name!r} {field} must be boolean")
    return value


def _read_disable_ipv6(policy_json_path: Path, policy_mode: str) -> bool:
    """Reproduce ``RuntimeConfig.disable_ipv6`` for the transport flagger.

    The flagger receives the SAME ``disable_ipv6`` the runtime rendered into
    torrc (``ClientUseIPv6 0``), but that Tor option is advisory from the
    provider SDK's perspective: it neither disables host IPv6 nor filters AAAA
    answers. The shared settings resolver keeps registration and hook-time
    diagnostics aligned without a circular import through ``network.__init__``.
    """
    data = load_policy_mapping(policy_json_path, log=_LOG)
    return settings_mod.resolve_disable_ipv6(data, policy_mode)


def _flag_transport_compat(
    *,
    active_path: ActivePath,
    providers: list[str],
    policy_mode: str,
    disable_ipv6: bool,
    overrides: Mapping[str, ProviderEntry] | None = None,
    audit: _AuditWriter | None,
    event: str = "on_session_start",
    refusal_context: str = "session",
) -> None:
    """Run the provider-vs-transport flagger and enforce its severity.

    Strict + an ``abort``-severity flag refuses the guarded operation by raising
    :class:`MordredPathBringupFailed` (``BaseException``), the same escape the
    bring-up refusal uses so Hermes' ``except Exception`` wrapper cannot
    swallow it. A ``warning`` flag (a lenient-downgraded abort or a clearnet
    informational) is audited and the guarded operation continues. Unknown and
    unverified providers abort on strict Tor because they have no transport
    evidence for the anonymity contract. ``off`` mode never reaches the abort
    branch: ``evaluate`` returns ``[]``.

    An ``abort`` severity only survives ``evaluate`` under strict policy
    (lenient downgrades abort→warning, off returns ``[]``), so the explicit
    ``policy_mode == "strict"`` guard is belt-and-braces around that invariant.
    """
    flags = evaluate(
        active_path=active_path,
        providers=providers,
        policy_mode=cast(PolicyMode, policy_mode),
        overrides=overrides,
        disable_ipv6=disable_ipv6,
    )
    if not flags:
        return
    abort_reasons: list[str] = []
    for flag in flags:
        if audit is not None:
            _safe_audit_append(
                audit,
                {
                    "event": event,
                    "decision": "block" if flag.severity == "abort" else "warn",
                    "reason": _REASON_TRANSPORT_FLAG,
                    "active_path": active_path,
                    "provider": flag.provider,
                    "severity": flag.severity,
                    "detail": flag.reason,
                    "policy_mode": policy_mode,
                },
            )
        if flag.severity == "abort":
            abort_reasons.append(f"{flag.provider}: {flag.reason}")
    if abort_reasons and policy_mode == "strict":
        msg = (
            f"Mordred strict mode: provider transport is incompatible with network path "
            f"{active_path!r}: {'; '.join(abort_reasons)}; refusing the {refusal_context}."
        )
        _LOG.error(msg)
        # The path is process-global and may serve other gateway sessions.
        # Session-scoped provider refusal must never tear it down.
        raise MordredPathBringupFailed(msg)


def _handle_transport_gate_error(
    *,
    error: Exception,
    stage: str,
    target_path: ActivePath,
    active_path: ActivePath,
    providers: list[str],
    policy_mode: str,
    audit: _AuditWriter | None,
    event: str = "on_session_start",
    refusal_context: str = "session",
) -> None:
    """Apply fail-closed semantics to an internal transport-gate error."""
    strict_protected = policy_mode == "strict" and (
        target_path in _PROTECTED_NETWORK_PATHS or active_path in _PROTECTED_NETWORK_PATHS
    )
    detail = f"transport gate {stage} failed ({type(error).__name__}: {error})"
    if audit is not None:
        _safe_audit_append(
            audit,
            {
                "event": event,
                "decision": "block" if strict_protected else "warn",
                "reason": _REASON_TRANSPORT_FLAG,
                "active_path": active_path,
                "provider": providers[0] if len(providers) == 1 else ",".join(providers),
                "severity": "abort" if strict_protected else "warning",
                "detail": detail,
                "policy_mode": policy_mode,
                "stage": stage,
            },
        )
    if not strict_protected:
        _LOG.warning("%s: %s; continuing in %s mode", event, detail, policy_mode)
        return

    msg = f"Mordred strict mode: {detail}; refusing the {refusal_context}."
    _LOG.error(msg)
    raise MordredPathBringupFailed(msg) from error


__all__ = [
    "on_session_end",
    "on_session_start",
    "pre_api_request",
    "pre_tool_call",
    "wait_until_ready",
]
