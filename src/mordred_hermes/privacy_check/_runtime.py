"""Module-level state for the privacy_check plugin.

Loaded lazily by hook handlers — keeps ``register(ctx)`` cheap and
test-friendly. State is reset between tests via :func:`reset_state_for_tests`.

H3 Path B (HOOK_PAYLOADS.md §2): sibling-disable detection prefers
``hermes_cli.plugins._get_disabled_plugins`` / ``_get_enabled_plugins``
when available, falling back to direct ``~/.hermes/config.yaml`` reads.

Why "poison flag" alongside ``MordredIntegrityRefused``: Hermes's
``invoke_hook`` wraps every callback in ``try: ... except Exception:``
and logs as a warning. The direct ``BaseException`` subclass propagates
past that guard, but if a higher-level harness catches it, the in-process
poison flag still forces ``pre_tool_call`` to refuse every tool — defense
in depth for strict mode.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from .._audit_support import build_audit_writer
from .._home import HERMES_BASE, hermes_home
from .._plugin_identity import LEGACY_PLUGIN_NAMES, PLUGIN_NAME
from .._policy_io import (
    policy_transaction_marker_for_config,
    policy_transaction_pending,
)
from .._policy_types import POLICY_MODES
from .._yaml_io import load_plugin_section, load_yaml_mapping
from ..plugin import COMPONENT_REQUIRED_HOOKS, COMPONENTS
from .audit import Writer
from .policy import PolicyMode

_LOG = logging.getLogger("mordred.privacy_check")

# Mordred is one Hermes plugin (``mordred``, :mod:`mordred_hermes.plugin`).
# The name "siblings" survives from the six-plugin layout; the gate now checks
# that plugin plus each of its components (reported as ``mordred/<component>``).
SIBLING_PLUGINS: Final = (PLUGIN_NAME,)

# Minimum runtime surface the plugin promises: the union of its components'
# hooks. ``hooks_registered`` is populated by Hermes only after register()
# returns successfully, so checking it catches both swallowed registration
# errors and partial/upstream-drifted registrations. Per-component coverage is
# checked separately against the plugin's own record (see
# :func:`_unloaded_components`), because one component's hook would otherwise
# mask another's missing one.
SIBLING_REQUIRED_HOOKS: Final[dict[str, frozenset[str]]] = {
    PLUGIN_NAME: frozenset().union(*COMPONENT_REQUIRED_HOOKS.values()),
}

_PLUGIN_MODULE: Final = "mordred_hermes.plugin"

# Backwards-compat aliases — pre-Phase-1.3 code (and in-module uses below)
# read these names directly. The resolver itself was promoted to
# ``mordred_hermes._home`` so wizard / network / keyvault can share it
# without copy-paste.
_hermes_home = hermes_home
_HERMES_BASE: Final = HERMES_BASE
DEFAULT_AUDIT_PATH: Final = _HERMES_BASE / "mordred" / "audit.log"
DEFAULT_HERMES_CONFIG_PATH: Final = _HERMES_BASE / "config.yaml"


@dataclass(frozen=True, slots=True)
class PluginState:
    """Resolved policy snapshot + audit writer."""

    policy_mode: PolicyMode
    allow_cloud_llm: bool
    cloud_provider_allowlist: tuple[str, ...]
    audit: Writer
    config_path: Path


_state: PluginState | None = None
_state_lock = threading.Lock()
_poison_reason: str | None = None
_degraded_no_origin_skill_emitted = False


def ensure_state(
    *,
    config_path: Path | None = None,
    audit_path: Path | None = None,
) -> PluginState:
    """Load PluginState on first call, return cached state thereafter.

    Test code calls :func:`reset_state_for_tests` between scenarios.
    """
    global _state
    with _state_lock:
        if _state is None:
            _state = _load_state(
                config_path or DEFAULT_HERMES_CONFIG_PATH,
                audit_path,
            )
        return _state


def reset_state_for_tests() -> None:
    """Test helper — clears module-level singletons. Not for production code."""
    global _state, _poison_reason, _degraded_no_origin_skill_emitted
    with _state_lock:
        _state = None
        _poison_reason = None
        _degraded_no_origin_skill_emitted = False


def reload_state() -> None:
    """Public reload entry point — clears the cached PluginState so the
    next hook invocation re-reads ``~/.hermes/config.yaml``.

    Called from ``hermes mordred policy reload``. Does NOT clear the
    poison flag or one-shot ``no_origin_skill`` marker — those are
    process-lifetime invariants and re-asserting them after reload
    requires restarting the session.
    """
    global _state
    with _state_lock:
        _state = None


def _load_config_document(config_path: Path, transaction_marker: Path) -> tuple[PolicyMode, None] | tuple[None, Any]:
    """Load ``config.yaml``, or decide the fail-closed mode without it.

    Returns ``(mode, None)`` when the decision is already settled (pending
    transaction, absent file, unreadable file) and ``(None, document)`` when the
    caller should inspect the parsed YAML.
    """
    if policy_transaction_pending(transaction_marker):
        _LOG.error(
            "policy transaction marker %s is present; failing closed to strict",
            transaction_marker,
        )
        return "strict", None
    try:
        f = config_path.open(encoding="utf-8")
    except FileNotFoundError:
        if policy_transaction_pending(transaction_marker):
            _LOG.error(
                "policy transaction began while opening %s; failing closed to strict",
                config_path,
            )
            return "strict", None
        return "lenient", None
    except OSError as e:
        _LOG.error("config file %s exists but is unreadable (%s); failing closed to strict", config_path, e)
        return "strict", None

    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    try:
        with f:
            data = YAML(typ="safe", pure=True).load(f)
    except (OSError, YAMLError) as e:
        _LOG.error("config file %s exists but is unreadable (%s); failing closed to strict", config_path, e)
        return "strict", None
    if policy_transaction_pending(transaction_marker):
        _LOG.error(
            "policy transaction began while reading %s; failing closed to strict",
            config_path,
        )
        return "strict", None
    return None, data


def _section_from_document(data: Any, config_path: Path) -> tuple[PolicyMode, dict[str, Any]]:
    """Extract ``(policy_mode, section)`` from an already-parsed config document.

    Absence stays lenient; anything PRESENT but wrong-typed is damage and fails
    closed, because collapsing damage into "not configured yet" would silently
    downgrade enforcement.
    """
    if data is None:
        return "lenient", {}  # empty file == freshly-touched config, not damage
    if not isinstance(data, dict):
        _LOG.error("config file %s has a non-mapping root; failing closed to strict", config_path)
        return "strict", {}
    plugins = data.get("plugins")
    if plugins is not None and not isinstance(plugins, dict):
        # A PRESENT but wrong-typed ``plugins`` (e.g. a hand-edited or corrupted
        # ``plugins: "oops"``) is damage, not "plugin not configured yet". It is
        # the same class of corruption as the non-mapping root above, so it must
        # fail closed to strict — collapsing it into the absent-key branch below
        # would silently downgrade enforcement on a damaged config.
        _LOG.error("config file %s has a non-mapping 'plugins' key; failing closed to strict", config_path)
        return "strict", {}
    section_raw = plugins.get("mordred_privacy_check") if plugins is not None else None
    if section_raw is None:
        return "lenient", {}  # plugin not configured — must stay lenient
    if not isinstance(section_raw, dict):
        # Present but wrong-typed OUR section: damage again, not absence.
        _LOG.error(
            "config file %s has a non-mapping 'plugins.mordred_privacy_check'; failing closed to strict",
            config_path,
        )
        return "strict", {}
    section: dict[str, Any] = section_raw
    raw = section.get("policy", "lenient")
    # isinstance before membership mirrors the shared reader; tuple keeps
    # unhashable YAML values on the False branch (hooks.py Codex round 3 P2).
    if isinstance(raw, str) and raw in POLICY_MODES:
        return cast(PolicyMode, raw), section
    _LOG.error("invalid policy %r in %s; failing closed to strict", raw, config_path)
    return "strict", section


def _read_section_fail_closed(config_path: Path) -> tuple[PolicyMode, dict[str, Any]]:
    """``(policy_mode, section)`` — the MODE fails closed, the section degrades.

    M1 port (the fix originally landed only on network's policy.json
    reader): an absent ``config.yaml`` or an absent / not-yet-written
    ``plugins.mordred_privacy_check`` section is a fresh or unconfigured
    install and keeps ``"lenient"`` — but a config.yaml that EXISTS and
    cannot be opened, read, or parsed, a non-mapping root, and an invalid
    ``policy`` value all read as ``"strict"``. Collapsing those to lenient
    (the old ``_load_own_section`` path) meant corrupting or chmod-ing
    config.yaml silently downgraded install-time enforcement.

    Open-first for the same reason as ``_policy_io.read_policy_mode_fail_closed``:
    an ``exists()`` pre-check would misread a stat failure as "absent" →
    lenient. The non-mode fields keep their own degraded defaults — the
    returned section is ``{}`` whenever the file is unreadable, and
    ``allow_cloud_llm``/``audit_log_path`` defaults are already safe.
    """
    settled, data = _load_config_document(
        config_path,
        policy_transaction_marker_for_config(config_path),
    )
    if settled is not None:
        return settled, {}
    return _section_from_document(data, config_path)


def get_active_policy_mode(*, config_path: Path | None = None) -> PolicyMode:
    """Read the active policy mode from ``~/.hermes/config.yaml``.

    Public read-only helper for tools (e.g. wizard's ``policy explain``)
    that must evaluate decisions identically to the install hook without
    touching the cached :class:`PluginState`. Reads via the same
    fail-closed reader the hook's :func:`_load_state` uses, so explainer
    output cannot drift from install-time enforcement when users edit
    (or damage) ``config.yaml`` directly.
    """
    return _read_section_fail_closed(config_path or DEFAULT_HERMES_CONFIG_PATH)[0]


def get_active_audit_path(*, config_path: Path | None = None) -> Path:
    """Read the active audit log path from ``~/.hermes/config.yaml``.

    Public read-only helper mirroring :func:`get_active_policy_mode`.
    Returns the same path the install hook's NDJSONWriter is constructed
    with -- :func:`_resolve_audit_path` applies the under-``_HERMES_BASE``
    sandbox so a malicious config edit cannot redirect the wizard CLI
    elsewhere.

    Required so ``hermes mordred audit tail`` / ``grep`` follow the writer
    when users configure a custom ``plugins.mordred_privacy_check.audit_log_path``;
    otherwise the CLI would silently read the default path and miss entries.
    """
    section = _load_own_section(config_path or DEFAULT_HERMES_CONFIG_PATH)
    if section is None:
        return DEFAULT_AUDIT_PATH
    return _resolve_audit_path(section.get("audit_log_path"))


def _load_state(config_path: Path, audit_path_override: Path | None) -> PluginState:
    # One fail-closed read serves both the mode (strict on a damaged file)
    # and the section (degrades to {} — the remaining fields' defaults are
    # already the safe ones).
    policy_mode, section = _read_section_fail_closed(config_path)

    # M2 (security review 2026-06-11): only the bool ``True`` may grant
    # cloud-LLM permission. ``bool(...)`` truthy-coerced YAML strings, so a
    # hand-edited ``allow_cloud_llm: "false"`` silently *enabled* cloud LLMs.
    raw_allow_cloud = section.get("allow_cloud_llm", False)
    if isinstance(raw_allow_cloud, bool):
        allow_cloud_llm = raw_allow_cloud
    else:
        _LOG.warning(
            "non-boolean allow_cloud_llm %r in config; defaulting to False",
            raw_allow_cloud,
        )
        allow_cloud_llm = False

    raw_allowlist = section.get("cloud_provider_allowlist") or []
    allowlist: tuple[str, ...] = (
        tuple(x for x in raw_allowlist if isinstance(x, str)) if isinstance(raw_allowlist, list) else ()
    )

    audit_path = audit_path_override
    if audit_path is None:
        audit_path = _resolve_audit_path(section.get("audit_log_path"))
    # Encrypt the audit log once the keyvault is initialized. The factory
    # fails open to plaintext NDJSON. keyvault_home is the Hermes
    # home — the directory holding config.yaml.
    # All Mordred plugins share one process-wide writer per normalized path.
    # Reloading this PluginState therefore reuses the active writer (and, for
    # MRAL, its DEK) instead of rotating the file out from under network,
    # llm_guard, or extension-sign hooks that still reference it.
    audit = build_audit_writer(audit_path, keyvault_home=config_path.parent)

    return PluginState(
        policy_mode=policy_mode,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=allowlist,
        audit=audit,
        config_path=config_path,
    )


def _resolve_audit_path(raw: object) -> Path:
    """Resolve and sandbox ``audit_log_path`` from user config.

    Defense-in-depth: even though ``~/.hermes/config.yaml`` is user-owned,
    we constrain the resolved path to live under ``~/.hermes/`` so a
    skill-driven config edit cannot redirect audit entries to e.g.
    ``~/.ssh/authorized_keys``. Out-of-base paths fall back to the default
    audit path with a logged warning.
    """
    if not raw:
        return DEFAULT_AUDIT_PATH
    candidate = Path(str(raw)).expanduser()
    try:
        resolved = candidate.resolve(strict=False)
        base = _HERMES_BASE.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        _LOG.warning("audit_log_path %r could not be resolved (%s); using default", raw, e)
        return DEFAULT_AUDIT_PATH
    if base not in resolved.parents and resolved != base:
        _LOG.warning("audit_log_path %r resolves outside %s; using default", raw, _HERMES_BASE)
        return DEFAULT_AUDIT_PATH
    return resolved


def _load_yaml(path: Path) -> dict[str, Any]:
    # Historically caught bare ``Exception``; ``catch=(Exception,)`` preserves
    # that wider net (see :mod:`mordred_hermes._yaml_io`).
    return load_yaml_mapping(path, catch=(Exception,), log=_LOG)


def _load_own_section(path: Path) -> dict[str, Any] | None:
    """Return the ``plugins.mordred_privacy_check`` mapping, or ``None``.

    Same broad ``catch=(Exception,)`` net as :func:`_load_yaml` — a config
    read must never crash a hook invocation.
    """
    return load_plugin_section(path, "mordred_privacy_check", catch=(Exception,), log=_LOG)


def _read_disabled_from_yaml(config_path: Path) -> set[str]:
    cfg = _load_yaml(config_path)
    plugins = cfg.get("plugins")
    if not isinstance(plugins, dict):
        return set()
    disabled = plugins.get("disabled")
    if isinstance(disabled, list):
        return {x for x in disabled if isinstance(x, str)}
    return set()


def _read_enabled_from_yaml(config_path: Path) -> set[str] | None:
    cfg = _load_yaml(config_path)
    plugins = cfg.get("plugins")
    if not isinstance(plugins, dict) or "enabled" not in plugins:
        return None
    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        return None
    return {x for x in enabled if isinstance(x, str)}


def _is_production_path(config_path: Path | None) -> bool:
    """``None`` and the default-path sentinel both mean "real user config"."""
    return config_path is None or config_path == DEFAULT_HERMES_CONFIG_PATH


def get_disabled_plugins(config_path: Path | None = None) -> set[str]:
    """Return the deny-list.

    Production paths (``None`` or ``DEFAULT_HERMES_CONFIG_PATH``) prefer
    Hermes's private ``_get_disabled_plugins`` API and fall back to reading
    the default YAML (HOOK_PAYLOADS §2). Explicit non-default paths
    (tests, scripted configs) read that path's YAML directly — never the
    user's real config.
    """
    if _is_production_path(config_path):
        try:
            from hermes_cli.plugins import _get_disabled_plugins
        except ImportError:
            pass
        else:
            try:
                return cast(set[str], set(_get_disabled_plugins()))
            except Exception as e:
                _LOG.warning("hermes_cli._get_disabled_plugins failed: %s; falling back to YAML", e)
        return _read_disabled_from_yaml(DEFAULT_HERMES_CONFIG_PATH)
    assert config_path is not None
    return _read_disabled_from_yaml(config_path)


def get_enabled_plugins(config_path: Path | None = None) -> set[str] | None:
    """Return opt-in allow-list (``None`` = key missing/malformed = nothing enabled).

    Path-resolution rules mirror :func:`get_disabled_plugins`.
    """
    if _is_production_path(config_path):
        try:
            from hermes_cli.plugins import _get_enabled_plugins
        except ImportError:
            pass
        else:
            try:
                result = _get_enabled_plugins()
                return None if result is None else cast(set[str], set(result))
            except Exception as e:
                _LOG.warning("hermes_cli._get_enabled_plugins failed: %s; falling back to YAML", e)
        return _read_enabled_from_yaml(DEFAULT_HERMES_CONFIG_PATH)
    assert config_path is not None
    return _read_enabled_from_yaml(config_path)


def find_disabled_siblings(
    siblings: Iterable[str] = SIBLING_PLUGINS,
    *,
    config_path: Path | None = None,
) -> set[str]:
    """Return Mordred plugins that are not loadable per config.

    A plugin is considered disabled if it appears in ``plugins.disabled`` or
    is absent from the opt-in ``plugins.enabled`` list.  Hermes 0.13+ treats a
    missing or malformed allow-list (reported here as ``None``) as "nothing
    enabled", not "everything loadable", so every sibling is disabled in that
    case.

    ``config_path=None`` uses production resolution (Hermes API + default YAML).
    Explicit paths read only that YAML — never the user's real config.
    """
    deny = get_disabled_plugins(config_path)
    allow = get_enabled_plugins(config_path)
    if allow is None:
        return set(siblings)
    return {s for s in siblings if s in deny or s not in allow}


def find_legacy_plugin_names(*, config_path: Path | None = None) -> set[str]:
    """Pre-0.2.0a0 per-component plugin names still listed in the config.

    Hermes ignores them now; they only explain why ``mordred`` is missing
    (an unmigrated config) and point at the migration command.
    """
    listed = set(get_disabled_plugins(config_path))
    listed |= get_enabled_plugins(config_path) or set()
    return listed & set(LEGACY_PLUGIN_NAMES)


def find_unloaded_siblings(
    plugin_manager: Any,
    siblings: Iterable[str] = SIBLING_PLUGINS,
) -> set[str]:
    """Return configured plugins/components absent or incomplete in Hermes's live state."""
    raw_plugins = getattr(plugin_manager, "_plugins", None)
    if not isinstance(raw_plugins, dict):
        # Manager shape drift means no live sibling can be proven loaded.
        return set(siblings)
    failed: set[str] = set()
    for sibling in siblings:
        loaded = raw_plugins.get(sibling)
        if loaded is None:
            failed.add(sibling)
            continue
        module = getattr(loaded, "module", None)
        if getattr(loaded, "enabled", False) is not True or bool(getattr(loaded, "error", None)) or module is None:
            failed.add(sibling)
            continue
        hooks = getattr(loaded, "hooks_registered", None)
        required = SIBLING_REQUIRED_HOOKS.get(sibling, frozenset())
        if not isinstance(hooks, list) or not required.issubset(hook for hook in hooks if isinstance(hook, str)):
            failed.add(sibling)
            continue
        if sibling == PLUGIN_NAME and getattr(module, "__name__", None) == _PLUGIN_MODULE:
            failed |= _unloaded_components(module)
    return failed


def _unloaded_components(plugin_module: Any) -> set[str]:
    """``mordred/<component>`` for each component that failed or lacks a promised hook.

    Reads the record kept by the loaded :mod:`mordred_hermes.plugin` module. A
    component that raised is reported even though Hermes shows the plugin as
    loaded — the bundle contains the failure so the other components keep
    protecting the process, exactly as a failed sibling plugin used to.
    """
    try:
        errors = plugin_module.component_errors()
        hooks = plugin_module.component_hooks()
    except Exception:
        return {f"{PLUGIN_NAME}/{component}" for component, _module in COMPONENTS}
    failed: set[str] = set()
    for component, _module in COMPONENTS:
        registered = hooks.get(component)
        if component in errors or registered is None or not COMPONENT_REQUIRED_HOOKS[component] <= registered:
            failed.add(f"{PLUGIN_NAME}/{component}")
    return failed


def poison(reason: str) -> None:
    """Mark this process as poisoned — every subsequent ``pre_tool_call`` blocks.

    In production the poison flag is monotonic (set once, never cleared), so
    racing reads always see a consistent value. The lock here is mainly for
    test cleanliness (``reset_state_for_tests`` runs concurrently with hooks
    in some test workers).
    """
    global _poison_reason
    with _state_lock:
        _poison_reason = reason


def is_poisoned() -> bool:
    with _state_lock:
        return _poison_reason is not None


def get_poison_reason() -> str | None:
    with _state_lock:
        return _poison_reason


def claim_no_origin_skill_emit() -> bool:
    """One-shot guard for the ``mordred.degraded.no_origin_skill`` audit entry.

    Returns ``True`` exactly once per process; subsequent calls return ``False``.
    """
    global _degraded_no_origin_skill_emitted
    with _state_lock:
        if _degraded_no_origin_skill_emitted:
            return False
        _degraded_no_origin_skill_emitted = True
        return True
