"""Hook handlers for ``mordred_privacy_check``.

Hermes invokes hooks via ``invoke_hook(name, **kwargs)``. Each handler
must accept arbitrary kwargs because Hermes adds new payload fields
without breaking the existing call-site contract — the handler should
ignore unknown kwargs.

Return shape contracts (HOOK_PAYLOADS.md §1, §4):

- ``on_session_start`` — return value ignored.
  :class:`MordredIntegrityRefused` propagates past Hermes's
  ``except Exception`` wrapper, letting strict mode actually abort the
  session without masquerading as an ordinary process exit. Defense in
  depth: also poisons the process so any
  subsequent ``pre_tool_call`` blocks unconditionally.
- ``pre_tool_call`` — return ``None`` to allow, or
  ``{"action": "block", "message": str}`` to block.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from typing import Any, cast

from .._audit_support import safe_audit_append
from .._plugin_identity import MIGRATE_COMMAND, PLUGIN_NAME
from .._policy_types import VALID_ACTIVE_PATHS, ActivePath
from . import _runtime
from ._exceptions import MordredIntegrityRefused
from .policy import evaluate_pre_tool_call

_LOG = logging.getLogger("mordred.privacy_check")


def _resolve_active_network_path() -> ActivePath | None:
    """Return a ready Mordred network path, failing closed to ``None``.

    The privacy plugin is loaded before the network plugin in the default
    plugin order, so this lookup must stay lazy. A missing runtime, a route
    still being brought up, or an invalid future status all map to ``None``;
    :func:`evaluate_pre_tool_call` deliberately treats that as clearnet under
    strict policy.
    """
    try:
        from ..network import api

        status = api.status()
    except Exception:
        return None
    if not status.ready or status.active_path not in VALID_ACTIVE_PATHS:
        return None
    return cast(ActivePath, status.active_path)


def check_plugin_integrity(**kwargs: Any) -> None:
    """Detect a disabled, unloaded, or partially registered Mordred plugin.

    Strict + disabled/incomplete → audit + poison + integrity refusal.
    Lenient/off + disabled/incomplete → audit (warn) + log warning, continue.

    The ``mordred`` plugin registers this callback first, before its
    components, and the ``.pth`` runtime bootstrap puts a mandatory copy at the
    front of ``on_session_start`` that runs even when the plugin is disabled or
    not enabled at all (``mordred_hermes._runtime_bootstrap``). With the
    manager in hand it also reports each failed component as
    ``mordred/<component>``.
    """
    state = _runtime.ensure_state()
    disabled = _runtime.find_disabled_siblings(config_path=state.config_path)
    plugin_manager = kwargs.get("plugin_manager")
    if plugin_manager is not None:
        disabled.update(_runtime.find_unloaded_siblings(plugin_manager))

    if disabled:
        hint = _legacy_names_hint(state.config_path) if PLUGIN_NAME in disabled else ""
        decision = "block" if state.policy_mode == "strict" else "warn"
        # safe_audit_append, not a bare append: Hermes wraps every hook callback
        # in ``except Exception`` and logs-and-continues. A plain Exception from
        # the audit write (disk full, permission flip, an over-long entry) would
        # therefore be swallowed BEFORE the refusal below ever fires, and the
        # session would proceed unprotected — a fail-open bypass of the very
        # gate this hook exists to enforce. The refusal must outrank the audit
        # write, so audit-side errors are logged and swallowed here instead.
        safe_audit_append(
            state.audit,
            {
                "event": "on_session_start",
                "decision": decision,
                "reason": "mordred.degraded.disable_unprotected",
                "disabled_siblings": sorted(disabled),
            },
            logger=_LOG,
        )
        if state.policy_mode == "strict":
            msg = (
                f"Mordred strict mode: Mordred plugin not loaded or incomplete: {sorted(disabled)}. "
                f"Enable the '{PLUGIN_NAME}' plugin and fix the failure, or switch to lenient/off mode.{hint}"
            )
            _runtime.poison(msg)
            _LOG.error(msg)
            # The refusal is a bare BaseException by design (_exceptions.py)
            # and typically surfaces in the host as an unhandled-exception
            # traceback. Print the policy line to stderr first so the
            # operator always sees the documented strict-policy abort, not
            # just a crash dump (review 2026-07-29: the pre-refactor
            # ``SystemExit(msg)`` printed exactly this one line). The print
            # itself must never outrank the refusal: with a closed or absent
            # stderr (daemonized gateway, pythonw) it raises an ordinary
            # Exception that Hermes's hook wrapper would swallow — a
            # fail-open — so any presenter error is suppressed.
            with contextlib.suppress(Exception):
                print(f"mordred: {msg}", file=sys.stderr)
            raise MordredIntegrityRefused(msg)
        _LOG.warning(
            "Mordred plugin not loaded or incomplete in %s mode: %s.%s", state.policy_mode, sorted(disabled), hint
        )


def _legacy_names_hint(config_path: Any) -> str:
    """Point an unmigrated config (old per-component plugin names) at the fix."""
    try:
        legacy = _runtime.find_legacy_plugin_names(config_path=config_path)
    except Exception:
        return ""
    if not legacy:
        return ""
    return (
        f" config.yaml still lists the old plugin names {sorted(legacy)}, which Hermes no longer loads; "
        f"run `{MIGRATE_COMMAND}` to switch to '{PLUGIN_NAME}'."
    )


def on_session_start(**kwargs: Any) -> None:
    """Run the shared integrity gate and emit one-shot degraded markers.

    Always emits ``mordred.degraded.no_origin_skill`` once per process
    (HOOK_PAYLOADS §4: ``origin_skill`` absent from ``pre_tool_call`` payload).
    """
    check_plugin_integrity(**kwargs)
    state = _runtime.ensure_state()
    if _runtime.claim_no_origin_skill_emit():
        safe_audit_append(
            state.audit,
            {
                "event": "on_session_start",
                "decision": "warn",
                "reason": "mordred.degraded.no_origin_skill",
            },
            logger=_LOG,
        )


def _check_tool_egress(state: Any, tool_name: str, kwargs: dict[str, Any]) -> dict[str, Any] | None:
    """Apply the tool-egress level (see :mod:`.egress`); fail closed on errors."""
    from . import egress

    session_id = str(kwargs.get("session_id") or "") or None
    try:
        policy = egress.load_policy()
        decision = egress.decide(tool_name, kwargs.get("args"), session_id, policy)
    except Exception:
        _LOG.exception("tool-egress evaluation failed; blocking %s", tool_name)
        policy = egress.EgressPolicy(level="lockdown")
        decision = egress._block("lockdown", "egress.evaluation_failed", "the egress check itself failed.")
    if decision.allow:
        if decision.taints and policy.taint:
            egress.mark_tainted(session_id)
        return None
    if decision.approve:
        # Hermes shows its approval prompt (once / session / always / deny) and
        # blocks the call on deny or when no human is present.
        safe_audit_append(
            state.audit,
            {
                "event": "pre_tool_call",
                "decision": "ask",
                "reason": "policy.egress.tool_blocked",
                "rule": decision.reason,
                "level": policy.level,
                "tool_name": tool_name,
            },
            logger=_LOG,
        )
        return {"action": "approve", "message": decision.message, "rule_key": decision.rule_key}
    safe_audit_append(
        state.audit,
        {
            "event": "pre_tool_call",
            "decision": "block",
            "reason": "policy.egress.tool_blocked",
            "rule": decision.reason,
            "level": policy.level,
            "tool_name": tool_name,
        },
        logger=_LOG,
    )
    return {"action": "block", "message": decision.message}


def pre_tool_call(**kwargs: Any) -> dict[str, Any] | None:
    """Evaluate the generic strict-mode tool-name allowlist.

    Per-skill enforcement is not possible at runtime — ``origin_skill``
    is absent from the payload (HOOK_PAYLOADS §4). Strict-mode
    per-skill checks live in :mod:`install_wrapper`.
    """
    state = _runtime.ensure_state()
    tool_name = str(kwargs.get("tool_name") or "")

    if _runtime.is_poisoned():
        # Same fail-open reasoning as on_session_start: the block decision must
        # survive an audit-write failure, so the append can never raise past us.
        safe_audit_append(
            state.audit,
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": "mordred.degraded.disable_unprotected",
                "tool_name": tool_name,
            },
            logger=_LOG,
        )
        return {
            "action": "block",
            "message": _runtime.get_poison_reason() or "Mordred strict mode: process poisoned",
        }

    egress_block = _check_tool_egress(state, tool_name, kwargs)
    if egress_block is not None:
        return egress_block

    outcome = evaluate_pre_tool_call(
        policy_mode=state.policy_mode,
        tool_name=tool_name,
        active_path=_resolve_active_network_path(),
    )
    if outcome.decision == "block":
        safe_audit_append(
            state.audit,
            {
                "event": "pre_tool_call",
                "decision": "block",
                "reason": outcome.reason,
                "tool_name": tool_name,
            },
            logger=_LOG,
        )
        return {
            "action": "block",
            "message": (
                f"Mordred strict policy blocks tool {tool_name!r} on the clearnet path. "
                "Switch the active network path or disable strict mode."
            ),
        }
    return None


NETWORK_PROMPT = """## Internet use (Mordred)
Do the work locally: files, local commands and code are fine. `web_search` is \
fine. Avoid any other internet access (opening URLs, browsing, curl/wget, \
installing packages, remote APIs, git push/pull): use it only when the task \
really needs it. Each such call shows the user an approval prompt with where \
it goes and what it sends, so say in one line why before you call it, and \
accept a refusal. Never send the user's private data (Telegram answers, file \
contents, notes) to the internet. Blocklisted sites and bare IP addresses are \
always refused."""


def network_prompt_section() -> str:
    """The prompt section for the ``ask`` level (empty when another level is set)."""
    from . import egress

    try:
        level = egress.load_policy().level
    except Exception:
        return ""
    return NETWORK_PROMPT if level == "ask" else ""
