"""Detect agent-harness primaries that bypass Hermes enforcement.

External harnesses (Codex CLI, Claude CLI, Cursor, and ACP clients) run their
own LLM call paths outside Hermes, so neither Mordred's ``pre_api_request``
hook nor its auxiliary-client guards observe that traffic. Strict mode refuses
the session at startup; lenient mode warns and audits; off mode is a no-op.

The harness identity is declared by the user in ``~/.hermes/config.yaml``:

.. code-block:: yaml

   plugins:
     mordred_llm_guard:
       harness_primary: codex      # or claude-cli / cursor / acp-claude / ...

Prefix-based matching avoids both:

- false negatives from version suffixes (``codex-0.130.0``)
- false positives from substring containment (``my-cursor-helper`` is NOT
  cursor; ``codex-style-prompt`` is NOT codex)

This module is read-only: it never writes to ``config.yaml`` or to
``policy.json``. The wizard is the sole writer of those files
(PATHS.md §writer column).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .._audit_support import AuditWriter as _AuditWriter
from .._audit_support import safe_audit_append
from .._yaml_io import load_plugin_section
from ._exceptions import MordredHarnessRefused

_LOG = logging.getLogger("mordred.llm_guard.harness_detect")

# Allowlist of harness-primary identifiers as compiled regexes.
# Keep in sync with SPEC.md §Threat Model & Accepted Limitations.
#
# Matching rules per harness:
#   - codex / claude-cli / cursor: exact OR ``<harness>-<semver>``
#     (semver = digits + dots only). This admits ``codex-0.130.0`` while
#     rejecting ``codex-style-prompt`` and ``my-cursor-helper``.
#   - acp-: prefix form, the suffix is the ACP flavor (``claude``, ``cline``).
#     Must contain at least one non-empty token after the dash; bare ``acp-``
#     does not match.
_VERSION_SUFFIX = r"(-\d+(?:\.\d+)*)?"  # optional ``-1`` / ``-0.130.0`` / etc.
_HARNESS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"^codex{_VERSION_SUFFIX}$"),
    re.compile(rf"^claude-cli{_VERSION_SUFFIX}$"),
    re.compile(rf"^cursor{_VERSION_SUFFIX}$"),
    re.compile(r"^acp-[a-z][a-z0-9-]*$"),
)

# Audit reason — shared with privacy_check's sibling-disable degradation
# because the operational risk is the same (Mordred cannot observe LLM
# traffic). The 12-code freeze (POLICY.md) does not yet include a
# harness-specific reason; if Phase 2 PR2 adds one, swap here.
_REASON = "mordred.degraded.disable_unprotected"


def _safe_audit_append(audit: _AuditWriter, entry: Mapping[str, Any]) -> None:
    """Best-effort audit write binding this module's logger.

    Thin wrapper over :func:`mordred_hermes._audit_support.safe_audit_append`
    (security review H1): the strict-mode refusal raises
    :class:`MordredHarnessRefused` (``BaseException``-derived) and must still
    fire even if the audit write itself raises a plain ``Exception`` before
    the refusal -- otherwise Hermes would swallow it and continue (fail-open).
    """
    safe_audit_append(audit, entry, logger=_LOG)


def check_harness_primary(
    *,
    policy_mode: str,
    config_path: Path,
    audit: _AuditWriter,
) -> None:
    """Inspect the declared harness primary and act according to ``policy_mode``.

    Raises :class:`MordredHarnessRefused` only under strict mode when a
    known harness prefix matches. Otherwise emits an audit warning (lenient)
    or returns silently (off / unknown harness / missing config).

    The audit entry is written BEFORE the raise so the refusal is
    observable even when the BaseException propagates past
    ``except Exception:`` wrappers.
    """
    harness = _read_harness_primary(config_path)
    if harness is None:
        return  # nothing to check

    if not _is_known_harness(harness):
        return  # user declared a non-harness primary; ignore

    if policy_mode == "off":
        # Off mode: silent no-op. The user has explicitly opted out of
        # Mordred enforcement; we do not even audit (matches the
        # privacy_check ``off`` semantics at install_wrapper).
        return

    decision = "block" if policy_mode == "strict" else "warn"

    # Best-effort: a failing audit write must not stop the strict-mode
    # refusal below from raising (security review H1).
    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": decision,
            "reason": _REASON,
            "harness_primary": harness,
        },
    )

    if decision == "block":
        msg = (
            f"Mordred strict mode: harness primary {harness!r} bypasses Hermes hooks; "
            "refusing the session. Switch to a non-harness primary or set policy to lenient."
        )
        _LOG.error(msg)
        raise MordredHarnessRefused(msg)

    # lenient (or fallback) — warn + continue
    _LOG.warning(
        "Mordred lenient mode: harness primary %r bypasses Hermes hooks; continuing with degraded enforcement",
        harness,
    )


def _is_known_harness(harness_primary: str) -> bool:
    """Match the declared primary against the allowlist of regex patterns.

    Empty string never matches. Substring containment never matches.
    Version-suffix forms (``codex-0.130.0``) match; non-version suffixes
    (``codex-style-prompt``) do not.
    """
    if not harness_primary:
        return False
    return any(pattern.match(harness_primary) for pattern in _HARNESS_PATTERNS)


def _read_harness_primary(config_path: Path) -> str | None:
    """Read ``plugins.mordred_llm_guard.harness_primary`` from config.yaml.

    Returns ``None`` if the file or key is absent — this is the wizard-
    not-yet-run path, which must never trigger a refusal (users would be
    locked out before they could configure).
    """
    # Historically caught bare ``Exception``; ``catch=(Exception,)`` preserves
    # that wider net (the wizard-not-yet-run path must never raise).
    section = load_plugin_section(config_path, "mordred_llm_guard", catch=(Exception,), log=_LOG)
    if section is None:
        return None

    value = section.get("harness_primary")
    if not isinstance(value, str):
        return None
    return value
