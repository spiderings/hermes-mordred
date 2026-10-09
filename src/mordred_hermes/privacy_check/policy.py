"""Pure policy evaluator — no I/O, no globals.

Two entry points:

- :func:`evaluate_install` — install-time decision driven by SKILL.md
  ``metadata.mordred.network_requirements`` + active policy mode.
- :func:`evaluate_pre_tool_call` — runtime ``pre_tool_call`` hook decision.
  v1 is generic tool-name allowlist only; per-skill enforcement is not
  possible because ``origin_skill`` is absent from the payload (HOOK_PAYLOADS.md §4).

All decisions return a :class:`PolicyOutcome` carrying a frozen
:data:`~._audit_reasons.ReasonCode`. Mypy strict catches drift between
this evaluator and the audit writer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

from .._policy_types import ActivePath as ActivePath
from .._policy_types import PolicyMode as PolicyMode
from ._audit_reasons import ReasonCode

NetworkRequirement: TypeAlias = Literal["tor", "vpn", "clearnet", "local-only"]
Decision: TypeAlias = Literal["allow", "block", "warn"]

VALID_NETWORK_REQUIREMENTS: Final[frozenset[str]] = frozenset({"tor", "vpn", "clearnet", "local-only"})

# Default strict-mode clearnet blocklist (POLICY.md §Runtime (`pre_tool_call`)).
DEFAULT_STRICT_CLEARNET_TOOL_BLOCKLIST: Final[frozenset[str]] = frozenset({"web_fetch", "web_search"})


@dataclass(frozen=True, slots=True)
class PolicyOutcome:
    """A policy decision and its frozen reason code (None for off-mode allow)."""

    decision: Decision
    reason: ReasonCode | None


def evaluate_install(
    *,
    policy_mode: PolicyMode,
    network_requirements: NetworkRequirement | None,
    requires_keyvault: bool = False,
    keyvault_initialized: bool = True,
) -> PolicyOutcome:
    """Decide whether ``hermes mordred install <skill>`` should proceed.

    Network decision matrix (POLICY.md §Install-time):

    ======= ========================== ============== ============================================
    mode    network_requirements       decision       reason
    ======= ========================== ============== ============================================
    off     *                          allow          None
    strict  None                       block          policy.strict.unknown_metadata
    strict  "clearnet"                 block          policy.strict.clearnet
    strict  "tor"|"vpn"|"local-only"   allow          None
    lenient None                       warn (audited) policy.lenient.unknown_metadata_warning
    lenient *                          allow          None
    ======= ========================== ============== ============================================

    Keyvault opt-in enforcement (POLICY.md §Install-time). When the skill
    declares ``metadata.mordred.requires_keyvault: true`` (``requires_keyvault``)
    and the Mordred keyvault holds no keys (``keyvault_initialized`` is False):

    ======= ============== ============================================
    mode    decision       reason
    ======= ============== ============================================
    off     allow          None
    strict  block          policy.strict.keyvault_uninitialized
    lenient warn (audited) policy.lenient.keyvault_uninitialized_warning
    ======= ============== ============================================

    A network-level ``block`` short-circuits before the keyvault check — the
    install will not run anyway. Otherwise ``block`` from the keyvault check
    wins over a network-level ``warn``/``allow`` (most paranoid outcome). The
    ``keyvault_initialized`` flag is supplied by the caller; this evaluator
    stays pure (the backend-free probe lives in :mod:`._keyvault_probe`).

    ``warn`` is treated as ``allow`` by the install wrapper but produces an
    audit entry — install proceeds, user is informed.
    """
    if policy_mode == "off":
        return PolicyOutcome("allow", None)

    if network_requirements is None:
        if policy_mode == "strict":
            return PolicyOutcome("block", "policy.strict.unknown_metadata")
        network_outcome = PolicyOutcome("warn", "policy.lenient.unknown_metadata_warning")
    elif policy_mode == "strict" and network_requirements == "clearnet":
        return PolicyOutcome("block", "policy.strict.clearnet")
    else:
        network_outcome = PolicyOutcome("allow", None)

    if requires_keyvault and not keyvault_initialized:
        if policy_mode == "strict":
            return PolicyOutcome("block", "policy.strict.keyvault_uninitialized")
        return PolicyOutcome("warn", "policy.lenient.keyvault_uninitialized_warning")

    return network_outcome


def evaluate_pre_tool_call(
    *,
    policy_mode: PolicyMode,
    tool_name: str,
    active_path: ActivePath | None,
    blocklist: frozenset[str] = DEFAULT_STRICT_CLEARNET_TOOL_BLOCKLIST,
) -> PolicyOutcome:
    """Decide whether a ``pre_tool_call`` should be blocked.

    v1 is generic tool-name allowlist only — ``origin_skill`` is absent from
    the Hermes payload (HOOK_PAYLOADS.md §4) so per-skill enforcement is not
    possible at runtime. Per-skill logic lives in :func:`evaluate_install`.

    Phase 1 ``active_path`` is always ``None`` because Phase 3 wires the
    network state. ``None`` is treated as ``"clearnet"`` in strict mode —
    the most paranoid default — so behaviour is well-defined before Phase 3
    lands. Lenient and off modes always allow.
    """
    if policy_mode != "strict":
        return PolicyOutcome("allow", None)

    effective_path: ActivePath = active_path if active_path is not None else "clearnet"
    if effective_path == "clearnet" and tool_name in blocklist:
        return PolicyOutcome("block", "policy.strict.clearnet")

    return PolicyOutcome("allow", None)
