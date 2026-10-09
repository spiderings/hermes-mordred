"""Tests for the ``network.*`` audit reason codes.

The central ``privacy_check._audit_reasons.ReasonCode`` Literal is the typed
source of truth used by every plugin's audit emit sites. Network reasons cover:

- ``network.use`` — successful path switch via ``api.use(path)``. Decision
  ``override``. Fields: ``prev_path`` / ``new_path`` / ``live_subprocess_count``
  (M3 transitive-failure visibility — ``> 0`` means env updates won't reach
  already-running children).
- ``network.use_failed`` — ``api.use(path)`` raised :class:`MordredNetworkError`.
  Decision ``raise``. Fields: ``requested_path`` / ``error_type`` / ``prev_path``.
- ``network.bringup_failed`` — lenient-mode path bring-up failure with
  clearnet fallback. Decision ``warn``. Fields: ``path`` / ``error_type``.
  Strict mode emits this *and* raises :class:`MordredPathBringupFailed`.
- ``network.path_dropped`` — M9 liveness probe detected 2 consecutive
  failures. Decision ``block`` (strict) / ``warn`` (lenient). Fields:
  ``path`` / ``consecutive_failures`` / ``last_health_at``.

Names use dotted form (``network.use``, not ``network_use``), consistently with
the ``policy.*`` and ``mordred.*`` families documented in POLICY.md.
"""

from __future__ import annotations

from typing import get_args


def test_network_use_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.use" in get_args(ReasonCode)


def test_network_use_failed_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.use_failed" in get_args(ReasonCode)


def test_network_bringup_failed_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.bringup_failed" in get_args(ReasonCode)


def test_network_path_dropped_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.path_dropped" in get_args(ReasonCode)


def test_network_transport_incompatible_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "network.transport_incompatible" in get_args(ReasonCode)


def test_phase1_freeze_preserved() -> None:
    """Adding Phase 3 codes must not remove or rename Phase 1 codes."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    phase1_codes = {
        "policy.strict.clearnet",
        "policy.strict.unknown_metadata",
        "policy.strict.unconditional_override",
        "policy.strict.cloud_not_allowlisted",
        "policy.strict.cloud_allowlisted",
        "policy.lenient.unknown_metadata_warning",
        "mordred.degraded.disable_unprotected",
        "mordred.degraded.no_origin_skill",
        "mordred.degraded.no_resolved_provider",
        "policy.strict.local_stream_interrupted",
        "policy.strict.session_refused",
        "policy.strict.provider_override_at_session_start",
    }
    members = set(get_args(ReasonCode))
    missing = phase1_codes - members
    assert not missing, f"Phase 1 codes accidentally removed: {sorted(missing)}"


def test_total_freeze_size_after_transport_gate_followup() -> None:
    """After the prompt-once freeze: 12 Phase 1 + 4 Phase 3 +
    2 Phase 4 PR2 + 2 Phase 4 PR3 + 3 Phase 4 PR4c (keyvault.init_*) +
    1 Phase 4 PR4 step-E (keyvault.backup_exported) + 2 Phase 4 §4.1
    (policy.*.keyvault_uninitialized) + 1 PR #39 review follow-up
    (mordred.degraded.audit_encryption_unavailable) + 2 prompt-once
    (policy.strict.cloud_prompted_allow / _deny) + 1 Phase 3 transport-gate
    follow-up (network.transport_incompatible) + 1 strict cloud endpoint
    binding follow-up (policy.strict.cloud_endpoint_mismatch) + 1 tool-egress
    levels (policy.egress.tool_blocked) = 32.

    The §4.1 codes graduated into the freeze because their emit site —
    ``install_wrapper.run``'s ``requires_keyvault`` enforcement — exists.
    The PR #39 follow-up code has its emit site in
    ``audit.make_audit_writer``'s encrypted→plaintext fallback branch. The
    prompt-once codes have their emit site in
    ``llm_guard.enforce._resolve_cloud_attempt``.

    If a future PR bumps this, update POLICY.md's "Total freeze becomes N"
    statement in the same commit so the doc and the type stay in lockstep.
    """
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert len(get_args(ReasonCode)) == 32


def test_no_underscore_typo_legacy_name() -> None:
    """Reject the old underscore spelling; dotted names are canonical."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    members = set(get_args(ReasonCode))
    assert "network_use" not in members
    assert "network.use" in members
