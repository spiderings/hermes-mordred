"""Phase 4 PR2 + PR3 step-0 freeze of ``keyvault.*`` audit reason codes.

Per ``docs/dev/POLICY.md`` §Phase 4 step-0 freeze (added
2026-05-14, PR2 + PR3): only codes with an emit site OR already
referenced by frozen SPEC text are included.

PR2 adds 2 codes (already landed):

- ``keyvault.recovery_digest_mismatch`` — emitted by
  ``recovery.import_backup`` BEFORE AES-GCM decryption runs, paired with
  :class:`mordred_hermes.keyvault.recovery.RecoveryDigestMismatch` raise.
  Codex review #4: verify-before-decrypt prevents secret materialization
  on mismatch. Decision ``block``. Fields: ``blob_version``,
  ``event="keyvault.import_backup"``.
- ``keyvault.seed_display_aborted_screenshot`` — SPEC §Seed phrase display
  security requires this stable reason at the ``seed_display.py`` emit site.
  Decision
  ``block``. Fields: ``event="keyvault.seed_display"``, ``detector``.

PR3 adds 2 codes (this PR) for Secure-Enclave-authorized DEK unwrap.
Authorization happens on **unwrap** only — wrap uses the Enclave public
key + a software ephemeral private key and never prompts the user
(codex review BLOCKER-1 / HIGH-3):

- ``keyvault.unwrap_authorized`` — emitted by ``wrap.unwrap_dek`` after
  ``SecKeyCopyKeyExchangeResult`` succeeds (biometric / passcode access
  control satisfied). Decision ``allow``. Fields:
  ``event="keyvault.unwrap_dek"``, ``key_id_hash`` (hex prefix; never
  the full ``key_id``).
- ``keyvault.unwrap_denied`` — emitted when the Enclave returns
  ``errSecUserCancelled`` / ``errSecAuthFailed`` / equivalent NSError,
  paired with :class:`mordred_hermes.keyvault.wrap.WrapAuthCancelled`
  raise. Decision ``block``. Fields: ``event="keyvault.unwrap_dek"``,
  ``native_error_code`` (translated; never the raw OSStatus).

PR4 step-D (``keyvault.init_*``) and step-E (``keyvault.backup_exported``)
reason codes graduate into the freeze as each emit site lands — the
"freeze a code only once it has an emit site" discipline that avoids the
"frozen but unused" footgun Phase 2 hit with
``policy.strict.local_stream_interrupted`` (POLICY.md entry #12).
``keyvault.backup_exported`` (#24) is frozen as of step-E because
``api.export_backup`` now emits it; the membership assertion lives in
``test_keyvault_api_backup.test_backup_exported_is_now_in_freeze``
alongside the emit-site behavior tests.
"""

from __future__ import annotations

from typing import get_args


def test_keyvault_recovery_digest_mismatch_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.recovery_digest_mismatch" in get_args(ReasonCode)


def test_keyvault_seed_display_aborted_screenshot_in_freeze() -> None:
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.seed_display_aborted_screenshot" in get_args(ReasonCode)


def test_keyvault_unwrap_authorized_in_freeze() -> None:
    """PR3 step-0 freeze: emit site is ``wrap.unwrap_dek`` after a
    successful ``SecKeyCopyKeyExchangeResult`` call. Codex review
    BLOCKER-1: authorization happens on unwrap, not wrap."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.unwrap_authorized" in get_args(ReasonCode)


def test_keyvault_unwrap_denied_in_freeze() -> None:
    """PR3 step-0 freeze: paired with
    :class:`mordred_hermes.keyvault.wrap.WrapAuthCancelled` raise when the
    Enclave returns ``errSecUserCancelled`` / ``errSecAuthFailed``."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.unwrap_denied" in get_args(ReasonCode)


def test_keyvault_init_started_in_freeze() -> None:
    """PR4 step-D (PR4c-2): emit site is ``api.confirm_generate`` — the
    durability barrier, emitted before any Keychain / meta.json mutation.
    Sink failure aborts the whole init (fail-closed). POLICY.md #21."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.init_started" in get_args(ReasonCode)


def test_keyvault_init_completed_in_freeze() -> None:
    """PR4 step-D (PR4c-2): emit site is ``api.confirm_generate`` success
    path — Enclave key created, meta.json row + digests/<kid>.commit
    persisted. Sink failure suppressed (init already durable). POLICY.md #22."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.init_completed" in get_args(ReasonCode)


def test_keyvault_init_denied_in_freeze() -> None:
    """PR4 step-D (PR4c-2): emit site is ``api.confirm_generate`` on a
    digest mismatch — paired with a ``VerificationDigestMismatch`` raise,
    emitted before any mutation. Sink failure chains as ``__context__``
    on the raised exception. POLICY.md #23."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.init_denied" in get_args(ReasonCode)


def test_keyvault_codes_use_dotted_form() -> None:
    """Naming convention check: ``keyvault.*`` mirrors ``policy.*`` /
    ``mordred.*`` / ``network.*`` dotted form."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    keyvault_codes = [c for c in get_args(ReasonCode) if c.startswith("keyvault")]
    assert keyvault_codes, "Phase 4 freeze added no keyvault.* codes"
    for code in keyvault_codes:
        assert "." in code, f"underscore-form {code!r} violates dotted convention"
        assert "_" not in code.split(".", 1)[0], (
            f"prefix segment of {code!r} must be a single token (got {code.split('.', 1)[0]!r})"
        )


def test_policy_strict_keyvault_uninitialized_in_freeze() -> None:
    """Phase 4 §4.1: emit site is ``install_wrapper.run`` — strict policy +
    ``requires_keyvault: true`` skill + an uninitialized keyvault, paired
    with an ``InstallBlocked`` raise. POLICY.md #25."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "policy.strict.keyvault_uninitialized" in get_args(ReasonCode)


def test_policy_lenient_keyvault_uninitialized_warning_in_freeze() -> None:
    """Phase 4 §4.1: lenient counterpart — install proceeds with an audit
    ``decision=warn``. POLICY.md #26."""
    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "policy.lenient.keyvault_uninitialized_warning" in get_args(ReasonCode)
