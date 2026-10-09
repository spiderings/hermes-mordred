"""Tests for ``mordred_hermes.keyvault.recovery`` — verify-before-decrypt.

Phase 4 PR2 fourth RED → GREEN target (after digest + backup).

The core safety property (Codex review #4): when the user attempts to
import a backup blob, recovery.import_backup MUST verify the embedded
verification_digest against a caller-supplied recomputed digest BEFORE
running the Argon2id KDF or the AES-GCM decryption. This means:

1. Mismatched digest → :class:`RecoveryDigestMismatch` raise, no
   ciphertext ever decrypted, no secret materialized in memory.
2. Mismatched digest with an ``audit_sink`` supplied → emit a single
   audit entry with reason ``keyvault.recovery_digest_mismatch`` and
   decision ``block`` (POLICY.md Phase 4 freeze table entry #17),
   THEN raise.
3. Matching digest → proceed to ``backup.decrypt_body`` and return the
   secret on success. ``InvalidTag`` from the AES layer (wrong
   passphrase, header tamper, ciphertext tamper) propagates as-is —
   recovery does NOT swallow or remap it.

The audit_sink contract intentionally accepts a single ``dict`` so it
matches POLICY.md's audit entry shape (event/decision/reason/extras)
rather than a POLICY-incompatible (reason, extras) tuple form (Codex
review #9).
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

# Re-used 32-byte verification_digest stand-in (same as
# test_keyvault_backup.py).
DIGEST_FIXTURE = bytes.fromhex("25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93")
WRONG_DIGEST = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
OFF_BY_ONE_DIGEST = bytes.fromhex(
    # Same as DIGEST_FIXTURE except the last byte is 0x92 instead of 0x93.
    "25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c92"
)
PASSPHRASE = "correct horse battery staple"
SECRET = b"the quick brown fox jumps over 24 BIP39 words"


@pytest.fixture
def valid_blob() -> bytes:
    """A real backup blob produced via ``backup.export`` with the
    canonical ``DIGEST_FIXTURE``."""
    from mordred_hermes.keyvault import backup

    return backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)


class TestDigestMatchSucceeds:
    def test_import_with_matching_digest_returns_secret(self, valid_blob: bytes) -> None:
        from mordred_hermes.keyvault import recovery

        result = recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=DIGEST_FIXTURE)
        assert result == SECRET


class TestDigestMismatchRefuses:
    def test_off_by_one_byte_digest_raises_recovery_digest_mismatch(self, valid_blob: bytes) -> None:
        """A one-byte transcription error produces a digest mismatch."""
        from mordred_hermes.keyvault import recovery

        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=OFF_BY_ONE_DIGEST)

    def test_zero_digest_raises_recovery_digest_mismatch(self, valid_blob: bytes) -> None:
        from mordred_hermes.keyvault import recovery

        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=WRONG_DIGEST)

    def test_recovery_digest_mismatch_subclasses_verification_digest_mismatch(
        self,
    ) -> None:
        """Callers catching :class:`VerificationDigestMismatch` (digest
        layer) must also catch the recovery-layer variant — they
        represent the same user-facing concept (mis-transcription)."""
        from mordred_hermes.keyvault.digest import VerificationDigestMismatch
        from mordred_hermes.keyvault.recovery import RecoveryDigestMismatch

        assert issubclass(RecoveryDigestMismatch, VerificationDigestMismatch)


class TestVerifyBeforeDecrypt:
    """Codex review #4 CORE invariant: on digest mismatch the secret is
    never materialized. Asserted two independent ways: (a) spy on
    ``backup.decrypt_body`` to confirm it's NOT called on mismatch,
    (b) spy on the KDF (Argon2id) — Argon2 is by far the slowest step,
    so skipping it on mismatch is both a safety property AND a
    performance one."""

    def test_mismatch_does_not_call_decrypt_body(
        self,
        valid_blob: bytes,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        from mordred_hermes.keyvault import backup, recovery

        called = False

        def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            nonlocal called
            called = True
            raise AssertionError(
                "recovery.import_backup MUST NOT call decrypt_body on "
                "digest mismatch — Codex review #4 verify-before-decrypt"
            )

        monkeypatch.setattr(backup, "decrypt_body", boom)
        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=WRONG_DIGEST)
        assert not called

    def test_mismatch_does_not_call_argon2_kdf(
        self,
        valid_blob: bytes,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        """The KDF (Argon2id) is the most expensive step. Skipping it
        on mismatch is both a safety property (no key material derived)
        AND a performance one (instant rejection feedback).

        Patch target: ``backup.hash_secret_raw``, NOT
        ``argon2.low_level.hash_secret_raw``. The backup module
        imports the name via ``from argon2.low_level import
        hash_secret_raw``, so the impl's call resolves through the
        module-local global. Patching the original module misses the
        call entirely and produces a silently-passing dead test —
        verified during third-pass review (codex MEDIUM-3, 2026-05-14).
        """
        from mordred_hermes.keyvault import backup, recovery

        def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError(
                "recovery.import_backup MUST NOT invoke Argon2 KDF on digest mismatch — verify-before-decrypt"
            )

        monkeypatch.setattr(backup, "hash_secret_raw", boom)
        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=WRONG_DIGEST)

    def test_import_backup_uses_constant_time_compare(
        self,
        valid_blob: bytes,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        """Code-reviewer HIGH-2: digest.py's verify_digest is verified to
        use hmac.compare_digest via spy, but recovery.py's equality
        check had no equivalent regression guard. A future PR that
        replaces ``_compare_digest(a, b)`` with ``a == b`` would be a
        timing-leakable digest comparison and must trip a test.
        """
        from mordred_hermes.keyvault import recovery

        real = recovery._compare_digest
        calls: list[tuple[bytes, bytes]] = []

        def spy(a: object, b: object) -> bool:
            calls.append((bytes(a), bytes(b)))  # type: ignore[arg-type]
            return real(a, b)  # type: ignore[arg-type]

        monkeypatch.setattr(recovery, "_compare_digest", spy, raising=True)
        # Match path: ensures the spy fires on a successful digest check.
        recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=DIGEST_FIXTURE)

        assert calls, (
            "recovery.import_backup must route digest comparison through a timing-safe primitive (hmac.compare_digest)"
        )
        # Second-pass code-reviewer MEDIUM: ``assert calls`` alone is
        # too weak — a future refactor that calls _compare_digest with
        # a 1-byte decoy and then does an ``==`` comparison on the
        # full 32-byte digest would still pass. Verify each spy call
        # received two 32-byte operands (full-width digest compare).
        for actual, expected in calls:
            assert len(actual) == 32, (
                f"_compare_digest received a non-32-byte operand "
                f"(len={len(actual)}); a partial compare would bypass "
                f"the timing-safety guarantee"
            )
            assert len(expected) == 32, (
                f"_compare_digest received a non-32-byte operand "
                f"(len={len(expected)}); a partial compare would bypass "
                f"the timing-safety guarantee"
            )


class TestAuditSink:
    """Codex review #9: audit_sink receives a single ``dict`` shaped like
    POLICY.md §Audit entry shape, not a (reason, extras) tuple.

    PR2 only emits ``keyvault.recovery_digest_mismatch`` from recovery —
    success path is silent (the actual ``keyvault.backup_exported`` /
    ``keyvault.import_completed`` codes are not frozen yet, so we don't
    emit them).
    """

    def test_mismatch_emits_audit_entry_with_correct_shape(self, valid_blob: bytes) -> None:
        from mordred_hermes.keyvault import recovery

        captured: list[dict[str, object]] = []
        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(
                valid_blob,
                PASSPHRASE,
                recomputed_digest=WRONG_DIGEST,
                audit_sink=captured.append,
            )

        assert len(captured) == 1
        entry = captured[0]
        # Fields required by POLICY.md §Audit entry shape (excluding
        # ``ts`` which the upstream Writer auto-adds).
        assert entry["event"] == "keyvault.import_backup"
        assert entry["decision"] == "block"
        assert entry["reason"] == "keyvault.recovery_digest_mismatch"
        # Phase 4 event-specific extras (POLICY.md entry #17 Fields):
        assert entry["blob_version"] == 1

    def test_audit_reason_is_in_frozen_enum(self, valid_blob: bytes) -> None:
        """Belt-and-suspenders: the emitted reason code must be a
        member of the typed Literal. Avoid drift between the audit
        emit site and ``_audit_reasons.ReasonCode``."""
        from typing import get_args

        from mordred_hermes.keyvault import recovery
        from mordred_hermes.privacy_check._audit_reasons import ReasonCode

        captured: list[dict[str, object]] = []
        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(
                valid_blob,
                PASSPHRASE,
                recomputed_digest=WRONG_DIGEST,
                audit_sink=captured.append,
            )
        assert captured[0]["reason"] in get_args(ReasonCode)

    def test_match_path_does_not_emit_audit(self, valid_blob: bytes) -> None:
        """PR2 success path is silent — no ``keyvault.import_completed``
        code in the freeze yet (Codex #8 scope policy)."""
        from mordred_hermes.keyvault import recovery

        captured: list[dict[str, object]] = []
        recovery.import_backup(
            valid_blob,
            PASSPHRASE,
            recomputed_digest=DIGEST_FIXTURE,
            audit_sink=captured.append,
        )
        assert captured == []

    def test_mismatch_with_no_audit_sink_still_raises(self, valid_blob: bytes) -> None:
        """audit_sink is optional; absence does not change the safety
        property (still raise on mismatch)."""
        from mordred_hermes.keyvault import recovery

        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=WRONG_DIGEST)

    def test_audit_sink_exception_does_not_mask_recovery_digest_mismatch(self, valid_blob: bytes) -> None:
        """Code-reviewer HIGH-1: if audit_sink raises (e.g. disk-full
        when writing the audit log), the caller's primary exception
        must be :class:`RecoveryDigestMismatch` — the safety-critical
        signal — with the sink exception chained as ``__context__`` so
        operators can still diagnose the audit-log failure.

        Why this matters: a caller writing
        ``except RecoveryDigestMismatch:`` to display a "wrong
        passphrase / transcription" error to the user would otherwise
        leak the AuditDiskFull through to a higher unhandled-exception
        layer, breaking the UX contract for the digest mismatch path.
        Safety-critical exceptions always win at the top; operational
        ones live in __context__.
        """
        from mordred_hermes.keyvault import recovery

        class AuditDiskFull(RuntimeError):
            pass

        def angry_sink(_entry: dict[str, object]) -> None:
            raise AuditDiskFull("simulated audit log write failure")

        with pytest.raises(recovery.RecoveryDigestMismatch) as excinfo:
            recovery.import_backup(
                valid_blob,
                PASSPHRASE,
                recomputed_digest=WRONG_DIGEST,
                audit_sink=angry_sink,
            )

        # The sink exception must be reachable for diagnostics, but it
        # must NOT be the surface exception.
        assert isinstance(excinfo.value.__context__, AuditDiskFull), (
            "audit_sink exception must be chained as __context__ so "
            "operators can diagnose audit-log failures without losing "
            "the primary RecoveryDigestMismatch signal"
        )

    def test_audit_sink_keyboard_interrupt_propagates_unmasked(self, valid_blob: bytes) -> None:
        """Second-pass code-reviewer HIGH: the exception-chaining fix
        (HIGH-1) must NOT swallow ``KeyboardInterrupt`` or
        ``SystemExit``. If the user hits Ctrl-C while the audit sink
        is writing, the program must terminate — masking the
        KeyboardInterrupt by chaining it as
        ``RecoveryDigestMismatch.__context__`` would break the CLI's
        ability to be interrupted.

        Test asserts the surface exception is ``KeyboardInterrupt``,
        not ``RecoveryDigestMismatch``. Same property applies to
        ``SystemExit`` (covered by the next test).
        """
        from mordred_hermes.keyvault import recovery

        def ctrl_c_during_audit(_entry: dict[str, object]) -> None:
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            recovery.import_backup(
                valid_blob,
                PASSPHRASE,
                recomputed_digest=WRONG_DIGEST,
                audit_sink=ctrl_c_during_audit,
            )

    def test_audit_sink_system_exit_propagates_unmasked(self, valid_blob: bytes) -> None:
        """Companion to KeyboardInterrupt: SystemExit raised by the
        audit sink (e.g. a sink that decides to abort the process)
        must propagate without being chained into
        RecoveryDigestMismatch."""
        from mordred_hermes.keyvault import recovery

        def aborting_sink(_entry: dict[str, object]) -> None:
            raise SystemExit(1)

        with pytest.raises(SystemExit) as excinfo:
            recovery.import_backup(
                valid_blob,
                PASSPHRASE,
                recomputed_digest=WRONG_DIGEST,
                audit_sink=aborting_sink,
            )

        assert excinfo.value.code == 1


class TestInvalidTagPropagation:
    """Wrong passphrase / header tamper / ciphertext tamper should
    raise InvalidTag *from* the AES layer — recovery does NOT swallow
    or remap that distinct failure mode. (Recovery's job is digest
    mismatch handling; integrity failures are AES's contract.)"""

    def test_wrong_passphrase_propagates_invalid_tag(self, valid_blob: bytes) -> None:
        from mordred_hermes.keyvault import recovery

        with pytest.raises(InvalidTag):
            recovery.import_backup(
                valid_blob,
                "WRONG passphrase",
                recomputed_digest=DIGEST_FIXTURE,
            )


class TestRecomputedDigestLengthValidation:
    """recomputed_digest must be 32 bytes — same length-confusion
    discipline as verify_digest (Codex review #6). If caller passes
    a short/long digest, raise a RecoveryDigestMismatch BEFORE doing
    any work."""

    def test_short_recomputed_digest_raises(self, valid_blob: bytes) -> None:
        from mordred_hermes.keyvault import recovery

        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=b"\x00" * 31)

    def test_long_recomputed_digest_raises(self, valid_blob: bytes) -> None:
        from mordred_hermes.keyvault import recovery

        with pytest.raises(recovery.RecoveryDigestMismatch):
            recovery.import_backup(valid_blob, PASSPHRASE, recomputed_digest=b"\x00" * 33)
