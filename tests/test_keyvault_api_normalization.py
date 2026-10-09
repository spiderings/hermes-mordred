"""Tests for ``mordred_hermes.keyvault.api`` normalization + verify_digest.

Phase 4 PR4 step-A RED (2026-05-15) — implementation lands in step-A GREEN.

Codex review HIGH #1 corrected the original "BIP39-style" normalization plan:
applying NFKD + casefold + whitespace-collapse uniformly to *passphrase* weakens
entropy (casefold conflates distinct Unicode strings; whitespace collapse drops
information). The freeze (see SPEC.md §"PR4 API contract" / "Mordred
normalization") splits the two:

- ``_normalize_seed_phrase`` — BIP39 word-list tolerance: NFKD decompose,
  casefold, collapse runs of whitespace.
- ``_normalize_passphrase``  — BIP39 reference: NFKD only.

These tests pin the split. The canonical SPEC vector (ASCII inputs
``"test seed"`` / ``"test pass"`` / ``deadbeef00…``) remains valid
because NFKD + casefold are no-ops on already-lowercase ASCII without
combining marks.
"""

from __future__ import annotations

import inspect
import typing

import pytest

from mordred_hermes.keyvault import api
from mordred_hermes.keyvault.digest import VerificationDigestMismatch

# Precomposed/decomposed Japanese katakana pairs for NFKD equivalence tests.
# Precomposed `パ` (U+30D1) NFKD-decomposes to `ハ` (U+30CF) + handakuten
# (U+309A); precomposed `ド` (U+30C9) decomposes to `ト` (U+30C8) + dakuten
# (U+3099). Using \u escapes here so the source file's UTF-8 bytes are not
# already normalized by an editor (which would silently make the two literals
# identical and defeat the test).
_JP_PASSWORD_PRECOMPOSED = "パスワード"  # パスワード, fully precomposed
_JP_PASSWORD_DECOMPOSED = "パスワード"  # パスワート゛, fully decomposed
_JP_CAFE_PRECOMPOSED = "カフェ"  # カフェ (no combining marks; here only for completeness)

# SPEC.md §Key generation and verification digest canonical regression vector;
# ASCII inputs are unaffected by split normalization.
_SPEC_SEED = "test seed"
_SPEC_PASS = "test pass"
_SPEC_POW = bytes.fromhex("deadbeef") + bytes(28)
_SPEC_DIGEST = bytes.fromhex("25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93")


# -------------------------- _normalize_seed_phrase --------------------------


class TestNormalizeSeedPhrase:
    def test_empty_string_passes_through(self) -> None:
        assert api._normalize_seed_phrase("") == ""

    def test_ascii_lowercase_passes_through(self) -> None:
        assert api._normalize_seed_phrase("test seed") == "test seed"

    def test_casefold_lowercases_ascii(self) -> None:
        assert api._normalize_seed_phrase("TEST SEED") == "test seed"

    def test_casefold_handles_mixed_case(self) -> None:
        assert api._normalize_seed_phrase("Test Seed") == "test seed"

    def test_whitespace_collapse_runs_of_spaces(self) -> None:
        assert api._normalize_seed_phrase("  test  seed  ") == "test seed"

    def test_whitespace_collapse_tabs_and_newlines(self) -> None:
        assert api._normalize_seed_phrase("test\tseed\nfoo") == "test seed foo"

    def test_whitespace_collapse_nbsp(self) -> None:
        # U+00A0 NBSP decomposes to ASCII space under NFKD, then collapse runs.
        assert api._normalize_seed_phrase("test\u00a0seed") == "test seed"

    def test_whitespace_collapse_ideographic_space(self) -> None:
        # U+3000 IDEOGRAPHIC SPACE decomposes to ASCII space under NFKD.
        assert api._normalize_seed_phrase("test　seed") == "test seed"

    def test_nfkd_decomposes_precomposed_and_decomposed_to_same_string(self) -> None:
        precomposed = "café"  # 'é' as U+00E9
        decomposed = "café"  # 'e' + combining acute U+0301
        assert api._normalize_seed_phrase(precomposed) == api._normalize_seed_phrase(decomposed)

    def test_japanese_voicing_marks_precomposed_and_decomposed_equivalent(self) -> None:
        # ハ + dakuten (U+3099) ↔ precomposed パ (U+30D1). NFKD canonicalizes
        # both to the same combining-mark sequence; casefold is a no-op on kana;
        # whitespace collapse is a no-op (no whitespace).
        precomposed = "パスワード"  # パスワード
        decomposed = "パスワード"  # NFKD of パスワード (handakuten on ha, dakuten on to)
        assert api._normalize_seed_phrase(precomposed) == api._normalize_seed_phrase(decomposed)

    def test_runs_of_whitespace_only_normalize_to_empty(self) -> None:
        assert api._normalize_seed_phrase("   \t\n   ") == ""

    def test_idempotent(self) -> None:
        for raw in [
            "test seed",
            "  TEST  SEED  ",
            "café",
            "パスワード",
            "",
            "Mixed CASE　with\tIDEOGRAPHIC",
        ]:
            once = api._normalize_seed_phrase(raw)
            twice = api._normalize_seed_phrase(once)
            assert once == twice, f"normalization not idempotent for {raw!r}"

    def test_signature_matches_spec(self) -> None:
        # `from __future__ import annotations` (PEP 563) makes annotations strings,
        # so resolve via typing.get_type_hints to get the actual types.
        sig = inspect.signature(api._normalize_seed_phrase)
        hints = typing.get_type_hints(api._normalize_seed_phrase)
        params = list(sig.parameters.items())
        assert len(params) == 1, "expected single positional parameter"
        name, _param = params[0]
        assert name == "s"
        assert hints == {"s": str, "return": str}


# ---------------------------- _normalize_passphrase ----------------------------


class TestNormalizePassphrase:
    def test_empty_string_passes_through(self) -> None:
        assert api._normalize_passphrase("") == ""

    def test_ascii_lowercase_passes_through(self) -> None:
        assert api._normalize_passphrase("test pass") == "test pass"

    def test_case_preserved_uppercase(self) -> None:
        # Case-SENSITIVE — entropy must not be casefolded away.
        assert api._normalize_passphrase("TEST PASS") == "TEST PASS"

    def test_case_preserved_mixed(self) -> None:
        assert api._normalize_passphrase("Test Pass") == "Test Pass"

    def test_distinct_cases_remain_distinct(self) -> None:
        assert api._normalize_passphrase("Password") != api._normalize_passphrase("password")
        assert api._normalize_passphrase("PASSWORD") != api._normalize_passphrase("password")

    def test_whitespace_preserved_internal(self) -> None:
        # Two internal spaces stay two; we do NOT collapse — entropy preserved.
        assert api._normalize_passphrase("test  pass") == "test  pass"

    def test_whitespace_preserved_leading_trailing(self) -> None:
        assert api._normalize_passphrase("  test pass  ") == "  test pass  "

    def test_nfkd_decomposes_combining_marks(self) -> None:
        precomposed = "café"
        decomposed = "café"
        # Both should decompose to the same NFKD form.
        assert api._normalize_passphrase(precomposed) == api._normalize_passphrase(decomposed)

    def test_nfkd_decomposes_nbsp_to_space_but_does_not_collapse(self) -> None:
        # NFKD compatibility-decomposes NBSP (U+00A0) to ASCII space (U+0020),
        # but unlike the seed normalizer we do NOT collapse runs.
        out = api._normalize_passphrase("a\u00a0 b")
        assert out == "a  b", f"expected 'a  b' (two spaces, preserved), got {out!r}"

    def test_japanese_passphrase_precomposed_and_decomposed_equivalent(self) -> None:
        precomposed = "パスワード"  # パスワード
        decomposed = "パスワード"
        assert api._normalize_passphrase(precomposed) == api._normalize_passphrase(decomposed)

    def test_does_not_casefold_kana_or_other_scripts(self) -> None:
        # Kana have no case; what we verify is that we don't somehow mangle
        # them. Compared to _normalize_seed_phrase, the passphrase variant
        # produces identical output for ASCII-cased letters while preserving
        # case.
        out = api._normalize_passphrase("カフェ")  # カフェ
        assert out == "カフェ"

    def test_idempotent(self) -> None:
        for raw in [
            "test pass",
            "TEST Pass",
            "café",
            "パスワード",
            "",
            "with  multiple  spaces",
            " a\u00a0b ",
        ]:
            once = api._normalize_passphrase(raw)
            twice = api._normalize_passphrase(once)
            assert once == twice, f"normalization not idempotent for {raw!r}"

    def test_signature_matches_spec(self) -> None:
        sig = inspect.signature(api._normalize_passphrase)
        hints = typing.get_type_hints(api._normalize_passphrase)
        params = list(sig.parameters.items())
        assert len(params) == 1
        name, _param = params[0]
        assert name == "s"
        assert hints == {"s": str, "return": str}


# ------------------- seed-vs-passphrase divergence (the point) -------------------


class TestSplitNormalizationDiverges:
    """Codex HIGH #1: the seed normalizer collapses & casefolds, the
    passphrase normalizer does neither. These tests pin the divergence."""

    def test_uppercase_diverges(self) -> None:
        assert api._normalize_seed_phrase("TEST") == "test"
        assert api._normalize_passphrase("TEST") == "TEST"

    def test_whitespace_diverges(self) -> None:
        assert api._normalize_seed_phrase("a  b") == "a b"
        assert api._normalize_passphrase("a  b") == "a  b"

    def test_leading_trailing_diverges(self) -> None:
        assert api._normalize_seed_phrase(" a ") == "a"
        assert api._normalize_passphrase(" a ") == " a "


# ------------ Unicode format (Cf) character handling (review-fix-1 MEDIUM-1) ------------


class TestSeedPhraseStripsFormatChars:
    """Code-reviewer MEDIUM-1: Unicode Cf-category chars (ZWSP, ZWJ, ZWNJ,
    BOM, RTL mark, MVS, soft hyphen) are NFKD-stable and ``str.split()`` does
    NOT treat them as whitespace. Without an explicit strip step they survive
    seed-phrase normalization and silently produce a different digest. The
    seed normalizer therefore drops all Cf-category chars; the passphrase
    normalizer preserves them (see TestPassphrasePreservesFormatChars)."""

    def test_zwsp_is_stripped(self) -> None:
        # ZWSP between letters is removed (treated as invisible noise, not a separator).
        assert api._normalize_seed_phrase("a​b") == "ab"

    def test_zwj_is_stripped(self) -> None:
        assert api._normalize_seed_phrase("a‍b") == "ab"

    def test_zwnj_is_stripped(self) -> None:
        assert api._normalize_seed_phrase("a‌b") == "ab"

    def test_bom_is_stripped(self) -> None:
        # U+FEFF as BOM at the start of pasted content.
        assert api._normalize_seed_phrase("﻿abandon") == "abandon"

    def test_ltr_rtl_marks_are_stripped(self) -> None:
        # U+200E LRM and U+200F RLM both Cf.
        assert api._normalize_seed_phrase("abc‏") == "abc"
        assert api._normalize_seed_phrase("‎abc") == "abc"

    def test_mongolian_vowel_separator_is_stripped(self) -> None:
        # U+180E is Cf (Mongolian Vowel Separator — a former whitespace re-categorized).
        assert api._normalize_seed_phrase("a᠎b") == "ab"

    def test_soft_hyphen_is_stripped(self) -> None:
        # U+00AD soft hyphen is Cf-category (visually invisible in most fonts).
        assert api._normalize_seed_phrase("a­b") == "ab"

    def test_zwsp_next_to_real_space_preserves_real_space(self) -> None:
        # "abandon<SPACE><ZWSP>abandon" → ZWSP removed, real space preserved.
        assert api._normalize_seed_phrase("abandon ​abandon") == "abandon abandon"

    def test_spec_vector_unaffected_by_injected_zwsp_in_seed(self) -> None:
        # Canonical SPEC vector: seed "test seed" + ZWSP between letters
        # → after Cf strip, identical to canonical → digest matches.
        api.verify_digest("test​ seed", _SPEC_PASS, _SPEC_POW, expected=_SPEC_DIGEST)

    def test_multiple_format_chars_all_stripped(self) -> None:
        # A copy-paste from a webpage might inject several Cf chars at once.
        polluted = "﻿test​‍ seed‎"
        assert api._normalize_seed_phrase(polluted) == "test seed"


class TestPassphrasePreservesFormatChars:
    """The passphrase normalizer is BIP39-reference (NFKD-only) and explicitly
    preserves Cf-category chars. Rationale: passphrase entropy must not be
    trimmed. A user who chose an embedded ZWSP did so intentionally; the
    SPEC mandates that distinct inputs produce distinct keys."""

    def test_zwsp_preserved(self) -> None:
        assert api._normalize_passphrase("a​b") == "a​b"

    def test_zwj_preserved(self) -> None:
        assert api._normalize_passphrase("a‍b") == "a‍b"

    def test_bom_preserved(self) -> None:
        assert api._normalize_passphrase("﻿abc") == "﻿abc"

    def test_soft_hyphen_preserved(self) -> None:
        assert api._normalize_passphrase("a­b") == "a­b"

    def test_injected_zwsp_in_passphrase_changes_digest(self) -> None:
        # User who pastes a passphrase containing an invisible ZWSP gets a
        # DIFFERENT digest than canonical — the system does not silently
        # fold the invisible char away. The mismatch surfaces at verify time.
        with pytest.raises(VerificationDigestMismatch):
            api.verify_digest(_SPEC_SEED, "test​ pass", _SPEC_POW, expected=_SPEC_DIGEST)


# ------------------------------ api.verify_digest ------------------------------


class TestApiVerifyDigest:
    def test_signature_matches_spec(self) -> None:
        sig = inspect.signature(api.verify_digest)
        hints = typing.get_type_hints(api.verify_digest)
        params = sig.parameters
        assert list(params.keys()) == ["seed_phrase", "passphrase", "pow_bytes", "expected"]
        assert hints == {
            "seed_phrase": str,
            "passphrase": str,
            "pow_bytes": bytes,
            "expected": bytes,
            "return": type(None),
        }
        assert params["expected"].kind is inspect.Parameter.KEYWORD_ONLY

    def test_re_exports_verification_digest_mismatch(self) -> None:
        # Callers can import the exception class from api without reaching into
        # the digest submodule.
        from mordred_hermes.keyvault.api import VerificationDigestMismatch as ApiMismatch

        assert ApiMismatch is VerificationDigestMismatch

    def test_spec_fixed_vector_matches(self) -> None:
        # No normalization delta on ASCII inputs → original digest still valid.
        api.verify_digest(_SPEC_SEED, _SPEC_PASS, _SPEC_POW, expected=_SPEC_DIGEST)

    def test_mismatch_raises(self) -> None:
        wrong = bytes(32)
        with pytest.raises(VerificationDigestMismatch):
            api.verify_digest(_SPEC_SEED, _SPEC_PASS, _SPEC_POW, expected=wrong)

    def test_seed_normalized_before_digest_casefold(self) -> None:
        # "TEST SEED" + casefold → "test seed" → SPEC vector matches.
        api.verify_digest("TEST SEED", _SPEC_PASS, _SPEC_POW, expected=_SPEC_DIGEST)

    def test_seed_normalized_before_digest_whitespace(self) -> None:
        # Extra whitespace folded away → matches SPEC vector.
        api.verify_digest("  test  seed  ", _SPEC_PASS, _SPEC_POW, expected=_SPEC_DIGEST)

    def test_passphrase_NOT_casefolded(self) -> None:
        # Uppercase passphrase must produce a DIFFERENT digest than the SPEC
        # vector, because _normalize_passphrase is NFKD-only and case-sensitive.
        with pytest.raises(VerificationDigestMismatch):
            api.verify_digest(_SPEC_SEED, "TEST PASS", _SPEC_POW, expected=_SPEC_DIGEST)

    def test_passphrase_whitespace_preserved(self) -> None:
        # Extra internal whitespace on the passphrase changes the digest.
        with pytest.raises(VerificationDigestMismatch):
            api.verify_digest(_SPEC_SEED, "test  pass", _SPEC_POW, expected=_SPEC_DIGEST)

    def test_length_guard_propagates_from_digest_layer(self) -> None:
        # Codex review #6 length-confusion guard: != 32 bytes always rejected.
        with pytest.raises(VerificationDigestMismatch):
            api.verify_digest(_SPEC_SEED, _SPEC_PASS, _SPEC_POW, expected=b"too short")

    def test_length_guard_over_32_also_rejected(self) -> None:
        with pytest.raises(VerificationDigestMismatch):
            api.verify_digest(_SPEC_SEED, _SPEC_PASS, _SPEC_POW, expected=b"\x00" * 33)

    def test_normalization_applied_consistently_japanese_seed(self) -> None:
        # Precomposed and decomposed Japanese seed phrases both verify against
        # the same digest. The expected digest is computed from the normalized
        # form so both inputs round-trip the same way.
        precomposed_seed = "パスワード"
        decomposed_seed = "パスワード"
        expected = _digest_after_normalize(precomposed_seed, _SPEC_PASS, _SPEC_POW)
        api.verify_digest(precomposed_seed, _SPEC_PASS, _SPEC_POW, expected=expected)
        api.verify_digest(decomposed_seed, _SPEC_PASS, _SPEC_POW, expected=expected)

    def test_normalization_applied_consistently_japanese_passphrase(self) -> None:
        precomposed_pass = "パスワード"
        decomposed_pass = "パスワード"
        expected = _digest_after_normalize(_SPEC_SEED, precomposed_pass, _SPEC_POW)
        api.verify_digest(_SPEC_SEED, precomposed_pass, _SPEC_POW, expected=expected)
        api.verify_digest(_SPEC_SEED, decomposed_pass, _SPEC_POW, expected=expected)


# ------------------------------ helpers ------------------------------


def _digest_after_normalize(seed: str, passphrase: str, pow_bytes: bytes) -> bytes:
    """Compute the canonical digest using the same normalization as the api.

    Used by tests that need a "known good" digest for non-ASCII inputs.
    """
    from mordred_hermes.keyvault.digest import compute_digest

    return compute_digest(
        api._normalize_seed_phrase(seed),
        api._normalize_passphrase(passphrase),
        pow_bytes,
    )
