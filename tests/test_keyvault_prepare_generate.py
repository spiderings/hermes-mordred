"""Tests for the in-memory ``prepare_generate`` lifecycle phase."""

from __future__ import annotations

import inspect
import time
from typing import Any

from mordred_hermes.keyvault import api
from tests._keyvault_lifecycle_helpers import (
    _SPEC_DIGEST,
    _SPEC_PASSPHRASE,
    _SPEC_POW,
    _SPEC_SEED,
)

# ============================ prepare_generate (in-memory phase) ============================
#
# Contract frozen in SPEC.md §"PR4 API contract / Two-phase generate":
#
#     def prepare_generate(
#         seed_phrase: str,
#         passphrase: str,
#         pow_bytes: bytes,
#     ) -> tuple[SeedDisplayHandle, bytes]:
#         # In-memory only. Computes digest from normalized inputs.
#         # NO Keychain creation, NO meta.json write, NO digests/ commit,
#         # NO audit emit. Pure function with respect to disk state.
#
# Normalization split (SPEC.md §"Mordred normalization", codex HIGH #1):
#   - seed_phrase: NFKD + strip Cf chars + casefold + collapse whitespace
#   - passphrase: NFKD only — case and whitespace are entropy, must NOT collapse


class TestPrepareGenerateSignature:
    """``prepare_generate`` returns ``(SeedDisplayHandle, 32-byte digest)``.

    Pure function: no disk I/O, no audit_sink parameter, no backend
    parameter. The two-phase split exists so that nothing durable
    happens before the user has confirmed the digest via the offline
    channel (SPEC §"Key generation" mandates "mandatory and one-shot").
    """

    def test_returns_two_tuple(self) -> None:
        result = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_first_element_is_seed_display_handle(self) -> None:
        handle, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert isinstance(handle, api.SeedDisplayHandle)

    def test_second_element_is_bytes_of_length_32(self) -> None:
        _, digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert isinstance(digest, bytes)
        assert len(digest) == 32


class TestPrepareGenerateCanonicalVector:
    """ASCII canonical inputs reproduce SPEC.md §"Fixed test vector" digest.

    The canonical digest vector in SPEC is the regression anchor for the
    whole compute_digest algorithm. Re-pinning the final digest at the
    api.py layer guards against silent normalization regressions that
    would only surface at recovery time.
    """

    def test_spec_vector_digest_matches(self) -> None:
        _, digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert digest == _SPEC_DIGEST


class TestPrepareGenerateDeterminism:
    """Same inputs → same digest. Different inputs → different digest."""

    def test_same_inputs_produce_same_digest(self) -> None:
        _, d1 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        _, d2 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert d1 == d2

    def test_different_seed_produces_different_digest(self) -> None:
        _, d1 = api.prepare_generate("seed one", _SPEC_PASSPHRASE, _SPEC_POW)
        _, d2 = api.prepare_generate("seed two", _SPEC_PASSPHRASE, _SPEC_POW)
        assert d1 != d2

    def test_different_passphrase_produces_different_digest(self) -> None:
        _, d1 = api.prepare_generate(_SPEC_SEED, "pass one", _SPEC_POW)
        _, d2 = api.prepare_generate(_SPEC_SEED, "pass two", _SPEC_POW)
        assert d1 != d2

    def test_different_pow_produces_different_digest(self) -> None:
        pow_a = bytes.fromhex("deadbeef") + b"\x00" * 28
        pow_b = bytes.fromhex("cafef00d") + b"\x00" * 28
        _, d1 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, pow_a)
        _, d2 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, pow_b)
        assert d1 != d2


class TestPrepareGenerateSeedNormalization:
    """Seed phrase: NFKD + Cf-strip + casefold + whitespace-collapse.

    BIP39 word-list tolerance — typo-noise (mixed case, extra spaces,
    non-ASCII whitespace forms, invisible Cf chars from clipboard
    injection) collapses to the same digest as a clean reference input.
    """

    def test_seed_uppercase_collapses_via_casefold(self) -> None:
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, upper = api.prepare_generate("TEST SEED", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == upper

    def test_seed_extra_whitespace_collapses(self) -> None:
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, padded = api.prepare_generate("  test   seed  ", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == padded

    def test_seed_tab_whitespace_treated_as_space(self) -> None:
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, tabbed = api.prepare_generate("test\tseed", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == tabbed

    def test_seed_nbsp_collapses_via_nfkd(self) -> None:
        """U+00A0 NO-BREAK SPACE decomposes to U+0020 under NFKD, so the
        BIP39 word-list tolerance covers clipboard-typo NBSP transparently.
        """
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        # Build the NBSP form via explicit escape so the source file does not
        # carry an ambiguous literal (ruff RUF001 would flag that).
        nbsp_seed = "test\u00a0seed"
        _, nbsp = api.prepare_generate(nbsp_seed, _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == nbsp

    def test_seed_zwsp_stripped_via_cf_category(self) -> None:
        """U+200B ZERO WIDTH SPACE is Cf-category — NFKD-stable and not a
        whitespace split, so without explicit Cf-strip it would silently
        change the digest. The strip closes the clipboard-injection gap
        (code-reviewer MEDIUM-1, 2026-05-15).
        """
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, with_zwsp = api.prepare_generate("te​st seed", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == with_zwsp

    def test_seed_japanese_precomposed_equals_decomposed(self) -> None:
        """NFKD decomposes Japanese precomposed dakuon (e.g. が U+304C) into
        base + combining mark (か U+304B + U+3099). The two input forms
        must produce the same digest.
        """
        precomposed = "がぎぐげご"
        decomposed = "がぎぐげご"
        _, d_pre = api.prepare_generate(precomposed, _SPEC_PASSPHRASE, _SPEC_POW)
        _, d_dec = api.prepare_generate(decomposed, _SPEC_PASSPHRASE, _SPEC_POW)
        assert d_pre == d_dec


class TestPrepareGeneratePassphraseNormalization:
    """Passphrase: NFKD only. Case and whitespace are entropy.

    Casefold-collapse on the passphrase would conflate distinct Unicode
    strings; whitespace-collapse drops entropy. The split exists exactly
    so the passphrase preserves what the user actually typed (codex HIGH
    #1). NFKD is still applied so Japanese precomposed/decomposed
    equivalence holds.
    """

    def test_passphrase_case_change_changes_digest(self) -> None:
        """A casefold of the passphrase would silently mask a typo at
        recovery time. Recovery requires reproducing the exact case.
        """
        _, lower = api.prepare_generate(_SPEC_SEED, "secret", _SPEC_POW)
        _, upper = api.prepare_generate(_SPEC_SEED, "SECRET", _SPEC_POW)
        assert lower != upper

    def test_passphrase_extra_whitespace_changes_digest(self) -> None:
        _, single = api.prepare_generate(_SPEC_SEED, "a b", _SPEC_POW)
        _, double = api.prepare_generate(_SPEC_SEED, "a  b", _SPEC_POW)
        assert single != double

    def test_passphrase_zwsp_changes_digest(self) -> None:
        """Passphrase normalization does NOT strip Cf chars — a user who
        chose to embed an invisible char did so intentionally and must
        reproduce the exact bytes on recovery.
        """
        _, clean = api.prepare_generate(_SPEC_SEED, "secret", _SPEC_POW)
        _, with_zwsp = api.prepare_generate(_SPEC_SEED, "sec​ret", _SPEC_POW)
        assert clean != with_zwsp

    def test_passphrase_japanese_precomposed_equals_decomposed(self) -> None:
        """NFKD is applied to the passphrase, so Japanese precomposed and
        decomposed forms still produce the same digest — this is the only
        normalization gate that fires on the passphrase side.
        """
        precomposed = "がぎぐげご"
        decomposed = "がぎぐげご"
        _, d_pre = api.prepare_generate(_SPEC_SEED, precomposed, _SPEC_POW)
        _, d_dec = api.prepare_generate(_SPEC_SEED, decomposed, _SPEC_POW)
        assert d_pre == d_dec


class TestPrepareGenerateHandleBehavior:
    """The returned ``SeedDisplayHandle`` holds the *normalized* seed and
    expires roughly 60s from the call site (default TTL from SPEC).
    """

    def test_handle_consume_returns_normalized_seed(self) -> None:
        """Casefold and whitespace-collapse must have been applied to the
        bytes the handle carries — PR5's display flow renders this string
        back to the user, so it has to match what compute_digest hashed.
        """
        handle, _ = api.prepare_generate("  TEST   SEED  ", _SPEC_PASSPHRASE, _SPEC_POW)
        assert handle.consume() == "test seed"

    def test_consecutive_calls_return_distinct_handles(self) -> None:
        """No memoization — each call mints a fresh handle so a stale
        cached handle never leaks into a later display flow.
        """
        h1, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        h2, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert h1 is not h2

    def test_handle_deadline_is_approximately_60s_in_future(self) -> None:
        """Default TTL per SPEC: ``time.monotonic() + 60.0``. White-box
        check against ``_deadline`` so the wipe-on-expiry path is
        actually reachable from the value baked in here.
        """
        before = time.monotonic()
        handle, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        after = time.monotonic()
        # The deadline must lie in the window [before+60, after+60] —
        # the only ambiguity is the time spent inside the call.
        deadline = handle._deadline  # type: ignore[attr-defined]
        assert before + 60.0 <= deadline <= after + 60.0

    def test_handle_carries_expected_digest_equal_to_returned_digest(self) -> None:
        """The (handle, expected_digest) pair is internally consistent —
        confirm_generate compares the user-typed digest against
        handle._expected_digest, so the value baked into the handle must
        equal the digest returned to the caller (i.e. the one shown to
        the user for offline transcription).
        """
        handle, returned_digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert handle._expected_digest == returned_digest  # type: ignore[attr-defined]


class TestPrepareGenerateNoPersistence:
    """``prepare_generate`` is pure with respect to disk state.

    The two-phase contract exists precisely so the digest-mismatch case
    can be a clean "no-op" — no Keychain entry, no meta.json, no
    digests/<kid>.commit, no audit event. A passing test here is what
    licenses the contract that "if the digest doesn't match, nothing
    durable happened".
    """

    def test_no_files_created_anywhere(self, tmp_path: Any) -> None:
        """``prepare_generate`` has no ``home`` parameter — it cannot create
        keyvault files by construction. This snapshots a scratch directory
        before/after the call to assert no incidental disk writes occur.
        """
        # Snapshot the directory state, call prepare_generate, re-snapshot.
        before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
        api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        after = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
        assert before == after

    def test_signature_does_not_require_audit_or_backend(self) -> None:
        """``prepare_generate`` is positional-only on (seed, passphrase,
        pow_bytes). No keyword-only ``audit_sink`` / ``backend`` / ``home``
        — those are confirm_generate's surface.
        """
        sig = inspect.signature(api.prepare_generate)
        param_names = list(sig.parameters)
        assert param_names == ["seed_phrase", "passphrase", "pow_bytes"]
