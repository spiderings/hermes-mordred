"""mordred_keyvault.digest — BLAKE3 verification digest.

Binds (SeedPhrase, Passphrase, PoW) into a 32-byte digest used as the
cross-machine recovery anti-mis-transcription anchor.

Canonical algorithm is frozen in
``docs/dev/SPEC.md §Key generation and verification digest``::

    H               := BLAKE3 (32-byte digest mode)
    seed_hash       := H(SeedPhrase as UTF-8 bytes)
    pass_hash       := H(Passphrase as UTF-8 bytes)
    top4            := PoW_bytes[0:4]
    masked_pass[0:4]  := pass_hash[0:4] XOR top4
    masked_pass[4:32] := pass_hash[4:32]
    digest          := H(seed_hash || masked_pass)        # 32 bytes

Unicode normalization is the caller's responsibility. The public API applies
split normalization in :mod:`mordred_hermes.keyvault.api`:
seed phrase uses ``NFKD + strip-Cf + casefold + whitespace-collapse``,
passphrase uses ``NFKD only``. See :func:`mordred_hermes.keyvault.api.verify_digest`
and :func:`mordred_hermes.keyvault.api.prepare_generate` /
:func:`mordred_hermes.keyvault.api.confirm_generate`, or SPEC.md
§"PR4 API contract / Mordred normalization" for the canonical definitions.
PoW is precomputed by the caller; this module does not re-hash it.

This module imports :mod:`blake3` from the cross-platform ``keyvault`` extra.
Platform-specific native-key selection happens outside this digest layer.
"""

from __future__ import annotations

from hmac import compare_digest as _compare_digest

from blake3 import blake3

_DIGEST_LEN = 32
_TOP4_LEN = 4


class VerificationDigestMismatch(ValueError):
    """Raised when ``verify_digest`` finds a transcribed/recomputed digest
    that does not match the canonical one.

    Subclasses :class:`ValueError` so callers using
    ``except ValueError:`` for input-validation handling catch it
    naturally, without special-casing the keyvault module.
    """


def top4(pow_bytes: bytes) -> bytes:
    """Return the first 4 bytes of a precomputed PoW artifact.

    The SPEC notation ``top4(PoW)`` is deliberately narrow: only the
    first 4 bytes feed into the digest, so cross-machine recovery only
    needs to transmit 4 bytes of mask material rather than 32.
    """
    if len(pow_bytes) < _TOP4_LEN:
        raise ValueError(f"PoW must be at least {_TOP4_LEN} bytes for top4 extraction, got {len(pow_bytes)}")
    return pow_bytes[:_TOP4_LEN]


def compute_digest(seed_phrase: str, passphrase: str, pow_bytes: bytes) -> bytes:
    """Compute the 32-byte verification digest.

    See module docstring for the canonical algorithm and SPEC reference.
    Inputs are encoded as UTF-8 as-is; Unicode normalization is the
    caller's responsibility.
    """
    seed_hash = blake3(seed_phrase.encode("utf-8")).digest()
    pass_hash = blake3(passphrase.encode("utf-8")).digest()
    mask = top4(pow_bytes)
    masked_pass = bytes(p ^ t for p, t in zip(pass_hash[:_TOP4_LEN], mask, strict=True)) + pass_hash[_TOP4_LEN:]
    return blake3(seed_hash + masked_pass).digest()


def verify_digest(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
    *,
    expected: bytes,
) -> None:
    """Recompute the digest from inputs and compare against ``expected``
    using a timing-safe primitive. Raise
    :class:`VerificationDigestMismatch` on disagreement.

    Length-confusion guard (Codex review #6): ``expected`` of length
    != 32 always raises the mismatch exception — the algorithm only
    ever emits 32 bytes, so any other length is by definition a
    mismatch.
    """
    if len(expected) != _DIGEST_LEN:
        raise VerificationDigestMismatch(f"expected digest must be exactly {_DIGEST_LEN} bytes, got {len(expected)}")
    actual = compute_digest(seed_phrase, passphrase, pow_bytes)
    if not _compare_digest(actual, expected):
        raise VerificationDigestMismatch("verification digest mismatch — transcription or PoW may be incorrect")
