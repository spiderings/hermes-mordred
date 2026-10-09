"""mordred_keyvault.pow — Proof-of-Work artifact for ``keyvault init``.

Canonical algorithm frozen in
``docs/dev/SPEC.md §"Proof-of-Work (PoW) algorithm"``::

    H                    := BLAKE3 (32-byte digest mode; unkeyed)
    POW_PREFIX           := b"MRPOW\\x01"
    POW_DIFFICULTY_BITS  := 20
    preimage(n)  := POW_PREFIX || normalized_seed_utf8 || n.to_bytes(8, "little")
    find smallest n with leading_zero_bits(H(preimage(n))) >= POW_DIFFICULTY_BITS
    pow_bytes    := H(preimage(n))

PoW is a *seed-bound* artifact: ``pow_bytes`` is a deterministic function
of the normalized seed alone, so cross-machine recovery recomputes the
same value from the transcribed seed without a separate transcription.
Like :mod:`mordred_hermes.keyvault.digest`, this module takes an
already-normalized seed — Unicode normalization is the caller's
responsibility (``api._normalize_seed_phrase``).

``blake3`` is part of the cross-platform ``keyvault`` extra; native backend
selection happens outside this pure module.
"""

from __future__ import annotations

from blake3 import blake3

#: Domain-separation tag (``MRPOW``) followed by the format version byte.
POW_PREFIX = b"MRPOW\x01"

#: v1 baseline difficulty. Tunable — see the SPEC caveat. ``compute_pow``
#: callers may override it for tests; production passes the default.
POW_DIFFICULTY_BITS = 20

_DIGEST_BITS = 256
_UINT64_LIMIT = 2**64
_COUNTER_LEN = 8


class PowExhausted(RuntimeError):
    """Raised if the uint64 counter space is exhausted without a hit.

    Astronomically improbable at any sane difficulty (a 64-bit search
    space versus a ~20-bit target) — defined only so the contract
    frozen in SPEC has a named failure mode rather than an infinite loop.
    """


def leading_zero_bits(digest: bytes) -> int:
    """Count the leading zero bits of ``digest`` (most-significant first)."""
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def compute_pow(normalized_seed: str, *, difficulty_bits: int = POW_DIFFICULTY_BITS) -> bytes:
    """Compute the 32-byte PoW artifact for ``normalized_seed``.

    Searches a uint64 counter for the smallest ``n`` whose preimage hash
    has at least ``difficulty_bits`` leading zero bits, and returns that
    winning 32-byte BLAKE3 digest.

    Raises:
        ValueError: ``difficulty_bits`` is negative or exceeds the
            256-bit digest width (unsatisfiable).
        PowExhausted: the counter space ran out (see :class:`PowExhausted`).
    """
    if difficulty_bits < 0:
        raise ValueError(f"difficulty_bits must be non-negative, got {difficulty_bits}")
    if difficulty_bits > _DIGEST_BITS:
        raise ValueError(f"difficulty_bits {difficulty_bits} exceeds the {_DIGEST_BITS}-bit digest width")
    base = POW_PREFIX + normalized_seed.encode("utf-8")
    n = 0
    while n < _UINT64_LIMIT:
        digest = blake3(base + n.to_bytes(_COUNTER_LEN, "little")).digest()
        if leading_zero_bits(digest) >= difficulty_bits:
            return digest
        n += 1
    raise PowExhausted("PoW counter space exhausted without satisfying the difficulty target")
