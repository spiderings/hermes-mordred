"""mordred_hermes.keyvault.anchor — device-bound vault freshness anchor.

The freshness root the manifest MAC cannot be on its own. ``wrap_dek`` is
offline (it only needs the Secure-Enclave *public* key), so an attacker
with disk access can mint a ``wmk`` that unwraps to a master *they* chose,
then MAC a whole forged manifest under it — the
:mod:`mordred_hermes.keyvault.manifest` MAC verifies fine. And the same
attacker can restore an older but validly-MAC'd manifest+files snapshot.
Neither attack moves a value the attacker cannot write.

The anchor closes both by pinning two **non-secret** values in a
device-bound store an offline attacker can read but not write (the real
backing item is a Keychain entry with ``ThisDeviceOnly`` +
``AfterFirstUnlock`` — a powered-off / stolen / imaged device cannot mint
or edit it):

- ``wmk_sha256`` — ``SHA-256`` of the canonical wmk. A substituted or
  cross-vault wmk has a different fingerprint (Codex review P1-a).
- ``generation`` — the monotonic counter the manifest also carries. A
  rolled-back snapshot's generation differs from the pin (Codex review P1-b).

:func:`verify_anchor` enforces strict equality on both before the vault
trusts the manifest's wmk. The store is abstracted by the
:class:`AnchorStore` ``Protocol`` (mirroring
:class:`mordred_hermes.keyvault.wrap.NativeBackend`): a software fake
drives these tests cross-platform; the production backend is a Keychain
generic-password item (lands with the native layer).

The anchor itself carries no MAC — its integrity rests entirely on the
store's write-control, which is exactly what an offline attacker lacks.
Both pinned values are non-secret, so storing them in the clear is fine.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

ANCHOR_VERSION: Final = 1
"""On-store anchor schema version."""


class AnchorError(Exception):
    """Base for every anchor failure — catch this to fail closed.

    An enrolled vault must never proceed past a failed anchor check: a
    missing, corrupt, or mismatched anchor all mean "cannot establish
    freshness," which under the threat model is indistinguishable from an
    offline tamper attempt.
    """


class AnchorMissing(AnchorError):
    """The store has no anchor for the label.

    Either the vault was never initialized, or an attacker deleted the
    anchor hoping the caller falls back to trusting the manifest alone.
    Fail closed.
    """


class AnchorMismatch(AnchorError):
    """The anchor is present but its pin does not match the candidate.

    Raised when ``SHA-256(wmk)`` differs from the pinned fingerprint
    (wmk substitution / cross-vault swap) or when ``generation`` differs
    from the pinned counter (rollback, or a forged-forward generation).
    """


class AnchorCorrupt(AnchorError):
    """The stored anchor bytes are unparseable or structurally invalid.

    Treated as a hard failure rather than a "reinitialize" signal: a
    corrupt anchor on an enrolled vault is suspicious, and silently
    rewriting it would erase the very pin that defends the vault.
    """


@runtime_checkable
class AnchorStore(Protocol):
    """Device-bound non-secret key→value store (Keychain generic password).

    The narrow seam the anchor logic needs. Only ``read`` is on the
    verification hot path; ``write`` / ``delete`` are used when the vault
    re-pins on a generation bump or tears a vault down.
    """

    def read(self, label: str) -> bytes | None:
        """Return the stored value for ``label``, or ``None`` if absent."""
        ...

    def write(self, label: str, value: bytes) -> None:
        """Store ``value`` under ``label``, overwriting any previous value."""
        ...

    def delete(self, label: str) -> None:
        """Remove ``label``. Idempotent — no-op when already absent."""
        ...


@dataclass(frozen=True, slots=True)
class VaultAnchor:
    """The pinned freshness state of one vault.

    ``wmk_sha256``: 32-byte ``SHA-256`` of the canonical wmk.
    ``generation``: the monotonic counter mirrored from the manifest.
    """

    wmk_sha256: bytes
    generation: int


def wmk_fingerprint(wmk: bytes) -> bytes:
    """The 32-byte ``SHA-256(wmk)`` pinned in the anchor."""
    return hashlib.sha256(wmk).digest()


def _serialize(anchor: VaultAnchor) -> bytes:
    body = {
        "v": ANCHOR_VERSION,
        "wmk_sha256": anchor.wmk_sha256.hex(),
        "generation": anchor.generation,
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _deserialize(raw: bytes) -> VaultAnchor:
    try:
        parsed: Any = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise AnchorCorrupt("anchor is not valid JSON") from e
    if not isinstance(parsed, dict) or parsed.get("v") != ANCHOR_VERSION:
        raise AnchorCorrupt(f"anchor is not a v{ANCHOR_VERSION} record")

    fp_hex = parsed.get("wmk_sha256")
    if not isinstance(fp_hex, str):
        raise AnchorCorrupt("anchor wmk_sha256 must be a hex string")
    try:
        fp = bytes.fromhex(fp_hex)
    except ValueError as e:
        raise AnchorCorrupt("anchor wmk_sha256 is not valid hex") from e
    if len(fp) != hashlib.sha256().digest_size:
        raise AnchorCorrupt("anchor wmk_sha256 is not a 32-byte digest")

    generation = parsed.get("generation")
    # bool is an int subclass; reject it so a stray `true` is not read as 1.
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise AnchorCorrupt("anchor generation must be a non-negative integer")

    return VaultAnchor(wmk_sha256=fp, generation=generation)


def write_anchor(store: AnchorStore, label: str, *, wmk: bytes, generation: int) -> None:
    """Pin ``SHA-256(wmk)`` + ``generation`` under ``label`` (overwriting).

    Raises:
        ValueError: ``wmk`` is empty or ``generation`` is negative.
    """
    if not wmk:
        raise ValueError("anchor wmk must not be empty")
    if generation < 0:
        raise ValueError("anchor generation must not be negative")
    store.write(label, _serialize(VaultAnchor(wmk_fingerprint(wmk), generation)))


def read_anchor(store: AnchorStore, label: str) -> VaultAnchor:
    """Read + parse the anchor at ``label``.

    Raises:
        AnchorMissing: the store has no value for ``label``.
        AnchorCorrupt: the stored bytes are unparseable / malformed.
    """
    raw = store.read(label)
    if raw is None:
        raise AnchorMissing(f"no vault anchor at label {label!r}")
    return _deserialize(raw)


def verify_anchor(store: AnchorStore, label: str, *, wmk: bytes, generation: int) -> None:
    """Verify a candidate ``(wmk, generation)`` against the pinned anchor.

    Strict equality on both pins: the manifest the vault is about to trust
    must match the exact wmk fingerprint and generation the anchor holds.

    Raises:
        AnchorMissing: no anchor at ``label`` (fail closed).
        AnchorCorrupt: the anchor bytes are malformed (fail closed).
        AnchorMismatch: the wmk fingerprint or generation does not match.
    """
    verify_pinned(read_anchor(store, label), wmk=wmk, generation=generation)


def verify_pinned(pinned: VaultAnchor, *, wmk: bytes, generation: int) -> None:
    """:func:`verify_anchor` against an anchor the caller has just read.

    Lets an open read the Keychain item once and pin-check the manifest
    against that same value, instead of reading it a second time (every
    Keychain read can cost the operator a macOS access dialog).

    Raises:
        AnchorMismatch: the wmk fingerprint or generation does not match.
    """
    if not hmac.compare_digest(pinned.wmk_sha256, wmk_fingerprint(wmk)):
        raise AnchorMismatch("wmk fingerprint does not match the device-bound anchor")
    if pinned.generation != generation:
        raise AnchorMismatch(
            f"generation {generation} does not match the anchor's pinned generation {pinned.generation}"
        )
