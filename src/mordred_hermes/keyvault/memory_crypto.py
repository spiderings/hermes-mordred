"""Wire format for at-rest agent-memory files (``~/.hermes/memories/*.md``).

No Hermes release encrypts those files, so Mordred owns the format end to end
(:mod:`._memory_hook` wraps the upstream read/write seam with it). The format is
**frozen** — a change here orphans every already-sealed memory file, which no
upstream re-key path can recover:

.. code-block:: text

    HERMES-MEMORY-ENC-v1\\n
    <base64url( nonce[12] || AES-256-GCM(plaintext, aad) )>\\n

Two properties the layout buys us:

* the magic line is the same byte string as ``wizard/memory_cli._ENC_HEADER``, so
  ``encryption status`` can classify a file by reading its first 20 bytes; and
* the AAD binds a ciphertext to its **basename**, so a sealed ``USER.md`` cannot
  be renamed over ``MEMORY.md`` (or a ``.bak.<ts>`` snapshot swapped for the live
  file) without failing authentication.

The whole encoding is ASCII, so a sealed file survives the upstream reader's
``utf-8`` / ``utf-8-sig`` decode and its ``str.strip()`` on entries.

``cryptography`` imports stay function-local so this module imports on a minimal
install (``encryption status`` classifies files without it).
"""

from __future__ import annotations

import base64
import os
from typing import Final

__all__ = [
    "AAD_PREFIX",
    "MAGIC",
    "MemoryCryptoError",
    "MemoryKeyError",
    "aad_for",
    "decode_key",
    "is_sealed",
    "looks_like_magic_line",
    "seal",
    "unseal",
]

#: First line of a sealed file. Identical bytes to ``wizard/memory_cli._ENC_HEADER``.
MAGIC: Final = b"HERMES-MEMORY-ENC-v1"

#: AAD = this prefix + the file's basename.
AAD_PREFIX: Final = b"hermes-memory-v1:"

_KEY_LEN: Final = 32
_NONCE_LEN: Final = 12
_TAG_LEN: Final = 16

#: A UTF-8 BOM ahead of the magic (a Notepad-edited file) must not hide the seal:
#: upstream reads memory files with ``utf-8-sig``, so it would strip the BOM and
#: hand us a sealed body we had already classified as plaintext.
_BOM: Final = b"\xef\xbb\xbf"

#: Every byte a sealed body can hold: URL-safe base64 plus its padding.
_BODY_ALPHABET: Final = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")


class MemoryCryptoError(Exception):
    """A sealed memory blob could not be produced or opened."""


class MemoryKeyError(MemoryCryptoError):
    """``HERMES_MEMORY_KEY`` is absent, malformed, or not 32 bytes."""


def aad_for(name: str) -> bytes:
    """The AAD binding a ciphertext to ``name`` (a **basename**, not a path)."""
    return AAD_PREFIX + name.encode("utf-8")


def decode_key(value: str) -> bytes:
    """Decode a ``HERMES_MEMORY_KEY`` value into its 32 raw bytes.

    Accepts exactly what ``wizard/vault_memory_key._is_valid_memory_key`` accepts,
    replicated rather than imported (keyvault must not depend on wizard): one pair
    of surrounding quotes is dropped — ``python-dotenv`` strips them, so a quoted
    key reaches the runtime unquoted — then a ``base64:`` / ``hex:`` prefix, else
    URL-safe base64 with missing padding tolerated. Raises :class:`MemoryKeyError`
    for anything that does not yield exactly 32 bytes.
    """
    raw = value.strip()
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        raw = raw[1:-1]

    if raw.startswith("hex:"):
        try:
            key = bytes.fromhex(raw[len("hex:") :].strip())
        except ValueError as exc:
            raise MemoryKeyError("HERMES_MEMORY_KEY is not valid hex") from exc
    else:
        if raw.startswith("base64:"):
            raw = raw[len("base64:") :].strip()
        try:
            key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (ValueError, TypeError) as exc:
            raise MemoryKeyError("HERMES_MEMORY_KEY is not valid URL-safe base64") from exc

    if len(key) != _KEY_LEN:
        raise MemoryKeyError(f"HERMES_MEMORY_KEY decodes to {len(key)} bytes, expected {_KEY_LEN} (AES-256)")
    return key


def is_sealed(data: bytes | str) -> bool:
    """Whether ``data`` is structurally a v1 seal (BOM / whitespace / CRLF tolerated).

    The whole structure is required — magic line, newline, one base64url body long
    enough to hold a nonce and a tag — not just the magic. An operator or the model
    can write the magic *text* into a memory file; treating that as sealed would
    make the file unopenable and hand the write path a "sealed" file with no key.

    Deliberately cheap and total: it classifies a file, so it must answer for
    arbitrary bytes without a key and without raising.
    """
    body = _strip_leading(_as_bytes(data))
    if not body.startswith(MAGIC + b"\n"):
        return False
    encoded = body[len(MAGIC) + 1 :].rstrip()
    if not encoded or not _BODY_ALPHABET.issuperset(encoded):
        return False
    try:
        raw = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except (ValueError, TypeError):
        return False
    return len(raw) >= _NONCE_LEN + _TAG_LEN


def looks_like_magic_line(text: str) -> bool:
    """Whether ``text`` merely *starts* with the magic (BOM / whitespace / CRLF tolerated).

    The prefix-only half of :func:`is_sealed`, for the callers that must treat an
    impersonation as suspicious rather than as a seal: the write guard (which
    refuses to create a plaintext file starting with it), the three-state read
    (which refuses a file that starts with the magic but is not a valid seal), and
    the CLI's drift detection.
    """
    return _strip_leading(_as_bytes(text)).startswith(MAGIC)


def seal(plaintext: bytes, *, key: bytes, name: str) -> bytes:
    """Seal ``plaintext`` for the file called ``name`` under a fresh random nonce."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _require_key_len(key)
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad_for(name))
    return MAGIC + b"\n" + base64.urlsafe_b64encode(nonce + ciphertext) + b"\n"


def unseal(blob: bytes, *, key: bytes, name: str) -> bytes:
    """Open a blob sealed for the file called ``name``.

    Tolerates a BOM, surrounding whitespace, ``\\r\\n`` line ends, and the trailing
    newline — the upstream reader hands us entries it has already ``strip()``ped
    (and a file may have been CRLF-converted at rest, see :func:`is_sealed`). Raises
    :class:`MemoryCryptoError` for a missing magic, a malformed body, or a failed
    authentication (wrong key, wrong filename, tampered bytes).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _require_key_len(key)
    body = _strip_leading(blob)
    if not body.startswith(MAGIC):
        raise MemoryCryptoError(f"{name}: not a sealed memory blob (no {MAGIC.decode()} header)")

    encoded = body[len(MAGIC) :].strip()
    try:
        raw = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except (ValueError, TypeError) as exc:
        raise MemoryCryptoError(f"{name}: sealed body is not valid base64") from exc
    if len(raw) < _NONCE_LEN + _TAG_LEN:
        raise MemoryCryptoError(f"{name}: sealed body is too short to hold a nonce and a tag")

    try:
        return AESGCM(key).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], aad_for(name))
    except InvalidTag as exc:
        raise MemoryCryptoError(
            f"{name}: sealed body failed to authenticate — wrong key, renamed file, or modified bytes"
        ) from exc


def _require_key_len(key: bytes) -> None:
    if len(key) != _KEY_LEN:
        raise MemoryKeyError(f"memory key is {len(key)} bytes, expected {_KEY_LEN} (AES-256)")


def _as_bytes(data: bytes | str) -> bytes:
    # surrogateescape: classification must never raise on text that came back from
    # a lossy decode somewhere upstream.
    return data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data


def _strip_leading(blob: bytes) -> bytes:
    """Drop a BOM and leading whitespace, and normalise ``\\r\\n`` line ends.

    CRLF is not cosmetic here. A sealed file that has been through a Windows
    editor, ``git`` with ``core.autocrlf``, or an ``rsync --crlf`` comes back with
    ``\\r\\n``, and every *text* reader in the chain (upstream's ``read_text``, ours)
    decodes it in universal-newline mode and sees the original ``\\n`` — while a
    classifier looking at the raw bytes would call the same file plaintext. That
    split view is a data-loss bug: the read seam decrypts the file and the write
    seam publishes plaintext over it. Normalising here gives every caller, bytes or
    text, one answer.
    """
    body = blob[len(_BOM) :] if blob.startswith(_BOM) else blob
    return body.replace(b"\r\n", b"\n").lstrip()
