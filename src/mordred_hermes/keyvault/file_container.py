"""mordred_hermes.keyvault.file_container — ``MVLT`` encrypted-file codec.

The generic at-rest container for the Mordred vault. Where the earlier
``MENV`` codec only handled ``KEY=value`` env entries, this encrypts an
*arbitrary byte payload* — a whole ``.env`` file, a
``config.yaml``, or a single agent-memory file — under the SE+KEK hybrid:

- a per-vault **master key** (:class:`mordred_hermes.keyvault.kek.MasterKey`)
  runs the bulk software AES-GCM at memory speed, and
- a **Secure-Enclave wrapping key** wraps that master at rest (the ``wmk``
  header field), so the file is device-bound and the Enclave is touched at
  most once per session.

This module is the pure codec: it encodes/decodes the wire format given an
*already-opened* master key. Sealing the master, opening it through the Enclave,
persisting the blob to disk, and registering it in the vault manifest are the
orchestration layers above this one.

Wire format ``MVLT`` v1::

    line 0   header   {"fmt":"MVLT","ver":1,"key_id":<str>,"wmk":<base64>,"name":<str>}
    \n
    body              base64( nonce(12) ‖ ciphertext ‖ tag(16) )

The AES-GCM AAD is ``MAGIC ‖ version ‖ SHA-256(header) ‖ name``. The header
carries the vault's ``wmk`` and the file's logical ``name``, so the blob cannot
be spliced onto another logical file, have its header (``key_id`` / ``wmk`` /
``name``) edited, or have its ``name`` rewritten to match a different decode
target (the original name was bound into the tag).

This codec does NOT defend against *whole-blob rollback* — replacing the current
blob with an older, still-valid blob for the same ``name`` and master
re-authenticates. Freshness / generation tracking is the vault manifest's job,
not the per-file codec's. The vault also uses a single canonical ``wmk`` across
all of its files (see :mod:`mordred_hermes.keyvault.vault_master`); this codec
records whatever ``wmk`` it is given and does not enforce that invariant itself.

Imports :mod:`cryptography` through the cross-platform ``keyvault`` extra. The
codec itself is platform-neutral.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Final

from cryptography.exceptions import InvalidTag

from .kek import MasterKey

MAGIC: Final = b"MVLT"
"""File-format magic — Mordred VauLT (encrypted file container)."""

FORMAT_VERSION: Final = 1
"""``MVLT`` wire-format version. Bump only on a breaking layout change."""

_MIN_TOKEN_LEN: Final = 12 + 16
"""Smallest valid AES-GCM token: nonce(12) + tag(16), empty ciphertext allowed."""


class EncryptedFileError(Exception):
    """An ``MVLT`` blob could not be decoded.

    Raised by :func:`decode` for every structural / integrity failure: a
    missing or malformed ``MVLT`` header, a non-encrypted (legacy plaintext)
    file, an empty file, a base64 / JSON decode failure, a ``name`` that does
    not match the requested logical name, or an AES-GCM tag check failure
    (tampered, header-rebound, name-rewritten, or wrong master key).
    """


def _build_header_bytes(key_id: str, wmk: bytes, name: str) -> bytes:
    """Serialize the ``MVLT`` header line to compact, key-sorted UTF-8 JSON."""
    header = {
        "fmt": MAGIC.decode("ascii"),
        "ver": FORMAT_VERSION,
        "key_id": key_id,
        "wmk": base64.b64encode(wmk).decode("ascii"),
        "name": name,
    }
    return json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _aad(header_bytes: bytes, name: str) -> bytes:
    """Per-blob AAD binding the ciphertext to its header *and* its logical name."""
    return MAGIC + bytes([FORMAT_VERSION]) + hashlib.sha256(header_bytes).digest() + name.encode("utf-8")


def encode(master: MasterKey, plaintext: bytes, *, key_id: str, wmk: bytes, name: str) -> bytes:
    """Encode *plaintext* into an ``MVLT`` v1 blob under *master*.

    Args:
        master: The opened KEK master key doing the AES-GCM.
        plaintext: Arbitrary file bytes (may be empty, may contain any byte).
        key_id: The Keychain id of the Secure-Enclave wrapping key that wrapped
            *master* into *wmk* — recorded in the header for the opener.
        wmk: The wrapped master key blob, persisted verbatim in the header.
        name: The file's logical name (e.g. ``".env"``, ``"config.yaml"``, or a
            memory file's relative path). Bound into the AAD so the blob cannot
            be reused under a different name.

    Raises:
        ValueError: *name* is empty.
    """
    if not name:
        raise ValueError("file container name must not be empty")
    header_bytes = _build_header_bytes(key_id, wmk, name)
    token = master.encrypt(plaintext, aad=_aad(header_bytes, name))
    return header_bytes + b"\n" + base64.b64encode(token)


def decode(blob: bytes, master: MasterKey, *, name: str) -> bytes:
    """Decode an ``MVLT`` v1 *blob* under *master*; return the file bytes.

    Args:
        blob: The encrypted container contents.
        master: The opened KEK master key (a wrong key fails the tag check).
        name: The logical name the caller expects this blob to hold. Must match
            the header's ``name`` and the name bound into the AAD, or decoding
            fails — this is the anti-blob-swap defence.

    Raises:
        ValueError: *name* is empty (a caller bug — mirrors :func:`encode`).
        EncryptedFileError: The blob is not a valid ``MVLT`` container, its name
            does not match *name*, or it failed to decode / authenticate.
    """
    if not name:
        raise ValueError("file container name must not be empty")
    header_bytes, sep, b64 = blob.partition(b"\n")
    if not sep:
        raise EncryptedFileError("not an MVLT container (missing header/body separator)")

    try:
        header = json.loads(header_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise EncryptedFileError("header line is not valid JSON") from e
    if (
        not isinstance(header, dict)
        or header.get("fmt") != MAGIC.decode("ascii")
        or header.get("ver") != FORMAT_VERSION
    ):
        raise EncryptedFileError(
            f"not a {MAGIC.decode('ascii')} v{FORMAT_VERSION} encrypted file "
            "(a legacy plaintext file is read directly, not through this codec)"
        )
    if header.get("name") != name:
        raise EncryptedFileError("container name does not match the requested logical name")

    try:
        token = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise EncryptedFileError("container body is not valid base64") from e
    if len(token) < _MIN_TOKEN_LEN:
        # Too short to hold an AES-GCM nonce + tag. Reject here so the cipher
        # layer does not raise a raw ValueError ("Nonce must be ...") that
        # escapes the EncryptedFileError contract (codex review).
        raise EncryptedFileError("container body is too short to be a valid AES-GCM token")

    try:
        return master.decrypt(token, aad=_aad(header_bytes, name))
    except InvalidTag as e:
        raise EncryptedFileError("container failed authentication — tampered, header-rebound, or wrong key") from e
