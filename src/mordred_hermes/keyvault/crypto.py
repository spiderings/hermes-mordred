"""mordred_keyvault.crypto — AES-GCM primitives.

Self-contained blob carries its own 96-bit nonce so callers do not have
to manage nonce uniqueness manually. Wire format:

    nonce(12) || ciphertext || tag(16)

AES-GCM key sizes accepted: 128 / 192 / 256 bit. The keyvault uses 256-bit
data-encryption keys (DEKs) per SPEC §Plugin: ``mordred_keyvault``.

``cryptography`` is supplied by the cross-platform ``keyvault`` extra. Native
key custody is selected separately (Secure Enclave on macOS or TPM 2.0 on
Linux), so these pure primitives remain platform-neutral.
"""

from __future__ import annotations

from secrets import token_bytes

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE = 12
_TAG_SIZE = 16


def encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    """Encrypt ``plaintext`` with AES-GCM and return ``nonce || ct || tag``.

    ``nonce`` is drawn from :func:`secrets.token_bytes` rather than
    :func:`os.urandom` to express the cryptographic intent at the call
    site — both call the same kernel CSPRNG on CPython, but the import
    line documents *why* the bytes need to be unpredictable.
    """
    nonce = token_bytes(_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, *, aad: bytes = b"") -> bytes:
    """Decrypt a blob produced by :func:`encrypt`. Raises ``InvalidTag`` on tamper.

    A blob structurally too short for ``nonce(12) || tag(16)`` also raises
    ``InvalidTag`` — without the explicit guard the error type would flip
    between AESGCM's nonce-size ``ValueError`` (< 12 bytes survived) and
    ``InvalidTag`` (12-27 bytes), making truncation corruption look like a
    caller bug instead of the documented tamper signal.
    """
    if len(blob) < _NONCE_SIZE + _TAG_SIZE:
        raise InvalidTag(f"blob too short for AES-GCM nonce + tag ({len(blob)} bytes)")
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
