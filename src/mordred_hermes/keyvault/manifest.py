"""mordred_hermes.keyvault.manifest — ``MVMF`` vault manifest codec.

The integrity-critical registry of the Mordred vault. Where
:mod:`mordred_hermes.keyvault.file_container` encrypts individual files,
the manifest records *which* files are enrolled, the digest of each one's
ciphertext, the single canonical SE-wrapped master (``wmk``), and a
monotonic ``generation`` counter — and authenticates the whole thing with
:meth:`mordred_hermes.keyvault.kek.MasterKey.mac` (HMAC-SHA256 under a
master-derived subkey).

Wire format ``MVMF`` v1::

    line 0   body   {"files":{<name>:<sha256-hex>},"fmt":"MVMF","generation":<int>,
                     "key_id":<str>,"ver":1,"wmk":<base64>}
    \n
    tag           base64( HMAC-SHA256(master-subkey, body) )

The body is plaintext — it holds no secret (``wmk`` is device-bound but
not secret, the digests are public, the names are operational metadata).
What it needs is *tamper evidence*, which the trailing MAC provides:
:func:`decode` verifies the MAC over the exact body bytes **before**
parsing the JSON, so a tampered manifest is rejected without trusting any
attacker-controlled structure.

What this codec does NOT do on its own — and why the vault layer is
required for the full threat model (offline disk reads + offline disk
swaps, B2 unattended SE):

- **Master substitution.** ``wrap_dek`` is offline (public-key only), so
  an attacker with disk access can mint a ``wmk`` under the victim's SE
  *public* key that unwraps to a master *they* chose, then MAC a whole
  forged manifest under it. The MAC alone cannot catch this — the vault
  layer pins ``SHA-256(wmk)`` in a device-bound Keychain anchor (which an
  offline attacker can read but not *write*) and rejects any manifest
  whose ``wmk`` does not match the pin.
- **Whole-manifest rollback.** An attacker can restore an older but
  validly-MAC'd manifest+files snapshot. The in-body ``generation`` is
  carried here so the vault layer can compare it to the same Keychain
  anchor's pinned counter and reject a rewind. (An *in-place* generation
  edit without re-MACing is caught here, by the MAC.)

It imports :mod:`cryptography` through ``.kek`` from the cross-platform
``keyvault`` extra; the codec itself has no platform dependency.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from .kek import MasterKey

MAGIC: Final = "MVMF"
"""Body ``fmt`` tag — Mordred Vault ManiFest."""

FORMAT_VERSION: Final = 1
"""``MVMF`` wire-format version. Bump only on a breaking layout change."""

_MANIFEST_MAC_INFO: Final = b"mordred-vault-manifest-v1"
"""HKDF ``info`` domain-separating the manifest MAC subkey from every other
:meth:`MasterKey.mac` use (e.g. a future per-purpose tag)."""

_SHA256_HEX: Final = re.compile(r"\A[0-9a-f]{64}\Z")
"""Exactly what ``hashlib.sha256(...).hexdigest()`` emits. A ``files`` value is
used verbatim to build ``blobs/<digest>.blob``, so anything else is both
malformed and a path-traversal vector — reject it at the codec."""


class ManifestError(Exception):
    """An ``MVMF`` manifest could not be decoded or authenticated.

    Raised by :func:`decode` for every structural / integrity failure: a
    missing body/tag separator, a non-base64 tag, a MAC mismatch
    (tampered body, rolled-back in-body generation, or wrong master), a
    JSON parse failure, a bad ``fmt`` / ``ver``, or a malformed field.
    """


@dataclass(frozen=True, slots=True)
class VaultManifest:
    """The authenticated registry of one vault.

    ``key_id``: the Keychain id of the Secure-Enclave wrapping key.
    ``wmk``: the ONE canonical SE-wrapped master, identical to the ``wmk``
        carried in every enrolled file's ``MVLT`` header.
    ``files``: logical name -> ``SHA-256(ciphertext)`` hex. The vault layer
        re-hashes each on-disk blob and compares, so a swapped-in older
        blob (different digest) is rejected.
    ``generation``: monotonic counter bumped on every manifest write and
        mirrored in the device-bound Keychain anchor for rollback defence.
    """

    key_id: str
    wmk: bytes
    files: Mapping[str, str]
    generation: int


def _body_bytes(manifest: VaultManifest) -> bytes:
    """Serialize the manifest body to compact, key-sorted UTF-8 JSON."""
    body = {
        "fmt": MAGIC,
        "ver": FORMAT_VERSION,
        "key_id": manifest.key_id,
        "wmk": base64.b64encode(manifest.wmk).decode("ascii"),
        "files": dict(manifest.files),
        "generation": manifest.generation,
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def encode(manifest: VaultManifest, master: MasterKey) -> bytes:
    """Encode *manifest* into an authenticated ``MVMF`` v1 blob under *master*.

    Raises:
        ValueError: ``key_id`` is empty or ``generation`` is negative
            (caller bugs — an empty vault is ``generation=0`` with an
            empty ``files`` map, which is valid).
    """
    if not manifest.key_id:
        raise ValueError("manifest key_id must not be empty")
    if manifest.generation < 0:
        raise ValueError("manifest generation must not be negative")
    body = _body_bytes(manifest)
    tag = master.mac(body, info=_MANIFEST_MAC_INFO)
    return body + b"\n" + base64.b64encode(tag)


def _verify_mac(body: bytes, tag_b64: bytes, master: MasterKey) -> None:
    """Authenticate *body* against the base64 *tag_b64* under *master*.

    Verification happens before any JSON parse so a tampered manifest is
    rejected without trusting attacker-controlled structure.
    """
    try:
        tag = base64.b64decode(tag_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ManifestError("manifest tag is not valid base64") from e
    expected = master.mac(body, info=_MANIFEST_MAC_INFO)
    if not hmac.compare_digest(tag, expected):
        raise ManifestError("manifest failed authentication — tampered or wrong master")


def _parse_body(body: bytes) -> VaultManifest:
    """Parse an already-authenticated manifest body into a :class:`VaultManifest`."""
    try:
        parsed: Any = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ManifestError("manifest body is not valid JSON") from e
    if not isinstance(parsed, dict) or parsed.get("fmt") != MAGIC or parsed.get("ver") != FORMAT_VERSION:
        raise ManifestError(f"not a {MAGIC} v{FORMAT_VERSION} manifest")

    key_id = parsed.get("key_id")
    if not isinstance(key_id, str):
        raise ManifestError("manifest key_id must be a string")

    wmk_b64 = parsed.get("wmk")
    if not isinstance(wmk_b64, str):
        raise ManifestError("manifest wmk must be a base64 string")
    try:
        wmk = base64.b64decode(wmk_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ManifestError("manifest wmk is not valid base64") from e

    files = parsed.get("files")
    if not isinstance(files, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and _SHA256_HEX.match(v) for k, v in files.items()
    ):
        raise ManifestError("manifest files must map names to 64-char lowercase sha256 hex digests")

    generation = parsed.get("generation")
    # bool is an int subclass; reject it so a stray `true` is not read as 1.
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise ManifestError("manifest generation must be a non-negative integer")

    return VaultManifest(key_id=key_id, wmk=wmk, files=dict(files), generation=generation)


def _split(blob: bytes) -> tuple[bytes, bytes]:
    """Split a manifest blob into ``(body, tag_b64)``; raise on no separator."""
    body, sep, tag_b64 = blob.partition(b"\n")
    if not sep:
        raise ManifestError("not an MVMF manifest (missing body/tag separator)")
    return body, tag_b64


def decode(blob: bytes, master: MasterKey) -> VaultManifest:
    """Decode + authenticate an ``MVMF`` v1 *blob* under *master*.

    Raises:
        ManifestError: the blob is not a valid ``MVMF`` manifest, failed
            its MAC (tampered body, in-place generation rollback, or wrong
            master), or carries a malformed field.
    """
    body, tag_b64 = _split(blob)
    _verify_mac(body, tag_b64, master)
    return _parse_body(body)


def parse_unverified(blob: bytes) -> VaultManifest:
    """Parse an ``MVMF`` blob WITHOUT authenticating its MAC.

    The two-phase bootstrap: the master needed to verify the manifest MAC
    can only be obtained by unwrapping the ``wmk`` carried *inside* the
    manifest, so the vault must read ``wmk`` (and ``generation``) before it
    can authenticate anything. This extracts those fields from a
    structurally-valid manifest and does NOT check the tag.

    The result is therefore UNTRUSTED. A safe caller must, before relying
    on any field: (1) confirm ``SHA-256(wmk)`` matches the device-bound
    anchor pin (an offline attacker cannot write that pin), (2) unwrap the
    so-confirmed ``wmk`` to obtain the master, and (3) call :func:`decode`
    to authenticate the full manifest under that master.

    Structural validation still applies — a non-manifest blob raises
    :class:`ManifestError` rather than feeding junk into the unwrap path.
    Only the MAC is skipped.
    """
    body, _tag_b64 = _split(blob)
    return _parse_body(body)
