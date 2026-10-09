"""mordred_keyvault.log_encryption — AES-GCM encryption layer for the audit log.

The current format contract is documented in SPEC.md §Audit log policy and
§Encrypted audit-log wire format.

:class:`EncryptedWriter` is an AES-GCM-encrypting implementation of the
Phase 1 ``Writer`` Protocol frozen in
:mod:`mordred_hermes.privacy_check.audit`. At Phase 4 launch the audit
factory swaps it in for :class:`~mordred_hermes.privacy_check.audit.NDJSONWriter`
so new audit entries are encrypted at rest. Pre-Phase-4 plaintext logs are
NOT retroactively encrypted (``hermes mordred audit purge`` handles them);
an :class:`EncryptedWriter` that finds a foreign file at its path rotates
it aside rather than corrupt or overwrite it.

Wire format (``MRAL`` v1 — frozen here)::

    line 0  header   {"fmt":"MRAL","ver":1,"key_id":<str>,"wdek":<base64>}
    line 1+ entry    base64( nonce(12) ‖ AES-GCM-ciphertext ‖ tag(16) )

- ``wdek`` is the audit-log DEK wrapped by :func:`mordred_keyvault.wrap.wrap_dek`
  — a 127-byte ``MRKW`` blob. Only the *wrapped* DEK touches disk; the
  plaintext 32-byte DEK lives in process memory for the writer's lifetime
  and is dropped on :meth:`EncryptedWriter.close`.
- Each entry is encrypted independently and written as one base64 line, so
  a single :meth:`~EncryptedWriter.append` stays whole-entry atomic (Writer
  Protocol invariant #2) and the file never needs a whole-file rewrite.
- The per-entry AES-GCM AAD binds every entry to its file header
  (``MAGIC ‖ version ‖ SHA-256(header_line)``). An entry lifted from
  another file — or replayed after the header is edited — fails the GCM
  tag check.

Every append, rotation, and partial-write rollback is serialized through
the same stable sidecar ``flock`` used by the plaintext writer. A writer
also verifies that the active path still names its own inode and header
before reusing its in-memory DEK. If another process took ownership, the
stale DEK is wiped and the foreign file is rotated intact before a fresh
header/DEK is created. A write-all loop completes the whole line even when
``os.write`` returns short.

The DEK is unwrapped through the selected native-key authorization boundary
(:func:`mordred_keyvault.wrap.unwrap_dek`) only on the *read* side
(:func:`decrypt_log_file`), which `hermes-mordred audit decrypt` drives.
Writing never authorizes: :func:`~mordred_keyvault.wrap.wrap_dek` is an offline
operation against the native key's public half.

This module imports :mod:`cryptography` from the cross-platform ``keyvault``
extra. Platform-specific custody stays behind ``NativeBackend``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import errno
import gzip
import hashlib
import json
import logging
import os
import re
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cryptography.exceptions import InvalidTag

from .._audit_io import (
    audit_path_stat as _audit_path_stat,
)
from .._audit_io import (
    exclusive_audit_lock as _exclusive_audit_lock,
)
from .._audit_io import (
    open_audit_file as _open_audit_file,
)
from .._audit_io import (
    read_first_line as _read_first_line,
)
from .._log_rotation import rotate_and_compress as _rotate_and_compress
from .._log_rotation import today_utc_date as _today_utc_date
from .._log_rotation import utcnow_iso as _utcnow_iso
from . import _native_key_id, _storage
from ._exceptions import WrapAuthCancelled, WrapError, WrapKeyNotFound
from .crypto import decrypt as _aes_decrypt
from .crypto import encrypt as _aes_encrypt
from .wrap import DEK_LEN, AuditSink, NativeBackend, unwrap_dek, wrap_dek

if TYPE_CHECKING:  # pragma: no cover - type-only conformance check
    from mordred_hermes.privacy_check.audit import Writer as _Writer

_LOG = logging.getLogger("mordred.keyvault.log_encryption")

MAGIC: Final = b"MRAL"
"""File-format magic — Mordred Audit Log (encrypted)."""

FORMAT_VERSION: Final = 1
"""``MRAL`` wire-format version. Bump only on a breaking layout change."""

AUDIT_LOG_KEY_ID: Final = "mordred.audit-log"
"""Keychain key id of the Secure-Enclave wrapping key for the audit-log DEK."""

_LEGACY_HEADER_FIELDS: Final = frozenset({"fmt", "ver", "key_id", "wdek"})
_SCOPED_HEADER_FIELDS: Final = _LEGACY_HEADER_FIELDS | frozenset({_native_key_id.NATIVE_KEY_ID_FIELD})

# Cap on the *plaintext* entry, matching NDJSONWriter so callers see one
# uniform limit regardless of which writer the factory installs. (The
# encrypted on-disk line is larger; see the module docstring atomicity note.)
MAX_ENTRY_BYTES: Final = 4000

DEFAULT_ROTATE_BYTES: Final = 10 * 1024 * 1024  # 10 MB
DEFAULT_RETENTION_DAYS: Final = 30

_GZIP_MAGIC: Final = b"\x1f\x8b"
_ROTATED_LOG_NAME: Final = re.compile(r"^(?P<active>.+)\.\d{4}-\d{2}-\d{2}(?:\.\d+)?(?:\.gz)?$")


class AuditLogDecryptError(Exception):
    """The encrypted audit log could not be read.

    Raised by :func:`decrypt_log_file` for every structural / integrity
    failure: a missing or malformed ``MRAL`` header, a non-encrypted
    (legacy plaintext) file, an empty file, a base64 / JSON decode
    failure, a wrapped-DEK that fails to unwrap for a non-authorization
    reason, or a per-entry AES-GCM tag check failure (tampered or
    cross-file-spliced line).

    Two wrap-layer exceptions deliberately propagate *unwrapped* instead
    because the caller (the ``audit decrypt`` CLI) must react differently:

    - :class:`~mordred_hermes.keyvault._exceptions.WrapAuthCancelled` —
      the user denied the Secure Enclave biometric / passcode prompt.
    - :class:`~mordred_hermes.keyvault._exceptions.WrapKeyNotFound` — the
      audit-log wrapping key is gone (different device, or revoked); the
      log is unrecoverable, not corrupt.
    """


def _serialize(entry: Mapping[str, Any]) -> bytes:
    """Serialize an audit entry to compact UTF-8 JSON (no trailing newline).

    ``sort_keys=True`` keeps the plaintext deterministic, which makes the
    test fixtures' fixed expectations stable. Raises :class:`ValueError`
    if the entry exceeds :data:`MAX_ENTRY_BYTES`.
    """
    data = json.dumps(entry, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(data) > MAX_ENTRY_BYTES:
        raise ValueError(f"audit entry exceeds {MAX_ENTRY_BYTES} bytes (got {len(data)})")
    return data


def _write_all(fd: int, data: bytes, *, rollback_to: int) -> None:
    """Write every byte, restoring the prior length on any failure.

    ``os.write`` may legally return short. A later no-progress/error result
    must not leave half a base64 entry (or half a header) behind, because that
    would make every subsequent decrypt fail. The caller holds the stable
    cross-process audit lock, so rollback cannot truncate another cooperating
    writer's later append.
    """
    view = memoryview(data)
    offset = 0
    try:
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise OSError("os.write returned 0 bytes while writing the encrypted audit log")
            offset += written
    except BaseException as exc:
        try:
            os.ftruncate(fd, rollback_to)
        except OSError as rollback_exc:
            exc.add_note(f"failed to remove the partial audit-log write: {rollback_exc}")
        raise


def _read_log_snapshot(path: Path) -> bytes:
    """Read one stable regular-file snapshot under the writer sidecar lock."""
    rotated = _ROTATED_LOG_NAME.fullmatch(path.name)
    lock_owner = path.with_name(rotated.group("active")) if rotated is not None else path
    with _exclusive_audit_lock(lock_owner):
        if _audit_path_stat(path) is None:
            raise FileNotFoundError(errno.ENOENT, "audit log file does not exist", str(path))
        fd = _open_audit_file(path, os.O_RDONLY)
        try:
            chunks: list[bytes] = []
            while chunk := os.read(fd, 65536):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)


def _entry_aad(header_bytes: bytes) -> bytes:
    """Derive the per-entry AES-GCM AAD that binds entries to *header_bytes*.

    ``MAGIC ‖ version ‖ SHA-256(header_line)``. The header line carries the
    file's unique random ``wdek``, so the digest differs per file: an entry
    encrypted under file A's AAD fails the tag check when spliced into
    file B, and editing the header invalidates every entry below it.
    """
    return MAGIC + bytes([FORMAT_VERSION]) + hashlib.sha256(header_bytes).digest()


def _encrypted_line_len(plaintext_len: int) -> int:
    """On-disk byte length of the base64 entry line for a plaintext of *plaintext_len*.

    ``crypto.encrypt`` prepends a 12-byte nonce and AES-GCM appends a
    16-byte tag; base64 expands by 4/3 (rounded up to a 4-char group).
    The trailing newline adds one byte. Used by the size-cap rotation
    check before the entry is actually encrypted.
    """
    enc_len = 12 + plaintext_len + 16
    b64_len = ((enc_len + 2) // 3) * 4
    return b64_len + 1


class EncryptedWriter:
    """AES-GCM-encrypting audit-log writer (Phase 1 ``Writer`` Protocol).

    One instance owns one active log file for its lifetime. Because the
    DEK is unwrappable only through an Enclave authorization prompt, an
    :class:`EncryptedWriter` cannot resume appending to an encrypted file
    written by an earlier process — on its first :meth:`append` it rotates
    any pre-existing file aside and starts a fresh file with a fresh DEK.
    Date-change and size-cap rotations during the writer's lifetime each
    likewise start a new file with a new DEK + header.

    Cooperating processes serialize through the stable audit sidecar lock.
    Since each process owns a different in-memory DEK, a writer verifies the
    active inode and header before every append and rotates a successor's file
    aside before taking ownership again.
    """

    def __init__(
        self,
        path: Path,
        *,
        backend: NativeBackend,
        key_id: str = AUDIT_LOG_KEY_ID,
        native_key_id: str | None = None,
        keyvault_root: Path | None = None,
        rotate_bytes: int = DEFAULT_ROTATE_BYTES,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        self.path = path
        self.backend = backend
        self.key_id = key_id
        self.native_key_id = native_key_id
        self.keyvault_root = Path(keyvault_root) if keyvault_root is not None else None
        self._keyvault_root_identity: tuple[int, int] | None = None
        self._keyvault_generation_epoch: bytes | None = None
        if self.keyvault_root is not None:
            # Factory-created writers are leases on one concrete keyvault
            # generation. Capture the root inode under the stable lifecycle
            # lock so reset + same-path re-init cannot let a stale cached DEK
            # append into the successor profile.
            with _storage.keyvault_lifecycle_lock(self.keyvault_root):
                _storage.assert_keyvault_active(self.keyvault_root)
                _storage._check_dir_mode(self.keyvault_root)
                self._keyvault_generation_epoch = _storage.ensure_generation_epoch(self.keyvault_root)
                metadata = self.keyvault_root.lstat()
                self._keyvault_root_identity = (metadata.st_dev, metadata.st_ino)
        self.rotate_bytes = rotate_bytes
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._last_date = ""
        # ``None`` => no active encrypted file yet (lazy: created on first
        # append and after each rotation). The plaintext DEK lives here for
        # the active file's lifetime; the wrapped form is on disk.
        self._dek: bytearray | None = None
        self._aad = b""
        self._header_bytes = b""
        self._active_identity: tuple[int, int] | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(self, entry: Mapping[str, Any]) -> None:
        """Encrypt one audit entry and append it as a single base64 line.

        Injects a millisecond-precision ``ts`` if the caller did not
        supply one (Writer Protocol invariant #1).
        """
        merged: dict[str, Any] = {"ts": _utcnow_iso(), **dict(entry)}
        plaintext = _serialize(merged)
        incoming = _encrypted_line_len(len(plaintext))

        lifecycle = (
            _storage.keyvault_lifecycle_lock(self.keyvault_root)
            if self.keyvault_root is not None
            else contextlib.nullcontext()
        )
        # Lock order is load-bearing: lifecycle -> writer mutex -> audit
        # sidecar. Keyvault unwrap paths already hold lifecycle while their
        # synchronous audit sink appends; the storage lock is reentrant for
        # exactly that nesting. Taking lifecycle after the sidecar would
        # deadlock against such an unwrap in another thread/process.
        with lifecycle, self._lock:
            self._assert_keyvault_generation()
            with _exclusive_audit_lock(self.path):
                self._refresh_active_ownership()
                self._maybe_rotate(incoming)
                dek, aad = self._active()
                token = base64.b64encode(_aes_encrypt(dek, plaintext, aad=aad))
                fd = _open_audit_file(
                    self.path,
                    os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                )
                try:
                    _write_all(fd, token + b"\n", rollback_to=os.fstat(fd).st_size)
                finally:
                    os.close(fd)

    def close(self) -> None:
        """Zero and drop the in-memory DEK.

        The DEK's authoritative buffer is a ``bytearray`` (see :meth:`_active`),
        so it is wiped in place here rather than merely dereferenced — better
        than leaving the long-lived audit-log key for the GC. Note this cannot
        be a total heap scrub: :meth:`_active` hands callers an immutable
        ``bytes`` snapshot per append and AES-GCM copies the key into OpenSSL,
        and those transient copies live until GC — wiping the ``bytearray``
        bounds the key's lifetime, it does not erase every copy. Kept for the
        ``Writer`` Protocol contract — each ``append`` already opens and closes
        its own fd.
        """
        with self._lock:
            self._wipe_dek()

    def _wipe_dek(self) -> None:
        """Zero the DEK buffer in place (it is a ``bytearray``), then drop it.

        Caller must hold ``self._lock``. Mirrors ``kek.MasterKey``'s wipe so the
        DEK's authoritative buffer is zeroed, not just dereferenced (transient
        ``bytes``/OpenSSL copies are inherent and out of scope — see
        :meth:`close`).
        """
        if self._dek is not None:
            self._dek[:] = bytes(len(self._dek))
        self._dek = None
        self._aad = b""
        self._header_bytes = b""
        self._active_identity = None

    # -- internals ---------------------------------------------------------

    def _assert_keyvault_generation(self) -> None:
        """Require the profile root captured when this writer was created.

        A successful reset removes ``keyvault_root``. A later init may recreate
        that same pathname with a new native key generation while this object
        still holds the old audit DEK. Comparing both a durable random
        generation epoch and the root inode prevents that stale writer from
        appending old-generation ciphertext into the new profile's active
        audit stream, including the unlikely case where dev/inode is reused.

        Caller holds both the lifecycle lock and ``self._lock``.
        """
        if self.keyvault_root is None:
            return
        try:
            _storage.assert_keyvault_active(self.keyvault_root)
            _storage._check_dir_mode(self.keyvault_root)
            epoch = _storage.read_generation_epoch(self.keyvault_root)
            metadata = self.keyvault_root.lstat()
        except BaseException:
            self._wipe_dek()
            raise
        identity = (metadata.st_dev, metadata.st_ino)
        if self._keyvault_generation_epoch != epoch or self._keyvault_root_identity != identity:
            self._wipe_dek()
            raise _storage.KeyvaultPermissionError(
                getattr(errno, "ESTALE", errno.EAGAIN),
                "keyvault root changed since the encrypted audit writer was created",
                str(self.keyvault_root),
            )

    def _refresh_active_ownership(self) -> None:
        """Drop a stale DEK when another process replaced the active file.

        Caller holds both writer and stable process locks. ``_active`` will
        rotate the successor file intact and mint a fresh DEK/header before
        this append proceeds.
        """
        if self._dek is None:
            return
        metadata = _audit_path_stat(self.path)
        owns_inode = (
            metadata is not None
            and self._active_identity is not None
            and (metadata.st_dev, metadata.st_ino) == self._active_identity
        )
        header = _read_first_line(self.path, limit=MAX_ENTRY_BYTES + 1) if owns_inode else None
        if not owns_inode or header != self._header_bytes:
            self._wipe_dek()

    def _active(self) -> tuple[bytes, bytes]:
        """Return ``(dek, aad)`` for the active file, creating it if needed.

        When no active file exists, any pre-existing file at ``path`` —
        a legacy plaintext NDJSON log, or an encrypted file from a prior
        process whose DEK this writer cannot unwrap without a prompt — is
        rotated aside first so it is preserved, not clobbered.
        """
        if self._dek is not None:
            return bytes(self._dek), self._aad

        if _audit_path_stat(self.path) is not None:
            self._rotate(_today_utc_date())

        dek = bytearray(os.urandom(DEK_LEN))
        wrapped = wrap_dek(
            bytes(dek),
            self.key_id,
            backend=self.backend,
            native_key_id=self.native_key_id,
        )
        header = {
            "fmt": MAGIC.decode("ascii"),
            "ver": FORMAT_VERSION,
            "key_id": self.key_id,
            "wdek": base64.b64encode(wrapped).decode("ascii"),
        }
        if self.native_key_id is not None:
            header[_native_key_id.NATIVE_KEY_ID_FIELD] = self.native_key_id
        header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        aad = _entry_aad(header_bytes)

        # O_EXCL: the file must not exist — _rotate above moved any prior
        # file aside. The stable lock excludes cooperating creators; a
        # survivor therefore means an unsafe external replacement.
        fd = _open_audit_file(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        )
        try:
            _write_all(fd, header_bytes + b"\n", rollback_to=0)
            metadata = os.fstat(fd)
        finally:
            os.close(fd)

        self._dek = dek
        self._aad = aad
        self._header_bytes = header_bytes
        self._active_identity = (metadata.st_dev, metadata.st_ino)
        return bytes(dek), aad

    def _maybe_rotate(self, incoming_bytes: int) -> None:
        """Rotate the active file on a UTC date change or a size-cap breach.

        Only an *active* file (``_dek is not None``) is rotated here; a
        foreign / stale file is left for :meth:`_active` to rotate aside.
        A rotation clears ``_dek`` so the next :meth:`_active` mints a
        fresh file, DEK and header.
        """
        today = _today_utc_date()
        metadata = _audit_path_stat(self.path)
        if self._last_date and self._last_date != today and self._dek is not None and metadata is not None:
            self._rotate(self._last_date)
            self._wipe_dek()
        elif self._dek is not None and metadata is not None and metadata.st_size + incoming_bytes > self.rotate_bytes:
            self._rotate(today)
            self._wipe_dek()
        self._last_date = today

    def _rotate(self, date_suffix: str) -> None:
        """Rename the active file to ``<name>.<date>[.N]`` and gzip it.

        No longer merely *mirrors*
        :class:`mordred_hermes.privacy_check.audit.NDJSONWriter`'s rotation —
        the two byte-for-byte identical bodies are now the one
        :func:`mordred_hermes._log_rotation.rotate_and_compress`: same-day
        collisions get an ``.N`` suffix; a gzip failure keeps the un-gzipped
        rotated file rather than losing data. This module's own ``_LOG`` is
        passed in, so that warning still reports under
        ``mordred.keyvault.log_encryption``.
        """
        _rotate_and_compress(self.path, date_suffix, retention_days=self.retention_days, log=_LOG)


def _reject_duplicate_header_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """JSON object hook that rejects ambiguous duplicate MRAL fields."""

    parsed: dict[str, object] = {}
    for field, value in pairs:
        if field in parsed:
            raise AuditLogDecryptError("header contains a duplicate JSON field")
        parsed[field] = value
    return parsed


def _parse_log_header(path: Path, header_bytes: bytes) -> tuple[dict[str, object], bytes]:
    """Parse and validate the unauthenticated MRAL header before backend I/O."""

    try:
        header = json.loads(header_bytes, object_pairs_hook=_reject_duplicate_header_fields)
    except AuditLogDecryptError as exc:
        raise AuditLogDecryptError(f"{path}: {exc}") from None
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise AuditLogDecryptError(f"{path}: header line is not valid JSON") from e
    if (
        not isinstance(header, dict)
        or header.get("fmt") != MAGIC.decode("ascii")
        or type(header.get("ver")) is not int
        or header.get("ver") != FORMAT_VERSION
    ):
        raise AuditLogDecryptError(
            f"{path}: not a {MAGIC.decode('ascii')} v{FORMAT_VERSION} encrypted audit log "
            "(a pre-Phase-4 plaintext log is read with `audit tail`, not `audit decrypt`)"
        )
    fields = frozenset(header)
    if fields not in {_LEGACY_HEADER_FIELDS, _SCOPED_HEADER_FIELDS}:
        raise AuditLogDecryptError(f"{path}: header does not match the exact MRAL v1 schema")
    key_id = header["key_id"]
    if key_id != AUDIT_LOG_KEY_ID:
        raise AuditLogDecryptError(f"{path}: header key_id is not the audit-log key role")
    wdek_b64 = header.get("wdek")
    if not isinstance(wdek_b64, str):
        raise AuditLogDecryptError(f"{path}: header wdek must be a base64 string")
    try:
        wrapped = base64.b64decode(wdek_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise AuditLogDecryptError(f"{path}: header wdek is not valid base64") from e
    if base64.b64encode(wrapped).decode("ascii") != wdek_b64:
        raise AuditLogDecryptError(f"{path}: header wdek is not canonical base64")
    return header, wrapped


def _unwrap_log_dek(
    path: Path,
    header_bytes: bytes,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    keyvault_home: Path | None,
) -> bytes:
    """Validate the ``MRAL`` header line and unwrap the audit-log DEK.

    Raises:
        AuditLogDecryptError: The header line is not valid JSON, is not a
            recognised exact-schema ``MRAL`` audit header, selects a non-audit
            logical/native key, or carries an unwrappable DEK.
        WrapAuthCancelled / WrapKeyNotFound: Propagated from the unwrap so
            the CLI can handle a denied prompt and a missing key distinctly
            from a corrupt file.
    """
    header, wrapped = _parse_log_header(path, header_bytes)

    root = _storage.resolve_keyvault_dir(keyvault_home)
    try:
        if _native_key_id.NATIVE_KEY_ID_FIELD in header:
            native_key_id = _native_key_id.persisted_native_key_id(
                root,
                AUDIT_LOG_KEY_ID,
                header[_native_key_id.NATIVE_KEY_ID_FIELD],
            )
        else:
            # The exact four-field v1 schema predates profile-scoped native
            # selectors. It can only mean the historical global audit role.
            # A current header with this field stripped is byte-for-byte
            # indistinguishable here; the fixed role hash and wrap integrity
            # still prevent it from selecting or decrypting with a main key.
            native_key_id = AUDIT_LOG_KEY_ID
    except _native_key_id.NativeKeyIdMismatch as e:
        raise AuditLogDecryptError(f"{path}: header native_key_id does not match this keyvault profile") from e

    backend = _native_key_id.backend_for_persisted_key(
        backend,
        root,
        AUDIT_LOG_KEY_ID,
        native_key_id,
    )
    try:
        return unwrap_dek(
            wrapped,
            AUDIT_LOG_KEY_ID,
            audit_sink=audit_sink,
            backend=backend,
            native_key_id=native_key_id,
        )
    except (WrapAuthCancelled, WrapKeyNotFound):
        # Propagate unwrapped — the CLI handles a denied prompt and a
        # missing key distinctly from a corrupt file.
        raise
    except WrapError as e:
        raise AuditLogDecryptError(f"{path}: cannot unwrap the audit-log DEK") from e


def _decode_log_entries(
    path: Path,
    lines: list[bytes],
    dek: bytes,
    aad: bytes,
) -> list[dict[str, Any]]:
    """Decode every entry line (oldest first) under the unwrapped DEK.

    ``lines`` is the whole file split on newlines; the header (``lines[0]``)
    is skipped. Raises :class:`AuditLogDecryptError` on any entry that fails
    to base64-decode, authenticate, or parse as a JSON object.
    """
    out: list[dict[str, Any]] = []
    for n, line in enumerate(lines[1:], start=2):
        if not line:
            continue
        try:
            blob = base64.b64decode(line, validate=True)
        except (binascii.Error, ValueError) as e:
            raise AuditLogDecryptError(f"{path}: line {n} is not valid base64") from e
        try:
            plaintext = _aes_decrypt(dek, blob, aad=aad)
        except InvalidTag as e:
            raise AuditLogDecryptError(
                f"{path}: line {n} failed authentication — tampered, truncated, or spliced from another file"
            ) from e
        try:
            entry = json.loads(plaintext)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise AuditLogDecryptError(f"{path}: line {n} decrypted to invalid JSON") from e
        if not isinstance(entry, dict):
            raise AuditLogDecryptError(f"{path}: line {n} decrypted to a non-object JSON value")
        out.append(entry)
    return out


def decrypt_log_file(
    path: Path,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    file_bytes: bytes | None = None,
    keyvault_home: Path | None = None,
) -> list[dict[str, Any]]:
    """Decrypt one ``MRAL`` audit-log file and return its entries in order.

    Transparently decompresses a gzip-rotated file. Unwraps the audit-log
    DEK through :func:`mordred_keyvault.wrap.unwrap_dek` — the Secure
    Enclave authorization boundary — which emits a
    ``keyvault.unwrap_authorized`` audit entry through *audit_sink* on
    success (or ``keyvault.unwrap_denied`` on a denied prompt).

    Args:
        path: The ``audit.log`` (or rotated ``audit.log.<date>.gz``) file.
        backend: Secure-Enclave backend for the DEK unwrap.
        audit_sink: Sink the wrap layer records the unwrap decision into.
        file_bytes: An optional already-read snapshot of ``path``.  The audit
            CLI supplies this after opening the source through a bound
            directory descriptor with ``O_NOFOLLOW``; ordinary callers can
            omit it to take an equivalent regular-file/no-follow snapshot
            under the writer's stable audit sidecar.

    Returns:
        The decrypted audit entries, oldest first.

    Raises:
        AuditLogDecryptError: The file is not a valid ``MRAL`` log, is
            empty, or any header / entry failed to decode or authenticate.
        WrapAuthCancelled: The user denied the Enclave prompt.
        WrapKeyNotFound: The audit-log wrapping key is missing.
    """
    root = _storage.resolve_keyvault_dir(keyvault_home)
    lifecycle: contextlib.AbstractContextManager[None]
    try:
        root.parent.lstat()
    except FileNotFoundError:
        # Standalone callers with an injected backend may have no profile tree
        # at all. Initialization can only begin after creating this stable
        # parent, so this decrypt linearizes before that future generation.
        lifecycle = contextlib.nullcontext()
    else:
        lifecycle = _storage.keyvault_lifecycle_lock(root)

    with lifecycle:
        _storage.assert_keyvault_active(root)
        try:
            root.lstat()
        except FileNotFoundError:
            pass
        else:
            _storage._check_dir_mode(root)
        # Lock order matches EncryptedWriter: lifecycle -> audit sidecar. The
        # sidecar is released after the immutable snapshot is complete and
        # before unwrap emits to audit_sink, so a sink that appends to this log
        # cannot self-deadlock.
        raw = _read_log_snapshot(Path(path)) if file_bytes is None else file_bytes
        if raw[:2] == _GZIP_MAGIC:
            raw = gzip.decompress(raw)

        lines = raw.splitlines()
        if not lines:
            raise AuditLogDecryptError(f"{path}: empty audit log file")

        header_bytes = lines[0]
        dek = _unwrap_log_dek(
            path,
            header_bytes,
            backend=backend,
            audit_sink=audit_sink,
            keyvault_home=keyvault_home,
        )
        aad = _entry_aad(header_bytes)
        # Keep reset outside the whole logical read, not only ECDH. Otherwise
        # reset could report key destruction while this call was still
        # authenticating entries and preparing plaintext for its caller.
        return _decode_log_entries(path, lines, dek, aad)


if TYPE_CHECKING:  # pragma: no cover - mypy-only Writer Protocol conformance

    def _conformance(w: EncryptedWriter) -> _Writer:
        """Fail mypy if EncryptedWriter drifts from the frozen Writer surface."""
        return w
