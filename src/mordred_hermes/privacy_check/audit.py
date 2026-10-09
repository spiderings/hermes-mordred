"""Audit log writer — serialized NDJSON with daily + size rotation, gzip + retention.

Phase 1 implementation per SPEC.md §Audit log policy + TODO.md §1.1:

- File mode ``0o600``, parent dir mode ``0o700``
- POSIX ``O_APPEND`` open per write with a short-write completion loop
- Entries capped at the frozen 4000-byte writer limit
- Daily roll to ``audit.log.YYYY-MM-DD``, gzip after rotation
- 10 MB size cap forces same-day rotation (``audit.log.YYYY-MM-DD.N.gz``)
- 30-day retention swept on each rotation
- In-process ``threading.Lock`` plus a stable ``fcntl.flock`` sidecar lock;
  cooperating Mordred processes cannot interleave rotation/write/rollback

Phase 4 will swap :class:`NDJSONWriter` for ``EncryptedWriter`` behind the
:class:`Writer` Protocol; the Protocol is frozen here.

Why fd-per-write: keeps the writer fork-safe and tolerant of external file
deletion (e.g. user manually rm'd audit.log). The cost is a syscall pair
per entry, which is negligible at audit-log volumes.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol

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
from .._log_rotation import next_rotation_target as _next_rotation_target
from .._log_rotation import rotate_and_compress as _rotate_and_compress
from .._log_rotation import today_utc_date as _today_utc_date
from .._log_rotation import utcnow_iso as _utcnow_iso

if TYPE_CHECKING:
    from ..keyvault.wrap import NativeBackend

_LOG = logging.getLogger("mordred.privacy_check.audit")

# Frozen bounded-entry limit shared with the encrypted writer. Cross-process
# whole-entry serialization comes from the stable sidecar lock, not PIPE_BUF
# (which specifies pipe/FIFO writes, not regular audit files).
MAX_ENTRY_BYTES: Final = 4000

DEFAULT_ROTATE_BYTES: Final = 10 * 1024 * 1024  # 10 MB
DEFAULT_RETENTION_DAYS: Final = 30


class Writer(Protocol):
    """Frozen audit-log writer surface (Phase 1 contract for Phase 4 swap).

    Implementors MUST honor the following invariants so consumers of the
    audit log (and callers like :mod:`mordred_hermes.keyvault.recovery`)
    can rely on a uniform entry shape regardless of which writer is
    installed (plaintext NDJSON in Phase 1-3, AES-GCM-encrypted in Phase 4):

    1. **``ts`` injection**: if the caller-supplied ``entry`` does not
       carry a ``ts`` field, the writer MUST add one set to the current
       UTC time in ISO-8601 with **3-digit millisecond** precision —
       literally ``"%Y-%m-%dT%H:%M:%S." + "{ms:03d}" + "Z"``. Python's
       ``%f`` directive yields 6-digit microseconds, so the
       :func:`_utcnow_iso` helper builds the string manually rather
       than relying on a single ``strftime`` format string. Callers
       further up the stack — including the keyvault ``audit_sink``
       contract documented in :mod:`mordred_hermes.keyvault.recovery`
       — assume this and do not inject ``ts`` themselves.
       Code-reviewer MEDIUM-3 (2026-05-14) + second-pass NIT
       (2026-05-14): this contract was previously only enforced by
       :class:`NDJSONWriter` and documented with a misleading ``fff``
       glyph that Python developers might read as ``%f%f%f`` (18-digit
       microseconds). Documenting the exact assembly here prevents
       a future Phase 4 ``EncryptedWriter`` from silently shipping
       ``ts``-less entries or, worse, microsecond-precision ones.
    2. **Whole-entry atomicity**: a single :meth:`append` call either
       writes the entire serialized entry (one NDJSON line) or none of
       it. No partial-write states should be observable on disk.
    3. **0600 file mode**: any underlying file MUST be opened with
       mode ``0600`` so audit history is not readable by other local
       users.
    """

    def append(self, entry: Mapping[str, Any]) -> None: ...
    def close(self) -> None: ...


def _serialize(entry: Mapping[str, Any]) -> bytes:
    """Serialize an audit entry to NDJSON bytes (terminated with newline).

    ``sort_keys=True`` yields stable field order across processes/builds —
    ``audit grep`` users get predictable output.
    """
    line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False, sort_keys=True) + "\n"
    data = line.encode("utf-8")
    if len(data) > MAX_ENTRY_BYTES:
        raise ValueError(f"audit entry exceeds {MAX_ENTRY_BYTES} bytes (got {len(data)})")
    return data


@dataclass
class NDJSONWriter:
    """Serialized NDJSON audit logger.

    The in-process lock serializes threads using one writer instance.  A
    stable sidecar ``flock`` additionally serializes cooperating Mordred
    processes, including the separate installer CLI process, across rotation,
    append, and rollback.
    """

    path: Path
    rotate_bytes: int = DEFAULT_ROTATE_BYTES
    retention_days: int = DEFAULT_RETENTION_DAYS
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _last_date: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Tighten an existing regular inode through a no-follow descriptor.
        # Symlinks and specials fail closed without chmoding or opening their
        # target (a FIFO open could otherwise block interpreter startup).
        if _audit_path_stat(self.path) is not None:
            # ``tighten=True`` is the point of this open: repair a log the user
            # touched at the umask default. Plain reads elsewhere deliberately
            # leave permissions alone.
            fd = _open_audit_file(self.path, os.O_RDONLY, tighten=True)
            os.close(fd)

    def append(self, entry: Mapping[str, Any]) -> None:
        """Append one audit entry. Adds ``ts`` if caller did not."""
        merged: dict[str, Any] = {"ts": _utcnow_iso(), **dict(entry)}
        data = _serialize(merged)

        with self._lock, _exclusive_audit_lock(self.path):
            _assert_plaintext_append_safe(self.path)
            self._maybe_rotate(len(data))
            fd = _open_audit_file(
                self.path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            )
            offset = 0
            try:
                original_size = os.fstat(fd).st_size
                view = memoryview(data)
                while offset < len(view):
                    written = os.write(fd, view[offset:])
                    if written <= 0:
                        raise OSError("os.write returned 0 bytes while appending the audit entry")
                    offset += written
            except BaseException:
                # Writer protocol invariant: append is whole-entry or none.
                # The stable sidecar flock is still held here, so no
                # cooperating process can append between original_size and
                # this rollback and have its entry truncated with ours.
                if offset:
                    try:
                        os.ftruncate(fd, original_size)
                    except OSError as rollback_error:
                        raise OSError(
                            "audit append failed and its partial entry could not be rolled back"
                        ) from rollback_error
                raise
            finally:
                os.close(fd)

    def close(self) -> None:
        # Each append opens+closes its own fd, so close() is a no-op.
        # Kept for the Writer Protocol contract.
        return None

    def _maybe_rotate(self, incoming_bytes: int) -> None:
        """Check whether the active file needs to be rotated.

        Two triggers:

        - **Date change**: first append on a new UTC day rotates yesterday.
        - **Size cap**: file size + incoming bytes would exceed
          ``rotate_bytes``. Same-day collisions get an ``.N`` suffix.

        Process restart resets the in-memory ``_last_date``; the file from
        a prior day continues collecting today's entries until the size
        cap or the next date change. This is acceptable for v1 (loose
        "daily roll" intent — strict midnight-UTC rotation is v2).
        """
        today = _today_utc_date()
        metadata = _audit_path_stat(self.path)
        if self._last_date and self._last_date != today and metadata is not None:
            self._rotate(self._last_date)
        elif metadata is not None and metadata.st_size + incoming_bytes > self.rotate_bytes:
            self._rotate(today)
        self._last_date = today

    def _rotate(self, date_suffix: str) -> None:
        """Rename the active file aside, gzip it, and sweep expired rotations.

        Shared with ``EncryptedWriter._rotate`` via
        :func:`mordred_hermes._log_rotation.rotate_and_compress` (the two
        bodies were byte-for-byte identical apart from the logger). This
        module's own ``_LOG`` is passed in, so a gzip failure is still reported
        under ``mordred.privacy_check.audit``.
        """
        _rotate_and_compress(self.path, date_suffix, retention_days=self.retention_days, log=_LOG)


# Phase 4 ``MRAL`` encrypted-log format tag — mirrors
# ``keyvault.log_encryption.MAGIC`` (b"MRAL"). Duplicated as a literal so
# this module stays importable without the macOS-extra-gated keyvault
# crypto stack (``wizard.audit_cli`` keeps its own copy for the same
# reason). ``MRAL`` is a frozen v1 wire constant, so the copies cannot drift.
_MRAL_FMT: Final = "MRAL"


def _assert_plaintext_append_safe(audit_path: Path) -> None:
    """Refuse MRAL, malformed, or foreign active-file formats."""
    first_line = _read_first_line(audit_path, limit=MAX_ENTRY_BYTES + 1)
    if first_line is None or not first_line:
        return
    try:
        first_entry = json.loads(first_line)
    except ValueError as exc:
        raise OSError("refusing to append plaintext to an unrecognized or corrupt audit log") from exc
    if not isinstance(first_entry, dict):
        raise OSError("refusing to append plaintext to a foreign audit-log format")
    if first_entry.get("fmt") == _MRAL_FMT:
        raise OSError("refusing to append plaintext to an MRAL-encrypted audit log")


def _audit_log_is_encrypted(audit_path: Path) -> bool:
    """Return True if ``audit_path`` is a Phase 4 ``MRAL``-encrypted log.

    The ``MRAL`` format's line 0 is a JSON header carrying ``fmt:"MRAL"``;
    a plaintext NDJSON log's first line is an ordinary audit entry that
    never carries that field. A missing file is "not encrypted"; unsafe
    path types and I/O failures propagate so callers fail closed.
    """
    try:
        first_line = _read_first_line(audit_path, limit=MAX_ENTRY_BYTES + 1)
    except FileNotFoundError:
        return False
    if first_line is None:
        return False
    if first_line[:1] != b"{":
        return False
    try:
        header = json.loads(first_line)
    except ValueError:  # JSONDecodeError / UnicodeDecodeError both subclass it
        return False
    return isinstance(header, dict) and header.get("fmt") == _MRAL_FMT


def _rotate_encrypted_log_aside(audit_path: Path) -> None:
    """Move an existing ``MRAL`` log aside before a plaintext writer opens it.

    A fallback :class:`NDJSONWriter` opens ``audit_path`` with ``O_APPEND``.
    If a prior session left a Phase 4 ``MRAL``-encrypted log there, a
    plaintext append would splice cleartext into the ciphertext stream and
    make ``decrypt_log_file`` (``hermes mordred audit decrypt``) fail for
    the whole file — losing that file's encrypted entries. Rename the
    encrypted log to a dated ``audit.log.<date>`` sibling, which
    ``audit decrypt --date`` still resolves and decrypts, so the plaintext
    writer starts a fresh file. This mirrors :class:`EncryptedWriter`'s
    rotate-aside of a foreign plaintext file (the forward transition).
    """
    with _exclusive_audit_lock(audit_path):
        if not _audit_log_is_encrypted(audit_path):
            return
        before = _audit_path_stat(audit_path)
        if before is None:
            return
        target = _next_rotation_target(audit_path, _today_utc_date())
        os.replace(audit_path, target)
        moved = _audit_path_stat(target)
        if moved is None or (moved.st_dev, moved.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise OSError("audit path changed during encrypted-log rotation")
    _LOG.warning(
        "audit log at %s is MRAL-encrypted but a plaintext writer is taking over; "
        "rotated the encrypted log aside to %s (still readable via `audit decrypt`)",
        audit_path,
        target,
    )


def _select_audit_native_key(root: Path, meta: Mapping[str, Any]) -> str | None:
    """Return the scoped committed audit id, or ``None`` for legacy main."""

    from ..keyvault import _native_key_id, _secret_ops, _storage
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID

    rows = list(meta["keys"].items())
    if len(rows) != 1 or not isinstance(rows[0][1], dict):
        raise _storage.KeyvaultCorruptError("initialized keyvault must have exactly one metadata row")
    main_key_id_hash, main_row = rows[0]
    main_key_id = main_row.get("key_id")
    if not isinstance(main_key_id_hash, str) or not isinstance(main_key_id, str):
        raise _storage.KeyvaultCorruptError("keyvault metadata row has no valid logical key id")
    if _native_key_id.PENDING_AUDIT_KEY_FIELD in meta:
        raise _storage.KeyvaultCorruptError("audit-key provisioning is incomplete")
    if _native_key_id.NATIVE_KEY_ID_FIELD not in main_row:
        if _native_key_id.AUDIT_KEY_FIELD in meta:
            raise _storage.KeyvaultCorruptError("legacy keyvault has unexpected scoped audit-key ownership metadata")
        # Pre-profile-scoping metadata selects the legacy global audit key.
        return None

    # Validation accepts both the current canonical scoped id and the
    # exact-abspath scoped id written before path canonicalization.
    _secret_ops._assert_key_committed(
        root,
        main_key_id,
        main_key_id_hash,
    )
    try:
        audit_native_key_id = _native_key_id.committed_audit_key_from_meta(
            root,
            meta,
            AUDIT_LOG_KEY_ID,
        )
    except _native_key_id.NativeKeyIdMismatch as exc:
        raise _storage.KeyvaultCorruptError(str(exc)) from None
    if audit_native_key_id is None:
        raise _storage.KeyvaultCorruptError("scoped keyvault has no committed audit-key ownership record")
    return audit_native_key_id


def make_audit_writer(
    audit_path: Path,
    *,
    keyvault_home: Path | None = None,
    backend: NativeBackend | None = None,
) -> Writer:
    """Return the audit-log :class:`Writer` for the current keyvault state.

    Once the Mordred keyvault is initialized, the audit log should be
    AES-GCM-encrypted at rest. This factory returns a keyvault
    :class:`~mordred_hermes.keyvault.log_encryption.EncryptedWriter` when
    the keyvault is initialized *and* its audit-log wrapping key is
    usable, and an :class:`NDJSONWriter` otherwise.

    Fail-open by design: an uninitialized keyvault, a corrupt keyvault, a
    missing audit-log wrapping key, a non-macOS host, or any other
    keyvault / Enclave error all fall back to :class:`NDJSONWriter` so
    privacy_check never stops auditing. Every fallback is logged.

    The keyvault crypto stack is imported only after the cheap,
    stdlib-only "is the keyvault initialized?" probe passes, so an
    uninitialized install carries no dependency on the keyvault plugin.
    ``backend=None`` builds the production Secure-Enclave backend; tests
    inject a software backend.
    """
    try:
        from ._keyvault_probe import keyvault_initialized

        if not keyvault_initialized(keyvault_home):
            # A de-initialized keyvault can leave a stale MRAL log behind;
            # rotate it aside so the plaintext writer does not corrupt it.
            _rotate_encrypted_log_aside(audit_path)
            return NDJSONWriter(path=audit_path)

        # Keyvault is initialized — only now touch the crypto stack.
        from ..keyvault import _native_key_id, _storage
        from ..keyvault._identity import resolve_backend
        from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID, EncryptedWriter
        from ..keyvault.wrap import get_wrapping_key_public

        root = _storage.resolve_keyvault_dir(keyvault_home)
        with _storage.keyvault_lifecycle_lock(root):
            # The cheap probe above is intentionally unlocked. Re-check after
            # acquiring the stable lifecycle lock: import may have published a
            # meta rename and then rolled it back, or reset may have removed the
            # profile while this factory was resolving the backend.
            if not keyvault_initialized(keyvault_home):
                _rotate_encrypted_log_aside(audit_path)
                return NDJSONWriter(path=audit_path)

            _storage.assert_keyvault_active(root)
            meta = _storage.load_meta(root)
            audit_native_key_id = _select_audit_native_key(root, meta)

            backend = resolve_backend(backend)
            selected_native_key_id = audit_native_key_id or AUDIT_LOG_KEY_ID
            backend = _native_key_id.backend_for_persisted_key(
                backend,
                root,
                AUDIT_LOG_KEY_ID,
                selected_native_key_id,
            )
            # Probe that the audit-log wrapping key exists and the backend is
            # usable. get_wrapping_key_public needs no Enclave authorization.
            get_wrapping_key_public(
                AUDIT_LOG_KEY_ID,
                backend=backend,
                native_key_id=audit_native_key_id,
            )
            return EncryptedWriter(
                audit_path,
                backend=backend,
                native_key_id=audit_native_key_id,
                keyvault_root=root,
            )
    except Exception as exc:
        _LOG.warning(
            "encrypted audit log unavailable (%s: %s); falling back to plaintext NDJSON",
            type(exc).__name__,
            exc,
        )
        # Codex PR #40 review (P1): if the keyvault was encrypting until
        # now, audit_path is an MRAL log — rotate it aside so the plaintext
        # fallback below does not splice cleartext into the ciphertext.
        _rotate_encrypted_log_aside(audit_path)
        writer = NDJSONWriter(path=audit_path)
        # L1 (PR #39 review): reaching this branch means the keyvault was
        # initialized — or its state could not be read — so encryption was
        # *expected*. Record the encrypted→plaintext downgrade in the trail
        # itself, not only in Python logging. The clean "keyvault never
        # initialized" path returns above and is intentionally silent.
        # Best-effort: a degraded path must not let an audit-sink failure
        # crash the caller (_runtime._load_state).
        with contextlib.suppress(Exception):
            writer.append(
                {
                    "event": "mordred.audit_writer",
                    "decision": "warn",
                    "reason": "mordred.degraded.audit_encryption_unavailable",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
        return writer
