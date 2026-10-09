"""Shared audit-log rotation / timestamp / retention helpers -- root pure-stdlib module.

Single-sources logic that was independently copy-pasted, near-verbatim,
across three call sites:

* :mod:`mordred_hermes.privacy_check.audit` -- ``_utcnow_iso``,
  ``_today_utc_date``, ``_next_rotation_target`` (shared by
  :class:`NDJSONWriter`'s size/date rotation and the encrypted-log
  rotate-aside), and :class:`NDJSONWriter`'s ``_sweep_retention`` method.
* :mod:`mordred_hermes.keyvault.log_encryption` -- an identical
  ``_utcnow_iso`` / ``_today_utc_date`` pair, a ``_rotate`` that reimplemented
  the same collision-suffix loop inline instead of calling a shared helper,
  and an ``_sweep_retention`` method that was byte-for-byte identical to
  ``NDJSONWriter``'s.
* :mod:`mordred_hermes.wizard.openclaw_migration` -- a third copy of the
  ``_utcnow_iso``-shaped timestamp helper, used only for the idempotency
  marker file (its docstring said "matches privacy_check.audit format" --
  now it just imports the format).

This is the pure-stdlib sibling of :mod:`mordred_hermes._yaml_io` and
:mod:`mordred_hermes._policy_io`: no ``cryptography``, no ``ruamel``, and no
import of ``privacy_check`` or ``keyvault`` themselves, so this module stays
importable regardless of which optional extras (e.g. ``[macos]``) are
installed -- exactly the property that let ``privacy_check.audit`` host the
canonical copy without dragging the keyvault crypto stack into every
importer of ``NDJSONWriter``.

Import-shape note (load-bearing for a test): ``test_keyvault_log_encryption
.py`` monkeypatches ``log_encryption._today_utc_date`` directly (via
``monkeypatch.setattr(le, "_today_utc_date", ...)``) to pin the rotation
clock for date-change tests. An unqualified call inside a function body
resolves against *that function's own module* globals, not this module's,
so each importer must bind the name at module scope in its own namespace
(``from .._log_rotation import today_utc_date as _today_utc_date``) and call
it unqualified -- re-exporting via a qualified ``_log_rotation.today_utc_date()``
call at the use site would silently break that monkeypatch.
"""

from __future__ import annotations

import gzip
import logging
import os
import re
import zlib
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Literal

from ._audit_io import AuditSession, audit_path_stat, compress_rotated_file
from ._private_fs import FileMetadata, PrivateFSError
from ._private_fs._types import validate_leaf, validate_limit


def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp with 3-digit millisecond precision.

    Built by hand -- ``strftime`` ``%f`` yields 6-digit microseconds --
    literally ``"%Y-%m-%dT%H:%M:%S." + "{ms:03d}" + "Z"``. This exact shape
    is a frozen wire contract: the Phase 1 audit-log ``Writer`` Protocol
    (:mod:`mordred_hermes.privacy_check.audit`) invariant #1 requires every
    ``ts`` field written by any implementor -- plaintext ``NDJSONWriter`` or
    Phase 4 AES-GCM ``EncryptedWriter`` -- to match it byte-for-byte.
    """
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def today_utc_date() -> str:
    """Current UTC date as ``YYYY-MM-DD`` (rotation suffix source)."""
    return datetime.now(UTC).strftime("%Y-%m-%d")


def next_rotation_target(path: Path, date_suffix: str) -> Path:
    """Pick a collision-free rotation target ``<name>.<date>[.N]``.

    Shared by every rotator that renames an active log file aside before
    gzipping it: ``NDJSONWriter._rotate`` and ``EncryptedWriter._rotate``
    (same-day size/date rotation), and the encrypted-log rotate-aside in
    ``privacy_check.audit`` (``_rotate_encrypted_log_aside``, which moves a
    stale ``MRAL`` file out of a plaintext writer's way). All three must
    skip names already taken by a prior rotation -- including rotations
    that were subsequently gzipped -- so a same-day rotation can never
    overwrite history.
    """
    target = path.with_name(f"{path.name}.{date_suffix}")
    n = 0
    while target.exists() or target.with_suffix(target.suffix + ".gz").exists():
        n += 1
        target = path.with_name(f"{path.name}.{date_suffix}.{n}")
    return target


def sweep_retention(path: Path, retention_days: int) -> None:
    """Delete rotated siblings of ``path`` older than ``retention_days``.

    ``path`` is the *active* log file (e.g. ``audit.log``); rotated siblings
    are every entry in ``path.parent`` whose name starts with
    ``path.name + "."`` (``audit.log.2026-05-16``, ``audit.log.2026-05-16.gz``,
    ``audit.log.2026-05-16.1.gz``, ...). Age is judged by mtime, not the date
    embedded in the filename, so a rotated file's on-disk age is
    authoritative even if it were manually renamed or copied in. A file that
    disappears between the ``iterdir()`` listing and the ``stat()`` call
    (e.g. a concurrent sweep, or manual cleanup) is silently skipped rather
    than raising.
    """
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    prefix = path.name + "."
    lock_paths = {
        path.with_name(f".{path.name}.lock"),
        path.with_name(f"{path.name}.lock"),
    }
    for child in path.parent.iterdir():
        if child in lock_paths or not child.name.startswith(prefix):
            continue
        try:
            mtime = datetime.fromtimestamp(child.stat().st_mtime, tz=UTC)
        except FileNotFoundError:
            continue
        if mtime < cutoff:
            child.unlink(missing_ok=True)


def rotate_and_compress(path: Path, date_suffix: str, *, retention_days: int, log: logging.Logger) -> None:
    """Rename the active log aside, gzip it, and sweep expired rotations.

    The whole body of ``NDJSONWriter._rotate``
    (:mod:`mordred_hermes.privacy_check.audit`) and ``EncryptedWriter._rotate``
    (:mod:`mordred_hermes.keyvault.log_encryption`), which were byte-for-byte
    identical apart from which module's ``_LOG`` emitted the gzip warning.
    Each writer keeps its own ``_rotate`` method (the size/date decision in
    ``_maybe_rotate`` differs, and ``EncryptedWriter`` must also wipe its DEK)
    and passes its own logger in, so warnings still carry
    ``mordred.privacy_check.audit`` / ``mordred.keyvault.log_encryption``.

    Sequence, and why each step is load-bearing:

    1. ``audit_path_stat`` before the rename — a missing active file means
       there is nothing to rotate (return quietly), and a symlink / FIFO /
       device raises rather than being renamed.
    2. ``os.replace`` onto :func:`next_rotation_target`, which never picks a
       name a prior rotation already took (gzipped or not), so a same-day
       rotation cannot overwrite history.
    3. Re-stat the *target* and compare ``(st_dev, st_ino)`` with the
       pre-rename identity. A mismatch means the path was swapped underneath
       the rename, so the caller must not go on to create a fresh active file
       over an attacker-chosen inode — hence the fail-closed
       ``OSError("audit path changed during rotation")``.
    4. Gzip is best-effort **by design**: ``target`` already holds the rotated
       content, so a gzip failure loses nothing. It is logged at WARNING and
       the un-gzipped file is left in place; the next rotation's collision loop
       simply picks a new suffix.
    5. Retention sweep last, so the file just rotated is itself eligible for
       deletion under the same age rule as every older sibling.

    Note for ``privacy_check``: this module is pure stdlib and imports only
    :mod:`mordred_hermes._audit_io` (also pure stdlib), so hosting the shared
    body here keeps ``privacy_check.audit`` importable without the
    macOS-extra-gated keyvault crypto stack — the property that kept these two
    copies separate in the first place.
    """
    before = audit_path_stat(path)
    if before is None:
        return

    target = next_rotation_target(path, date_suffix)
    os.replace(path, target)
    moved = audit_path_stat(target)
    if moved is None or (moved.st_dev, moved.st_ino) != (before.st_dev, before.st_ino):
        raise OSError("audit path changed during rotation")

    gz_target = target.with_suffix(target.suffix + ".gz")
    try:
        compress_rotated_file(target, gz_target)
    except Exception as e:
        log.warning("audit gzip rotation failed; raw rotated file kept at %s: %s", target, e)

    sweep_retention(path, retention_days)


@dataclass(frozen=True)
class AuditRotationResult:
    raw_name: str | None
    gzip_name: str | None
    compression: Literal["not_needed", "compressed", "raw_oversize", "raw_error"]
    warning: str | None


def audit_rotation_names(session: AuditSession, *, max_entries: int = 4096) -> tuple[tuple[str, date, int, bool], ...]:
    """Enumerate only exact dated siblings, retaining raw/gzip duplicates."""
    validate_limit(max_entries)
    pattern = re.compile(re.escape(session.active_name) + r"\.(\d{4}-\d{2}-\d{2})(?:\.([0-9]+))?(\.gz)?", re.ASCII)
    result: list[tuple[str, date, int, bool]] = []
    for name in session.list_names(max_entries=max_entries):
        match = pattern.fullmatch(name)
        if match is None:
            continue
        try:
            dated = date.fromisoformat(match[1])
        except ValueError:
            continue
        result.append((name, dated, int(match[2] or "0"), bool(match[3])))
    return tuple(sorted(result, key=lambda item: (item[1], item[2], item[3], item[0])))


def _verify_raw(session: AuditSession, name: str, expected: FileMetadata) -> None:
    if session.stat(name) != expected:
        raise PrivateFSError("unsafe", "audit_rotation_identity")


def rotate_audit(
    session: AuditSession,
    date_suffix: str,
    *,
    compress: bool = True,
    max_raw_bytes: int = 16 * 1024 * 1024,
    max_gzip_bytes: int = 16 * 1024 * 1024 + 65536,
    max_entries: int = 4096,
) -> AuditRotationResult:
    """Rotate under the caller's session, preserving evidence on uncertainty.

    Protect returned artifact names during the immediate retention sweep.
    Caller must not acknowledge success until its transaction owner exits.
    """
    for limit in (max_raw_bytes, max_gzip_bytes, max_entries):
        validate_limit(limit)
    if date.fromisoformat(date_suffix).isoformat() != date_suffix:
        raise ValueError("rotation date must be canonical YYYY-MM-DD")
    source = session.stat(session.active_name)
    if source is None:
        return AuditRotationResult(None, None, "not_needed", None)
    raw_name: str | None = None
    try:
        raw_name, moved = _rename_audit(session, date_suffix, source, max_entries)
        if not compress:
            return AuditRotationResult(raw_name, None, "not_needed", None)
        return _compress_audit(session, raw_name, moved, max_raw_bytes, max_gzip_bytes)
    except PrivateFSError as exc:
        if raw_name is not None:
            exc.commit_state = "uncertain"
            exc.add_note(f"audit rotation completed rename to {raw_name}")
        raise


def _rename_audit(
    session: AuditSession, date_suffix: str, source: FileMetadata, max_entries: int
) -> tuple[str, FileMetadata]:
    occupied = set(session.list_names(max_entries=max_entries))
    for number in range(max_entries):
        candidate = f"{session.active_name}.{date_suffix}" + (f".{number}" if number else "")
        gzip_name = candidate + ".gz"
        if candidate in occupied or gzip_name in occupied:
            continue
        if session.stat(candidate) is not None or session.stat(gzip_name) is not None:
            continue
        try:
            moved = session.rename(session.active_name, candidate, expected_identity=source.identity)
        except PrivateFSError as exc:
            if exc.reason != "exists" or exc.commit_state != "not_committed":
                raise
            _verify_raw(session, session.active_name, source)
            continue
        return candidate, moved
    raise PrivateFSError("busy", "audit_rotation_limit")


def _compress_audit(
    session: AuditSession, raw_name: str, moved: FileMetadata, max_raw_bytes: int, max_gzip_bytes: int
) -> AuditRotationResult:
    if moved.size > max_raw_bytes:
        return AuditRotationResult(raw_name, None, "raw_oversize", "raw compression limit exceeded")
    raw = session.snapshot(raw_name, max_bytes=max_raw_bytes)
    if raw is None or raw.metadata != moved:
        raise PrivateFSError("unsafe", "audit_rotation_identity")
    try:
        compressed = gzip.compress(raw.data, mtime=0)
    except PrivateFSError:
        raise
    except (OSError, zlib.error, OverflowError, MemoryError):
        _verify_raw(session, raw_name, moved)
        return AuditRotationResult(raw_name, None, "raw_error", "local gzip compression failed")
    if len(compressed) > max_gzip_bytes:
        _verify_raw(session, raw_name, moved)
        return AuditRotationResult(raw_name, None, "raw_error", "gzip output limit exceeded")
    gzip_name = raw_name + ".gz"
    try:
        published = session.create(gzip_name, compressed)
    except PrivateFSError as exc:
        if exc.commit_state != "not_committed" or exc.reason not in ("io", "access_denied", "busy"):
            raise
        _verify_raw(session, raw_name, moved)
        return AuditRotationResult(raw_name, None, "raw_error", f"gzip publication failed: {exc.reason}")
    verified = session.snapshot(gzip_name, max_bytes=max_gzip_bytes)
    if verified is None or verified.metadata != published or verified.data != compressed:
        raise PrivateFSError("unsafe", "audit_gzip_verification")
    _verify_raw(session, raw_name, moved)
    session.delete(raw_name, expected_identity=moved.identity)
    return AuditRotationResult(None, gzip_name, "compressed", None)


def sweep_audit_retention(
    session: AuditSession,
    *,
    cutoff_mtime_ns: int,
    protected_names: frozenset[str] = frozenset(),
    max_entries: int = 4096,
) -> tuple[str, ...]:
    """Delete checked old dated files; never retry partial or uncertain sweeps."""
    if type(cutoff_mtime_ns) is not int:
        raise ValueError("cutoff_mtime_ns must be an integer")
    for name in protected_names:
        validate_leaf(name)
    deleted: list[str] = []
    try:
        for name, _date, _number, _gzip in audit_rotation_names(session, max_entries=max_entries):
            if name in protected_names:
                continue
            metadata = session.stat(name)
            if metadata is not None and metadata.mtime_ns < cutoff_mtime_ns:
                session.delete(name, expected_identity=metadata.identity)
                deleted.append(name)
    except PrivateFSError as exc:
        if deleted:
            exc.commit_state = "uncertain"
            exc.add_note("audit retention completed deletions: " + ", ".join(deleted))
        raise
    return tuple(deleted)
