"""Opt-in checked audit sessions. Crypto, policy and consumers live above this layer."""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import threading
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from . import _private_fs as fs
from ._private_fs import FileIdentity, FileMetadata, PrivateDirectory, PrivateFSError, PrivateTransaction
from ._private_fs._types import validate_limit


@dataclass(frozen=True)
class AuditSnapshot:
    name: str
    metadata: FileMetadata
    data: bytes


@dataclass(frozen=True)
class AuditProbe:
    kind: Literal["missing", "empty", "ndjson", "mral", "unknown"]
    metadata: FileMetadata | None
    first_line: bytes | None


@dataclass
class _Owner:
    transaction: PrivateTransaction | None
    identity: FileIdentity | None
    mutated: bool = False


_local = threading.local()


def _validate_name(name: str) -> None:
    # This new API uses the Windows sibling-name contract even for an absent
    # view. Reuse the foundation's pure validator; no backend IO occurs here.
    from ._private_fs._windows_paths import windows_leaf

    windows_leaf(name)


def _require_identity(identity: FileIdentity) -> None:
    if not isinstance(identity, FileIdentity):
        raise ValueError("expected_identity must be a checked FileIdentity")


def _missing(exc: PrivateFSError) -> bool:
    # Only a checked leaf open/stat absence, never security/cleanup failure.
    return (
        exc.reason == "missing"
        and exc.commit_state == "not_committed"
        and exc.operation in ("open", "stat")
        and exc.native_code in (2, 3)
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> object:
    raise ValueError("non-JSON constant")


class AuditSession:
    """A scoped capability; only immutable snapshots survive its context."""

    def __init__(self, active_name: str, owner: _Owner) -> None:
        self.active_name = active_name
        self._owner = owner
        self._active = True
        self._pid = os.getpid()
        self._thread = threading.get_ident()

    def _check(self, name: str | None = None) -> PrivateTransaction | None:
        if not self._active or self._pid != os.getpid() or self._thread != threading.get_ident():
            raise RuntimeError("audit session is closed or belongs to another process/thread")
        if name is not None:
            _validate_name(name)
        tx = self._owner.transaction
        if tx is not None:
            tx.assert_private_admission()
            if tx.directory_identity() != self._owner.identity:
                raise PrivateFSError("unsafe", "audit_directory_identity")
        return tx

    def _writable(self, name: str) -> PrivateTransaction:
        tx = self._check(name)
        if tx is None:
            raise PrivateFSError("missing", "audit_absent_directory")
        return tx

    def directory_identity(self) -> FileIdentity:
        self._check()
        if self._owner.identity is None:
            raise PrivateFSError("missing", "audit_absent_directory")
        return self._owner.identity

    def stat(self, name: str) -> FileMetadata | None:
        tx = self._check(name)
        if tx is None:
            return None
        try:
            return tx.stat(name)
        except PrivateFSError as exc:
            if _missing(exc):
                return None
            raise

    def _same(self, name: str, before: FileMetadata) -> FileMetadata:
        tx = self._writable(name)
        after = tx.stat(name)
        if after != before:
            raise PrivateFSError("unsafe", "audit_snapshot_identity")
        return after

    def snapshot(self, name: str, *, max_bytes: int) -> AuditSnapshot | None:
        validate_limit(max_bytes)
        before = self.stat(name)
        if before is None:
            return None
        if before.size > max_bytes:
            raise PrivateFSError("unsafe", "audit_read_limit")
        data = self._writable(name).read_bytes(name, max_bytes=max_bytes)
        self._same(name, before)
        if len(data) != before.size:
            raise PrivateFSError("unsafe", "audit_snapshot_size")
        return AuditSnapshot(name, before, data)

    def probe(self, name: str, *, max_line_bytes: int = 4096) -> AuditProbe:
        validate_limit(max_line_bytes)
        before = self.stat(name)
        if before is None:
            return AuditProbe("missing", None, None)
        data = self._writable(name).read_prefix(name, max_bytes=max_line_bytes + 1)
        self._same(name, before)
        if len(data) != min(before.size, max_line_bytes + 1):
            raise PrivateFSError("unsafe", "audit_snapshot_size")
        if before.size == 0:
            return AuditProbe("empty", before, None)
        line, newline, _rest = data.partition(b"\n")
        if not newline or len(line) > max_line_bytes:
            return AuditProbe("unknown", before, None)
        try:
            value = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        except (UnicodeError, ValueError, RecursionError):
            return AuditProbe("unknown", before, line)
        if not isinstance(value, dict):
            return AuditProbe("unknown", before, line)
        return AuditProbe("mral" if value.get("fmt") == "MRAL" else "ndjson", before, line)

    def snapshot_many(
        self, names: Sequence[str], *, max_file_bytes: int, max_total_bytes: int
    ) -> tuple[AuditSnapshot, ...]:
        validate_limit(max_file_bytes)
        validate_limit(max_total_bytes)
        self._check()
        if len({name.casefold() for name in names}) != len(names):
            raise ValueError("duplicate snapshot names")
        for name in names:
            _validate_name(name)
        snapshots: list[AuditSnapshot] = []
        total = 0
        for name in names:
            before = self.stat(name)
            if before is None:
                continue
            if before.size > max_total_bytes - total:
                raise PrivateFSError("unsafe", "audit_total_limit")
            snapshot = self.snapshot(name, max_bytes=min(max_file_bytes, max_total_bytes - total) or 1)
            if snapshot is None or snapshot.metadata != before:
                raise PrivateFSError("unsafe", "audit_snapshot_identity")
            total += len(snapshot.data)
            snapshots.append(snapshot)
        return tuple(snapshots)

    def list_names(self, *, max_entries: int = 4096) -> tuple[str, ...]:
        validate_limit(max_entries)
        tx = self._check()
        return () if tx is None else tx.list_names(max_entries=max_entries)

    def _result(self, name: str, *, expected_identity: FileIdentity | None = None) -> FileMetadata:
        try:
            metadata = self._writable(name).stat(name)
            if expected_identity is not None and metadata.identity != expected_identity:
                raise PrivateFSError("unsafe", "audit_mutation_identity")
            return metadata
        except PrivateFSError as exc:
            exc.commit_state = "uncertain"
            exc.add_note("audit mutation completed before metadata verification failed")
            raise

    def create(self, name: str, data: bytes) -> FileMetadata:
        self._writable(name).create_bytes(name, data)
        self._owner.mutated = True
        return self._result(name)

    def append(self, name: str, data: bytes, *, expected_identity: FileIdentity) -> FileMetadata:
        _require_identity(expected_identity)
        tx = self._writable(name)
        if tx.stat(name).identity != expected_identity:
            raise PrivateFSError("unsafe", "audit_append_identity")
        tx.append_bytes(name, data)
        self._owner.mutated = True
        return self._result(name, expected_identity=expected_identity)

    def rename(self, name: str, target: str, *, expected_identity: FileIdentity) -> FileMetadata:
        _require_identity(expected_identity)
        _validate_name(target)
        self._writable(name).rename_file(name, target, expected_identity=expected_identity)
        self._owner.mutated = True
        return self._result(target, expected_identity=expected_identity)

    def delete(self, name: str, *, expected_identity: FileIdentity) -> None:
        _require_identity(expected_identity)
        self._writable(name).delete_file(name, expected_identity=expected_identity)
        self._owner.mutated = True


def _nested_owner(
    previous: AuditSession, identity: FileIdentity | None, transaction: PrivateTransaction | None
) -> _Owner:
    owner = previous._owner
    if identity is None or owner.identity != identity:
        raise PrivateFSError("unsafe", "audit_nested_directory")
    if transaction is not None and transaction is not owner.transaction:
        raise PrivateFSError("unsafe", "audit_borrow_owner")
    return owner


@contextlib.contextmanager
def audit_session(
    path: Path, *, create: bool = False, blocking: bool = True, transaction: PrivateTransaction | None = None
) -> Iterator[AuditSession]:
    """Hold a checked directory lock, or explicitly borrow its owner's lock.

    The borrowed owner's successful final exit is the publication boundary.
    No callbacks, key providers or lock-order inversions are permitted here.
    """
    _validate_name(path.name)
    previous: AuditSession | None = getattr(_local, "session", None)
    if previous is not None:
        previous._check()
    if transaction is not None:
        transaction.assert_private_admission()
    owner: _Owner | None = None
    try:
        with contextlib.ExitStack() as stack:
            directory: PrivateDirectory | None
            if create:
                directory = stack.enter_context(
                    fs.open_private_directory(path.parent, create=previous is None and transaction is None)
                )
            else:
                directory = stack.enter_context(fs.open_optional_private_directory(path.parent))
            identity = None if directory is None else directory.directory_identity()
            if transaction is not None and (identity is None or transaction.directory_identity() != identity):
                raise PrivateFSError("unsafe", "audit_borrow_identity")
            if previous is not None:
                owner = _nested_owner(previous, identity, transaction)
            else:
                if transaction is None and directory is not None:
                    transaction = stack.enter_context(directory.transaction(blocking=blocking))
                    transaction.assert_private_admission()
                owner = _Owner(transaction, identity)
            session = AuditSession(path.name, owner)
            _local.session = session
            try:
                yield session
            finally:
                session._active = False
                _local.session = previous
    except PrivateFSError as exc:
        if owner is not None and owner.mutated:
            exc.commit_state = "uncertain"
            exc.add_note("audit session completed a persistent mutation")
        raise


def read_audit_snapshot(path: Path, *, max_bytes: int) -> AuditSnapshot | None:
    validate_limit(max_bytes)
    with audit_session(path) as session:
        snapshot = session.snapshot(session.active_name, max_bytes=max_bytes)
    return snapshot


def decode_audit_bytes(data: bytes, *, max_output_bytes: int) -> bytes:
    """Decode plaintext or gzip magic, bounding combined concatenated output."""
    validate_limit(max_output_bytes)
    if data.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            result = stream.read(max_output_bytes + 1)
    else:
        result = data
    if len(result) > max_output_bytes:
        raise PrivateFSError("unsafe", "audit_decode_limit")
    return result
