"""Internal storage contract, without platform imports."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Literal, Protocol

Reason = Literal["unsafe", "unsupported", "missing", "exists", "busy", "access_denied", "io"]
CommitState = Literal["not_committed", "uncertain"]


class PrivateFSError(OSError):
    """A classified refusal; uncertain publication must never be blindly retried."""

    def __init__(
        self,
        reason: Reason,
        operation: str,
        *,
        native_code: int | None = None,
        commit_state: CommitState = "not_committed",
    ) -> None:
        super().__init__()
        self.reason = reason
        self.operation = operation
        self.native_code = native_code
        self.commit_state = commit_state

    @property
    def commit_state(self) -> CommitState:
        return self._commit_state

    @commit_state.setter
    def commit_state(self, state: CommitState) -> None:
        self._commit_state = state
        # Publication reconciliation can promote an existing exception. Keep
        # str(), repr(), and args consistent without replacing that exception.
        self.args = (f"private filesystem {self.operation}: {self.reason} ({state})",)


@dataclass(frozen=True)
class FileIdentity:
    volume: int
    file_id: bytes


@dataclass(frozen=True)
class FileMetadata:
    identity: FileIdentity
    size: int
    mtime_ns: int


class PrivateTransaction(Protocol):
    def assert_private_admission(self) -> None: ...
    def directory_identity(self) -> FileIdentity: ...
    def stat(self, name: str) -> FileMetadata: ...
    def read_prefix(self, name: str, *, max_bytes: int) -> bytes: ...
    def list_names(self, *, max_entries: int) -> tuple[str, ...]: ...
    def delete_file(self, name: str, *, expected_identity: FileIdentity | None = None) -> None: ...
    def rename_file(self, name: str, destination: str, *, expected_identity: FileIdentity | None = None) -> None: ...
    def append_bytes(self, name: str, data: bytes) -> None: ...
    def read_bytes(self, name: str, *, max_bytes: int) -> bytes: ...
    def create_bytes(self, name: str, data: bytes) -> None: ...
    def replace_bytes(self, name: str, data: bytes) -> None: ...


class PrivateDirectory(Protocol):
    def directory_identity(self) -> FileIdentity: ...
    def stat(self, name: str) -> FileMetadata: ...
    def read_prefix(self, name: str, *, max_bytes: int) -> bytes: ...
    def list_names(self, *, max_entries: int) -> tuple[str, ...]: ...
    def read_bytes(self, name: str, *, max_bytes: int) -> bytes: ...
    def transaction(self, *, blocking: bool = True) -> AbstractContextManager[PrivateTransaction]: ...


class ConfidentialTransaction(Protocol):
    def directory_identity(self) -> FileIdentity: ...
    def list_names(self, *, max_entries: int) -> tuple[str, ...]: ...
    def stat(self, name: str) -> FileMetadata: ...
    def read_bytes(self, name: str, *, max_bytes: int) -> bytes: ...
    def create_bytes(self, name: str, data: bytes) -> None: ...
    def replace_bytes(self, name: str, data: bytes) -> None: ...
    def delete_file(self, name: str, *, expected_identity: FileIdentity | None = None) -> None: ...


class ConfidentialDirectory(Protocol):
    def directory_identity(self) -> FileIdentity: ...
    def list_names(self, *, max_entries: int) -> tuple[str, ...]: ...
    def stat(self, name: str) -> FileMetadata: ...
    def read_bytes(self, name: str, *, max_bytes: int) -> bytes: ...
    def transaction(self, *, blocking: bool = True) -> AbstractContextManager[ConfidentialTransaction]: ...


def validate_leaf(name: str) -> None:
    if (
        not name
        or name in (".", "..")
        or any(c in name for c in "/\\:\x00")
        or name.casefold() == ".mordred-fs.lock"
        or name.casefold().startswith(".mordred-fs-tmp-")
    ):
        raise PrivateFSError("unsafe", "leaf")


def validate_limit(value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("limit must be a positive integer")


def reserved(name: str) -> bool:
    return name.casefold() == ".mordred-fs.lock" or name.casefold().startswith(".mordred-fs-tmp-")


def cleanup_failure(original: BaseException | None, failure: OSError, *, committed: bool) -> None:
    """Keep body failures primary while exposing cleanup and mutation uncertainty."""
    if original is not None:
        original.add_note(f"private filesystem cleanup failed: {type(failure).__name__}")
        if committed and isinstance(original, PrivateFSError):
            original.commit_state = "uncertain"
        return
    if isinstance(failure, PrivateFSError):
        if committed:
            failure.commit_state = "uncertain"
        raise failure
    raise PrivateFSError(
        "io", "cleanup", native_code=failure.errno, commit_state="uncertain" if committed else "not_committed"
    ) from failure
