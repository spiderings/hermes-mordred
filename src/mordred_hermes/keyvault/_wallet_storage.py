"""Checked Windows storage for the wallet selection document, not key custody."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path

from .._private_fs import PrivateFSError, open_private_directory
from ._extension_config import _WALLET_CONFIG_MAX_BYTES, _WALLET_FILE, WalletConfigError


class WalletStorageError(WalletConfigError):
    """A content-free refusal retaining publication state for the caller."""

    def __init__(self, error: PrivateFSError) -> None:
        self.reason = error.reason
        self.native_code = error.native_code
        self.commit_state = error.commit_state
        message = "extension wallet storage is unavailable or unsafe; refusing automatic wallet fallback"
        if self.commit_state == "uncertain":
            message = "extension wallet save outcome is uncertain; inspect the saved selection before retrying"
        super().__init__(message)


def _missing_open(error: PrivateFSError, posix_operation: str) -> bool:
    # Windows identifies CreateFile failures as "open". The POSIX backend
    # labels the corresponding operation "directory"/"read". Metadata and
    # handle-cleanup errors must never authorize discovery or provisioning.
    return (
        error.reason == "missing"
        and error.commit_state == "not_committed"
        and error.operation in ("open", posix_operation)
    )


def read_wallet_bytes(directory: Path) -> bytes | None:
    """Only missing checked directory/file opens mean no explicit selection."""
    try:
        with ExitStack() as stack:
            try:
                checked = stack.enter_context(open_private_directory(directory))
            except PrivateFSError as exc:
                if _missing_open(exc, "directory"):
                    return None
                raise
            with checked.transaction() as tx:
                try:
                    return tx.read_bytes(_WALLET_FILE, max_bytes=_WALLET_CONFIG_MAX_BYTES)
                except PrivateFSError as exc:
                    if _missing_open(exc, "read"):
                        return None
                    raise
    except PrivateFSError as exc:
        # Translate after every context exits: cleanup can promote commit state.
        raise WalletStorageError(exc) from None


def write_wallet_bytes(directory: Path, payload: bytes) -> None:
    """Select exclusive create or checked replacement while holding one lock."""
    if len(payload) > _WALLET_CONFIG_MAX_BYTES:
        raise WalletStorageError(PrivateFSError("unsafe", "write_limit"))
    try:
        with open_private_directory(directory, create=True) as checked, checked.transaction() as tx:
            try:
                tx.read_bytes(_WALLET_FILE, max_bytes=_WALLET_CONFIG_MAX_BYTES)
            except PrivateFSError as exc:
                if not _missing_open(exc, "read"):
                    raise
                tx.create_bytes(_WALLET_FILE, payload)
            else:
                tx.replace_bytes(_WALLET_FILE, payload)
    except PrivateFSError as exc:
        raise WalletStorageError(exc) from None
