"""Non-inherited stable sidecar byte lock across ordinary Windows processes."""

from __future__ import annotations

import contextlib
import sys
import threading
import time
from collections.abc import Iterator

from ._types import FileIdentity, PrivateFSError, cleanup_failure
from ._windows_api import OwnedHandle
from ._windows_paths import CheckedDirectory
from ._windows_security import validate_private

_guard = threading.Lock()
_owners: set[tuple[FileIdentity, int]] = set()


@contextlib.contextmanager
def exclusive_lock(directory: CheckedDirectory, *, blocking: bool) -> Iterator[None]:
    owner = (directory.identity, threading.get_ident())
    with _guard:
        if owner in _owners:
            raise RuntimeError("recursive private transaction")
        _owners.add(owner)
    try:
        with _lock_handle(directory) as handle:
            api = handle.api
            identity = api.metadata(handle).identity
            while True:
                try:
                    api.lock(handle)
                    break
                except PrivateFSError as exc:
                    if exc.native_code != 33 or not blocking:
                        raise
                    time.sleep(0.05)
            try:
                validate_private(handle, directory=False)
                with api.open(directory.path + "\\.mordred-fs.lock", access=0x120089) as named:
                    if api.metadata(named).identity != identity:
                        raise PrivateFSError("unsafe", "lock_identity")
                yield
            finally:
                original = sys.exception()
                try:
                    api.unlock(handle)
                except OSError as exc:
                    cleanup_failure(original, exc, committed=False)
    finally:
        with _guard:
            _owners.remove(owner)


def _lock_handle(directory: CheckedDirectory) -> OwnedHandle:
    api = directory.handle.api
    path = directory.path + "\\.mordred-fs.lock"
    try:
        handle = api.open(path, access=0xC0020000, create=True)
    except PrivateFSError as exc:
        if exc.reason != "exists":
            raise
        handle = api.open(path, access=0xC0020000)
    try:
        validate_private(handle, directory=False)
    except BaseException:
        handle.close()
        raise
    return handle
