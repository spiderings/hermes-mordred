"""Read-only public build artifacts, distinct from stored confidential files.

Cargo release images may have multiple hardlinks. This narrow capability pins
trusted parents and an immutable read handle; it never modifies or adopts the
source. Stored private/confidential files still require exactly one link.
"""

from __future__ import annotations

from pathlib import Path

from ._types import PrivateFSError
from ._windows_api import Metadata, OwnedHandle
from ._windows_paths import CheckedDirectory, checked_directory_optional, windows_leaf
from ._windows_security import check_ancestor


def _verify_source(parent: CheckedDirectory, handle: OwnedHandle, path: str, max_bytes: int) -> Metadata:
    parent.check()
    api = handle.api
    info = api.metadata(handle)
    if (
        info.directory
        or info.reparse
        or info.links < 1
        or not 0 <= info.size <= max_bytes
        or info.identity.volume != parent.identity.volume
    ):
        raise PrivateFSError("unsafe", "public_build_source")
    # Public readers are harmless; mutation rights and trusted ownership use
    # the shared admission policy. creating_child also forbids append-data.
    check_ancestor(api.descriptor(handle), api.user_sid(), creating_child=True)
    if api.final_path(handle).casefold() != path.casefold():
        raise PrivateFSError("unsafe", "public_build_source_path")
    return info


def read_public_build_output(path: str | Path, *, max_bytes: int) -> bytes:
    if type(max_bytes) is not int or not 0 < max_bytes <= 64 * 1024 * 1024:
        raise PrivateFSError("unsafe", "public_build_bound")
    source = Path(path)
    windows_leaf(source.name)
    with checked_directory_optional(source.parent, confidential=True) as parent:
        if parent is None:
            raise PrivateFSError("missing", "public_build_parent")
        bound = parent.path.rstrip("\\") + "\\" + source.name
        api = parent.handle.api
        # OPEN_REPARSE_POINT is supplied by the shared NativeAPI. Share-read
        # denies concurrent write/delete access through every hardlink alias.
        with api.open(bound, share=1) as handle:
            original = _verify_source(parent, handle, bound, max_bytes)
            content = api.read(handle, original.size + 1)
            if len(content) != original.size or _verify_source(parent, handle, bound, max_bytes) != original:
                raise PrivateFSError("unsafe", "public_build_source_changed")
            with api.open(bound, share=1) as named:
                if _verify_source(parent, named, bound, max_bytes) != original:
                    raise PrivateFSError("unsafe", "public_build_source_changed")
            parent.check()
    # No bytes escape until source and all pinned ancestor handles close.
    return content
