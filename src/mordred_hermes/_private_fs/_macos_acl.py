"""Fail closed on macOS ACL grants that mode bits cannot describe."""

from __future__ import annotations

import ctypes as c
import errno
from functools import cache

from ._types import PrivateFSError


@cache
def _libc() -> c.CDLL:
    library = c.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    library.acl_get_fd_np.argtypes = [c.c_int, c.c_int]
    library.acl_get_fd_np.restype = c.c_void_p
    library.acl_valid.argtypes = [c.c_void_p]
    library.acl_valid.restype = c.c_int
    library.acl_get_entry.argtypes = [c.c_void_p, c.c_int, c.POINTER(c.c_void_p)]
    library.acl_get_entry.restype = c.c_int
    library.acl_get_tag_type.argtypes = [c.c_void_p, c.POINTER(c.c_int)]
    library.acl_get_tag_type.restype = c.c_int
    library.acl_free.argtypes = [c.c_void_p]
    library.acl_free.restype = c.c_int
    return library


def _query_error() -> PrivateFSError:
    return PrivateFSError("io", "macos_acl_query", native_code=c.get_errno())


def validate_acl(fd: int) -> None:
    """Allow absent/empty/deny-only ACLs; never repair an existing descriptor.

    Even owner-only or read-only allow entries are conservatively refused.
    This covers inherit-only entries before creating any private child. Deny
    entries (including the normal home-directory deny-delete ACE) add no rights.
    """
    library = _libc()
    c.set_errno(0)
    acl = library.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED, via the checked fd.
    if not acl:
        # Darwin filesec_get_property reports an absent ACL as ENOENT. This is
        # not a path lookup; every other failure, including ENOTSUP, is refused.
        if c.get_errno() == errno.ENOENT:
            return
        raise _query_error()
    failed = True
    try:
        if library.acl_valid(acl) != 0:
            raise _query_error()
        entry_id = 0  # ACL_FIRST_ENTRY; Darwin's ACL_NEXT_ENTRY is -1.
        for _ in range(129):  # SDK ACL_MAX_ENTRIES=128, plus the end query.
            entry = c.c_void_p()
            c.set_errno(0)
            result = library.acl_get_entry(acl, entry_id, c.byref(entry))
            if result == -1 and c.get_errno() == errno.EINVAL:
                # Darwin uses EINVAL for the end of this validated ACL copy.
                failed = False
                return
            if result != 0 or not entry.value:
                raise _query_error()
            tag = c.c_int()
            if library.acl_get_tag_type(entry, c.byref(tag)) != 0:
                raise _query_error()
            if tag.value != 2:  # ACL_EXTENDED_DENY; unknown tags are unsafe too.
                raise PrivateFSError("unsafe", "macos_acl")
            entry_id = -1
        raise PrivateFSError("unsafe", "macos_acl_size")
    finally:
        if library.acl_free(acl) != 0 and not failed:
            raise _query_error()
