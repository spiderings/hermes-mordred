"""Explicit Win32 ABI and owned resources. DLLs load only on first native use."""

from __future__ import annotations

import contextlib
import ctypes as c
import os
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ._types import FileIdentity, PrivateFSError, Reason, cleanup_failure
from ._windows_security import ADMINISTRATORS, SYSTEM, Ace, Descriptor

DWORD = c.c_uint32
BOOL = c.c_int32
HANDLE = c.c_void_p
PTR = c.c_void_p


class SecurityAttributes(c.Structure):
    _fields_ = [("length", DWORD), ("descriptor", PTR), ("inherit", BOOL)]


class FileId(c.Structure):
    _fields_ = [("volume", c.c_uint64), ("identifier", c.c_ubyte * 16)]


class StandardInfo(c.Structure):
    _fields_ = [
        ("allocation", c.c_int64),
        ("size", c.c_int64),
        ("links", DWORD),
        ("deleted", c.c_ubyte),
        ("directory", c.c_ubyte),
    ]


class BasicInfo(c.Structure):
    _fields_ = [
        ("creation", c.c_int64),
        ("access", c.c_int64),
        ("write", c.c_int64),
        ("change", c.c_int64),
        ("attributes", DWORD),
    ]


class RenameInfo(c.Structure):
    _fields_ = [("flags", DWORD), ("root", HANDLE), ("length", DWORD), ("name", c.c_uint16 * 1)]


class Overlapped(c.Structure):
    _fields_ = [
        ("internal", c.c_size_t),
        ("high", c.c_size_t),
        ("offset", DWORD),
        ("offset_high", DWORD),
        ("event", HANDLE),
    ]


@dataclass(frozen=True)
class Metadata:
    identity: FileIdentity
    directory: bool
    reparse: bool
    links: int
    size: int


class OwnedHandle:
    def __init__(self, api: NativeAPI, value: int) -> None:
        self.api = api
        self.value: int | None = value

    def close(self) -> None:
        value, self.value = self.value, None
        if value is not None:
            self.api.checked(self.api.CloseHandle(value), "close")

    def __enter__(self) -> OwnedHandle:
        if self.value is None:
            raise RuntimeError("closed native handle")
        return self

    def __exit__(self, *args: object) -> None:
        if args and args[0] is not None:
            try:
                self.close()
            except OSError as exc:
                original = args[1] if isinstance(args[1], BaseException) else None
                cleanup_failure(original, exc, committed=False)
        else:
            self.close()


def native_error(code: int, operation: str) -> PrivateFSError:
    reasons: dict[int, Reason] = {
        2: "missing",
        3: "missing",
        5: "access_denied",
        32: "busy",
        33: "busy",
        80: "exists",
        183: "exists",
    }
    return PrivateFSError(reasons.get(code, "io"), operation, native_code=code)


class NativeAPI:
    def __init__(self) -> None:
        if os.name != "nt" or c.sizeof(HANDLE) != 8:
            raise PrivateFSError("unsupported", "windows_platform")
        dll = c.WinDLL  # type: ignore[attr-defined]  # Win32-only ctypes exports
        self.kernel = dll("kernel32", use_last_error=True)
        self.security = dll("advapi32", use_last_error=True)
        self._bind_functions()

    def _bind(self, dll: Any, name: str, args: list[Any], result: Any) -> Any:
        function = getattr(dll, name)
        function.argtypes = args
        function.restype = result
        return function

    def _bind_functions(self) -> None:
        k, a = self.kernel, self.security
        self.CloseHandle = self._bind(k, "CloseHandle", [HANDLE], BOOL)
        self.LocalFree = self._bind(k, "LocalFree", [PTR], PTR)
        self.CreateFile = self._bind(k, "CreateFileW", [c.c_wchar_p, DWORD, DWORD, PTR, DWORD, DWORD, HANDLE], HANDLE)
        self.CreateDirectory = self._bind(k, "CreateDirectoryW", [c.c_wchar_p, PTR], BOOL)
        self.GetInfo = self._bind(k, "GetFileInformationByHandleEx", [HANDLE, c.c_int, PTR, DWORD], BOOL)
        self.SetInfo = self._bind(k, "SetFileInformationByHandle", [HANDLE, c.c_int, PTR, DWORD], BOOL)
        self.GetType = self._bind(k, "GetFileType", [HANDLE], DWORD)
        self.FinalPath = self._bind(k, "GetFinalPathNameByHandleW", [HANDLE, c.c_wchar_p, DWORD, DWORD], DWORD)
        self.VolumeInfo = self._bind(
            k, "GetVolumeInformationByHandleW", [HANDLE, c.c_wchar_p, DWORD, PTR, PTR, PTR, c.c_wchar_p, DWORD], BOOL
        )
        self.DriveType = self._bind(k, "GetDriveTypeW", [c.c_wchar_p], DWORD)
        self.QueryDevice = self._bind(k, "QueryDosDeviceW", [c.c_wchar_p, c.c_wchar_p, DWORD], DWORD)
        self.Read = self._bind(k, "ReadFile", [HANDLE, PTR, DWORD, PTR, PTR], BOOL)
        self.Write = self._bind(k, "WriteFile", [HANDLE, PTR, DWORD, PTR, PTR], BOOL)
        self.Flush = self._bind(k, "FlushFileBuffers", [HANDLE], BOOL)
        self.Seek = self._bind(k, "SetFilePointerEx", [HANDLE, c.c_int64, PTR, DWORD], BOOL)
        self.EndOfFile = self._bind(k, "SetEndOfFile", [HANDLE], BOOL)
        self.Lock = self._bind(k, "LockFileEx", [HANDLE, DWORD, DWORD, DWORD, DWORD, PTR], BOOL)
        self.Unlock = self._bind(k, "UnlockFileEx", [HANDLE, DWORD, DWORD, DWORD, PTR], BOOL)
        self.CurrentProcess = self._bind(k, "GetCurrentProcess", [], HANDLE)
        self.CurrentThread = self._bind(k, "GetCurrentThread", [], HANDLE)
        self.OpenProcessToken = self._bind(a, "OpenProcessToken", [HANDLE, DWORD, PTR], BOOL)
        self.OpenThreadToken = self._bind(a, "OpenThreadToken", [HANDLE, DWORD, BOOL, PTR], BOOL)
        self.TokenInfo = self._bind(a, "GetTokenInformation", [HANDLE, c.c_int, PTR, DWORD, PTR], BOOL)
        self.SidLength = self._bind(a, "GetLengthSid", [PTR], DWORD)
        self.ValidSid = self._bind(a, "IsValidSid", [PTR], BOOL)
        self.SidString = self._bind(a, "ConvertSidToStringSidW", [PTR, PTR], BOOL)
        self.ConvertSD = self._bind(
            a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [c.c_wchar_p, DWORD, PTR, PTR], BOOL
        )
        self.SecurityInfo = self._bind(a, "GetSecurityInfo", [HANDLE, c.c_int, DWORD, PTR, PTR, PTR, PTR, PTR], DWORD)
        self.SDControl = self._bind(a, "GetSecurityDescriptorControl", [PTR, PTR, PTR], BOOL)
        self.GetAce = self._bind(a, "GetAce", [PTR, DWORD, PTR], BOOL)

    def last_error(self) -> int:
        return int(c.get_last_error())  # type: ignore[attr-defined]

    def checked(self, result: object, operation: str) -> None:
        if not result:
            raise native_error(self.last_error(), operation)

    def user_sid(self) -> bytes:
        token = HANDLE()
        if not self.OpenThreadToken(self.CurrentThread(), 8, True, c.byref(token)):
            code = self.last_error()
            if code != 1008:
                raise native_error(code, "thread_token")
            self.checked(self.OpenProcessToken(self.CurrentProcess(), 8, c.byref(token)), "process_token")
        assert token.value is not None
        with OwnedHandle(self, token.value):
            needed = DWORD()
            self.TokenInfo(token, 1, None, 0, c.byref(needed))
            if self.last_error() != 122 or not 0 < needed.value <= 65536:
                raise PrivateFSError("io", "token_size")
            buffer = c.create_string_buffer(needed.value)
            self.checked(self.TokenInfo(token, 1, buffer, len(buffer), c.byref(needed)), "token_user")
            pointer = PTR.from_buffer(buffer)
            return self._sid_bytes(pointer)

    def _sid_bytes(self, pointer: PTR) -> bytes:
        if not pointer.value or not self.ValidSid(pointer):
            raise PrivateFSError("unsafe", "invalid_sid")
        return c.string_at(pointer, self.SidLength(pointer))

    def sid_text(self, sid: bytes) -> str:
        output = PTR()
        self.checked(self.SidString(sid, c.byref(output)), "sid_string")
        try:
            return c.wstring_at(output)
        finally:
            self.LocalFree(output)

    @contextlib.contextmanager
    def attributes(self) -> Iterator[SecurityAttributes]:
        user = self.user_sid()
        trustees = dict.fromkeys((user, SYSTEM, ADMINISTRATORS))
        sddl = "O:" + self.sid_text(user) + "D:P" + "".join("(A;;FA;;;" + self.sid_text(sid) + ")" for sid in trustees)
        descriptor = PTR()
        self.checked(self.ConvertSD(sddl, 1, c.byref(descriptor), None), "security_descriptor")
        try:
            yield SecurityAttributes(c.sizeof(SecurityAttributes), descriptor, False)
        finally:
            self.LocalFree(descriptor)

    def open(self, path: str, *, access: int = 0x120089, share: int = 3, create: bool = False) -> OwnedHandle:
        with self.attributes() if create else contextlib.nullcontext(None) as attributes:
            value = self.CreateFile(
                path, access, share, c.byref(attributes) if attributes else None, 1 if create else 3, 0x02200000, None
            )
            code = self.last_error()
        if value is None or value == c.c_void_p(-1).value:
            raise native_error(code, "create" if create else "open")
        return OwnedHandle(self, int(value))

    def mkdir(self, path: str) -> None:
        with self.attributes() as attributes:
            self.checked(self.CreateDirectory(path, c.byref(attributes)), "mkdir")

    def metadata(self, handle: OwnedHandle) -> Metadata:
        if self.GetType(handle.value) != 1:
            raise PrivateFSError("unsafe", "file_type")
        identity = FileId()
        standard = StandardInfo()
        tags = (DWORD * 2)()
        self.checked(self.GetInfo(handle.value, 18, c.byref(identity), c.sizeof(identity)), "file_identity")
        self.checked(self.GetInfo(handle.value, 1, c.byref(standard), c.sizeof(standard)), "file_standard")
        self.checked(self.GetInfo(handle.value, 9, tags, c.sizeof(tags)), "file_attributes")
        if standard.deleted:
            raise PrivateFSError("unsafe", "delete_pending")
        return Metadata(
            FileIdentity(identity.volume, bytes(identity.identifier)),
            bool(standard.directory),
            bool(tags[0] & 0x400),
            standard.links,
            standard.size,
        )

    def mtime_ns(self, handle: OwnedHandle) -> int:
        basic = BasicInfo()
        self.checked(self.GetInfo(handle.value, 0, c.byref(basic), c.sizeof(basic)), "file_basic")
        return (int(basic.write) - 116444736000000000) * 100

    def seek(self, handle: OwnedHandle, offset: int) -> None:
        self.checked(self.Seek(handle.value, offset, None, 0), "seek")

    def truncate(self, handle: OwnedHandle, length: int) -> None:
        self.seek(handle, length)
        self.checked(self.EndOfFile(handle.value), "truncate")

    def names(self, handle: OwnedHandle) -> Iterator[str]:
        # FILE_FULL_DIR_INFO: fixed prefix 68 bytes, UTF-16 name, 8-byte
        # aligned next-entry offsets. Native batches never grow allocations.
        restart = True
        while True:
            buffer = c.create_string_buffer(65536)
            if not self.GetInfo(handle.value, 15 if restart else 14, buffer, len(buffer)):
                code = self.last_error()
                if code == 18:  # ERROR_NO_MORE_FILES
                    return
                raise native_error(code, "list")
            restart = False
            yield from _directory_batch(buffer.raw)

    def descriptor(self, handle: OwnedHandle) -> Descriptor:
        owner = PTR()
        dacl = PTR()
        sd = PTR()
        code = self.SecurityInfo(handle.value, 1, 5, c.byref(owner), None, c.byref(dacl), None, c.byref(sd))
        if code:
            raise native_error(code, "security_info")
        try:
            control = c.c_uint16()
            revision = DWORD()
            self.checked(self.SDControl(sd, c.byref(control), c.byref(revision)), "descriptor_control")
            return Descriptor(
                self._sid_bytes(owner),
                bool(control.value & 0x1000),
                self._aces(dacl) if control.value & 4 and dacl.value else None,
            )
        finally:
            self.LocalFree(sd)

    def _aces(self, acl: PTR) -> list[Ace]:
        header = c.string_at(acl, 8)
        length = int.from_bytes(header[2:4], "little")
        count = int.from_bytes(header[4:6], "little")
        result = []
        assert acl.value is not None
        for index in range(count):
            pointer = PTR()
            self.checked(self.GetAce(acl, index, c.byref(pointer)), "ace")
            if pointer.value is None or not acl.value + 8 <= pointer.value <= acl.value + length - 4:
                raise PrivateFSError("unsafe", "ace_bounds")
            prefix = c.string_at(pointer, 4)
            size = int.from_bytes(prefix[2:4], "little")
            if size < 16 or pointer.value + size > acl.value + length or prefix[0] not in (0, 1):
                raise PrivateFSError("unsafe", "ace_type")
            raw = c.string_at(pointer, size)
            sid = raw[8:]
            if len(sid) < 8 or sid[0] != 1 or len(sid) != 8 + 4 * sid[1]:
                raise PrivateFSError("unsafe", "ace_sid")
            result.append(Ace(prefix[0], prefix[1], int.from_bytes(raw[4:8], "little"), sid))
        return result

    def final_path(self, handle: OwnedHandle) -> str:
        buffer = c.create_unicode_buffer(32768)
        size = self.FinalPath(handle.value, buffer, len(buffer), 1)
        self.checked(size, "final_path")
        if size >= len(buffer) or not buffer.value.startswith("\\\\?\\Volume{"):
            raise PrivateFSError("unsupported", "volume_path")
        return str(buffer.value)

    def validate_drive(self, drive: str) -> None:
        import re

        if self.DriveType(drive) != 3:
            raise PrivateFSError("unsupported", "drive")
        target = c.create_unicode_buffer(32768)
        self.checked(self.QueryDevice(drive[:2], target, len(target)), "drive_mapping")
        if not re.fullmatch(r"\\Device\\HarddiskVolume[0-9]+", target.value):
            raise PrivateFSError("unsupported", "drive_mapping")

    def validate_volume(self, handle: OwnedHandle) -> None:
        name = c.create_unicode_buffer(32)
        self.checked(self.VolumeInfo(handle.value, None, 0, None, None, None, name, len(name)), "volume")
        path = self.final_path(handle)
        root = path[: path.index("}") + 1] + "\\"
        if name.value != "NTFS" or self.DriveType(root) != 3:
            raise PrivateFSError("unsupported", "filesystem")

    def read(self, handle: OwnedHandle, count: int) -> bytes:
        buffer = c.create_string_buffer(count)
        size = DWORD()
        self.checked(self.Read(handle.value, buffer, count, c.byref(size), None), "read")
        return buffer.raw[: size.value]

    def write(self, handle: OwnedHandle, data: bytes) -> int:
        size = DWORD()
        self.checked(self.Write(handle.value, data, len(data), c.byref(size), None), "write")
        return int(size.value)

    def flush(self, handle: OwnedHandle) -> None:
        self.checked(self.Flush(handle.value), "flush")

    def rename(self, handle: OwnedHandle, destination: str, *, replace: bool) -> None:
        raw = destination.encode("utf-16-le")
        buffer = c.create_string_buffer(c.sizeof(RenameInfo) + len(raw) + 2)
        info = RenameInfo.from_buffer(buffer)
        info.flags = int(replace)
        info.root = None
        info.length = len(raw)
        c.memmove(c.addressof(buffer) + RenameInfo.name.offset, raw, len(raw))
        self.checked(self.SetInfo(handle.value, 3, buffer, len(buffer)), "rename")

    def discard(self, handle: OwnedHandle) -> None:
        delete = c.c_ubyte(1)
        self.checked(self.SetInfo(handle.value, 4, c.byref(delete), c.sizeof(delete)), "discard_staging")

    def lock(self, handle: OwnedHandle) -> None:
        overlap = Overlapped()
        self.checked(self.Lock(handle.value, 3, 0, 1, 0, c.byref(overlap)), "lock")

    def unlock(self, handle: OwnedHandle) -> None:
        overlap = Overlapped()
        self.checked(self.Unlock(handle.value, 0, 1, 0, c.byref(overlap)), "unlock")


_api: NativeAPI | None = None


def get_api() -> NativeAPI:
    global _api
    if _api is None:
        _api = NativeAPI()
    return _api


def _directory_batch(raw: bytes) -> Iterator[str]:
    offset = 0
    while True:
        if offset + 68 > len(raw):
            raise PrivateFSError("unsafe", "list_buffer")
        following = int.from_bytes(raw[offset : offset + 4], "little")
        length = int.from_bytes(raw[offset + 60 : offset + 64], "little")
        end = offset + 68 + length
        if length == 0 or length % 2 or end > len(raw):
            raise PrivateFSError("unsafe", "list_buffer")
        if following and (following % 8 or following < 68 + length or offset + following >= len(raw)):
            raise PrivateFSError("unsafe", "list_buffer")
        try:
            name = raw[offset + 68 : end].decode("utf-16-le")
        except UnicodeError as exc:
            raise PrivateFSError("unsafe", "list_name") from exc
        if name not in (".", ".."):
            yield name
        if following == 0:
            break
        offset += following
