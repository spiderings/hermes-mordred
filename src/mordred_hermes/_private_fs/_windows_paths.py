"""Checked local NTFS paths, with all ancestor handles pinned until exit."""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ._types import FileIdentity, PrivateFSError, validate_leaf
from ._windows_api import OwnedHandle, get_api
from ._windows_security import validate_ancestor, validate_private


def windows_leaf(name: str) -> None:
    validate_leaf(name.casefold())
    base = name.split(".")[0].upper()
    if (
        name.endswith((" ", "."))
        or any(ord(char) < 32 or char in '<>"|?*' for char in name)
        or base in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        or re.fullmatch(r"(COM|LPT)[1-9¹²³]", base)
    ):
        raise PrivateFSError("unsafe", "windows_leaf")


def split_path(path: str | Path) -> tuple[str, list[str]]:
    raw = os.fspath(path).replace("/", "\\")
    if raw.startswith("\\\\"):
        raise PrivateFSError("unsupported", "namespace")
    if not re.match(r"^[a-zA-Z]:\\", raw):
        raise PrivateFSError("unsafe", "absolute_path")
    drive = raw[:3]
    parts = raw[3:].split("\\")
    if not parts or any(not part for part in parts):
        raise PrivateFSError("unsafe", "directory_path")
    for part in parts:
        windows_leaf(part)
    return drive, parts


@dataclass(frozen=True)
class CheckedDirectory:
    handle: OwnedHandle
    identity: FileIdentity
    path: str
    confidential: bool = False
    ancestors: tuple[tuple[OwnedHandle, FileIdentity], ...] = ()

    def check(self) -> None:
        for handle, identity in self.ancestors:
            validate_ancestor(handle, creating_child=False)
            if handle.api.metadata(handle).identity != identity:
                raise PrivateFSError("unsafe", "ancestor_identity")
        if self.confidential:
            validate_ancestor(self.handle, creating_child=True)
        else:
            validate_private(self.handle, directory=True)
        if self.handle.api.metadata(self.handle).identity != self.identity:
            raise PrivateFSError("unsafe", "directory_identity")
        if self.ancestors and self.handle.api.final_path(self.handle).casefold() != self.path.casefold():
            raise PrivateFSError("unsafe", "directory_path")


@contextlib.contextmanager
def checked_directory(path: str | Path, *, create: bool = False) -> Iterator[CheckedDirectory]:
    with checked_directory_optional(path, create=create) as checked:
        assert checked is not None
        yield checked


@contextlib.contextmanager
def checked_directory_optional(
    path: str | Path,
    *,
    create: bool = False,
    confidential: bool = False,
    optional: bool = False,
) -> Iterator[CheckedDirectory | None]:
    drive, parts = split_path(path)
    api = get_api()
    api.validate_drive(drive)
    with contextlib.ExitStack() as stack:
        parent = stack.enter_context(api.open(drive))
        api.validate_volume(parent)
        volume = api.metadata(parent).identity.volume
        ancestors: list[tuple[OwnedHandle, FileIdentity]] = []
        for index, part in enumerate(parts):
            validate_ancestor(parent, creating_child=False)
            ancestors.append((parent, api.metadata(parent).identity))
            destination = api.final_path(parent).rstrip("\\") + "\\" + part
            created = False
            child: OwnedHandle | None = None
            try:
                child = api.open(destination)
            except PrivateFSError as exc:
                if (
                    exc.reason != "missing"
                    or exc.operation != "open"
                    or exc.commit_state != "not_committed"
                    or index != len(parts) - 1
                    or not (optional or create)
                ):
                    raise
                validate_ancestor(parent, creating_child=True)
                if create:
                    child, created = _create_directory(destination)
            if child is None:
                for ancestor, identity in ancestors:
                    validate_ancestor(ancestor, creating_child=ancestor is parent)
                    if api.metadata(ancestor).identity != identity:
                        raise PrivateFSError("unsafe", "ancestor_identity")
                # No missing exception crosses either the yield or cleanup.
                yield None
                return
            parent = stack.enter_context(child)
            if created:
                validate_private(parent, directory=True)
            metadata = api.metadata(parent)
            if metadata.reparse or not metadata.directory or metadata.identity.volume != volume:
                raise PrivateFSError("unsafe", "ancestor_identity")
        checked = CheckedDirectory(
            parent, api.metadata(parent).identity, api.final_path(parent), confidential, tuple(ancestors)
        )
        checked.check()
        yield checked


def _create_directory(destination: str) -> tuple[OwnedHandle, bool]:
    api = get_api()
    created = True
    try:
        api.mkdir(destination)
    except PrivateFSError as exc:
        if exc.reason != "exists":
            raise
        created = False
    return api.open(destination), created
