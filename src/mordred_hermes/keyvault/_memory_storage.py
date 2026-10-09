"""Bounded checked Windows memory inventory; mutations belong to the lifecycle."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from .._private_fs import FileMetadata, PrivateFSError, open_optional_confidential_directory

MEMORY_FILE_LIMIT = 8 * 1024 * 1024
MEMORY_TOTAL_LIMIT = 64 * 1024 * 1024
MEMORY_ENTRY_LIMIT = 4096


@dataclass(frozen=True)
class MemoryFileSnapshot:
    name: str
    metadata: FileMetadata
    data: bytes


def inventory_memory_files(home: Path) -> tuple[MemoryFileSnapshot, ...]:
    """Call under the canonical home/mordred lifecycle; never suppress I/O failure."""
    with open_optional_confidential_directory(home / "memories") as directory:
        if directory is None:
            return ()
        with directory.transaction() as tx:
            snapshots = []
            total = 0
            for name in sorted(tx.list_names(max_entries=MEMORY_ENTRY_LIMIT)):
                if not (
                    fnmatch.fnmatchcase(name.casefold(), "*.md") or fnmatch.fnmatchcase(name.casefold(), "*.md.bak.*")
                ):
                    continue
                metadata = tx.stat(name)
                data = tx.read_bytes(name, max_bytes=min(MEMORY_FILE_LIMIT, MEMORY_TOTAL_LIMIT - total))
                if tx.stat(name) != metadata or len(data) != metadata.size:
                    raise PrivateFSError("unsafe", "memory_inventory_changed")
                total += len(data)
                snapshots.append(MemoryFileSnapshot(name, metadata, data))
            return tuple(snapshots)
