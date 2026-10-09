"""Telegram requires agent-memory encryption to be on.

Anything the agent remembers about a Telegram conversation lands in
``<home>/memories/*.md``. Hermes writes those files in plaintext unless
Mordred's memory encryption is armed, so every Telegram entry point (login,
sync, listing chats, questions — from the CLI, the browser extension or the
Hermes tools) refuses with ``memory_encryption_required`` until
``hermes-mordred encryption enable memory`` is active and no plaintext
memory file is left on disk.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


class MemoryEncryptionRequired(RuntimeError):
    def __init__(self, code: str = "memory_encryption_required") -> None:
        super().__init__(code)
        self.code = code


def memory_encryption_active(home: Path | None = None) -> bool:
    """True only when the memory hook is armed and nothing on disk is plaintext."""
    from ..._home import hermes_home
    from ...wizard.encryption_cli import memory_status

    try:
        status: Any = memory_status(home=home or hermes_home(), platform=sys.platform)
    except Exception:
        return False
    return bool(status.active) and not bool(status.drift)


def require_memory_encryption(home: Path | None = None) -> None:
    if not memory_encryption_active(home):
        raise MemoryEncryptionRequired()
