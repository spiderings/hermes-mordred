"""Keep unsealed credentials and message plaintext in memory only.

Applied by every process that unseals Telegram credentials or reads the
archive (the ``telegram`` CLI commands and ``extension serve`` before its
first Telegram operation):

- core dumps are disabled, so a crash cannot write process memory to disk;
- on macOS, ``ptrace(PT_DENY_ATTACH)`` refuses debugger / memory-inspection
  attachment by other processes of the same user;
- Telethon's own logger is capped at WARNING so no TL object (which can carry
  message text) is ever logged.

macOS encrypts swap by default, so memory paged out stays encrypted at rest.
Every step is best-effort and idempotent; a failure never blocks the caller.
"""

from __future__ import annotations

import contextlib
import logging
import sys

_PT_DENY_ATTACH = 31
_applied = False


def harden_process() -> None:
    global _applied
    if _applied:
        return
    _applied = True
    with contextlib.suppress(Exception):
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform == "darwin":
        with contextlib.suppress(Exception):
            import ctypes

            libc = ctypes.CDLL(None)
            libc.ptrace(_PT_DENY_ATTACH, 0, None, 0)
    elif sys.platform == "linux":
        with contextlib.suppress(Exception):
            import ctypes

            pr_set_dumpable = 4
            ctypes.CDLL(None).prctl(pr_set_dumpable, 0, 0, 0, 0)
    logging.getLogger("telethon").setLevel(logging.WARNING)
