"""``~/.hermes/.env`` upsert writer (Phase 3 PR3a Task #6b).

The Mordred wizard writes a single secret (the Mullvad account number) to
``~/.hermes/.env`` so the Mullvad CLI can pick it up via env-var indirection
without ever being persisted into ``policy.json`` / ``config.yaml``. The
secret never crosses any other Mordred-owned filesystem path -- that file's
0600 mode plus the parent dir's 0700 mode is the only at-rest protection
v1 provides (Phase 4 keyvault encrypts it later).

Contract (mirrors PATHS.md §193 "credentials directory"):
- Upserts ``KEY=value`` lines without disturbing unrelated lines.
- Empty value → remove the line if present (so a user clearing the
  prompt removes the stale secret instead of leaving ``KEY=`` empty).
- Refuses non-POSIX env-var names + values containing newlines (defence
  in depth against shell-injection from a maliciously edited config).
- Atomic write via :func:`mordred_hermes.wizard.policy_writer._atomic_write_text`
  so a crash mid-write leaves the previous file intact.
"""

from __future__ import annotations

import errno
import re
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Protocol, runtime_checkable

from .._config_io import DOTENV_LIMIT, CanonicalPaths, canonical_session
from .._file_lock import private_flock
from .policy_writer import _atomic_write_text, _bounded_utf8, _ensure_real_directory, _read_regular_text, _windows

# POSIX env-var name: start with letter/underscore, followed by alnum/underscore.
# We also require at least one uppercase letter -- Mordred owns the
# ``MORDRED_*`` namespace, and the prompts only ever emit fully-uppercase
# names. Restricting at this layer makes the file shell-injection-safe.
_VALID_ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_ENV_THREAD_LOCK = threading.RLock()


def _reject_unopenable_dotenv_lock(lock_path: Path, exc: OSError) -> NoReturn:
    """Wrap an ``os.open`` failure on the dotenv lock as a tagged ``EPERM``."""
    raise OSError(errno.EPERM, "dotenv lock is unsafe or unavailable", str(lock_path)) from exc


def _reject_unsafe_dotenv_lock(lock_path: Path) -> NoReturn:
    """Fail closed when ``.env.lock`` is not a private regular file."""
    raise OSError(errno.EPERM, "dotenv lock must be a mode-0600 regular file", str(lock_path))


@contextmanager
def _dotenv_lock(path: Path) -> Iterator[None]:
    """Stable sibling lock shared by every Mordred ``.env`` RMW writer.

    The descriptor lifecycle is :func:`mordred_hermes._file_lock.private_flock`;
    the in-process ``RLock``, the parent-directory check, and both raises stay
    here so the tagged ``EPERM`` :exc:`OSError`\\ s (and the ``from exc``
    chaining on the open failure) are unchanged.
    """
    with _ENV_THREAD_LOCK:
        _ensure_real_directory(path.parent)
        with private_flock(
            path.with_name(path.name + ".lock"),
            on_unsafe=_reject_unsafe_dotenv_lock,
            on_open_error=_reject_unopenable_dotenv_lock,
        ):
            yield


def update_dotenv_file(path: Path, transform: Callable[[str], str]) -> None:
    """Atomically transform a regular dotenv file under the shared RMW lock."""
    if _windows():
        if path.name != ".env":
            raise ValueError("canonical dotenv filename must be .env")
        with canonical_session(CanonicalPaths(path.parent), scope="home", create=True) as session:
            source = session.read_home(".env", max_bytes=DOTENV_LIMIT)
            updated = transform(source.data.decode("utf-8") if source is not None else "")
            session.write_home(".env", _bounded_utf8(updated, DOTENV_LIMIT))
        return
    with _dotenv_lock(path):
        existing = _read_regular_text(path)
        updated = transform(existing if existing is not None else "")
        _atomic_write_text(path, updated, mode=0o600)


@runtime_checkable
class EnvFileWriter(Protocol):
    """Persists one secret value (or its absence) to a ``.env``-style file."""

    def upsert(self, path: Path, *, key: str, value: str) -> None: ...


@dataclass(frozen=True, slots=True)
class DotEnvFileWriter:
    """Production :class:`EnvFileWriter` for ``~/.hermes/.env``.

    Upserts ``KEY=value`` lines atomically. Empty values remove the line.
    Refuses values / keys that could break the file format.
    """

    def upsert(self, path: Path, *, key: str, value: str) -> None:
        if not _VALID_ENV_KEY.fullmatch(key):
            raise ValueError(
                f"refusing to write env var key {key!r}: must be uppercase, start with letter/underscore, "
                "and contain only alnum/underscore"
            )
        if "\n" in value or "\r" in value:
            raise ValueError(f"refusing to write env var value with newline in key {key!r}")

        if _windows():
            _bounded_utf8(value, DOTENV_LIMIT)

        def transform(existing: str) -> str:
            new_lines, found = _replace_or_strip_key(existing.splitlines(), key, value)
            if not found and value:
                new_lines.append(f"{key}={value}")
            return "\n".join(new_lines) + ("\n" if new_lines else "")

        update_dotenv_file(path, transform)


def _replace_or_strip_key(lines: list[str], key: str, value: str) -> tuple[list[str], bool]:
    """Return (lines, found) where lines either has the new value or has the
    key removed (when ``value`` is empty).

    Used by :meth:`DotEnvFileWriter.upsert`. Match is exact: ``key=...`` only
    matches lines starting with ``<key>=``. Comments and lines that happen to
    contain ``key=`` as a substring elsewhere are preserved.

    Deduplication (review M2): if the on-disk file already had multiple
    matching lines (from a hand-edit or a half-finished write), only the
    first match keeps the new value -- subsequent matches are stripped --
    so the result is a single line. Empty-value removal strips all
    matches.
    """
    out: list[str] = []
    found = False
    prefix = f"{key}="
    for line in lines:
        export = "export " if line.startswith("export " + prefix) else ""
        if line.startswith(prefix) or export:
            if value and not found:
                out.append(f"{export}{key}={value}")
            # subsequent matches dropped (or all matches dropped when value is empty)
            found = True
            continue
        out.append(line)
    return out, found
