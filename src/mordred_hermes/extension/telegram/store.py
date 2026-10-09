"""Encrypted at-rest archive of imported Telegram messages.

Layout under ``<home>/mordred/telegram/`` (directory 0700, files 0600)::

    index.enc                    dialog list + sync cursors
    dialogs/<name>.enc           one file per SEGMENT of a dialog's messages
    .lock                        non-blocking flock (one sync at a time)

A dialog is split into segments of :data:`SEGMENT_SIZE` messages in ascending
id order, so an incremental sync rewrites only the last, partially filled
segment instead of the whole conversation.

Every file is ``MTG1 || nonce(12) || AES-256-GCM(ciphertext)``. The AAD binds
each blob to its logical name, so swapping two segment files, or renaming one
onto the index, fails authentication instead of silently mixing chats.

Two subkeys are derived from the vault-held ``store_key`` with HKDF-SHA256:
one encrypts, the other names files — ``HMAC(name_key, "dialog:<id>:<n>")`` —
so the directory listing does not reveal which chats exist. File count and
sizes remain observable; that is an accepted leak.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import hmac
import json
import os
import secrets
import stat
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_MAGIC = b"MTG1"
_NONCE_LEN = 12
_AAD_PREFIX = b"mordred-telegram-store-v1|"
_HKDF_SALT = b"mordred-telegram-store-v1"
_INDEX_NAME = "index"
_INDEX_VERSION = 1
SEGMENT_SIZE = 2000


class StoreError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class StoredMessage:
    id: int
    date: int  # unix seconds (UTC)
    sender: str  # display name at import time ("" when unknown)
    text: str
    out: bool = False  # sent by the account owner
    reply_to: int | None = None
    media: str | None = None  # media kind placeholder, e.g. "photo"; bytes are never imported


@dataclass
class DialogInfo:
    dialog_id: int  # Telethon "marked" peer id
    kind: str  # "user" | "group" | "channel" | "bot"
    title: str
    last_message_id: int = 0
    message_count: int = 0
    last_date: int = 0
    archived: bool = False


@dataclass
class ArchiveIndex:
    account_label: str = ""
    account_id: int = 0
    last_sync: int = 0
    dialogs: dict[int, DialogInfo] = field(default_factory=dict)


def telegram_dir() -> Path:
    from ..._home import hermes_home

    return hermes_home() / "mordred" / "telegram"


_GITIGNORE = b"# Mordred Telegram archive: encrypted, never version-controlled.\n*\n"


def _ensure_private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise StoreError("store_path_unsafe")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise StoreError("store_path_unsafe")
    os.chmod(path, 0o700)
    _ensure_gitignored(path)
    return path


def _ensure_gitignored(path: Path) -> None:
    """Drop a ``*`` .gitignore so nothing here is ever committed.

    Everything written here is already encrypted; this stops even the
    ciphertext (and file names/sizes) from reaching a repository if
    ``HERMES_HOME`` is ever placed inside a git working tree.
    """
    marker = path / ".gitignore"
    if marker.is_symlink():
        raise StoreError("store_path_unsafe")
    try:
        if marker.read_bytes() == _GITIGNORE:
            return
    except FileNotFoundError:
        pass
    from ...keyvault._storage import atomic_write

    if marker.exists():
        os.chmod(marker, 0o600)
    atomic_write(marker, _GITIGNORE)


def _subkey(key: bytes, info: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=info).derive(key)


class ArchiveStore:
    """Read/write the encrypted archive with one ``store_key``."""

    def __init__(self, key: bytes, root: Path | None = None) -> None:
        if len(key) != 32:
            raise StoreError("store_key_invalid")
        self._enc_key = _subkey(key, b"encrypt")
        self._name_key = _subkey(key, b"names")
        self._root = root if root is not None else telegram_dir()

    # -- low-level blob codec ---------------------------------------------

    def _seal(self, name: str, plaintext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = secrets.token_bytes(_NONCE_LEN)
        return _MAGIC + nonce + AESGCM(self._enc_key).encrypt(nonce, plaintext, _AAD_PREFIX + name.encode("ascii"))

    def _open(self, name: str, blob: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(blob) < len(_MAGIC) + _NONCE_LEN + 16 or not blob.startswith(_MAGIC):
            raise StoreError("store_undecryptable")
        nonce = blob[len(_MAGIC) : len(_MAGIC) + _NONCE_LEN]
        try:
            return AESGCM(self._enc_key).decrypt(
                nonce, blob[len(_MAGIC) + _NONCE_LEN :], _AAD_PREFIX + name.encode("ascii")
            )
        except InvalidTag as exc:
            raise StoreError("store_undecryptable") from exc

    def _write(self, rel: str, name: str, payload: Any) -> None:
        from ...keyvault._storage import atomic_write

        path = self._root / rel
        _ensure_private_dir(path.parent)
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        atomic_write(path, self._seal(name, data))

    def _read(self, rel: str, name: str) -> Any | None:
        path = self._root / rel
        if path.is_symlink():
            raise StoreError("store_path_unsafe")
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            return json.loads(self._open(name, blob).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise StoreError("store_undecryptable") from exc

    # -- naming -------------------------------------------------------------

    def segment_name(self, dialog_id: int, segment: int) -> str:
        message = f"dialog:{dialog_id}:{segment}".encode("ascii")
        return hmac.new(self._name_key, message, hashlib.sha256).hexdigest()[:40]

    # -- index ----------------------------------------------------------------

    def load_index(self) -> ArchiveIndex:
        payload = self._read(f"{_INDEX_NAME}.enc", _INDEX_NAME)
        if payload is None:
            return ArchiveIndex()
        if not isinstance(payload, dict) or payload.get("version") != _INDEX_VERSION:
            raise StoreError("store_undecryptable")
        dialogs: dict[int, DialogInfo] = {}
        for raw in payload.get("dialogs", []):
            try:
                info = DialogInfo(**raw)
            except TypeError as exc:
                raise StoreError("store_undecryptable") from exc
            dialogs[info.dialog_id] = info
        return ArchiveIndex(
            account_label=str(payload.get("account_label", "")),
            account_id=int(payload.get("account_id", 0)),
            last_sync=int(payload.get("last_sync", 0)),
            dialogs=dialogs,
        )

    def save_index(self, index: ArchiveIndex) -> None:
        self._write(
            f"{_INDEX_NAME}.enc",
            _INDEX_NAME,
            {
                "version": _INDEX_VERSION,
                "account_label": index.account_label,
                "account_id": index.account_id,
                "last_sync": index.last_sync,
                "dialogs": [asdict(d) for d in index.dialogs.values()],
            },
        )

    # -- dialogs --------------------------------------------------------------

    def _load_segment(self, dialog_id: int, segment: int) -> list[StoredMessage] | None:
        name = self.segment_name(dialog_id, segment)
        payload = self._read(f"dialogs/{name}.enc", name)
        if payload is None:
            return None
        if not isinstance(payload, list):
            raise StoreError("store_undecryptable")
        try:
            return [StoredMessage(**raw) for raw in payload]
        except TypeError as exc:
            raise StoreError("store_undecryptable") from exc

    def _write_segment(self, dialog_id: int, segment: int, messages: list[StoredMessage]) -> None:
        name = self.segment_name(dialog_id, segment)
        self._write(f"dialogs/{name}.enc", name, [asdict(m) for m in messages])

    def _last_segment(self, dialog_id: int) -> int:
        """Index of the last existing segment, or -1 when the dialog is empty."""
        segment = 0
        while (self._root / "dialogs" / f"{self.segment_name(dialog_id, segment)}.enc").exists():
            segment += 1
        return segment - 1

    def load_messages(self, dialog_id: int) -> list[StoredMessage]:
        messages: list[StoredMessage] = []
        segment = 0
        while True:
            chunk = self._load_segment(dialog_id, segment)
            if chunk is None:
                return messages
            messages.extend(chunk)
            segment += 1

    def append_messages(self, dialog_id: int, new: list[StoredMessage]) -> int:
        """Append messages newer than the stored ones; return how many were added.

        Only the last segment is rewritten (plus any new segments it spills
        into). Messages at or below the newest stored id are ignored, which
        keeps segments in ascending id order.
        """
        last = self._last_segment(dialog_id)
        tail = (self._load_segment(dialog_id, last) or []) if last >= 0 else []
        newest = tail[-1].id if tail else 0
        fresh: dict[int, StoredMessage] = {}
        for message in new:
            if message.id > newest:
                fresh[message.id] = message
        if not fresh:
            return 0
        combined = tail + [fresh[k] for k in sorted(fresh)]
        segment = max(last, 0)
        for start in range(0, len(combined), SEGMENT_SIZE):
            self._write_segment(dialog_id, segment, combined[start : start + SEGMENT_SIZE])
            segment += 1
        return len(fresh)

    # -- lifecycle ------------------------------------------------------------

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Exclusive, NON-blocking cross-process lock.

        A second sync (CLI vs. server) fails fast with ``sync_in_progress``
        instead of parking a thread that could outlive a cancelled task and
        keep the lock forever.
        """
        _ensure_private_dir(self._root)
        with _nonblocking_flock(self._root / ".lock"):
            yield

    def wipe(self) -> None:
        wipe_archive(self._root)


@contextlib.contextmanager
def _nonblocking_flock(path: Path) -> Iterator[None]:
    import fcntl

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise StoreError("store_path_unsafe") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise StoreError("store_path_unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise StoreError("sync_in_progress") from exc
            raise StoreError("store_path_unsafe") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def archive_busy(root: Path | None = None) -> bool:
    """True while another process holds the sync lock (checked without waiting)."""
    base = root if root is not None else telegram_dir()
    if not (base / ".lock").exists():
        return False
    try:
        with _nonblocking_flock(base / ".lock"):
            return False
    except StoreError as exc:
        if exc.code == "sync_in_progress":
            return True
        raise


def wipe_archive(root: Path | None = None) -> None:
    """Delete every archive file, refusing while a sync holds the lock."""
    base = root if root is not None else telegram_dir()
    if base.is_symlink() or not base.is_dir():
        return
    with _nonblocking_flock(base / ".lock"):
        dialogs = base / "dialogs"
        for directory in (dialogs, base):
            if not directory.is_dir() or directory.is_symlink():
                continue
            for child in directory.iterdir():
                if child.is_file() and not child.is_symlink() and (child.suffix in {".enc", ".tmp"}):
                    child.unlink()
        if dialogs.is_dir() and not dialogs.is_symlink() and not any(dialogs.iterdir()):
            dialogs.rmdir()
