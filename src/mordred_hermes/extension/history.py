"""Encrypted conversation history for the Mordred extension (SPEC §4 / §1 chat).

History is recorded **encrypted at rest** with the pairing's shared AES key
(the same `🔒ENC:v1:` envelope used for Slack), so it survives gateway restarts
and is readable from any paired surface — extension, Slack, or the localhost
page — without re-running the conversation. It is NOT wiped when viewed.

Storage: ``~/.hermes/extension/history.enc`` — a single `🔒ENC:v1:` blob whose
plaintext is the JSON agent-message list. We rewrite the whole blob per turn
(chat-scale data); a paired client decrypts it (or Hermes decrypts server-side
for the keyless localhost page).
"""

from __future__ import annotations

import contextlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..keyvault._storage import atomic_write
from .crypto import decrypt_message, encrypt_message
from .pairing import load_pairing

logger = logging.getLogger(__name__)

# Load outcomes. "empty" and "undecryptable" used to be the same ``[]``: after a
# re-pairing the stored blob is encrypted under a key that no longer exists, and
# a viewer rendered that as "you have never talked to Hermes" rather than "your
# history is here but unreadable".
STATUS_OK = "ok"
STATUS_EMPTY = "empty"
STATUS_UNAVAILABLE = "unavailable"  # not paired — no key to decrypt with
STATUS_UNDECRYPTABLE = "undecryptable"

# One warning per process for an undecryptable store, not one per read (the
# page polls ``history_get``) and not one per message.
_undecryptable_warned = False


@dataclass(frozen=True, slots=True)
class HistoryLoad:
    """One history read: the messages plus *why* the list looks like it does."""

    messages: list[dict[str, Any]]
    status: str

    @property
    def undecryptable(self) -> bool:
        return self.status == STATUS_UNDECRYPTABLE


@dataclass(frozen=True, slots=True)
class HistoryProjection:
    """Viewer-facing turns plus the status of the read they came from."""

    turns: list[dict[str, str]]
    status: str


def _history_path() -> Path:
    from .._home import hermes_home

    d = hermes_home() / "extension"
    d.mkdir(parents=True, exist_ok=True)
    return d / "history.enc"


def _key() -> bytes | None:
    p = load_pairing()
    return p.aes_key if p else None


def save_messages(messages: list[dict[str, Any]]) -> None:
    """Encrypt and persist the full agent message list (best-effort)."""
    key = _key()
    if key is None:
        return
    try:
        blob = encrypt_message(key, json.dumps(messages, ensure_ascii=False))
        # Canonical 0600 atomic write (keyvault._storage): unpredictable tmp
        # name, O_EXCL | O_NOFOLLOW, fsync of the tmp fd and the parent dir, and
        # tmp cleanup on failure — the hand-rolled version used a fixed ".tmp"
        # name and leaked it when the write blew up. The parent dir is mkdir'd
        # by _history_path().
        atomic_write(_history_path(), blob.encode("utf-8"))
    except Exception:
        logger.debug("extension history save failed", exc_info=True)


def _warn_undecryptable_once() -> None:
    global _undecryptable_warned
    if _undecryptable_warned:
        return
    _undecryptable_warned = True
    logger.warning(
        "extension history is undecryptable and is being served as an empty "
        "conversation (a re-pairing replaces the key the blob was sealed with)",
        exc_info=True,
    )


def load_history() -> HistoryLoad:
    """Decrypt the stored agent message list and report why it is what it is."""
    global _undecryptable_warned
    key = _key()
    if key is None:
        return HistoryLoad([], STATUS_UNAVAILABLE)
    path = _history_path()
    if not path.exists():
        return HistoryLoad([], STATUS_EMPTY)
    try:
        blob = path.read_text("utf-8").strip()
        data = json.loads(decrypt_message(key, blob))
    except Exception:
        _warn_undecryptable_once()
        return HistoryLoad([], STATUS_UNDECRYPTABLE)
    if not isinstance(data, list):
        _warn_undecryptable_once()
        return HistoryLoad([], STATUS_UNDECRYPTABLE)
    _undecryptable_warned = False
    return HistoryLoad(data, STATUS_OK)


def load_messages() -> list[dict[str, Any]]:
    """Decrypt and return the stored agent message list ([] if none).

    Retained for callers that only need the messages (the chat turn loop).
    Anything that *renders* history should use :func:`load_history` so it can
    tell "no history" from "history that no longer decrypts".
    """
    return load_history().messages


def clear() -> None:
    global _undecryptable_warned
    with contextlib.suppress(OSError):
        _history_path().unlink()
    _undecryptable_warned = False


def projected_history() -> HistoryProjection:
    """A viewer-friendly projection plus the status of the underlying read."""
    loaded = load_history()
    return HistoryProjection(_projected_turns(loaded.messages), loaded.status)


def projected_turns() -> list[dict[str, str]]:
    """A viewer-friendly [{role, content}] projection (user + assistant text)."""
    return _projected_turns(load_messages())


def _projected_turns(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for msg in messages:
        role = msg.get("role")
        if role not in ("user", "assistant"):
            continue
        text = _content_text(msg.get("content"))
        if text:
            out.append({"role": role, "content": text})
    return out


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                if p.get("type") in ("text", "input_text", "output_text") and p.get("text"):
                    parts.append(str(p["text"]))
                elif "text" in p and isinstance(p["text"], str):
                    parts.append(p["text"])
        return "\n".join(parts)
    return ""
