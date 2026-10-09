"""Telegram credentials sealed by the Secure Enclave (TEE) — and nothing else.

Everything that grants access to the account or the archive (API credentials,
the Telethon session, the archive key, the LLM API key) is stored in ONE file,
``<home>/mordred/telegram/credentials.sealed``:

    MTC1 || u16 len || wrap_blob || nonce(12) || AES-256-GCM(json)

``wrap_blob`` is the keyvault's ECIES wrap (:func:`keyvault.wrap.wrap_dek`) of a
fresh 32-byte data key under a P-256 key that lives inside the Secure Enclave.
Opening the file therefore requires an ECDH *inside the Enclave*
(:func:`keyvault.wrap.unwrap_dek`) — the private key never leaves the chip, so
the file is useless on any other machine or without this device's Enclave.

Rules enforced here:

- **Hardware only.** The backend is built from the signed Enclave helper
  (``hermes-mordred keyvault enable-se``) with NO software-key namespace and NO
  legacy fallback. Without the helper, every read and write is refused with
  ``tee_unavailable``; there is no plaintext or software-key fallback.
- **The Enclave is used on every connection.** Nothing decrypted from the
  sealed file is cached: each ``load()`` is a fresh Enclave ECDH. Callers open
  the credentials right before connecting to Telegram (or the LLM) and drop
  them afterwards.
- **Optional user presence.** The Enclave key is created with a Touch ID /
  passcode requirement unless the operator opts out, so each unseal can
  demand the owner's presence.

Non-secret flags for the status screen (logged in? which LLM?) live in
``credentials.meta.json`` so polling never touches the Enclave.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets as _secrets
import struct
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .secrets import TelegramSecrets, TelegramSecretsError, decode, encode

KEY_ID = "mordred-hermes.telegram.credentials.v1"
_MAGIC = b"MTC1"
_NONCE_LEN = 12
_AAD = b"mordred-telegram-credentials-v1"
_SEALED_NAME = "credentials.sealed"
_META_NAME = "credentials.meta.json"

#: ``(value, token)`` from :meth:`TeeSecretStore.load_snapshot`.
Snapshot = tuple[TelegramSecrets | None, bytes | None]


def _home() -> Path:
    from ..._home import hermes_home

    return hermes_home()


def hardware_backend(home: Path | None = None) -> Any:
    """Enclave-only backend: the signed helper, no software/legacy namespaces."""
    from ...keyvault import _seckey_helper
    from ...keyvault._seckey_backend import _SecKeyBackend

    if sys.platform == "darwin":
        ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_sekey_helper)
    elif sys.platform == "linux":
        ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_tpmkey_helper)
    else:
        ops = None
    if ops is None:
        raise TelegramSecretsError("tee_unavailable")
    base = home if home is not None else _home()
    backend = _SecKeyBackend(ops=ops, legacy_ops=None, sw_ops=None)
    return backend._for_keyvault_root(base / "mordred" / "keyvault")


def _audit_sink(entry: dict[str, Any]) -> None:
    try:
        import logging

        from ..._audit_support import build_audit_writer, safe_audit_append

        writer = build_audit_writer(_home() / "mordred" / "audit.log")
        safe_audit_append(writer, entry, logger=logging.getLogger(__name__))
    except Exception:
        pass


class TeeSecretStore:
    """Read/modify/write the Enclave-sealed Telegram credentials.

    Same interface as the former vault store (``load`` / ``update``), plus
    :meth:`flags` for non-secret status and :meth:`ensure_key`.
    """

    def __init__(
        self,
        root: Path | None = None,
        *,
        backend_factory: Callable[[], Any] | None = None,
        audit_sink: Callable[[dict[str, Any]], None] = _audit_sink,
    ) -> None:
        self._root = root
        self._backend_factory = backend_factory or hardware_backend
        self._audit_sink = audit_sink

    # -- paths ----------------------------------------------------------------

    def _dir(self) -> Path:
        from .store import _ensure_private_dir, telegram_dir

        return _ensure_private_dir(self._root if self._root is not None else telegram_dir())

    @property
    def sealed_path(self) -> Path:
        return self._dir() / _SEALED_NAME

    @property
    def meta_path(self) -> Path:
        return self._dir() / _META_NAME

    # -- Enclave key ----------------------------------------------------------

    def ensure_key(self, *, require_presence: bool = True) -> None:
        """Create the Enclave key if it does not exist yet."""
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError, WrapKeyNotFound

        backend = self._backend_factory()
        try:
            wrap.get_wrapping_key_public(KEY_ID, backend=backend)
            return
        except WrapKeyNotFound:
            pass
        except WrapError as exc:
            raise TelegramSecretsError("tee_unavailable") from exc
        try:
            wrap.generate_wrapping_key(KEY_ID, backend=backend, unattended=not require_presence)
        except WrapError as exc:
            raise TelegramSecretsError("tee_unavailable") from exc

    def delete_key(self) -> None:
        from ...keyvault import wrap

        wrap.delete_wrapping_key(KEY_ID, backend=self._backend_factory())

    # -- seal / unseal ----------------------------------------------------------

    def _seal(self, plaintext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError

        dek = _secrets.token_bytes(32)
        try:
            # Offline: uses the Enclave PUBLIC key; no prompt.
            blob = wrap.wrap_dek(dek, KEY_ID, backend=self._backend_factory())
        except WrapError as exc:
            raise TelegramSecretsError("tee_unavailable") from exc
        nonce = _secrets.token_bytes(_NONCE_LEN)
        body = AESGCM(dek).encrypt(nonce, plaintext, _AAD)
        return _MAGIC + struct.pack(">H", len(blob)) + blob + nonce + body

    def _unseal(self, sealed: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapAuthCancelled, WrapError

        header = len(_MAGIC) + 2
        if len(sealed) < header or not sealed.startswith(_MAGIC):
            raise TelegramSecretsError("secrets_corrupt")
        (blob_len,) = struct.unpack(">H", sealed[len(_MAGIC) : header])
        blob = sealed[header : header + blob_len]
        nonce = sealed[header + blob_len : header + blob_len + _NONCE_LEN]
        body = sealed[header + blob_len + _NONCE_LEN :]
        if len(blob) != blob_len or len(nonce) != _NONCE_LEN or len(body) < 16:
            raise TelegramSecretsError("secrets_corrupt")
        try:
            # The authorization boundary: ECDH inside the Secure Enclave.
            dek = wrap.unwrap_dek(blob, KEY_ID, audit_sink=self._audit_sink, backend=self._backend_factory())
        except WrapAuthCancelled as exc:
            raise TelegramSecretsError("tee_auth_cancelled") from exc
        except WrapError as exc:
            raise TelegramSecretsError("tee_unavailable") from exc
        try:
            return AESGCM(dek).decrypt(nonce, body, _AAD)
        except InvalidTag as exc:
            raise TelegramSecretsError("secrets_corrupt") from exc

    # -- public API -------------------------------------------------------------

    def _read_sealed(self) -> bytes | None:
        path = self.sealed_path
        if path.is_symlink():
            raise TelegramSecretsError("secrets_corrupt")
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def load(self, *, fresh: bool = True) -> TelegramSecrets | None:
        """Unseal through the Enclave. Never cached (``fresh`` is ignored)."""
        del fresh
        return self.load_snapshot()[0]

    def load_snapshot(self) -> Snapshot:
        """:meth:`load` plus a token for :meth:`update_from_snapshot`.

        One Enclave unwrap (none when nothing is sealed yet). The token is the
        SHA-256 of the sealed file that was unsealed (``None`` when absent); it
        is not secret and holds nothing derived from the plaintext.
        """
        sealed = self._read_sealed()
        if sealed is None:
            return None, None
        return decode(self._unseal(sealed)), hashlib.sha256(sealed).digest()

    def update(self, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]) -> TelegramSecrets | None:
        """Unseal (one Enclave unwrap), apply ``mutate``, and seal the result."""
        return self._write(mutate(self.load()))

    def update_from_snapshot(
        self, snapshot: Snapshot, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]
    ) -> TelegramSecrets | None:
        """:meth:`update` for a value just read with :meth:`load_snapshot`,
        without unsealing it a second time (no second Touch ID).

        The sealed file must be byte-identical to the one the snapshot came from;
        if another writer changed (or removed / created) it in between, this
        falls back to a plain :meth:`update` (one unwrap) so that write is never
        lost. Sealing itself only uses the Enclave public key -- no prompt.
        """
        current, token = snapshot
        sealed = self._read_sealed()
        now = None if sealed is None else hashlib.sha256(sealed).digest()
        unchanged = (now is None and token is None) or (
            now is not None and token is not None and hmac.compare_digest(now, token)
        )
        if not unchanged:
            return self.update(mutate)
        return self._write(mutate(current))

    def _write(self, updated: TelegramSecrets | None) -> TelegramSecrets | None:
        from ...keyvault._storage import atomic_write

        if updated is None:
            for path in (self.sealed_path, self.meta_path):
                path.unlink(missing_ok=True)
            return None
        atomic_write(self.sealed_path, self._seal(encode(updated)))
        self._write_meta(updated)
        return updated

    def store(self, value: TelegramSecrets) -> None:
        """Seal *value* without unsealing first (migration / first login)."""
        from ...keyvault._storage import atomic_write

        atomic_write(self.sealed_path, self._seal(encode(value)))
        self._write_meta(value)

    def _write_meta(self, value: TelegramSecrets) -> None:
        from ...keyvault._storage import atomic_write

        meta = {
            "version": 1,
            "logged_in": value.session is not None,
            "api_configured": value.has_api,
            "llm_backend": value.llm_backend(),
            "llm_model": value.llm_model(),
        }
        previous = self._read_meta()
        if previous and isinstance(previous.get("sync_scope"), dict):
            meta["sync_scope"] = previous["sync_scope"]
        atomic_write(self.meta_path, json.dumps(meta).encode("utf-8"))

    def _read_meta(self) -> dict[str, Any] | None:
        try:
            meta = json.loads(self.meta_path.read_text("utf-8"))
        except (FileNotFoundError, ValueError):
            return None
        return meta if isinstance(meta, dict) else None

    def sync_scope(self) -> dict[str, Any]:
        """The import scope chosen at setup (non-secret); empty = everything."""
        meta = self._read_meta() or {}
        scope = meta.get("sync_scope")
        return dict(scope) if isinstance(scope, dict) else {}

    def save_sync_scope(self, scope: dict[str, Any]) -> None:
        from ...keyvault._storage import atomic_write

        meta = self._read_meta() or {"version": 1, "logged_in": False, "llm_backend": None, "llm_model": None}
        meta["sync_scope"] = {
            "include_channels": scope.get("include_channels") is not False,
            "include_archived": scope.get("include_archived") is True,
            "limit_per_dialog": scope.get("limit_per_dialog"),
            "since_days": scope.get("since_days"),
            "max_group_size": scope.get("max_group_size", 100),
        }
        atomic_write(self.meta_path, json.dumps(meta).encode("utf-8"))

    def flags(self) -> dict[str, Any] | None:
        """Non-secret status flags, or ``None`` when not configured. No Enclave."""
        path = self.meta_path
        if path.is_symlink() or not self.sealed_path.exists():
            return None
        try:
            meta = json.loads(path.read_text("utf-8"))
        except (FileNotFoundError, ValueError):
            return {"version": 1, "logged_in": False, "llm_backend": None, "llm_model": None}
        return meta if isinstance(meta, dict) else None

    def invalidate(self) -> None:
        """No-op: nothing is cached."""
