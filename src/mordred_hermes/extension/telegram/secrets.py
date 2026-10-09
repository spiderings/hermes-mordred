"""Keyvault custody for the Telegram importer's credentials.

Everything that grants access to the account or to the imported archive lives
in ONE vault-enrolled file, ``telegram.json``, next to (but separate from) the
vault ``.env``:

- ``api_id`` / ``api_hash`` — the operator's own my.telegram.org application;
- ``session`` — the Telethon ``StringSession`` (a full MTProto auth key: whoever
  holds it IS the account, so it is the most sensitive value here);
- ``store_key`` — the AES-256 key sealing the local message archive;
- ``venice_api_key`` / ``venice_model`` — the privacy-LLM credentials.

Why not the vault ``.env``: the runtime shim injects every ``.env`` entry into
``os.environ`` of every Hermes process, where the agent's own tools (a
terminal, a code runner) can read and exfiltrate it. A separate enrolled file is
never injected; only this module decrypts it, on demand, on the vault hot path.

No plaintext fallback exists. Without an initialized vault the importer
refuses to log in rather than writing an account credential to disk.
"""

from __future__ import annotations

import base64
import json
import secrets as _secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ...keyvault.anchor import AnchorStore
    from ...keyvault.wrap import NativeBackend

VAULT_FILE = "telegram.json"
_SCHEMA_VERSION = 1
# Short: status polls reuse it, while login/venice changes from the CLI show
# up quickly (sync and questions always read fresh).
_CACHE_TTL_SECONDS = 30.0
_API_HASH_LEN = 32


class TelegramSecretsError(RuntimeError):
    """Stable, content-free failure code (never carries secret material)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TelegramSecrets:
    api_id: int
    api_hash: str
    store_key: bytes
    session: str | None = None
    venice_api_key: str | None = None
    venice_model: str | None = None
    # Where imported text may be sent: "venice" or "local" (see .llm).
    backend: str | None = None
    local_endpoint: str | None = None
    local_model: str | None = None

    def __repr__(self) -> str:  # never let a traceback or log line print secrets
        return (
            f"TelegramSecrets(api_id={self.api_id}, logged_in={self.session is not None}, "
            f"llm_backend={self.llm_backend()!r})"
        )

    @property
    def has_api(self) -> bool:
        """False until the user's my.telegram.org app is entered."""
        return self.api_id > 0 and bool(self.api_hash)

    def llm_backend(self) -> str | None:
        """The configured destination, or None when neither is usable."""
        if self.backend == "local":
            return "local" if self.local_endpoint and self.local_model else None
        if self.backend in (None, "venice"):
            return "venice" if self.venice_api_key else None
        return None

    def llm_model(self) -> str | None:
        backend = self.llm_backend()
        if backend == "local":
            return self.local_model
        if backend == "venice":
            from .venice import DEFAULT_MODEL

            return self.venice_model or DEFAULT_MODEL
        return None


def new_store_key() -> bytes:
    return _secrets.token_bytes(32)


def empty_secrets() -> TelegramSecrets:
    """A record with no Telegram app yet (settings such as the LLM can be saved first)."""
    return TelegramSecrets(api_id=0, api_hash="", store_key=new_store_key())


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def validate_api_credentials(api_id: Any, api_hash: Any) -> tuple[int, str]:
    """Validate the my.telegram.org pair; raise ``invalid_api_credentials``."""
    if isinstance(api_id, str) and api_id.strip().isdigit():
        api_id = int(api_id.strip())
    if not isinstance(api_id, int) or isinstance(api_id, bool) or not 0 < api_id < 2**31:
        raise TelegramSecretsError("invalid_api_credentials")
    if not isinstance(api_hash, str):
        raise TelegramSecretsError("invalid_api_credentials")
    api_hash = api_hash.strip().lower()
    if len(api_hash) != _API_HASH_LEN or any(c not in "0123456789abcdef" for c in api_hash):
        raise TelegramSecretsError("invalid_api_credentials")
    return api_id, api_hash


def encode(value: TelegramSecrets) -> bytes:
    payload: dict[str, Any] = {
        "version": _SCHEMA_VERSION,
        "api_id": value.api_id,
        "api_hash": value.api_hash,
        "store_key": _b64e(value.store_key),
    }
    if value.session is not None:
        payload["session"] = value.session
    if value.venice_api_key is not None:
        payload["venice_api_key"] = value.venice_api_key
    if value.venice_model is not None:
        payload["venice_model"] = value.venice_model
    for key in ("backend", "local_endpoint", "local_model"):
        if getattr(value, key) is not None:
            payload[key] = getattr(value, key)
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _optional_str(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise TelegramSecretsError("secrets_corrupt")
    return value


def decode(blob: bytes) -> TelegramSecrets:
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TelegramSecretsError("secrets_corrupt") from exc
    if not isinstance(payload, dict) or payload.get("version") != _SCHEMA_VERSION:
        raise TelegramSecretsError("secrets_corrupt")
    if payload.get("api_id") == 0 and payload.get("api_hash") == "" and payload.get("session") is None:
        api_id, api_hash = 0, ""  # set up in order: LLM first, Telegram app later
    else:
        try:
            api_id, api_hash = validate_api_credentials(payload.get("api_id"), payload.get("api_hash"))
        except TelegramSecretsError as exc:
            raise TelegramSecretsError("secrets_corrupt") from exc
    raw_key = payload.get("store_key")
    try:
        store_key = _b64d(raw_key) if isinstance(raw_key, str) else b""
    except ValueError as exc:
        raise TelegramSecretsError("secrets_corrupt") from exc
    if len(store_key) != 32:
        raise TelegramSecretsError("secrets_corrupt")
    return TelegramSecrets(
        api_id=api_id,
        api_hash=api_hash,
        store_key=store_key,
        session=_optional_str(payload, "session"),
        venice_api_key=_optional_str(payload, "venice_api_key"),
        venice_model=_optional_str(payload, "venice_model"),
        backend=_optional_str(payload, "backend"),
        local_endpoint=_optional_str(payload, "local_endpoint"),
        local_model=_optional_str(payload, "local_model"),
    )


class VaultSecretStore:
    """Read/modify/write ``telegram.json`` in the Mordred file vault.

    ``backend`` / ``store`` default to the production hot-path implementations
    (Secure Enclave or its software fallback); tests inject fakes. Reads are
    cached briefly so the WebSocket status poll does not reopen the vault on
    every frame; every write invalidates the cache.
    """

    def __init__(
        self,
        root: Path | None = None,
        *,
        backend: NativeBackend | None = None,
        store: AnchorStore | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._root = root
        self._backend = backend
        self._store = store
        self._clock = clock
        self._lock = threading.Lock()
        self._cached: tuple[float, TelegramSecrets | None] | None = None

    def _resolved_root(self) -> Path:
        if self._root is not None:
            return self._root
        from ...keyvault._identity import default_vault_root

        return default_vault_root()

    def _open(self) -> Any:
        from ...keyvault import vault
        from ...keyvault._identity import resolve_backend_store, vault_identity

        root = self._resolved_root()
        if not vault.artifacts_present(root):
            raise TelegramSecretsError("vault_not_initialized")
        key_id = vault_identity(root)
        try:
            backend, store = resolve_backend_store(self._backend, self._store)
            return vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=key_id)
        except Exception as exc:
            raise TelegramSecretsError("vault_unavailable") from exc

    def load(self, *, fresh: bool = False) -> TelegramSecrets | None:
        """Return the stored secrets, ``None`` when never configured."""
        with self._lock:
            now = self._clock()
            if not fresh and self._cached is not None and now - self._cached[0] < _CACHE_TTL_SECONDS:
                return self._cached[1]
            with self._open() as opened:
                value = self._read(opened)
            self._cached = (now, value)
            return value

    @staticmethod
    def _read(opened: Any) -> TelegramSecrets | None:
        if VAULT_FILE not in opened.list_files():
            return None
        try:
            blob = opened.read_file(VAULT_FILE)
        except Exception as exc:
            raise TelegramSecretsError("vault_unavailable") from exc
        return decode(blob)

    def update(self, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]) -> TelegramSecrets | None:
        """Atomically replace ``telegram.json`` with ``mutate(current)``.

        Returning ``None`` from *mutate* unenrolls the file entirely.
        """
        with self._lock:
            self._cached = None
            with self._open() as opened:
                current = self._read(opened)
                updated = mutate(current)
                try:
                    if updated is None:
                        opened.unenroll_file(VAULT_FILE)
                    else:
                        opened.enroll_file(VAULT_FILE, encode(updated))
                except Exception as exc:
                    raise TelegramSecretsError("vault_unavailable") from exc
            return updated

    def invalidate(self) -> None:
        with self._lock:
            self._cached = None


def with_session(value: TelegramSecrets, session: str | None) -> TelegramSecrets:
    return replace(value, session=session)
