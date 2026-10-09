"""Telegram importer service used by the extension WebSocket server and CLI.

One instance per ``extension serve`` process. It owns at most one running sync
task, exposes a status snapshot, the dialog list, and question answering. All
failures surface as stable codes (``TelegramServiceError.code``) so no message
text, name, or credential can reach a client or a log line through an
exception string.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..egress import EgressError, EgressRoute, resolve_route
from . import venice
from .ask import (
    ANSWER_TOKENS,
    Aliases,
    AskError,
    AskRequest,
    budget_for,
    build_messages,
    dealias_stream,
    select_context,
    strip_thinking,
    validate_question,
)
from .client import (
    DEFAULT_MAX_GROUP_SIZE,
    DEFAULT_SINCE_DAYS,
    SyncOptions,
    SyncProgress,
    TelegramClientError,
    build_client,
    sync_archive,
    telethon_available,
)
from .llm import DEFAULT_LOCAL_CONTEXT_TOKENS, LlmConfigError, LlmTarget, resolve_target
from .memory_guard import MemoryEncryptionRequired
from .readonly import ReadOnlyViolation, RequestPolicy
from .secrets import TelegramSecrets, TelegramSecretsError
from .store import ArchiveStore, StoreError
from .tee import TeeSecretStore

_log = logging.getLogger(__name__)

_VENICE_HOST = "api.venice.ai"
_ASK_TIMEOUT_SECONDS = 300.0
_MAX_DIALOGS_LISTED = 2000

# Telethon RPC error class names → wire codes. Matched by name so this module
# imports without Telethon installed.
_TELETHON_ERROR_CODES = {
    "FloodWaitError": "telegram_rate_limited",
    "FloodPremiumWaitError": "telegram_rate_limited",
    "AuthKeyUnregisteredError": "telegram_session_revoked",
    "SessionRevokedError": "telegram_session_revoked",
    "SessionExpiredError": "telegram_session_revoked",
    "UserDeactivatedError": "telegram_session_revoked",
    "UserDeactivatedBanError": "telegram_session_revoked",
    "AuthKeyDuplicatedError": "telegram_session_revoked",
}


class TelegramServiceError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def error_code(exc: BaseException, fallback: str) -> str:
    """Map any exception from this package to a reviewed wire code."""
    for kind in (
        TelegramServiceError,
        TelegramClientError,
        TelegramSecretsError,
        StoreError,
        LlmConfigError,
        MemoryEncryptionRequired,
        AskError,
        venice.VeniceError,
        EgressError,
    ):
        if isinstance(exc, kind):
            return str(getattr(exc, "code", fallback))
    if isinstance(exc, ReadOnlyViolation):
        return "telegram_request_blocked"
    for cls in type(exc).__mro__:
        mapped = _TELETHON_ERROR_CODES.get(cls.__name__)
        if mapped is not None:
            return mapped
    if isinstance(exc, ConnectionError | OSError | asyncio.TimeoutError):
        return "telegram_unavailable"
    return fallback


@dataclass
class AskResult:
    model: str
    message_count: int
    dialog_count: int
    truncated: bool
    mode: str = "keyword"
    candidates: int = 0
    chats_searched: int = 0


def _audit(event: str, decision: str, **fields: Any) -> None:
    """Best-effort audit entry. Never includes content, names, or keys."""
    try:
        from ..._audit_support import build_audit_writer, safe_audit_append
        from ..._home import hermes_home

        writer = build_audit_writer(hermes_home() / "mordred" / "audit.log")
        safe_audit_append(writer, {"event": event, "decision": decision, "reason": None, **fields}, logger=_log)
    except Exception:
        _log.debug("telegram audit append failed", exc_info=True)


def check_llm_policy(backend: str, base_url: str) -> None:
    """Apply the llm_guard strict-mode gate to the Venice endpoint.

    This client is not a Hermes provider adapter, so the ``pre_api_request``
    hook never sees it; run the same per-request check explicitly. Under
    strict mode Venice must be allow-listed (``cloud_provider_allowlist``
    contains ``"venice"`` and ``allow_cloud_llm`` is true). There is no
    interactive prompt here: ``prompt-once`` fails closed.
    """
    from ..._home import hermes_home
    from ..._policy_io import read_policy_mode_fail_closed
    from ...llm_guard import enforce
    from ...llm_guard._exceptions import MordredSessionRefused

    path = hermes_home() / "mordred" / "policy.json"
    mode = read_policy_mode_fail_closed(path, default="lenient", log=_log)
    try:
        from ..._audit_support import build_audit_writer

        writer = build_audit_writer(hermes_home() / "mordred" / "audit.log")
        enforce.check_runtime_provider(
            policy_mode=mode,
            policy_json_path=path,
            active_provider="venice" if backend == "venice" else "mordred-local",
            audit=writer,
            runtime_base_url=base_url,
            prompt_fn=lambda _provider: False,
        )
    except MordredSessionRefused as exc:
        raise TelegramServiceError("llm_policy_refused") from exc


async def _without_thinking(chunks: AsyncIterator[str]) -> AsyncIterator[str]:
    """Stream text with any ``<think>…</think>`` block removed (local reasoning models)."""
    pending = ""
    async for chunk in chunks:
        pending += chunk
        if "<think>" in pending and "</think>" not in pending.split("<think>", 1)[1]:
            continue  # inside a reasoning block: hold until it closes
        cleaned = strip_thinking(pending)
        cut = cleaned.rfind("<")
        if cut != -1 and "<think>".startswith(cleaned[cut:]):
            pending, cleaned = cleaned[cut:], cleaned[:cut]  # maybe the start of "<think>"
        else:
            pending = ""
        if cleaned:
            yield cleaned
    rest = strip_thinking(pending).split("<think>", 1)[0]
    if rest:
        yield rest


def _default_http_session(route: EgressRoute, timeout: float) -> Any:
    import aiohttp

    connector = None
    if route.socks_proxy_url is not None:
        try:
            from aiohttp_socks import ProxyConnector

            connector = ProxyConnector.from_url(route.socks_proxy_url, rdns=True)
        except (ImportError, RuntimeError, ValueError) as exc:
            raise EgressError() from exc
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout),
        trust_env=False,
    )


class _ProxiedSession:
    """Adds the explicit HTTP proxy (if any) to every request."""

    def __init__(self, session: Any, http_proxy: str | None) -> None:
        self._session = session
        self._proxy = http_proxy

    def get(self, url: str, **kwargs: Any) -> Any:
        if self._proxy is not None:
            kwargs["proxy"] = self._proxy
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        if self._proxy is not None:
            kwargs["proxy"] = self._proxy
        return self._session.post(url, **kwargs)


class TelegramService:
    def __init__(
        self,
        *,
        secret_store: Any = None,
        archive_root: Path | None = None,
        client_factory: Callable[..., Any] = build_client,
        http_session_factory: Callable[[EgressRoute, float], Any] = _default_http_session,
        route_resolver: Callable[[str], EgressRoute] = resolve_route,
        policy_check: Callable[[str, str], None] = check_llm_policy,
        installed: Callable[[], bool] = telethon_available,
        memory_guard: Callable[[], None] | None = None,
    ) -> None:
        # Enclave-sealed; every load() is a fresh Secure Enclave unwrap.
        self._secrets = secret_store if secret_store is not None else TeeSecretStore()
        if secret_store is None:
            from .hardening import harden_process

            harden_process()
        self._archive_root = archive_root
        self._client_factory = client_factory
        self._http_session_factory = http_session_factory
        self._route_resolver = route_resolver
        self._policy_check = policy_check
        self._installed = installed
        if memory_guard is None:
            from .memory_guard import require_memory_encryption

            memory_guard = require_memory_encryption
        self._memory_guard = memory_guard
        self._sync_task: asyncio.Task[None] | None = None
        self._sync_starting = False
        self._progress = SyncProgress()
        self._last_error: str | None = None
        self._summary: dict[str, Any] | None = None

    # -- helpers --------------------------------------------------------------

    async def _load_secrets(self, *, fresh: bool = False) -> TelegramSecrets | None:
        return await asyncio.to_thread(self._secrets.load, fresh=fresh)

    def _archive(self, value: TelegramSecrets) -> ArchiveStore:
        return ArchiveStore(value.store_key, self._archive_root)

    @property
    def syncing(self) -> bool:
        return self._sync_task is not None and not self._sync_task.done()

    # -- status ---------------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        """Snapshot for the popup. Counts and flags only, plus the account label."""
        result: dict[str, Any] = {
            "installed": self._installed(),
            "configured": False,
            "logged_in": False,
            "llm_backend": None,
            "llm_model": None,
            "syncing": self.syncing,
            "progress": asdict(self._progress),
            "last_error": self._last_error,
            "last_sync": 0,
            "dialog_count": 0,
            "message_count": 0,
            "account_label": "",
        }
        # Flags only: polling must not unseal credentials through the Enclave.
        try:
            flags = await asyncio.to_thread(self._secrets.flags)
        except (TelegramSecretsError, StoreError, OSError) as exc:
            result["last_error"] = getattr(exc, "code", "telegram_unavailable")
            return result
        if flags is None:
            return result
        result["configured"] = True
        result["logged_in"] = flags.get("logged_in") is True
        backend = flags.get("llm_backend")
        model = flags.get("llm_model")
        result["llm_backend"] = backend if backend in ("venice", "local") else None
        result["llm_model"] = model if isinstance(model, str) and model else None
        summary = self._summary
        if summary is not None:
            result.update(summary)
        return result

    def _remember_summary(self, index: Any) -> None:
        """Keep counts (not content) for status, so polls need no Enclave unwrap."""
        self._summary = {
            "last_sync": index.last_sync,
            "dialog_count": len(index.dialogs),
            "message_count": sum(d.message_count for d in index.dialogs.values()),
            "account_label": index.account_label,
        }

    async def dialogs(self) -> list[dict[str, Any]]:
        await asyncio.to_thread(self._memory_guard)
        value = await self._load_secrets()
        if value is None:
            raise TelegramServiceError("telegram_not_configured")
        index = await asyncio.to_thread(self._archive(value).load_index)
        del value
        self._remember_summary(index)
        ordered = sorted(index.dialogs.values(), key=lambda d: d.last_date, reverse=True)
        return [
            {
                "id": str(d.dialog_id),
                "kind": d.kind,
                "title": d.title,
                "message_count": d.message_count,
                "last_date": d.last_date,
                "archived": d.archived,
            }
            for d in ordered[:_MAX_DIALOGS_LISTED]
        ]

    # -- sync -----------------------------------------------------------------

    def sync_options(self, overrides: dict[str, Any] | None = None) -> SyncOptions:
        """The saved scope (from setup), with any explicitly given fields on top."""
        scope_fn = getattr(self._secrets, "sync_scope", None)
        scope: dict[str, Any] = dict(scope_fn()) if scope_fn is not None else {}
        scope.update({k: v for k, v in (overrides or {}).items() if v is not None})

        def count(value: Any) -> int | None:
            return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None

        return SyncOptions(
            include_channels=scope.get("include_channels") is not False,
            # Archived chats only when explicitly asked for.
            include_archived=scope.get("include_archived") is True,
            limit_per_dialog=count(scope.get("limit_per_dialog")),
            # Absent/None = the default window; 0 = all history.
            since_days=(DEFAULT_SINCE_DAYS if scope.get("since_days") is None else count(scope.get("since_days"))),
            # Absent = the default limit; 0 = no limit (large groups included).
            max_group_size=(
                DEFAULT_MAX_GROUP_SIZE if "max_group_size" not in scope else count(scope.get("max_group_size"))
            ),
        )

    async def start_sync(self, options: SyncOptions | None = None) -> None:
        """Start a background sync; raise ``sync_in_progress`` if one runs.

        The check and the claim happen before the first ``await`` so two
        sockets cannot both start a sync; the cross-process lock is taken
        (non-blocking) before the task exists, so a CLI sync holding it is
        reported immediately instead of leaving a task waiting on it.
        """
        if self.syncing or self._sync_starting:
            raise TelegramServiceError("sync_in_progress")
        self._sync_starting = True
        try:
            if not self._installed():
                raise TelegramServiceError("telegram_not_installed")
            await asyncio.to_thread(self._memory_guard)
            value = await self._load_secrets(fresh=True)
            if value is None:
                raise TelegramServiceError("telegram_not_configured")
            if value.session is None:
                raise TelegramServiceError("telegram_not_logged_in")
            store = self._archive(value)
            lock = store.locked()
            lock.__enter__()
            self._last_error = None
            self._progress = SyncProgress(started_at=int(time.time()))
            chosen = options if options is not None else self.sync_options()
            self._sync_task = asyncio.create_task(self._run_sync(value, store, lock, chosen))
        finally:
            self._sync_starting = False

    async def wait_for_sync(self) -> None:
        if self._sync_task is not None:
            with contextlib.suppress(Exception):
                await self._sync_task

    async def _run_sync(self, value: TelegramSecrets, store: ArchiveStore, lock: Any, options: SyncOptions) -> None:
        client: Any = None
        try:
            # Built on the loop thread: Telethon binds a client to its loop.
            client = self._client_factory(value.api_id, value.api_hash, value.session, policy=RequestPolicy())
            await client.connect()
            if not await client.is_user_authorized():
                raise TelegramServiceError("telegram_session_revoked")

            def on_progress(state: SyncProgress) -> None:
                self._progress = state

            result = await sync_archive(client, store, options=options, progress=on_progress)
            self._progress = result
            self._remember_summary(await asyncio.to_thread(store.load_index))
            _audit(
                "telegram.sync",
                "allow",
                dialogs=result.dialogs_done,
                messages=result.messages_imported,
            )
        except asyncio.CancelledError:
            self._last_error = "sync_cancelled"
            raise
        except Exception as exc:
            code = error_code(exc, "telegram_sync_failed")
            self._last_error = code
            if code == "telegram_sync_failed":
                # Type name only: an exception message or traceback locals
                # could carry message text.
                _log.warning("telegram sync failed (%s)", type(exc).__name__)
            _audit("telegram.sync", "raise", code=code)
        finally:
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.disconnect()
            lock.__exit__(None, None, None)
            self._progress.finished_at = int(time.time())

    async def cancel_sync(self) -> None:
        task = self._sync_task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    # -- questions --------------------------------------------------------------

    @staticmethod
    def _target(value: TelegramSecrets) -> LlmTarget:
        """Venice (fixed URL, private models) or a loopback model — nothing else."""
        return resolve_target(
            value.backend,
            venice_api_key=value.venice_api_key,
            venice_model=value.venice_model or os.environ.get(venice.MODEL_ENV) or venice.DEFAULT_MODEL,
            local_endpoint=value.local_endpoint,
            local_model=value.local_model,
        )

    async def ask(self, request: AskRequest, on_meta: Callable[[AskResult], None]) -> AsyncIterator[str]:
        """Stream the answer; *on_meta* is called once before the first chunk."""
        question = validate_question(request.question)
        await asyncio.to_thread(self._memory_guard)
        # A fresh Enclave unwrap for every question; nothing is cached.
        value = await self._load_secrets(fresh=True)
        if value is None:
            raise TelegramServiceError("telegram_not_configured")
        target = self._target(value)
        store = self._archive(value)
        del value
        cfg = target.config
        await asyncio.to_thread(self._policy_check, target.backend, cfg.base_url)
        if target.backend == "venice":
            route = await asyncio.to_thread(self._route_resolver, _VENICE_HOST)
        else:
            # Loopback only (validated in .llm): never through a proxy.
            route = EgressRoute(None, None)
        raw_session = self._http_session_factory(route, _ASK_TIMEOUT_SECONDS)
        try:
            session = _ProxiedSession(raw_session, route.http_proxy_url)
            if target.backend == "venice":
                context_tokens = (await venice.require_private_model(session, cfg)).context_tokens
            else:
                context_tokens = DEFAULT_LOCAL_CONTEXT_TOKENS
            index = await asyncio.to_thread(store.load_index)
            if not index.dialogs:
                raise TelegramServiceError("archive_empty")
            aliases = Aliases(enabled=request.pseudonymize)
            selection = await asyncio.to_thread(
                select_context, store, index, request, aliases, budget_tokens=budget_for(context_tokens)
            )
            if selection.message_count == 0:
                raise TelegramServiceError("no_matching_messages")
            on_meta(
                AskResult(
                    model=cfg.model,
                    message_count=selection.message_count,
                    dialog_count=selection.dialog_count,
                    truncated=selection.truncated,
                    mode=selection.mode,
                    candidates=selection.candidates,
                    chats_searched=selection.chats_searched,
                )
            )
            _audit(
                "telegram.ask",
                "allow",
                backend=target.backend,
                model=cfg.model,
                messages=selection.message_count,
                dialogs=selection.dialog_count,
                pseudonymized=request.pseudonymize,
            )
            prompt = build_messages(question, selection, request=request, last_sync=index.last_sync)
            chunks = venice.stream_chat(session, cfg, prompt, max_tokens=ANSWER_TOKENS, backend=target.backend)
            produced = False
            async with contextlib.aclosing(chunks), contextlib.aclosing(dealias_stream(chunks, aliases)) as answer:
                async for text in _without_thinking(answer):
                    produced = produced or bool(text.strip())
                    yield text
            if not produced:
                # Never hand back a silent empty answer as if it were one.
                raise AskError("llm_empty_answer")
        finally:
            with contextlib.suppress(Exception):
                await raw_session.close()
