"""Mordred setup API for the Hermes Desktop plugin (``/api/plugins/mordred/...``).

The desktop half (``desktop/plugin.js``) collects secrets in masked dialogs
and sends them here with ``ctx.rest``: straight to this Python process, never
through the agent, the model, or the chat. This module:

- validates every body by hand (no pydantic models: a 422 would echo the
  secret back), never logs a body, and answers with stable error codes only;
- seals everything with the Secure Enclave (:mod:`..extension.telegram.tee`)
  or the Mordred file vault, and returns only non-secret status — with one
  deliberate exception: a freshly generated vault recovery passphrase is
  returned exactly once, to be shown to the user and written down;
- runs long work (building the Enclave helper, importing messages) as jobs
  and reports progress with plugin events plus a poll endpoint.

Served by Hermes' dashboard server, which requires the per-process session
token on every ``/api`` request and binds to loopback only.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

_log = logging.getLogger(__name__)
router = APIRouter()
PLUGIN_ID = "mordred"


# -- helpers ------------------------------------------------------------------------


def _error(code: str, status: int = 200) -> JSONResponse:
    """Expected failures answer 200 + ``ok: false``: a non-2xx is logged by Desktop.

    The body is only ever a code, never an echo of what was sent.
    """
    del status
    return JSONResponse({"ok": False, "error": code}, status_code=200)


def _code(exc: BaseException, fallback: str) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code else fallback


def _emit(event: str, payload: dict[str, Any]) -> None:
    with contextlib.suppress(Exception):
        from hermes_cli.plugin_events import broadcast_plugin_event

        broadcast_plugin_event(PLUGIN_ID, event, payload)


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _store() -> Any:
    from ..extension.telegram.tee import TeeSecretStore

    return TeeSecretStore()


@dataclass
class _Job:
    job_id: str
    kind: str
    state: str = "running"  # running | done | failed
    error: str | None = None
    progress: dict[str, Any] = field(default_factory=dict)
    started: float = field(default_factory=time.time)


_JOBS: dict[str, _Job] = {}


def _start_job(kind: str, work: Any) -> _Job:
    for job in _JOBS.values():
        if job.kind == kind and job.state == "running":
            return job
    job = _Job(secrets.token_urlsafe(12), kind)
    _JOBS[job.job_id] = job

    async def run() -> None:
        try:
            await work(job)
            job.state = "done"
        except Exception as exc:
            job.state, job.error = "failed", _code(exc, f"{kind}_failed")
            _log.warning("mordred desktop job %s failed (%s)", kind, type(exc).__name__)
        _emit("job", {"job_id": job.job_id, "kind": kind, "state": job.state, "error": job.error})

    asyncio.get_running_loop().create_task(run())
    return job


def _job_view(job: _Job) -> dict[str, Any]:
    return {"job_id": job.job_id, "kind": job.kind, "state": job.state, "error": job.error, "progress": job.progress}


# -- Hermes' own chat model ------------------------------------------------------------

_MODEL_CACHE: dict[str, Any] = {}
_MODEL_TTL = 600.0


async def hermes_model_check() -> dict[str, Any]:
    """Is the model Hermes chats with private (Venice ``private``) or local?

    Everything the agent reads goes to this model, so Telegram stays locked
    until it is. Venice privacy comes from its public model catalog (no key).
    """
    from ..extension.telegram import venice
    from ..extension.telegram.hermes_tools import _classify_endpoint, _configured_model

    model, base_url = await asyncio.to_thread(_configured_model)
    kind = _classify_endpoint(base_url)
    result: dict[str, Any] = {"model": model, "kind": kind or "other", "private": None, "ok": False}
    if kind == "local" and model:
        result.update(private=True, ok=True)
        return result
    if kind != "venice" or not model:
        return result
    cached = _MODEL_CACHE.get(model)
    if cached is not None and time.monotonic() - cached[0] < _MODEL_TTL:
        result.update(private=cached[1], ok=cached[1] is True)
        return result
    try:
        from ..extension.egress import resolve_route
        from ..extension.telegram.service import _default_http_session, _ProxiedSession

        route = await asyncio.to_thread(resolve_route, "api.venice.ai")
        raw = _default_http_session(route, 20.0)
        try:
            cfg = venice.VeniceConfig(api_key="", model=model)
            await venice.require_private_model(_ProxiedSession(raw, route.http_proxy_url), cfg)
            private: bool | None = True
        except venice.VeniceError as exc:
            private = False if exc.code in {"venice_model_not_private", "venice_model_unknown"} else None
        finally:
            await raw.close()
    except Exception:
        private = None  # could not verify (offline?): stay locked, let the UI retry
    if private is not None:
        _MODEL_CACHE[model] = (time.monotonic(), private)
    result.update(private=private, ok=private is True)
    return result


async def _require_hermes_model() -> JSONResponse | None:
    check = await hermes_model_check()
    return None if check["ok"] else _error("hermes_model_not_private")


# -- status -------------------------------------------------------------------------


@router.get("/status")
async def status(client_version: int = 1) -> dict[str, Any]:
    """Setup progress from metadata only (no Touch ID, no secrets, no content)."""
    platform_status = {
        "platform": sys.platform,
        "telegram_supported": sys.platform == "darwin" or (sys.platform == "linux" and client_version >= 2),
        "telegram_platform_supported": sys.platform in ("darwin", "linux"),
        "hardware_kind": {"darwin": "secure_enclave", "linux": "tpm"}.get(sys.platform),
        "user_presence_supported": sys.platform == "darwin",
    }
    jobs = [_job_view(j) for j in _JOBS.values() if j.state == "running"]
    if not platform_status["telegram_supported"]:
        return {"ok": True, **platform_status, "checks": {}, "jobs": jobs}

    from ..wizard.telegram_setup_cli import run_checks

    checks = await asyncio.to_thread(run_checks)
    return {
        "ok": True,
        **platform_status,
        "hermes_model": await hermes_model_check(),
        "checks": {c.name: {"ok": c.ok, "detail": c.detail} for c in checks},
        "hermes_venice_key": _hermes_venice_key() is not None,
        "telegram_api": bool((await asyncio.to_thread(_store().flags) or {}).get("api_configured")),
        "jobs": jobs,
    }


@router.get("/jobs/{job_id}")
async def job_status(job_id: str) -> Any:
    job = _JOBS.get(job_id)
    return {"ok": True, **_job_view(job)} if job else _error("job_not_found", 404)


# -- step 1: Secure Enclave ---------------------------------------------------------------


@router.post("/hardware/build")
async def hardware_build() -> Any:
    if sys.platform == "darwin":
        return await enclave_build()
    if sys.platform != "linux":
        return _error("telegram_platform_unsupported")

    async def work(job: _Job) -> None:
        from ..wizard.keyvault_native_cli import enable_tpm

        job.progress = {"message": "Building and probing the TPM 2.0 helper…"}
        _emit("progress", {"job_id": job.job_id, **job.progress})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = await asyncio.to_thread(enable_tpm)
        if rc != 0:
            raise _Fail("tpm_build_failed")

    return {"ok": True, **_job_view(_start_job("hardware", work))}


@router.post("/enclave/build")
async def enclave_build() -> Any:
    if sys.platform != "darwin":
        return _error("telegram_platform_unsupported")

    async def work(job: _Job) -> None:
        from ..wizard.keyvault_native_cli import enable_se

        job.progress = {"message": "Building the Secure Enclave helper (a few minutes)…"}
        _emit("progress", {"job_id": job.job_id, **job.progress})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = await asyncio.to_thread(enable_se)
        if rc != 0:
            raise _Fail("enclave_build_failed")

    return {"ok": True, **_job_view(_start_job("enclave", work))}


class _Fail(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# -- step 2: vault + memory encryption --------------------------------------------------


def generate_recovery_passphrase(words: int = 8) -> str:
    """Eight random words from the BIP-39 list (~88 bits)."""
    from ..keyvault._bip39 import _load_wordlist

    wordlist = _load_wordlist()
    return " ".join(secrets.choice(wordlist) for _ in range(words))


class _FixedPassphrase:
    """PromptIO that answers every passphrase prompt with one generated value."""

    def __init__(self, passphrase: str) -> None:
        self._passphrase = passphrase
        self.used = False

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        self.used = True
        return self._passphrase

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return default

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default

    def ask_choice(self, label: str, choices: Any, default: Any = None, **_: Any) -> Any:
        return default if default is not None else choices[0]

    def ask_multi(self, label: str, choices: Any, default: Any = ()) -> tuple[str, ...]:
        return tuple(default)


@router.post("/memory/enable")
async def memory_enable(body: dict[str, Any] | None = None) -> Any:
    """Turn on sealed .env + sealed memory; create the vault if needed.

    If a vault is created here, its recovery passphrase is generated and
    returned ONCE so the UI can show it. It is not stored anywhere else.

    Optional body ``{"unattended": true|false}`` sets the policy of the vault's
    device key if this call creates it. Absent, it matches ``hermes-mordred
    setup``'s default: ``MORDRED_SEKEY_UNATTENDED=1`` makes it unattended,
    otherwise it is attended (Touch ID / password on each use). Both steps run
    in one flow, so the vault is unlocked at most once (not at all when it is
    created here).
    """
    if sys.platform not in ("darwin", "linux"):
        return _error("telegram_platform_unsupported")

    if sys.platform == "linux" and (body or {}).get("acknowledge_tpm_no_recovery") is not True:
        return _error("telegram_platform_unsupported")

    from ..extension.telegram.memory_guard import memory_encryption_active
    from ..wizard import env_decrypt_cli, memory_cli
    from ..wizard._flow_session import FlowSession
    from ..wizard.vault_cli import _resolve_root

    if await asyncio.to_thread(memory_encryption_active):
        return {"ok": True, "already": True}
    if sys.platform == "linux":
        return await _linux_memory_enable()
    requested = (body or {}).get("unattended")
    unattended = requested if isinstance(requested, bool) else None
    prompt = _FixedPassphrase(generate_recovery_passphrase())
    home, root, platform = _home(), _resolve_root(None), sys.platform

    def enable() -> int:
        with (
            FlowSession(unattended=unattended) as flow,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            rc = env_decrypt_cli.enable(home=home, root=root, platform=platform, prompt_io=prompt, flow_session=flow)
            if rc == 0:
                rc = memory_cli.enable(home=home, root=root, platform=platform, prompt_io=prompt, flow_session=flow)
        return rc

    rc = await asyncio.to_thread(enable)
    if rc != 0 or not await asyncio.to_thread(memory_encryption_active):
        return _error("memory_encryption_failed", 500)
    result: dict[str, Any] = {"ok": True, "restart_required": True}
    if prompt.used:
        result["recovery_passphrase"] = prompt._passphrase  # shown once; never persisted by Mordred
    return result


async def _linux_memory_enable() -> Any:
    from ..extension.telegram.memory_guard import memory_encryption_active
    from ..wizard import memory_cli
    from ..wizard.vault_cli import _resolve_root

    def enable_linux() -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return memory_cli.enable(home=_home(), root=_resolve_root(None), platform="linux")

    rc = await asyncio.to_thread(enable_linux)
    if rc != 0 or not await asyncio.to_thread(memory_encryption_active):
        return _error("memory_encryption_failed", 500)
    return {"ok": True, "restart_required": True}


# -- step 3/4: Telegram API credentials and login -----------------------------------------------

_FLOWS: Any = None


def _flows() -> Any:
    global _FLOWS
    if _FLOWS is None:
        from ..extension.telegram.login_flow import LoginFlows

        _FLOWS = LoginFlows(_store())
    return _FLOWS


async def _require_memory() -> JSONResponse | None:
    from ..extension.telegram.memory_guard import memory_encryption_active

    ok = await asyncio.to_thread(memory_encryption_active)
    return None if ok else _error("memory_encryption_required", 409)


@router.post("/telegram/login/start")
async def telegram_login_start(body: dict[str, Any]) -> Any:
    """Body: {"phone", and on first setup "api_id", "api_hash"}."""
    blocked = await _require_memory() or await _require_hermes_model()
    if blocked is not None:
        return blocked
    from ..extension.telegram.login_flow import LoginError

    try:
        flow = await _flows().start(api_id=body.get("api_id"), api_hash=body.get("api_hash"), phone=body.get("phone"))
    except LoginError as exc:
        return _error(exc.code)
    except Exception as exc:
        return _error(_code(exc, "telegram_login_failed"), 500)
    return {"ok": True, "flow_id": flow.flow_id, "step": flow.step}


@router.post("/telegram/login/{flow_id}/code")
async def telegram_login_code(flow_id: str, body: dict[str, Any]) -> Any:
    from ..extension.telegram.login_flow import LoginError

    try:
        step = await _flows().submit_code(flow_id, body.get("code"))
    except LoginError as exc:
        return _error(exc.code)
    except Exception as exc:
        return _error(_code(exc, "telegram_login_failed"), 500)
    return {"ok": True, "step": step}


@router.post("/telegram/login/{flow_id}/password")
async def telegram_login_password(flow_id: str, body: dict[str, Any]) -> Any:
    from ..extension.telegram.login_flow import LoginError

    try:
        step = await _flows().submit_password(flow_id, body.get("password"))
    except LoginError as exc:
        return _error(exc.code)
    except Exception as exc:
        return _error(_code(exc, "telegram_login_failed"), 500)
    return {"ok": True, "step": step}


@router.post("/telegram/login/{flow_id}/cancel")
async def telegram_login_cancel(flow_id: str) -> Any:
    await _flows().cancel(flow_id)
    return {"ok": True}


# -- step 5: privacy LLM --------------------------------------------------------------------------


def _hermes_venice_key() -> str | None:
    """The Venice key Hermes itself is configured with (never returned to the UI)."""
    import os

    from dotenv import dotenv_values

    from .._yaml_io import load_yaml_mapping

    config = load_yaml_mapping(_home() / "config.yaml")
    names: list[str] = []
    entries: list[Any] = [config.get("model")]
    providers = config.get("custom_providers")
    if isinstance(providers, list):
        entries.extend(providers)
    for entry in entries:
        if isinstance(entry, dict) and "api.venice.ai" in str(entry.get("base_url", "")):
            name = entry.get("key_env")
            if isinstance(name, str) and name:
                names.append(name)
    names.append("VENICE_API_KEY")
    file_values = dotenv_values(_home() / ".env") if (_home() / ".env").is_file() else {}
    for name in dict.fromkeys(names):
        value = os.environ.get(name) or file_values.get(name)
        if value and value.strip():
            return value.strip()
    return None


def _set_venice(api_key: str, model: str | None) -> None:
    from dataclasses import replace

    from ..extension.telegram.secrets import empty_secrets

    store = _store()
    store.ensure_key()

    def mutate(old: Any) -> Any:
        base = old if old is not None else empty_secrets()
        return replace(base, venice_api_key=api_key, venice_model=model or base.venice_model, backend="venice")

    store.update(mutate)


@router.post("/llm/venice")
async def llm_venice(body: dict[str, Any]) -> Any:
    """Body: {"use_hermes_key": true} or {"api_key": "..."}; optional "model"."""
    model = body.get("model")
    if model is not None and (not isinstance(model, str) or not model.strip() or len(model) > 128):
        return _error("invalid_request")
    if body.get("use_hermes_key") is True:
        key = await asyncio.to_thread(_hermes_venice_key)
        if key is None:
            return _error("hermes_venice_key_missing", 404)
    else:
        raw = body.get("api_key")
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 512:
            return _error("invalid_request")
        key = raw.strip()
    try:
        await asyncio.to_thread(_set_venice, key, model.strip() if isinstance(model, str) else None)
    except Exception as exc:
        return _error(_code(exc, "llm_config_failed"), 500)
    return {"ok": True}


@router.post("/llm/local")
async def llm_local(body: dict[str, Any]) -> Any:
    from ..extension.telegram.llm import LlmConfigError, normalize_local_endpoint

    endpoint, model = body.get("endpoint"), body.get("model")
    if not isinstance(endpoint, str) or not isinstance(model, str) or not model.strip():
        return _error("invalid_request")
    try:
        canonical = normalize_local_endpoint(endpoint)
    except LlmConfigError as exc:
        return _error(exc.code)
    from dataclasses import replace

    from ..extension.telegram.secrets import empty_secrets

    def mutate(old: Any) -> Any:
        base = old if old is not None else empty_secrets()
        return replace(base, backend="local", local_endpoint=canonical, local_model=model.strip())

    def save() -> None:
        store = _store()
        store.ensure_key()
        store.update(mutate)

    try:
        await asyncio.to_thread(save)
    except Exception as exc:
        return _error(_code(exc, "llm_config_failed"), 500)
    return {"ok": True, "endpoint": canonical}


# -- step 6: import ------------------------------------------------------------------------------------

_SERVICE: Any = None


def _service() -> Any:
    global _SERVICE
    if _SERVICE is None:
        from ..extension.telegram.service import TelegramService

        _SERVICE = TelegramService()
    return _SERVICE


@router.post("/sync")
async def sync(body: dict[str, Any]) -> Any:
    """Body (all optional): days, include_archived, include_channels, include_large_groups."""
    days = body.get("days")
    if days is not None and (not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650):
        return _error("invalid_request")
    overrides = {
        "since_days": days,
        "include_archived": body.get("include_archived") if isinstance(body.get("include_archived"), bool) else None,
        "include_channels": body.get("include_channels") if isinstance(body.get("include_channels"), bool) else None,
        "max_group_size": 0 if body.get("include_large_groups") is True else None,
    }
    svc = _service()
    try:
        options = svc.sync_options(overrides)
        await svc.start_sync(options)
    except Exception as exc:
        from ..extension.telegram.service import error_code

        return _error(error_code(exc, "telegram_sync_failed"), 409)
    return {"ok": True}


@router.get("/sync")
async def sync_status() -> Any:
    status = await _service().status()
    return {
        "ok": True,
        "syncing": status["syncing"],
        "progress": status["progress"],
        "last_error": status["last_error"],
        "dialog_count": status["dialog_count"],
        "message_count": status["message_count"],
    }


# -- uninstall ----------------------------------------------------------------------------


class _UninstallAnswers(_FixedPassphrase):
    """Answers ``hermes-mordred uninstall``'s prompts with what the page collected.

    The page's own confirmation replaces the yes/no question; the typed
    ``delete my data`` phrase (``--purge-data`` only) and the vault recovery
    passphrase (only if the device key cannot open the vault) come from the
    request body and are used once, in memory.
    """

    def __init__(self, recovery_passphrase: str, purge_phrase: str) -> None:
        super().__init__(recovery_passphrase)
        self._purge_phrase = purge_phrase

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return True

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return self._purge_phrase


def _uninstall_context(prompt: Any = None) -> Any:
    from ..keyvault._identity import resolve_root
    from ..wizard.uninstall_cli import UninstallContext

    return UninstallContext(
        home=_home(), vault_root=resolve_root(None), user_home=Path.home(), prompt_io=prompt, interactive=False
    )


@router.get("/uninstall/plan")
async def uninstall_plan() -> Any:
    """What uninstalling would do (the dry run), for the page to show before confirming."""
    from ..wizard.uninstall_cli import UninstallOptions, run_uninstall

    def plan(purge: bool, erase: bool = False) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            run_uninstall(_uninstall_context(), UninstallOptions(dry_run=True, purge_data=purge, erase_encrypted=erase))
        return out.getvalue()

    keep, purge, erase = await asyncio.gather(
        asyncio.to_thread(plan, False), asyncio.to_thread(plan, True), asyncio.to_thread(plan, True, True)
    )
    return {"ok": True, "plan": keep, "plan_purge": purge, "plan_erase": erase}


@router.post("/uninstall")
async def uninstall(body: dict[str, Any] | None = None) -> Any:
    """Body: ``{"mode": "decrypt" | "erase", "purge_data": bool, "confirm": str, "recovery_passphrase"?: str}``.

    ``decrypt`` (default) restores every encrypted target to plaintext, removes
    Mordred from Hermes and uninstalls the package; ``purge_data`` also
    deletes Mordred's data and keys. ``erase`` does not decrypt anything: the
    encrypted data is deleted as it is, together with all Mordred data.
    Deleting anything needs ``confirm`` = ``delete my data``. Runs as a job;
    ``progress.summary`` carries the report.
    """
    from ..wizard.uninstall_cli import PURGE_PHRASE, UninstallOptions, run_uninstall

    body = body or {}
    erase = body.get("mode") == "erase"
    purge = erase or body.get("purge_data") is True
    phrase = str(body.get("confirm") or "")
    if purge and phrase.strip() != PURGE_PHRASE:
        return _error("uninstall_confirm_mismatch")
    prompt = _UninstallAnswers(str(body.get("recovery_passphrase") or ""), phrase)

    async def work(job: _Job) -> None:
        out = io.StringIO()

        def run() -> int:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                return run_uninstall(
                    _uninstall_context(prompt), UninstallOptions(yes=True, purge_data=purge, erase_encrypted=erase)
                )

        rc = await asyncio.to_thread(run)
        job.progress = {"summary": out.getvalue()}
        if rc != 0:
            raise _Fail("uninstall_failed")

    return {"ok": True, **_job_view(_start_job("uninstall", work))}
