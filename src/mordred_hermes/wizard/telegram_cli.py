"""``hermes-mordred telegram`` — read-only import of the operator's own account.

Subcommands:

- ``login``  — store the my.telegram.org API credentials and create a user
  session (phone code, then the 2FA password if the account has one). The
  password is read with ``getpass`` and never stored; the resulting session is
  sealed in the keyvault file vault (``telegram.json``), never in ``.env``.
- ``sync``   — import every dialog's new messages into the encrypted archive.
- ``status`` — show login state and archive counts.
- ``logout`` — revoke the session at Telegram and drop it from the vault;
  ``--forget`` also deletes the API credentials, the archive key, and the
  archive files.
- ``venice`` — store the Venice.ai API key (read with ``getpass``) and the
  model used for questions.

Everything that talks to Telegram goes through the allowlist-guarded client
in :mod:`mordred_hermes.extension.telegram.client`; login is the only time the
auth requests are unlocked.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import os
import sys
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from . import _term

InputFn = Callable[[str], str]

# Optional one-time source for `telegram login`; the values are then sealed in
# the vault and the variables are no longer needed.
API_ID_ENV = "TELEGRAM_MORDRED_APP_ID"
API_HASH_ENV = "TELEGRAM_MORDRED_APP_HASH"


def _load_for_update(secrets_store: Any) -> tuple[Any, Any]:
    """Unseal once and return ``(value, snapshot)`` for :func:`_write_back`.

    With the Enclave store the snapshot lets the later write skip a second
    unseal (a second Touch ID / password dialog); other stores just return the
    loaded value and are written back through a plain ``update``.
    """
    load_snapshot = getattr(secrets_store, "load_snapshot", None)
    if load_snapshot is not None:
        snapshot = load_snapshot()
        return snapshot[0], snapshot
    return secrets_store.load(fresh=True), None


def _write_back(secrets_store: Any, snapshot: Any, mutate: Callable[[Any], Any]) -> None:
    """Apply ``mutate`` to the value :func:`_load_for_update` read, without unsealing again."""
    if snapshot is not None:
        secrets_store.update_from_snapshot(snapshot, mutate)
    else:
        secrets_store.update(mutate)


def _secret_store() -> Any:
    from ..extension.telegram.tee import TeeSecretStore

    return TeeSecretStore()


def _report(code: str) -> int:
    hardware = "TPM" if sys.platform == "linux" else "Secure Enclave"
    setup = "enable-tpm" if sys.platform == "linux" else "enable-se"
    memory_setup = (
        "`hermes-mordred encryption enable memory`"
        if sys.platform == "linux"
        else "`hermes-mordred encryption enable env` and `hermes-mordred encryption enable memory`"
    )
    messages = {
        "vault_not_initialized": "no keyvault file vault exists. Run `hermes-mordred vault init` first: the Telegram "
        "session is an account credential and is only ever stored sealed in the vault.",
        "vault_unavailable": "the keyvault file vault could not be opened (see `hermes-mordred vault status`).",
        "telegram_not_installed": "Telethon is not installed. "
        "Install the extra: pip install 'hermes-mordred[telegram]'",
        "telegram_not_configured": "Telegram is not configured. Run `hermes-mordred telegram login` first.",
        "telegram_not_logged_in": "no Telegram session. Run `hermes-mordred telegram login` first.",
        "telegram_session_revoked": "the Telegram session was revoked (terminated from another device?). "
        "Run `hermes-mordred telegram login` again.",
        "telegram_rate_limited": "Telegram asked us to slow down (FloodWait). "
        "Try again later; progress so far is kept.",
        "routing_unavailable": "the selected network route (Tor/VPN) is not available, so nothing was sent.",
        "invalid_api_credentials": "api_id must be a number and api_hash a 32-character hex string "
        "(from https://my.telegram.org → API development tools).",
        "sync_in_progress": "another sync is already running.",
        "tee_unavailable": f"the {hardware} helper is not available. Run `hermes-mordred keyvault {setup}` "
        "first: Telegram credentials require hardware sealing (no software fallback).",
        "tee_auth_cancelled": "Touch ID / passcode was cancelled, so the credentials stayed sealed.",
        "local_endpoint_invalid": "the local model endpoint must be http(s)://127.0.0.1:<port>/... or "
        "http(s)://[::1]:<port>/... (loopback only, with an explicit port).",
        "memory_encryption_required": "Telegram needs agent-memory encryption on, so nothing Hermes remembers "
        f"about your chats is stored in plaintext. Run {memory_setup}, restart Hermes, then try again "
        "(`hermes-mordred telegram setup` does this for you).",
        "no_legacy_credentials": "there are no vault-stored Telegram credentials to migrate.",
        "telegram_already_logged_in": "a Telegram session is already stored. Run `hermes-mordred telegram logout` "
        "first so the old session is revoked instead of being left behind.",
    }
    _term.emit_error(messages.get(code, f"telegram operation failed ({code})."))
    return 1


# -- login ---------------------------------------------------------------------


def _read_api_credentials(input_fn: InputFn, secret_fn: InputFn) -> tuple[int, str]:
    from ..extension.telegram.secrets import validate_api_credentials

    env_id = os.environ.get(API_ID_ENV, "").strip()
    env_hash = os.environ.get(API_HASH_ENV, "").strip()
    if env_id and env_hash:
        print(f"Using api_id / api_hash from {API_ID_ENV} / {API_HASH_ENV}.")
        return validate_api_credentials(env_id, env_hash)
    print("Create an application at https://my.telegram.org → API development tools.")
    api_id = input_fn("api_id: ").strip()
    api_hash = secret_fn("api_hash (hidden): ").strip()
    return validate_api_credentials(api_id, api_hash)


async def _interactive_sign_in(client: Any, input_fn: InputFn, secret_fn: InputFn) -> Any:
    await client.connect()
    phone = input_fn("Phone number (international format, e.g. +81…): ").strip()
    await client.send_code_request(phone)
    code = input_fn("Login code sent by Telegram: ").strip()
    try:
        return await client.sign_in(phone=phone, code=code)
    except Exception as exc:
        if type(exc).__name__ != "SessionPasswordNeededError":
            raise
    password = secret_fn("Two-step verification password (hidden, not stored): ")
    return await client.sign_in(password=password)


def telegram_login(
    *,
    input_fn: InputFn = input,
    secret_fn: InputFn = getpass.getpass,
    store: Any = None,
    client_factory: Callable[..., Any] | None = None,
    require_presence: bool = True,
) -> int:
    from ..extension.telegram.client import TelegramClientError, build_client, save_session, telethon_available
    from ..extension.telegram.readonly import RequestPolicy
    from ..extension.telegram.secrets import TelegramSecretsError
    from ..extension.telegram.service import error_code

    factory = client_factory or build_client
    problem = None if client_factory is not None else _login_preflight(telethon_available)
    if problem is not None:
        return _report(problem)
    secrets_store = store if store is not None else _secret_store()
    try:
        current, snapshot = _load_for_update(secrets_store)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    if current is not None and current.session is not None:
        return _report("telegram_already_logged_in")
    try:
        if current is None or not current.has_api:
            fresh = _new_credentials(secrets_store, input_fn, secret_fn, require_presence)
            base = fresh if current is None else replace(current, api_id=fresh.api_id, api_hash=fresh.api_hash)
        else:
            base = current
            print(f"Using the stored API application (api_id {base.api_id}).")
        policy = RequestPolicy(login=True)
        me, session = asyncio.run(
            _login_and_disconnect(
                lambda: factory(base.api_id, base.api_hash, None, policy=policy),
                input_fn,
                secret_fn,
                save_session,
                policy,
            )
        )
    except (TelegramSecretsError, TelegramClientError) as exc:
        return _report(exc.code)
    except Exception as exc:
        return _report(error_code(exc, "telegram_login_failed"))
    if me is None:
        return _report("telegram_login_failed")
    try:
        _persist(secrets_store, replace(base, session=session), fresh=current is None, snapshot=snapshot)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    print("Logged in. The session is sealed by device hardware (credentials.sealed).")
    print(
        "Telegram will show a new-login notice on your other devices. Keep Two-Step Verification enabled; "
        "revoke this session any time with `hermes-mordred telegram logout` or Settings → Devices."
    )
    return 0


def _login_preflight(telethon_available: Callable[[], bool]) -> str | None:
    """Refuse before any code is sent: Telethon missing, or memory not encrypted."""
    if not telethon_available():
        return "telegram_not_installed"
    from ..extension.telegram.memory_guard import memory_encryption_active

    return None if memory_encryption_active() else "memory_encryption_required"


def _new_credentials(secrets_store: Any, input_fn: InputFn, secret_fn: InputFn, require_presence: bool) -> Any:
    from ..extension.telegram.secrets import TelegramSecrets, new_store_key

    if _orphaned_archive_present():
        # Its key went with the old credentials, so it can never be decrypted
        # again; a fresh key would otherwise fail on it.
        from ..extension.telegram.store import wipe_archive

        wipe_archive()
        _term.emit_warn("removed an undecryptable archive left by a previous setup.")
    api_id, api_hash = _read_api_credentials(input_fn, secret_fn)
    # Fail before any login code is sent if the Enclave cannot seal the result.
    ensure = getattr(secrets_store, "ensure_key", None)
    if ensure is not None:
        ensure(require_presence=require_presence)
    return TelegramSecrets(api_id=api_id, api_hash=api_hash, store_key=new_store_key())


def _persist(secrets_store: Any, value: Any, *, fresh: bool, snapshot: Any = None) -> None:
    if fresh and hasattr(secrets_store, "store"):
        secrets_store.store(value)  # nothing to unseal yet
    else:
        # Reuse the unseal done at the start of the login: no second Touch ID.
        _write_back(secrets_store, snapshot, lambda _old: value)


async def _login_and_disconnect(
    make_client: Callable[[], Any],
    input_fn: InputFn,
    secret_fn: InputFn,
    save: Callable[[Any], str],
    policy: Any,
) -> tuple[Any, str]:
    # Built inside the running loop: Telethon binds a client to its loop.
    client = make_client()
    try:
        me = await _interactive_sign_in(client, input_fn, secret_fn)
        return me, save(client)
    except BaseException:
        # If Telegram already accepted the sign-in, the new authorization would
        # otherwise stay on the account with no stored session to revoke it.
        with contextlib.suppress(Exception):
            if getattr(client, "_authorized", False):
                policy.logout = True
                await client.log_out()
        raise
    finally:
        with contextlib.suppress(Exception):
            await client.disconnect()


def _orphaned_archive_present() -> bool:
    from ..extension.telegram.store import telegram_dir

    base = telegram_dir()
    return base.is_dir() and not base.is_symlink() and any(base.rglob("*.enc"))


# -- sync / status ---------------------------------------------------------------


def _progress_line(progress: dict[str, Any]) -> str:
    return (
        f"dialogs {progress.get('dialogs_done', 0)}/{progress.get('dialogs_total', 0)}, "
        f"messages imported {progress.get('messages_imported', 0)}"
    )


async def _run_sync(service: Any, options: Any, *, poll: float = 1.0) -> int:
    await service.start_sync(options)
    last = ""
    while service.syncing:
        await asyncio.sleep(poll)
        status = await service.status()
        line = _progress_line(status["progress"])
        if line != last:
            print(f"  {line}", flush=True)
            last = line
    await service.wait_for_sync()
    status = await service.status()
    if status["last_error"]:
        return _report(str(status["last_error"]))
    print(f"Done: {_progress_line(status['progress'])}. Archive: {status['message_count']} messages.")
    return 0


def telegram_sync(
    *,
    include_channels: bool | None = None,
    include_archived: bool | None = None,
    limit_per_dialog: int | None = None,
    since_days: int | None = None,
    max_group_size: int | None = None,
    everything: bool = False,
    service: Any = None,
) -> int:
    """Import new messages. Options given here are remembered for the next plain `sync`."""
    from ..extension.telegram.client import SyncOptions
    from ..extension.telegram.service import TelegramService, error_code

    svc = service if service is not None else TelegramService()
    given = {
        "include_channels": include_channels,
        "include_archived": include_archived,
        "limit_per_dialog": limit_per_dialog,
        "since_days": since_days,
        "max_group_size": max_group_size,
    }
    options = (
        SyncOptions(include_channels=True, include_archived=True, since_days=None, max_group_size=None)
        if everything
        else svc.sync_options(given)
    )
    explicit = everything or any(v is not None for v in given.values())
    save = getattr(getattr(svc, "_secrets", None), "save_sync_scope", None)
    if explicit and save is not None:
        with contextlib.suppress(Exception):
            save(
                {
                    "include_channels": options.include_channels,
                    "include_archived": options.include_archived,
                    "limit_per_dialog": options.limit_per_dialog,
                    "since_days": options.since_days or 0,  # 0 = all history
                    "max_group_size": options.max_group_size or 0,
                }
            )
    skipped = [
        name
        for name, keep in (("channels", options.include_channels), ("archived", options.include_archived))
        if not keep
    ]
    limit = f"; at most {options.limit_per_dialog} per new chat" if options.limit_per_dialog else ""
    window = f"; last {options.since_days} days only" if options.since_days else ""
    if options.max_group_size:
        window += f"; groups over {options.max_group_size} members skipped"
    print(f"Scope: pinned first, all chats{' except ' + ' and '.join(skipped) if skipped else ''}{window}{limit}.")
    try:
        return asyncio.run(_run_sync(svc, options))
    except Exception as exc:
        return _report(error_code(exc, "telegram_sync_failed"))


def telegram_status(*, service: Any = None, show_account: bool = False) -> int:
    from ..extension.telegram.service import TelegramService

    svc = service if service is not None else TelegramService()
    status = asyncio.run(svc.status())
    if status["last_error"] and not status["configured"]:
        return _report(str(status["last_error"]))
    print(f"Telethon installed: {'yes' if status['installed'] else 'no'}")
    print(f"Logged in: {'yes' if status['logged_in'] else 'no'}")
    if show_account and status["account_label"]:
        print(f"Account: {status['account_label']}")
    print(f"Dialogs: {status['dialog_count']}  Messages: {status['message_count']}")
    backend = status["llm_backend"]
    print(f"LLM: {backend} ({status['llm_model']})" if backend else "LLM: not configured")
    return 0


# -- logout / venice ---------------------------------------------------------------


async def _revoke(make_client: Callable[[], Any]) -> None:
    client = make_client()
    await client.connect()
    try:
        if await client.is_user_authorized():
            await client.log_out()
    finally:
        await client.disconnect()


def telegram_logout(
    *, forget: bool = False, store: Any = None, client_factory: Callable[..., Any] | None = None
) -> int:
    from ..extension.telegram.client import build_client
    from ..extension.telegram.readonly import RequestPolicy
    from ..extension.telegram.secrets import TelegramSecretsError
    from ..extension.telegram.store import wipe_archive

    secrets_store = store if store is not None else _secret_store()
    try:
        current, snapshot = _load_for_update(secrets_store)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    if current is None:
        print("Telegram is not configured; nothing to do.")
        return 0
    if current.session is not None:
        factory = client_factory or build_client
        try:
            asyncio.run(
                _revoke(
                    lambda: factory(
                        current.api_id, current.api_hash, current.session, policy=RequestPolicy(logout=True)
                    )
                )
            )
            print("Revoked the session at Telegram.")
        except Exception:
            _term.emit_warn(
                "could not reach Telegram to revoke the session; it is removed locally. "
                "Also terminate it in Telegram → Settings → Devices."
            )
    try:
        # One unseal for the whole command: the write reuses the value read above.
        if forget:
            _write_back(secrets_store, snapshot, lambda _old: None)
        else:
            _write_back(secrets_store, snapshot, lambda old: replace(old, session=None) if old is not None else None)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    if forget:
        wipe_archive()
        delete_key = getattr(secrets_store, "delete_key", None)
        if delete_key is not None:
            with contextlib.suppress(Exception):
                delete_key()
        print("Deleted the API credentials, the archive key, the hardware key, and the local archive.")
    else:
        print("Logged out. The encrypted archive is kept (use --forget to delete it).")
    return 0


def telegram_venice(*, model: str | None, secret_fn: InputFn = getpass.getpass, store: Any = None) -> int:
    from ..extension.telegram.secrets import TelegramSecretsError

    secrets_store = store if store is not None else _secret_store()
    key = secret_fn("Venice API key (hidden; Enter keeps the stored key): ").strip()

    class _NoKey(Exception):
        pass

    def mutate(old: Any) -> Any:
        # Decided on the value update() already unsealed, so the whole command
        # costs one Enclave unwrap (one Touch ID), not a load() plus an update().
        if not key and (old is None or old.venice_api_key is None):
            raise _NoKey
        return replace(
            old if old is not None else empty_secrets(),
            venice_api_key=key or (old.venice_api_key if old else None),
            venice_model=model if model else (old.venice_model if old else None),
            backend="venice",
        )

    try:
        from ..extension.telegram.secrets import empty_secrets

        ensure = getattr(secrets_store, "ensure_key", None)
        if ensure is not None:
            ensure()  # public-key lookup / key creation only: no unseal
        secrets_store.update(mutate)
    except _NoKey:
        _term.emit_error("no Venice API key given.")
        return 1
    except TelegramSecretsError as exc:
        return _report(exc.code)
    print("Sealed the Venice settings with device hardware. Only models Venice labels 'private' are used.")
    print(
        'Under llm_guard strict mode, allow it: set allow_cloud_llm to true and add "venice" to '
        "cloud_provider_allowlist in <home>/mordred/policy.json."
    )
    return 0


def telegram_local_llm(*, endpoint: str, model: str, store: Any = None) -> int:
    """Send questions to a model on THIS machine instead of Venice."""
    from ..extension.telegram.llm import LlmConfigError, normalize_local_endpoint
    from ..extension.telegram.secrets import TelegramSecretsError

    try:
        canonical = normalize_local_endpoint(endpoint)
    except LlmConfigError as exc:
        return _report(exc.code)
    if not model.strip():
        _term.emit_error("a model name is required.")
        return 1
    from ..extension.telegram.secrets import empty_secrets

    secrets_store = store if store is not None else _secret_store()
    try:
        ensure = getattr(secrets_store, "ensure_key", None)
        if ensure is not None:
            ensure()
        secrets_store.update(
            lambda old: replace(
                old if old is not None else empty_secrets(),
                backend="local",
                local_endpoint=canonical,
                local_model=model.strip(),
            )
        )
    except TelegramSecretsError as exc:
        return _report(exc.code)
    print(f"Questions now go only to the local model at {canonical} (never through a proxy).")
    return 0


def telegram_migrate_tee(*, require_presence: bool = True, store: Any = None, legacy: Any = None) -> int:
    """Move credentials from the software-keyed file vault into the Enclave seal."""
    from ..extension.telegram.secrets import VAULT_FILE, TelegramSecretsError, VaultSecretStore

    target = store if store is not None else _secret_store()
    source = legacy if legacy is not None else VaultSecretStore()
    try:
        value = source.load(fresh=True)
        if value is None:
            return _report("no_legacy_credentials")
        target.ensure_key(require_presence=require_presence)
        target.store(value)
        if target.load() != value:  # read back through the Enclave before deleting the old copy
            return _report("secrets_corrupt")
        source.update(lambda _old: None)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    print(f"Moved the Telegram credentials into the Secure Enclave seal and removed {VAULT_FILE} from the vault.")
    return 0


# -- argparse ------------------------------------------------------------------------


def cli_telegram(args: argparse.Namespace) -> int:
    from ..extension.telegram.hardening import harden_process

    harden_process()
    command = getattr(args, "telegram_command", None)
    if command in ("setup", "doctor"):
        from . import telegram_setup_cli

        return telegram_setup_cli.cli_setup(args) if command == "setup" else telegram_setup_cli.cli_doctor(args)
    if command == "login":
        return telegram_login(require_presence=not getattr(args, "no_touch_id", False))
    if command == "sync":
        return telegram_sync(
            include_channels=False if args.skip_channels else None,
            include_archived=True
            if getattr(args, "include_archived", False)
            else (False if args.skip_archived else None),
            limit_per_dialog=args.limit_per_dialog,
            since_days=getattr(args, "days", None),
            max_group_size=0
            if getattr(args, "include_large_groups", False)
            else getattr(args, "large_group_size", None),
            everything=bool(getattr(args, "all", False)),
        )
    if command == "status":
        return telegram_status(show_account=bool(getattr(args, "show_account", False)))
    if command == "logout":
        return telegram_logout(forget=bool(args.forget))
    if command == "venice":
        return telegram_venice(model=args.model)
    if command == "local-llm":
        return telegram_local_llm(endpoint=args.endpoint, model=args.model)
    if command == "migrate-tee":
        return telegram_migrate_tee(require_presence=not getattr(args, "no_touch_id", False))
    print(
        "usage: hermes-mordred telegram {setup,doctor,login,sync,status,logout,venice,local-llm,migrate-tee}",
        file=sys.stderr,
    )
    return 2


__all__ = [
    "cli_telegram",
    "telegram_local_llm",
    "telegram_login",
    "telegram_logout",
    "telegram_migrate_tee",
    "telegram_status",
    "telegram_sync",
    "telegram_venice",
]
