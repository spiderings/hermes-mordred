"""``hermes-mordred telegram setup`` and ``telegram doctor``.

``setup`` walks a first-time user through everything in one command: the
hardware key helper, the Telegram login, the privacy LLM (Venice or a local
model) and a first import with conservative defaults, then says how to use it
from Hermes Desktop and the browser extension.

``doctor`` reports health from metadata only. It never unseals the credentials
(no Touch ID), never decrypts the archive, and never prints the account name
or any chat title.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from . import _term

InputFn = Callable[[str], str]

RECOMMENDED_LIMIT = 500
DEFAULT_SINCE_DAYS = 3  # mirrors extension.telegram.client.DEFAULT_SINCE_DAYS (no Telethon import here)


# -- doctor ------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""


def _check_telethon() -> Check:
    from ..extension.telegram.client import telethon_available

    ok = telethon_available()
    return Check(
        "telethon", ok, "installed" if ok else "missing", "" if ok else "pip install 'hermes-mordred[telegram]'"
    )


def _check_enclave() -> Check:
    from ..extension.telegram.secrets import TelegramSecretsError
    from ..extension.telegram.tee import KEY_ID, hardware_backend

    try:
        backend = hardware_backend()
    except TelegramSecretsError:
        return Check("secure_enclave", False, "helper not installed", _hardware_fix())
    from ..keyvault import wrap
    from ..keyvault._exceptions import WrapError, WrapKeyNotFound

    try:
        wrap.get_wrapping_key_public(KEY_ID, backend=backend)  # public key only: no prompt
    except WrapKeyNotFound:
        return Check(
            "secure_enclave", True, "helper ready; Telegram key not created yet", "hermes-mordred telegram setup"
        )
    except WrapError:
        return Check("secure_enclave", False, "helper present but not working", _hardware_fix())
    return Check("secure_enclave", True, "helper ready; Telegram key present")


def _check_credentials(flags: dict[str, Any] | None) -> list[Check]:
    if flags is None:
        return [Check("login", False, "not configured", "hermes-mordred telegram setup")]
    checks = [
        Check(
            "login",
            flags.get("logged_in") is True,
            "logged in (credentials sealed by device hardware)" if flags.get("logged_in") else "logged out",
            "" if flags.get("logged_in") else "hermes-mordred telegram setup",
        )
    ]
    backend = flags.get("llm_backend")
    model = flags.get("llm_model")
    checks.append(
        Check(
            "privacy_llm",
            backend in ("venice", "local"),
            f"{backend} ({model})" if backend else "not configured",
            "" if backend else "hermes-mordred telegram venice   (or: telegram local-llm)",
        )
    )
    return checks


def _check_archive() -> Check:
    from ..extension.telegram.store import telegram_dir

    base = telegram_dir()
    if not (base / "index.enc").exists():
        return Check("archive", False, "nothing imported yet", "hermes-mordred telegram sync")
    segments = list((base / "dialogs").glob("*.enc")) if (base / "dialogs").is_dir() else []
    size = sum(p.stat().st_size for p in segments)
    ignored = (base / ".gitignore").exists()
    return Check(
        "archive",
        True,
        f"{len(segments)} encrypted segment file(s), {size // 1024} KiB; git-ignored: {'yes' if ignored else 'no'}",
    )


def _check_hermes() -> Check:
    from ..extension.telegram.hermes_tools import _classify_endpoint, _configured_model

    model, base_url = _configured_model()
    kind = _classify_endpoint(base_url)
    if kind is None:
        return Check(
            "hermes_integration",
            False,
            "the Hermes model is not Venice or local, so the Telegram tools are hidden",
            "switch Hermes to a Venice private model or a local model",
        )
    return Check("hermes_integration", True, f"Hermes model {model} ({kind}): telegram_ask is offered")


def _check_memory() -> Check:
    from ..extension.telegram.memory_guard import memory_encryption_active

    ok = memory_encryption_active()
    return Check(
        "memory_encryption",
        ok,
        "agent memory sealed" if ok else "agent memory is plaintext (required for Telegram)",
        ""
        if ok
        else (
            "hermes-mordred encryption enable memory"
            if sys.platform == "linux"
            else "hermes-mordred encryption enable env && hermes-mordred encryption enable memory"
        ),
    )


def run_checks() -> list[Check]:
    from ..extension.telegram.tee import TeeSecretStore

    try:
        flags = TeeSecretStore().flags()
    except Exception:
        flags = None
    hardware = _check_enclave()
    return [
        _check_telethon(),
        hardware,
        Check("hardware", hardware.ok, hardware.detail, hardware.fix),
        _check_memory(),
        *_check_credentials(flags),
        _check_archive(),
        _check_hermes(),
    ]


def telegram_doctor(*, as_json: bool = False) -> int:
    checks = run_checks()
    if as_json:
        print(json.dumps([asdict(c) for c in checks], indent=2))
    else:
        for c in checks:
            mark = "OK " if c.ok else "!! "
            print(f"{mark}{c.name:20} {c.detail}")
            if c.fix:
                print(f"    -> {c.fix}")
    return 0 if all(c.ok for c in checks) else 1


# -- setup -------------------------------------------------------------------------


def _yes(input_fn: InputFn, prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input_fn(prompt + suffix).strip().casefold()
    return default if not answer else answer in {"y", "yes"}


def _ensure_enclave(input_fn: InputFn) -> bool:
    check = _check_enclave()
    if check.ok:
        return True
    label = "TPM 2.0" if sys.platform == "linux" else "Secure Enclave"
    print(f"Telegram credentials are sealed by {label}. Its helper must be built once (a few minutes).")
    if not _yes(input_fn, f"Build the {label} helper now?"):
        return False
    from .keyvault_native_cli import enable_se, enable_tpm

    return (enable_tpm() if sys.platform == "linux" else enable_se()) == 0


def _ensure_memory_encryption(input_fn: InputFn) -> bool:
    from ..extension.telegram.memory_guard import memory_encryption_active

    if memory_encryption_active():
        return True
    if sys.platform == "linux":
        print(
            "Memory and Telegram keys are bound to this TPM, without per-use user presence. "
            "There is no portable key recovery. Losing TPM state loses access; disable memory "
            "encryption while the TPM works to restore plaintext before moving hosts."
        )
        if not _yes(input_fn, "Turn on TPM memory encryption now?"):
            return False
        from .encryption_cli import _dispatch

        return _dispatch("enable", "memory") == 0 and memory_encryption_active()
    print(
        "Telegram requires agent-memory encryption, so nothing Hermes remembers about your chats is stored "
        "in plaintext. This turns on the sealed .env and sealed memory (Touch ID may be requested)."
    )
    if not _yes(input_fn, "Turn on memory encryption now?"):
        return False
    from ._flow_session import FlowSession
    from .encryption_cli import _dispatch

    # One flow: a new vault's passphrase is asked once, and the vault is
    # unlocked at most once (one Touch ID) for both targets.
    with FlowSession() as flow:
        for target in ("env", "memory"):
            if _dispatch("enable", target, flow_session=flow) != 0:
                return False
    ok = memory_encryption_active()
    if ok:
        print("Memory encryption is on. Restart Hermes Desktop so it picks up the key.")
    return ok


def _choose_llm(input_fn: InputFn, secret_fn: InputFn) -> int:
    from .telegram_cli import telegram_local_llm, telegram_venice

    print("Questions are answered by a privacy LLM. Choose one:")
    print("  1) Venice.ai private model (no retention; needs a Venice API key)")
    print("  2) A model running on this host (e.g. Ollama / LM Studio on 127.0.0.1)")
    choice = input_fn("Choice [1]: ").strip() or "1"
    if choice == "2":
        endpoint = input_fn("Local endpoint (e.g. http://127.0.0.1:11434/v1): ").strip()
        model = input_fn("Model name: ").strip()
        return telegram_local_llm(endpoint=endpoint, model=model)
    return telegram_venice(model=None, secret_fn=secret_fn)


def telegram_setup(
    *,
    input_fn: InputFn = input,
    secret_fn: InputFn = getpass.getpass,
    require_presence: bool = True,
) -> int:
    from .telegram_cli import telegram_login

    if not _supported_platform():
        return 1
    label = "TPM 2.0" if sys.platform == "linux" else "Secure Enclave"
    require_presence = require_presence and sys.platform != "linux"
    print(f"Mordred Telegram setup — read-only, {label}-sealed, Venice/local only.\n")
    print(f"Step 1/5  {label}")
    if not _ensure_enclave(input_fn):
        _term.emit_error(f"the {label} helper is required; setup stopped.")
        return 1

    print("\nStep 2/5  Memory encryption")
    if not _ensure_memory_encryption(input_fn):
        _term.emit_error("memory encryption is required for Telegram; setup stopped.")
        return 1

    from ..extension.telegram.tee import TeeSecretStore

    flags = TeeSecretStore().flags()
    print("\nStep 3/5  Telegram login")
    if flags and flags.get("logged_in"):
        print("Already logged in.")
    elif telegram_login(input_fn=input_fn, secret_fn=secret_fn, require_presence=require_presence) != 0:
        return 1

    flags = TeeSecretStore().flags() or {}
    print("\nStep 4/5  Privacy LLM")
    if flags.get("llm_backend") in ("venice", "local"):
        print(f"Already configured: {flags.get('llm_backend')} ({flags.get('llm_model')}).")
    elif _choose_llm(input_fn, secret_fn) != 0:
        return 1

    if _first_import(input_fn) != 0:
        return 1

    print(
        "\nDone. How to use it:\n"
        "  • Restart Hermes Desktop or the gateway, then ask e.g. “What did we decide on Telegram last week?”.\n"
        "    The agent uses telegram_ask; approve a hardware prompt if requested.\n"
        "  • Browser extension: ⚙ → ✈️ Telegram.\n"
        "  • Health check any time: hermes-mordred telegram doctor"
    )
    return 0


def cli_setup(args: argparse.Namespace) -> int:
    return telegram_setup(require_presence=not getattr(args, "no_touch_id", False))


def cli_doctor(args: argparse.Namespace) -> int:
    return telegram_doctor(as_json=bool(getattr(args, "json", False)))


def _hardware_fix() -> str:
    return "hermes-mordred keyvault " + ("enable-tpm" if sys.platform == "linux" else "enable-se")


def _supported_platform() -> bool:
    if sys.platform in ("darwin", "linux"):
        return True
    _term.emit_error("Private Telegram requires macOS Secure Enclave or Linux TPM 2.0.")
    return False


def _first_import(input_fn: InputFn) -> int:
    from ..extension.telegram.tee import TeeSecretStore
    from .telegram_cli import telegram_sync

    print("\nStep 5/5  First import")
    print(
        f"Recommended: the last {DEFAULT_SINCE_DAYS} days of personal chats and groups; archived chats and "
        "groups over 100 members skipped; pinned chats first. Later imports fetch only new messages."
    )
    recommended = {
        "include_channels": False,
        "include_archived": False,
        "since_days": DEFAULT_SINCE_DAYS,
        "limit_per_dialog": RECOMMENDED_LIMIT,
    }
    if _yes(input_fn, "Use this scope for imports (saved for later `telegram sync` runs)?"):
        TeeSecretStore().save_sync_scope(recommended)
    if _yes(input_fn, "Import now?"):
        rc = telegram_sync()
        if rc != 0:
            return rc
    else:
        print("Skipped. Run `hermes-mordred telegram sync` any time.")

    return 0
