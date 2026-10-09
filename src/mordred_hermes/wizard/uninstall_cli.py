"""``hermes-mordred uninstall`` -- remove Mordred and hand Hermes its files back.

Removing the package alone can leave Hermes unable to start or unable to read
its own files: with at-rest encryption on, ``.env`` / ``config.yaml`` live only
in Mordred's vault and ``memories/*.md`` are sealed, and nothing but Mordred can
open them. This command undoes the install in a safe order, printing the whole
plan first and asking once (``--yes`` skips the question):

a. **Restore plaintext.** Every encryption target that is on is turned off with
   the existing reversible ``encryption disable`` engines (config, then memory,
   then env), sharing one :class:`._flow_session.FlowSession` so the vault is
   unlocked at most once. If the device key cannot open the vault the recovery
   passphrase is offered instead. If any target cannot be restored the command
   stops *before removing anything* and says why.
b. **Give Hermes its config back.** The Hermes Desktop page is removed, and
   Mordred's entries leave ``config.yaml`` (plugin names, ``plugins.mordred_*``,
   the legacy memory flag -- a timestamped backup is kept) and ``.env``
   (``HERMES_MEMORY_KEY``, ``MORDRED_*`` -- saved under ``<home>/mordred``).
   See :mod:`._uninstall_config`.
c. **Launchers.** The ``hermes-mordred`` launcher the installer wrote is removed
   (only with the installer's marker, or a symlink to the uninstalled console
   script). The native helpers in ``~/.local/bin`` are removed only with
   ``--remove-helper`` / ``--purge-data`` and only when Mordred built them.
e. **Data.** Kept by default and listed with its location. ``--purge-data``
   (after a typed confirmation that ``--yes`` does not skip) logs Telegram out,
   deletes the device keys and Keychain anchor, resets the keyvault, and removes
   ``<home>/mordred`` and ``<home>/extension``.
d. **The package.** ``uv pip uninstall`` in Hermes's environment, last, because
   this very command usually runs from that environment.

Every step is idempotent: a second run finds nothing left and changes nothing.
``--dry-run`` prints the plan and changes nothing at all.
"""

from __future__ import annotations

import argparse
import dataclasses
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from . import _term
from ._uninstall_config import (
    ConfigCleanup,
    EnvCleanup,
    apply_config_cleanup,
    apply_env_cleanup,
    plan_config_cleanup,
    plan_env_cleanup,
)
from ._uninstall_hermes_env import (
    HelperFinding,
    HermesEnv,
    LauncherFinding,
    Runner,
    Which,
    classify_helpers,
    classify_launchers,
    default_runner,
    detect_hermes_env,
    uninstall_packages,
)

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO

__all__ = ["UninstallContext", "UninstallOptions", "UninstallPlan", "build_plan", "cli_uninstall", "run_uninstall"]

#: What the operator types to confirm ``--purge-data``.
PURGE_PHRASE = "delete my data"

#: Keychain services that may hold the vault's anchor item: the helper-owned
#: one and the legacy one. ``resolve_store(...).delete`` removes both.
_ANCHOR_SERVICES = ("mordred-hermes.vault.anchor.sekey", "mordred-hermes.vault.anchor")

#: Human descriptions of what lives under ``<home>/mordred``.
_DATA_DESCRIPTIONS: dict[str, str] = {
    "vault": "encrypted file vault (vault copies of .env / config.yaml)",
    "keyvault": "keyvault: hardware-wrapped keys and envelopes (wallet / API secrets)",
    "telegram": "Telegram archive and sealed credentials",
    "policy.json": "Mordred policy snapshot",
    "credentials": "network settings (non-secret references)",
    "tor-data": "Tor state",
    "uninstall": "lines this command moved out of .env",
}


@dataclass(frozen=True)
class UninstallOptions:
    dry_run: bool = False
    yes: bool = False
    purge_data: bool = False
    remove_helper: bool = False
    #: Delete encrypted data as it is instead of decrypting it back (implies ``purge_data``).
    erase_encrypted: bool = False


@dataclass
class UninstallContext:
    """Paths and injectable collaborators (tests replace every side effect)."""

    home: Path
    vault_root: Path
    user_home: Path
    platform: str = sys.platform
    backend: NativeBackend | None = None
    store: AnchorStore | None = None
    prompt_io: PromptIO | None = None
    which: Which = shutil.which
    runner: Runner = default_runner
    stamp: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d-%H%M%S"))
    interactive: bool = field(default_factory=lambda: sys.stdin.isatty())
    #: ``() -> rc``: revoke the Telegram session and forget its credentials.
    telegram_forget: Callable[[], int] | None = None
    #: ``(home) -> rc``: destroy the keyvault (native keys + directory).
    keyvault_reset: Callable[[Path], int] | None = None
    #: ``(home) -> [description]``: running Hermes gateways (diagnostic).
    gateways: Callable[[Path], list[str]] | None = None


@dataclass(frozen=True)
class Restore:
    target: str
    detail: str
    #: Whether the plaintext exists only in the vault (the vault must be opened).
    needs_vault: bool


@dataclass
class UninstallPlan:
    restores: list[Restore]
    config: ConfigCleanup
    env: EnvCleanup
    desktop_page: Path | None
    launchers: list[LauncherFinding]
    helpers: list[HelperFinding]
    hermes_env: HermesEnv
    data: list[tuple[Path, str]]
    device_keys: list[str]
    telegram_configured: bool
    #: Empty lock files Mordred's writers left next to Hermes's files.
    leftovers: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def nothing_to_do(self) -> bool:
        return not (
            self.restores
            or self.config.changed
            or self.env.names
            or self.desktop_page
            or self.leftovers
            or any(item.remove for item in self.launchers)
            or self.hermes_env.installed
        )


# -----------------------------------------------------------------------------
# Plan (read-only)
# -----------------------------------------------------------------------------
def _restores(ctx: UninstallContext) -> list[Restore]:
    from ..keyvault._config_bootstrap import _marker_path
    from ..keyvault._memory_hook import memory_marker_path
    from ..keyvault._runtime_env import _env_optout_marker_path
    from . import encryption_cli, memory_cli

    home = ctx.home
    out: list[Restore] = []
    if _marker_path(home).exists():
        sealed_away = not (home / "config.yaml").exists()
        detail = "vault-managed" + ("; the plaintext is sealed away and will be decrypted back" if sealed_away else "")
        out.append(Restore("config", detail, sealed_away))
    sealed = memory_cli._sealed_memory_files(home)
    if memory_marker_path(home).exists() or sealed:
        from ..keyvault._memory_key import memory_key_path

        tpm_memory = ctx.platform == "linux" or memory_key_path(home).exists()
        out.append(
            Restore(
                "memory", f"{len(sealed)} sealed memory file(s) will be decrypted back", bool(sealed) and not tpm_memory
            )
        )
    enrolled = ".env" in encryption_cli._enrolled_names(ctx.vault_root)
    plaintext = (home / ".env").exists()
    if enrolled and (not plaintext or not _env_optout_marker_path(home).exists()):
        detail = "vault-managed" + ("; the plaintext will be decrypted back from the vault" if not plaintext else "")
        out.append(Restore("env", detail, not plaintext))
    return out


def _data_inventory(ctx: UninstallContext) -> list[tuple[Path, str]]:
    data: list[tuple[Path, str]] = []
    mordred = ctx.home / "mordred"
    if mordred.is_dir():
        for child in sorted(mordred.iterdir()):
            name = child.name
            if name.startswith("."):
                continue  # lock files and journals; they go with the directory
            description = "audit log" if name.startswith("audit.log") else _DATA_DESCRIPTIONS.get(name, "Mordred state")
            data.append((child, description))
    extension = ctx.home / "extension"
    if extension.is_dir():
        data.append((extension, "browser-extension pairing, history and wallet settings"))
    for name in (".env.vault-purged", ".env.reseal.tmp"):
        if (ctx.home / name).exists():
            data.append((ctx.home / name, "a plaintext .env copy an earlier Mordred command left"))
    for backup in sorted(ctx.home.glob("config.yaml.mordred-uninstall-*.bak")):
        data.append((backup, "config.yaml backup from an earlier uninstall run"))
    return data


def _leftover_locks(home: Path) -> list[Path]:
    """``<home>/.env.lock`` -- the empty lock file Mordred's ``.env`` writer creates.

    Hermes itself does not use it; only an empty regular file is touched.
    """
    lock = home / ".env.lock"
    try:
        if lock.is_file() and not lock.is_symlink() and lock.stat().st_size == 0:
            return [lock]
    except OSError:
        pass
    return []


def _device_keys(ctx: UninstallContext, telegram_configured: bool) -> list[str]:
    from ..keyvault._identity import vault_identity

    keys: list[str] = []
    if ctx.vault_root.exists():
        label = vault_identity(ctx.vault_root)
        keys.append(
            f"vault device key {label}: a Secure Enclave key, or -- for a vault created before the Secure Enclave "
            "helper was installed -- a software P-256 key in the login keychain (tag prefix mordred-hermes.wrsw.)"
        )
        keys.append(f"vault Keychain anchor {label} (services {_ANCHOR_SERVICES[0]} and legacy {_ANCHOR_SERVICES[1]})")
    if (ctx.home / "mordred" / "keyvault").exists():
        keys.append("keyvault wrapping keys (listed by `hermes-mordred keyvault list`)")
    if telegram_configured:
        keys.append("Telegram Secure Enclave key mordred-hermes.telegram.credentials.v1")
    return keys


def _workspace_note() -> str | None:
    from ._encryption_status import _default_workspace_paths

    try:
        workspace = _default_workspace_paths()
    except Exception:  # an overview line must never break the plan
        return None
    if workspace.image.exists():
        return (
            f"The encrypted Claude workspace at {workspace.image} belongs to the external `claude-private` tool; "
            "it is not part of Mordred's package and keeps working. It is left as is."
        )
    return None


def _default_gateways(home: Path) -> list[str]:
    from .memory_cli import _running_gateways

    return [f"pid {g.pid} ({g.python})" if g.pid is not None else str(g.python) for g in _running_gateways(home)]


def build_plan(ctx: UninstallContext, opts: UninstallOptions) -> UninstallPlan:
    """Everything ``uninstall`` would do, computed without changing anything."""
    from ..desktop.install import page_dir, plugin_dir

    restores = _restores(ctx)
    config = plan_config_cleanup(ctx.home / "config.yaml")
    env = plan_env_cleanup(ctx.home / ".env")
    page = next(
        (d for d in (page_dir(ctx.home), plugin_dir(ctx.home)) if d.is_dir() and not d.is_symlink()),
        plugin_dir(ctx.home),
    )
    hermes_env = detect_hermes_env(ctx.home, which=ctx.which, runner=ctx.runner)
    telegram_configured = (ctx.home / "mordred" / "telegram" / "credentials.sealed").exists()
    plan = UninstallPlan(
        restores=restores,
        config=config,
        env=env,
        desktop_page=page if page.is_dir() and not page.is_symlink() else None,
        launchers=classify_launchers(hermes_env, user_home=ctx.user_home, hermes_home=ctx.home),
        helpers=classify_helpers(
            user_home=ctx.user_home, platform=ctx.platform, runner=ctx.runner, hermes_home=ctx.home
        ),
        hermes_env=hermes_env,
        data=_data_inventory(ctx),
        device_keys=_device_keys(ctx, telegram_configured),
        telegram_configured=telegram_configured,
        leftovers=_leftover_locks(ctx.home),
    )
    if any(r.target == "config" and r.needs_vault for r in restores):
        plan.notes.append("config.yaml is sealed right now; its Mordred entries are removed after it is restored.")
    if any(r.target == "env" for r in restores):
        plan.notes.append("After .env is restored, HERMES_MEMORY_KEY and MORDRED_* lines are moved out of it.")
    gateways = (ctx.gateways or _default_gateways)(ctx.home)
    if gateways:
        plan.notes.append(
            "A Hermes gateway is running (" + ", ".join(gateways) + "). Stop it first, or it may write sealed "
            "files or its old config.yaml again."
        )
    if not plan.nothing_to_do:
        plan.notes.append("Quit Hermes Desktop and any running `hermes` session before you run this for real.")
    workspace = _workspace_note()
    if workspace:
        plan.notes.append(workspace)
    if hermes_env.problem:
        plan.notes.append(f"Package: {hermes_env.problem}.")
    if opts.remove_helper and not opts.purge_data and plan.device_keys:
        plan.notes.append(
            "--remove-helper without --purge-data: the kept vault's device key can no longer be used after the helper "
            "is gone; the vault then opens only with its recovery passphrase."
        )
    return plan


# -----------------------------------------------------------------------------
# Rendering
# -----------------------------------------------------------------------------
def _section(title: str, lines: list[str]) -> list[str]:
    return [title, *(f"  - {line}" for line in lines)] if lines else []


def _hermes_lines(plan: UninstallPlan) -> list[str]:
    lines: list[str] = []
    if plan.desktop_page:
        lines.append(f"remove the Hermes Desktop page {plan.desktop_page}")
    if plan.config.error:
        lines.append(f"config.yaml: {plan.config.error}")
    lines += [f"config.yaml: remove {item}" for item in plan.config.removed]
    if plan.config.removed:
        lines.append("config.yaml: a timestamped backup is written next to it first")
    if plan.env.error:
        lines.append(f".env: {plan.env.error}")
    if plan.env.names:
        lines.append(f".env: move {', '.join(plan.env.names)} out (saved under <home>/mordred/uninstall)")
    lines += [f"remove {path} (empty lock file Mordred's .env writer created)" for path in plan.leftovers]
    return lines


def _launcher_lines(plan: UninstallPlan, opts: UninstallOptions) -> list[str]:
    lines = [f"{'remove' if f.remove else 'keep'} {f.path} ({f.reason})" for f in plan.launchers]
    for helper in plan.helpers:
        if not helper.mordred_built:
            lines.append(f"keep {helper.path} ({helper.reason})")
        elif opts.remove_helper or opts.purge_data:
            lines.append(f"remove {helper.path} ({helper.reason})")
        else:
            lines.append(f"keep {helper.path} ({helper.reason}; remove it with --remove-helper)")
    return lines


def _package_line(env: HermesEnv) -> str:
    if env.installed:
        return f"uv pip uninstall {' '.join(env.installed)} from {env.root} (last step)"
    where = f" ({env.root})" if env.root else ""
    return f"not installed in Hermes's environment{where}; nothing to remove"


def render_plan(plan: UninstallPlan, opts: UninstallOptions) -> str:
    out: list[str] = ["hermes-mordred uninstall plan", ""]
    if opts.erase_encrypted:
        erase = [_erase_line(r, plan) for r in plan.restores]
        out += _section("1. ERASE encrypted data WITHOUT decrypting it (cannot be undone):", erase) or [
            "1. Erase encrypted data: nothing is encrypted."
        ]
    else:
        restore = [f"{r.target}: {r.detail}" for r in plan.restores]
        out += _section("1. Restore plaintext for Hermes (encryption disable):", restore) or [
            "1. Restore plaintext: nothing is encrypted."
        ]
    out += _section("2. Hermes configuration:", _hermes_lines(plan)) or [
        "2. Hermes configuration: nothing of Mordred's left."
    ]
    out += _section("   Mordred cannot know the previous value of (check these yourself):", plan.config.unknowns)
    out += _section("3. Launchers and helpers:", _launcher_lines(plan, opts)) or ["3. Launchers and helpers: none."]
    out += _section("4. Package:", [_package_line(plan.hermes_env)])
    data = [f"{path}  -- {description}" for path, description in plan.data] + plan.device_keys
    if opts.purge_data:
        title = "5. Data -- PERMANENTLY DELETED (--purge-data):"
        if plan.telegram_configured:
            data.insert(0, "Telegram: revoke the session at Telegram, then forget the credentials")
    else:
        title = "5. Data -- kept (use --purge-data to delete):"
    out += _section(title, data) or ["5. Data: none."]
    if plan.notes:
        out += ["", *(f"Note: {note}" for note in plan.notes)]
    return "\n".join(out)


def _erase_line(restore: Restore, plan: UninstallPlan) -> str:
    del plan
    if restore.target == "memory":
        return "memory: the sealed memory files are deleted; Hermes starts with empty memory"
    if restore.target == "env":
        if restore.needs_vault:
            return ".env: exists only in the vault and is deleted with it; Hermes loses those API keys"
        return ".env: the plaintext .env stays; only the vault copy is deleted"
    if restore.needs_vault:
        return "config: config.yaml exists only in the vault and is deleted; Hermes starts with a new config"
    return "config: config.yaml stays; only the vault copy is deleted"


def _erase_encrypted(ctx: UninstallContext, restores: list[Restore]) -> int:
    """Step a in erase mode: remove sealed files without opening the vault.

    Only the sealed memory files live outside Mordred's own directories; the
    vault (sealed .env / config.yaml copies) and every marker are removed by
    the purge that erase mode always runs.
    """
    from . import memory_cli

    for restore in restores:
        if restore.target == "memory":
            for path in memory_cli._sealed_memory_files(ctx.home):
                path.unlink(missing_ok=True)
                print(f"Erased sealed memory file {path}.")
        else:
            print(f"Erasing the encrypted {restore.target} with the vault (not decrypted).")
    return 0


def _render_kept(plan: UninstallPlan, *, purged: bool = False) -> str:
    lines = [f"  {path}  -- {description}" for path, description in plan.data]
    lines += [f"  {key}" for key in plan.device_keys]
    if purged:
        return "Mordred data deleted." + ("\nStill here (Hermes files):\n" + "\n".join(lines) if lines else "")
    if not lines:
        return "No Mordred data is left."
    return "\n".join(
        [
            "Kept (not deleted) -- Mordred data that remains on this machine:",
            *lines,
            "To open any of it again you need Mordred plus this device's keys, or the vault recovery",
            "passphrase / the keyvault Seed Phrase, Passphrase and backup blob. To delete it, run",
            "`hermes-mordred uninstall --purge-data` while Mordred is still installed, or remove the paths by hand.",
        ]
    )


# -----------------------------------------------------------------------------
# Execution
# -----------------------------------------------------------------------------
def _open_vault_for_flow(ctx: UninstallContext, flow: FlowSession, *, needed: bool) -> bool:
    """Unlock the vault once for every restore.

    When a restore depends on the vault and the device key cannot open it, the
    recovery passphrase (cold path, read-only -- enough to decrypt) is offered.
    """
    from . import _vault_open

    if not ctx.vault_root.exists():
        return False
    opened = _vault_open._open_hot_path_or_report(
        ctx.vault_root, backend=ctx.backend, store=ctx.store, flow_session=flow
    )
    if opened is not None:
        return True
    if not needed or (not ctx.interactive and ctx.prompt_io is None):
        return False
    print("This device's key could not open the vault. You can open it with the vault recovery passphrase instead.")
    cold = _vault_open._open_cold_path(ctx.vault_root, prompt_io=ctx.prompt_io)
    if cold is None:
        return False
    flow.keep_vault(ctx.vault_root, cold)
    return True


def _restore_all(ctx: UninstallContext, restores: list[Restore]) -> int:
    """Step a. Returns 0, or 1 after explaining which target could not be restored."""
    from . import config_decrypt_cli, env_decrypt_cli, memory_cli
    from ._flow_session import FlowSession

    engines: dict[str, Callable[..., int]] = {
        "config": config_decrypt_cli.disable,
        "memory": memory_cli.disable,
        "env": env_decrypt_cli.disable,
    }
    with FlowSession() as flow:
        needed = any(r.needs_vault for r in restores)
        vault_open = _open_vault_for_flow(ctx, flow, needed=needed) if restores else False
        if not vault_open and needed:
            targets = ", ".join(r.target for r in restores if r.needs_vault)
            _term.emit_error(
                f"uninstall stopped: the vault could not be opened, and the plaintext of {targets} exists only "
                "in the vault. Nothing was removed. Fix vault access (see the message above) and re-run."
            )
            return 1
        for restore in restores:
            print(f"Restoring {restore.target} ...")
            rc = engines[restore.target](
                home=ctx.home, root=ctx.vault_root, backend=ctx.backend, store=ctx.store, flow_session=flow
            )
            if rc != 0:
                _term.emit_error(
                    f"uninstall stopped: {restore.target} could not be restored to plaintext (see above). "
                    "Nothing was removed and Mordred stays installed, so Hermes keeps working. "
                    f"Fix the cause, then re-run `hermes-mordred uninstall` (or `encryption disable {restore.target}`)."
                )
                return 1
    return 0


def _clean_hermes_files(ctx: UninstallContext, plan: UninstallPlan) -> int:
    """Step b. Returns 1 only when config.yaml could not be edited."""
    from ..desktop.install import remove_page

    if remove_page(ctx.home):
        print(f"Removed the Hermes Desktop page {plan.desktop_page or ctx.home / 'plugins' / 'mordred'}.")
    config = apply_config_cleanup(ctx.home / "config.yaml", lock_dir=ctx.home / "mordred", stamp=ctx.stamp)
    plan.config = config
    if config.error:
        _term.emit_error(f"config.yaml was not changed: {config.error}")
        return 1
    if config.changed:
        print(f"config.yaml: removed {', '.join(config.removed)} (backup: {config.backup}).")
    env = apply_env_cleanup(ctx.home / ".env", save_dir=ctx.home / "mordred" / "uninstall", stamp=ctx.stamp)
    plan.env = env
    if env.error:
        _term.emit_warn(f".env was not changed: {env.error}")
    elif env.names:
        print(f".env: moved {', '.join(env.names)} to {env.saved_to}.")
    for path in plan.leftovers:
        path.unlink(missing_ok=True)
    return 0


def _remove_launchers(plan: UninstallPlan) -> None:
    """Step c (launchers). Helpers go in :func:`_remove_helpers`, after the purge."""
    for launcher in plan.launchers:
        if launcher.remove:
            if launcher.path.name == "hermes-mordred.ps1":
                from ._windows_install import remove_owned

                remove_owned(launcher.path)
            else:
                launcher.path.unlink(missing_ok=True)
            print(f"Removed {launcher.path}.")


def _remove_helpers(plan: UninstallPlan, opts: UninstallOptions) -> None:
    """Step c (helpers). Runs after the purge: revoking the Telegram session and
    deleting the device keys both need the Secure Enclave helper."""
    if opts.remove_helper or opts.purge_data:
        for helper in plan.helpers:
            if helper.mordred_built:
                if helper.path.name == "mordred-hermes-winkey.exe":
                    from ._windows_install import remove_owned

                    remove_owned(helper.path)
                else:
                    helper.path.unlink(missing_ok=True)
                print(f"Removed {helper.path}.")
            else:
                _term.emit_warn(f"kept {helper.path}: {helper.reason}.")


def _default_telegram_forget() -> int:
    from .telegram_cli import telegram_logout

    return telegram_logout(forget=True)


def _default_keyvault_reset(ctx: UninstallContext) -> Callable[[Path], int]:
    def reset(home: Path) -> int:
        from .keyvault_cli import reset_keyvault

        return reset_keyvault(home=home, backend=ctx.backend, assume_yes=True)

    return reset


def _delete_vault_keys(ctx: UninstallContext) -> None:
    from ..keyvault._identity import resolve_backend, resolve_store, vault_identity

    label = vault_identity(ctx.vault_root)
    try:
        # Covers every namespace the key can live in: the helper's Secure
        # Enclave key, the legacy one, and the software P-256 fallback.
        resolve_backend(ctx.backend).delete_enclave_key(label)
    except Exception as exc:  # report and continue; the files are removed regardless
        _term.emit_warn(
            f"could not delete the vault device key {label}: {exc}. If it is a software key another Python "
            "created, remove it by hand: Keychain Access -> login -> Keys, the item whose application tag starts "
            "with mordred-hermes.wrsw. (or mordred-hermes.wrap.)."
        )
    try:
        resolve_store(ctx.store).delete(label)
    except Exception as exc:
        _term.emit_warn(
            f"could not delete the vault Keychain anchor {label}: {exc}. Remove it in Keychain Access: the "
            f"password items with account {label} under {' / '.join(_ANCHOR_SERVICES)}."
        )


def _purge_tpm_memory(ctx: UninstallContext) -> int:
    from ..keyvault._memory_key import memory_key_path
    from . import memory_cli

    wrapped = memory_key_path(ctx.home)
    if not (wrapped.exists() or wrapped.is_symlink()):
        return 0
    # Restore/erase already ran. Remove independent memory custody before
    # keyvault reset can remove the containing native TPM store.
    rc = memory_cli.purge(home=ctx.home, root=ctx.vault_root, backend=ctx.backend)
    if rc != 0:
        _term.emit_error("TPM memory could not be purged; Mordred data was retained")
    return rc


def _forget_telegram_for_uninstall(ctx: UninstallContext) -> None:
    forget = ctx.telegram_forget or _default_telegram_forget
    try:
        rc = forget()
    except Exception as exc:  # e.g. the optional Telegram extra is missing
        rc = 1
        _term.emit_warn(f"Telegram logout failed: {exc}")
    if rc != 0:
        _term.emit_warn(
            "the Telegram session could not be revoked here; terminate it in Telegram -> Settings -> Devices."
        )


def _purge_data(ctx: UninstallContext, plan: UninstallPlan) -> int:
    """Step e with ``--purge-data``. Returns 1 when the keyvault could not be reset."""
    if plan.telegram_configured:
        _forget_telegram_for_uninstall(ctx)
    if _purge_tpm_memory(ctx) != 0:
        return 1
    if ctx.vault_root.exists():
        _delete_vault_keys(ctx)
    if (ctx.home / "mordred" / "keyvault").exists():
        reset = ctx.keyvault_reset or _default_keyvault_reset(ctx)
        if reset(ctx.home) != 0:
            _term.emit_error(
                "the keyvault could not be reset (see above), so the Mordred data was NOT deleted -- deleting it "
                "would orphan the keyvault's hardware keys. Re-run `hermes-mordred uninstall --purge-data`."
            )
            return 1
    for path in (ctx.home / "mordred", ctx.home / "extension"):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
            print(f"Deleted {path}.")
    for name in (".env.vault-purged", ".env.reseal.tmp"):
        (ctx.home / name).unlink(missing_ok=True)
    return 0


def _confirm(ctx: UninstallContext, opts: UninstallOptions) -> bool:
    from ._defaults import resolve_prompt_io

    if opts.yes and not opts.purge_data:
        return True
    if not ctx.interactive and ctx.prompt_io is None:
        _term.emit_error(
            "uninstall needs a confirmation: re-run at a terminal"
            + (" (--purge-data always asks you to type the confirmation)." if opts.purge_data else ", or pass --yes.")
        )
        return False
    prompt_io = resolve_prompt_io(ctx.prompt_io)
    if not opts.yes and not prompt_io.ask_bool("Uninstall Mordred as shown above?", False):
        return False
    if opts.purge_data:
        print(
            "\nWARNING: --purge-data permanently deletes the data listed in step 5, including the device keys.\n"
            "Anything encrypted with them can be recovered only with the keyvault Seed Phrase / Passphrase /\n"
            "backup blob or the vault recovery passphrase -- and only if you kept a copy of the data elsewhere.",
            file=sys.stderr,
        )
        answer = prompt_io.ask_text(f"Type '{PURGE_PHRASE}' to delete it")
        if answer.strip() != PURGE_PHRASE:
            print("Confirmation did not match; nothing was changed.")
            return False
    return True


def _execute(ctx: UninstallContext, plan: UninstallPlan, opts: UninstallOptions) -> int:
    """Steps a-e in order, stopping at the first one that must not be passed."""
    step_a = _erase_encrypted if opts.erase_encrypted else _restore_all
    if step_a(ctx, plan.restores) != 0:
        return 1
    if _clean_hermes_files(ctx, plan) != 0:
        return 1
    _remove_launchers(plan)
    if opts.purge_data:
        if _purge_data(ctx, plan) != 0:
            return 1
        plan.data, plan.device_keys = _data_inventory(ctx), []
    _remove_helpers(plan, opts)

    # The package goes last: this command normally runs from it. Everything
    # printed afterwards is formatted now, before its files disappear.
    farewell = _render_kept(plan, purged=opts.purge_data)
    env = plan.hermes_env
    ok, output = uninstall_packages(env, runner=ctx.runner)
    if output:
        print(output)
    if not ok:
        _term.emit_error(
            f"uv pip uninstall failed in {env.root}; Hermes's files are already restored. "
            f"Remove the package by hand: {env.uv} pip uninstall --python {env.python} {' '.join(env.installed)}"
        )
        return 1
    if env.installed:
        print(f"Uninstalled {', '.join(env.installed)} from {env.root}.")
    print(farewell)
    print("Done. Restart Hermes (and Hermes Desktop) so it stops loading Mordred.")
    return 0


def run_uninstall(ctx: UninstallContext, opts: UninstallOptions) -> int:
    """Plan, confirm, and run the uninstall. Returns the process exit code."""
    if opts.erase_encrypted and not opts.purge_data:
        opts = dataclasses.replace(opts, purge_data=True)
    plan = build_plan(ctx, opts)
    print(render_plan(plan, opts))
    print()
    if opts.dry_run:
        print("Dry run: nothing was changed.")
        return 0
    optional_work = (opts.purge_data and bool(plan.data or plan.device_keys)) or (
        (opts.remove_helper or opts.purge_data) and any(helper.mordred_built for helper in plan.helpers)
    )
    if plan.nothing_to_do and not optional_work:
        print("Mordred is not installed here; nothing to do.")
        print(_render_kept(plan))
        return 0
    if not _confirm(ctx, opts):
        print("Uninstall cancelled; nothing was changed.")
        return 1
    return _execute(ctx, plan, opts)


def _context_from_environment() -> UninstallContext:
    from .._home import hermes_home
    from ..keyvault._identity import resolve_root

    return UninstallContext(home=hermes_home(), vault_root=resolve_root(None), user_home=Path.home())


def cli_uninstall(args: argparse.Namespace) -> int:
    """argparse handler for ``uninstall [--dry-run] [--yes] [--purge-data] [--remove-helper]``."""
    opts = UninstallOptions(
        dry_run=bool(getattr(args, "dry_run", False)),
        yes=bool(getattr(args, "yes", False)),
        purge_data=bool(getattr(args, "purge_data", False)),
        erase_encrypted=bool(getattr(args, "erase_encrypted", False)),
        remove_helper=bool(getattr(args, "remove_helper", False)),
    )
    return run_uninstall(_context_from_environment(), opts)
