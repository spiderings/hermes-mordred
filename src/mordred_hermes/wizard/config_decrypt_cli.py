"""``hermes-mordred vault {enable,disable}-config-decrypt`` — config.yaml at-rest opt-in.

ROADMAP v2-F8: put ``~/.hermes/config.yaml`` under the at-rest vault with
transparent decrypt at Hermes startup (the ``.pth`` hook in
:mod:`mordred_hermes._pth_bootstrap`). Unlike ``.env`` (lazy via ``os.environ``),
``config.yaml`` is read eagerly at import time, so the startup hook materializes
it before ``cli.py`` runs and reseals it on exit.

- **enable**: enroll the current ``<home>/config.yaml`` into the vault and write
  the opt-in marker (:func:`...keyvault._config_bootstrap._marker_path`) the
  startup hook keys on. The marker is written **only after** a successful enroll,
  so a failed enroll never leaves config.yaml marked-but-unprotected.
- **disable**: remove the marker and guarantee a readable plaintext config.yaml is
  back on disk (decrypting it from the vault if a managed session had sealed it
  away), leaving the vault copy intact. This is the recovery path.

Heavy imports stay function-local so this module imports on any platform,
matching the other wizard CLI modules.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .._home import hermes_home as _hermes_home
from ..keyvault._config_bootstrap import _marker_path, config_hook_installed
from . import _term
from ._runtime_gate import RuntimeProbe, runtime_gate
from ._vault_open import _vault_present

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO

__all__ = ["cli_disable", "cli_enable", "disable", "enable"]

_CONFIG_NAME = "config.yaml"


def _default_runtime_probe(*, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
    """Production runtime probe: can the interpreter that runs ``hermes`` decrypt
    a sealed ``config.yaml``? Imported lazily so this module stays import-light.

    ``runtime_python`` pins a specific interpreter — the gate passes it when
    probing an interpreter that is running a gateway *right now*; omitted, the
    probe resolves the expected runtime itself.
    """
    from ..keyvault._runtime_probe import runtime_config_decrypt_available

    return runtime_config_decrypt_available(home=home, runtime_python=runtime_python)


def _runtime_gate(
    *,
    home: Path,
    platform: str,
    runtime_probe: RuntimeProbe | None,
    force_runtime_unverified: bool,
) -> int:
    """Fail-closed macOS gate for arming the config.yaml seal.

    Returns 1 (after printing actionable guidance) when the interpreter that runs
    ``hermes`` — or one that is running a gateway right now — cannot materialize
    a sealed ``config.yaml`` at startup, else 0. A no-op (0) off macOS — the
    plaintext is kept there anyway — and when ``force_runtime_unverified`` is
    set. The gate core is shared with ``env_decrypt_cli`` via
    :func:`._runtime_gate.runtime_gate`; only the config.yaml-specific guidance
    text lives here (it is reused for both the expected-runtime and the
    running-gateway refusal).
    """
    return runtime_gate(
        home=home,
        platform=platform,
        runtime_probe=runtime_probe,
        force_runtime_unverified=force_runtime_unverified,
        default_probe=_default_runtime_probe,
        target="config.yaml",
        mechanism=(
            "  A sealed config.yaml is materialized at startup only by the mordred .pth\n"
            "  hook in the interpreter that runs `hermes`. hermes-mordred is not installed\n"
            "  in that runtime — install the wheel there before sealing the file\n"
        ),
        rerun_tail=(
            "  then re-run `encryption enable config`. To seal anyway (config stays\n"
            "  unreadable until the runtime has the hook), pass --force-runtime-unverified."
        ),
    )


def _default_root(home: Path) -> Path:
    """The vault root for a home: ``<home>/mordred/vault`` (matches ``_identity``)."""
    return home / "mordred" / "vault"


def enable(
    *,
    home: Path,
    root: Path,
    platform: str,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    prompt_io: PromptIO | None = None,
    runtime_probe: RuntimeProbe | None = None,
    force_runtime_unverified: bool = False,
    flow_session: FlowSession | None = None,
) -> int:
    """Enroll ``<home>/config.yaml`` into the vault and write the opt-in marker.

    If no vault exists yet, one is created first (prompting once for a recovery
    passphrase) — ``encryption enable`` drives the vault, so a fresh install need
    not run ``vault init`` by hand. Returns 0 on success, 1 when there is no
    config.yaml to protect, the vault cannot be created, or the enroll fails
    (unverifiable vault, device key-store error). The marker is written only after
    a clean enroll, so a failure never marks config.yaml as vault-managed without
    a vault copy behind it.

    On macOS the seal is **fail-closed on the runtime**: before enrolling/marking
    it probes the interpreter that actually runs ``hermes`` (see
    :mod:`...keyvault._runtime_probe`) and refuses (rc 1) when that runtime lacks
    the config-decrypt ``.pth`` hook — otherwise the marker would arm reseal-on-exit
    and strand Hermes with a config it cannot materialize at startup. The same
    probe is then run against every *running* ``hermes gateway`` interpreter from
    a different environment, because that is the process which must materialize
    the config in practice. ``runtime_probe`` is injectable for tests;
    ``force_runtime_unverified`` bypasses both checks (advanced; arms the seal
    anyway).

    ``flow_session`` (``encryption enable all``) shares the flow's passphrase,
    open vault and key policy (see :mod:`._flow_session`).
    """
    from . import vault_cli

    config_path = home / _CONFIG_NAME
    if not config_path.is_file():
        _term.emit_error(f"no config.yaml at {config_path} — nothing to protect.")
        return 1

    # Fail-closed runtime check (macOS only): writing the marker arms reseal-on-exit,
    # which removes the plaintext config.yaml. That only round-trips if the
    # interpreter that runs `hermes` has the config-decrypt .pth hook — the dev venv
    # driving this command is often NOT that runtime, and the managed runtime venv is
    # recreated (dropping the non-PyPI mordred) on every `hermes` self-update. Off
    # macOS the plaintext is kept anyway, so no gate. Mirrors env_decrypt_cli.enable.
    gate = _runtime_gate(
        home=home, platform=platform, runtime_probe=runtime_probe, force_runtime_unverified=force_runtime_unverified
    )
    if gate != 0:
        return gate

    rc = vault_cli.ensure_initialised(
        root=root, prompt_io=prompt_io, backend=backend, store=store, flow_session=flow_session
    )
    if rc != 0:
        return rc  # could not create the vault (reason already printed)

    rc = vault_cli.add(
        root=root, name=_CONFIG_NAME, source=config_path, backend=backend, store=store, flow_session=flow_session
    )
    if rc != 0:
        return rc  # vault_cli.add already printed the reason; do NOT write the marker

    marker = _marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("vault-managed\n", encoding="utf-8")
    print(f"config.yaml is now vault-managed (marker {marker}).")
    if config_hook_installed():
        print(
            "  The decrypt hook is installed here: each Hermes run materializes config.yaml\n"
            "  and reseals it (removes the plaintext) on exit. The marker is now set, so the\n"
            "  next `hermes` / `hermes-mordred` run seals the current plaintext on exit.\n"
            "  Next: run `hermes-mordred encryption status` once. When it exits, the current\n"
            "  plaintext config.yaml will be resealed and removed. Do not re-run\n"
            "  `encryption enable config` for this first seal or delete config.yaml manually."
        )
    else:
        print(
            "  ⚠ The decrypt hook is NOT installed in this environment, so the plaintext\n"
            "  config.yaml stays on disk. Install it by (re)installing the hermes-mordred\n"
            "  wheel (it ships the startup .pth hook); until then nothing reseals it."
        )
    return 0


def disable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> int:
    """Remove the opt-in marker and guarantee a readable plaintext config.yaml.

    If a managed session had sealed the plaintext away (reseal-on-exit removed it),
    it is decrypted back from the vault first so Hermes keeps a usable config. The
    vault copy is left intact. Returns 0 on success, 1 if the plaintext is missing
    and the vault cannot be opened to recover it. ``flow_session`` (``uninstall``)
    lends the flow's already open vault.
    """
    marker = _marker_path(home)
    config_path = home / _CONFIG_NAME

    # Recover a sealed-away plaintext only when config.yaml was actually managed
    # (the marker is present). A never-managed home has nothing to un-manage, so we
    # never touch a (possibly absent) vault — disable stays a clean idempotent no-op.
    if marker.exists() and not config_path.exists():
        from ..keyvault import _storage
        from . import vault_cli

        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store, flow_session=flow_session)
        if opened is None:
            return 1
        with opened:
            if _CONFIG_NAME in opened.list_files():
                _storage.atomic_write(config_path, opened.read_file(_CONFIG_NAME))
            # No enrolled config and no plaintext: Hermes will use defaults — not an error.

    marker.unlink(missing_ok=True)
    print("config.yaml is no longer vault-managed (marker removed).")
    if config_path.exists():
        print(f"  A plaintext config.yaml is at {config_path}; the vault copy is left intact.")
    return 0


def purge(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Remove ``config.yaml`` from the vault entirely (destructive), keeping plaintext.

    Safe order (Codex impl-review): **recover the plaintext first, then drop the
    vault copy, then remove the marker.** A sealed-away plaintext (reseal-on-exit
    removed it) is decrypted back before the vault copy is unenrolled, so the only
    readable copy is never lost. Removing the marker last means a crash mid-purge
    never leaves the marker pointing at a vault copy that is already gone (which
    would brick the fail-closed startup hook).

    Returns 0 on success (an unmanaged home with no vault is a clean no-op), 1 when
    the vault is present but cannot be opened to recover / unenroll.
    """
    config_path = home / _CONFIG_NAME

    if _vault_present(root):
        from ..keyvault import _storage, anchor, vault
        from . import vault_cli

        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        if opened is None:
            return 1
        with opened:
            try:
                if _CONFIG_NAME in opened.list_files():
                    if not config_path.exists():
                        _storage.atomic_write(config_path, opened.read_file(_CONFIG_NAME))  # recover BEFORE dropping
                    opened.unenroll_file(_CONFIG_NAME)
            except (vault.VaultError, anchor.AnchorError, OSError) as exc:
                _term.emit_error(f"cannot purge config.yaml from the vault: {exc}")
                return 1
    elif _marker_path(home).exists() and not config_path.exists():
        # Managed (marker) but no vault to recover from and no plaintext on disk:
        # dropping the marker here would silently convert a fail-closed managed
        # state into "boot on defaults". Refuse and surface the anomaly instead.
        _term.emit_error(
            "cannot purge: config.yaml is vault-managed but neither a plaintext copy nor a vault is present "
            "— recover the vault first, or remove the marker by hand to fall back to defaults."
        )
        return 1

    _marker_path(home).unlink(missing_ok=True)
    print("config.yaml purged from the vault; a plaintext config.yaml is kept on disk.")
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py. Root defaults under the resolved home so a custom
# HERMES_HOME / profile keeps home and vault root consistent.
# -----------------------------------------------------------------------------


def _resolve_root(home: Path, root_arg: str | None) -> Path:
    return Path(root_arg).resolve() if root_arg else _default_root(home)


def cli_enable(args: argparse.Namespace) -> int:
    """argparse handler for ``vault enable-config-decrypt [--root PATH]``."""
    home = _hermes_home()
    return enable(
        home=home,
        root=_resolve_root(home, getattr(args, "root", None)),
        platform=sys.platform,
        force_runtime_unverified=bool(getattr(args, "force_runtime_unverified", False)),
    )


def cli_disable(args: argparse.Namespace) -> int:
    """argparse handler for ``vault disable-config-decrypt [--root PATH]``."""
    home = _hermes_home()
    return disable(home=home, root=_resolve_root(home, getattr(args, "root", None)))
