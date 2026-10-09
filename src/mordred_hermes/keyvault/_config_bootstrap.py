"""config.yaml at-rest transparent-decrypt bootstrap (design note §8.2 / ROADMAP v2-F8).

The ``.env`` shim (:mod:`mordred_hermes.keyvault._runtime_env`) works by injecting
secrets into ``os.environ`` at ``register()`` time, because env vars are consumed
*lazily*. ``config.yaml`` is different: Hermes reads it **eagerly at import time**
— ``cli.py`` runs ``CLI_CONFIG = load_cli_config()`` at module import, and
``hermes_time`` / ``rl_cli`` / ``hermes_logging`` each ``yaml.safe_load`` the file
directly — all before any plugin ``register()`` runs. So a register-time shim is
too late.

This module materializes the vault-enrolled ``config.yaml`` onto its on-disk path
**before the interpreter imports those modules** (driven by a ``.pth`` startup
hook), and reseals it on exit:

- **materialize_config** (decrypt-on-start): if the operator opted in (the marker
  file is present), decrypt the vault ``config.yaml`` to ``<home>/config.yaml``
  at mode ``0o600`` so every upstream reader sees it unchanged. An on-disk working
  copy that differs from the vault (a live edit, or an unclean prior exit) is
  authoritative: its bytes are re-synced into the vault and the file is kept.
- **reseal_config** (reseal-on-stop): re-enroll the working copy if it changed,
  then remove the on-disk plaintext so ``config.yaml`` is at-rest again between
  sessions.

Opens on the **hot path** (device key — Secure Enclave or its software fallback,
no passphrase) and is **fail-closed**: a vault that is present but cannot be
opened, verified, or read aborts startup rather than silently falling back to a
default or stale config.

**Trade-off**: while a managed Hermes process runs, the plaintext ``config.yaml``
exists on disk (mode ``0o600``). This is weaker than the ``.env`` shim's
memory-only injection; it is the cost of supporting the eager direct readers
without a Hermes-core change (zero-PR / plugin-only). See ROADMAP v2-F8.

Heavy imports (the cryptography-backed vault modules) stay function-local so this
module imports on any platform, matching ``_runtime_env.py``.
"""

from __future__ import annotations

import atexit
import contextlib
import site
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .. import _term
from .._home import hermes_home
from ._identity import default_vault_root, resolve_backend_store, vault_identity
from ._plaintext_capture import (
    capture_plaintext,
    discard_capture,
    publish_plaintext_no_replace,
    read_captured_plaintext,
    read_regular_plaintext,
    restore_capture_no_replace,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .anchor import AnchorStore
    from .wrap import NativeBackend

__all__ = ["config_hook_installed", "install_config_decrypt", "materialize_config", "reseal_config"]

_CONFIG_NAME = "config.yaml"
# Opt-in marker: its presence puts config.yaml on the vault-managed lifecycle.
# Written by ``hermes-mordred vault enable-config-decrypt`` (wizard CLI).
_MARKER_SUBPATH = ("mordred", "config-vault.marker")

# A fail-closed materialize raises at interpreter startup via the .pth hook, which
# fires for EVERY Hermes invocation — including the recovery command itself. So the
# recovery hint must tell the operator to bypass the hook with MORDRED_CONFIG_DECRYPT=0,
# or `disable-config-decrypt` would be blocked by the very hook it is trying to undo.
_RECOVERY_HINT = "to recover, run: MORDRED_CONFIG_DECRYPT=0 hermes-mordred vault disable-config-decrypt"


def _marker_path(home: Path) -> Path:
    """The opt-in marker path for a Hermes home: ``<home>/mordred/config-vault.marker``."""
    return home.joinpath(*_MARKER_SUBPATH)


#: The startup ``.pth`` the wheel force-includes at the site-packages root (see
#: ``packaging/pth/`` + ``pyproject.toml``). Its presence is what makes a Hermes
#: interpreter run the materialize/reseal lifecycle.
_PTH_HOOK_FILENAME = "mordred_hermes_config_decrypt.pth"


def _interpreter_site_dirs() -> list[str]:
    """site-packages directories for the *current* interpreter (best-effort)."""
    dirs: list[str] = []
    # Some embedded / older virtualenv interpreters omit getsitepackages().
    with contextlib.suppress(AttributeError):
        dirs.extend(site.getsitepackages())
    user = site.getusersitepackages()
    if isinstance(user, str):
        dirs.append(user)
    return dirs


def config_hook_installed(*, site_dirs: Sequence[str] | None = None) -> bool:
    """Whether the config.yaml decrypt ``.pth`` hook is installed for THIS interpreter.

    Scans the interpreter's site-packages for the force-included
    :data:`_PTH_HOOK_FILENAME` and confirms it actually wires the bootstrap (a
    same-named file that does not reference ``_pth_bootstrap`` does not count).

    ``encryption enable`` / ``status`` run via the same ``hermes-mordred``
    interpreter whose startup would materialize/reseal ``config.yaml``, so this
    answers the real question — *will my runtime actually seal config.yaml?* —
    rather than merely *is the opt-in marker set?*. ``site_dirs`` is injectable
    for tests; production resolves it from the live interpreter.
    """
    dirs = list(site_dirs) if site_dirs is not None else _interpreter_site_dirs()
    for d in dirs:
        candidate = Path(d) / _PTH_HOOK_FILENAME
        try:
            if candidate.is_file() and "_pth_bootstrap" in candidate.read_text(encoding="utf-8"):
                return True
        except OSError:
            continue
    return False


def materialize_config(
    *,
    root: Path,
    home: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    config_name: str = _CONFIG_NAME,
) -> int:
    """Decrypt the vault-enrolled ``config_name`` onto ``<home>/config_name`` at startup.

    Returns 1 when a current plaintext working copy is present after the call (so
    Hermes can read it), 0 when the operator has not opted in (no marker → Hermes
    runs unchanged).

    Fail-closed: when the marker is present but the vault is missing, unopenable,
    tampered, or holds no enrolled config and no plaintext exists, the error
    propagates — the process must not start on a default / stale config. An
    on-disk working copy that differs from the vault is treated as authoritative
    (live edit / unclean prior exit) and re-synced into the vault.
    """
    if not _marker_path(home).exists():
        return 0  # not opted in

    from . import anchor, vault

    key_id = anchor_label = vault_identity(root)
    backend, store = resolve_backend_store(backend, store)

    # No anchor → no usable vault. The marker promises a vault-managed config, so
    # refusing is the fail-closed choice: starting on default config would silently
    # drop the operator's settings. Distinguish anchor deletion (artifacts remain,
    # vault.artifacts_present) for a sharper message — a Keychain *read error*
    # propagates untouched. The open's own anchor read is the presence check
    # (AnchorMissing only when the item is absent): one Keychain read, not two.
    try:
        opened = vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
    except anchor.AnchorMissing as exc:
        if vault.artifacts_present(root):
            raise vault.VaultError(
                f"config.yaml is vault-managed but the device anchor at {root} is missing "
                f"— refusing to start (possible anchor deletion). {_RECOVERY_HINT}"
            ) from exc
        raise vault.VaultError(
            f"config.yaml is marked vault-managed but no vault exists at {root}. {_RECOVERY_HINT}"
        ) from exc

    plaintext_path = home / config_name
    with opened:
        enrolled = config_name in opened.list_files()

        if plaintext_path.exists() or plaintext_path.is_symlink():
            disk_bytes = read_regular_plaintext(plaintext_path, make_private=True)
            vault_bytes = opened.read_file(config_name) if enrolled else None
            if disk_bytes != vault_bytes:
                # The working copy is authoritative — persist it into the vault and
                # leave it in place as this session's config.
                opened.enroll_file(config_name, disk_bytes)
            return 1

        if not enrolled:
            raise vault.VaultError(
                f"config.yaml is marked vault-managed but not enrolled in the vault at {root} "
                f"and no plaintext is present — nothing to materialize. {_RECOVERY_HINT}"
            )
        # No working copy was observed. Publish the complete decrypted inode
        # with atomic no-replace semantics: a host/process that creates a live
        # config during the vault read wins and must never be overwritten.
        vault_bytes = opened.read_file(config_name)
        if not publish_plaintext_no_replace(plaintext_path, vault_bytes):
            # The racing live file is authoritative by the same unclean-exit
            # rule as the initial-present branch. Read one regular inode
            # without following/blocking and reconcile it into the vault.
            disk_bytes = read_regular_plaintext(plaintext_path, make_private=True)
            if disk_bytes != vault_bytes:
                opened.enroll_file(config_name, disk_bytes)
        return 1


def _restore_failed_config_capture(captured_path: Path, plaintext_path: Path) -> None:
    """Restore without replacing a concurrent new live config."""
    try:
        restored = restore_capture_no_replace(captured_path, plaintext_path)
    except OSError as restore_exc:
        _term.emit_warn(
            f"config.yaml reseal failed and its captured plaintext could not "
            f"be restored: {restore_exc}. It remains at {captured_path}."
        )
        return
    if not restored:
        _term.emit_warn(
            f"config.yaml changed during the failed reseal. The newer live "
            f"file was preserved and the earlier capture remains at {captured_path}."
        )


def _discard_resealed_config_capture(captured_path: Path, plaintext_path: Path) -> int:
    """Remove only the enrolled capture, never a concurrent live replacement."""
    try:
        discard_capture(captured_path)
    except OSError as exc:
        _term.emit_warn(
            f"config.yaml was resealed but its captured plaintext deletion at "
            f"{captured_path} could not be made durable: {exc} — inspect and remove any residue."
        )
        return 0
    if plaintext_path.exists() or plaintext_path.is_symlink():
        _term.emit_warn(
            "config.yaml changed while it was being resealed. The captured "
            "version was enrolled and the newer live plaintext was left for "
            "the next reseal."
        )
        return 0
    return 1


def reseal_config(
    *,
    root: Path,
    home: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    config_name: str = _CONFIG_NAME,
) -> int:
    """Re-enroll the working copy if it changed, then remove the on-disk plaintext.

    Returns 1 when a plaintext working copy was resealed and removed, 0 when there
    was nothing to do (not opted in, or no plaintext present). Fail-closed: if the
    vault cannot be opened to persist a changed copy, the error propagates and the
    plaintext is **left in place** (no data loss) for the next start to self-heal.
    """
    if not _marker_path(home).exists():
        return 0  # not opted in — never touch an unmanaged config

    plaintext_path = home / config_name
    if not (plaintext_path.exists() or plaintext_path.is_symlink()):
        return 0

    from . import vault

    key_id = anchor_label = vault_identity(root)
    backend, store = resolve_backend_store(backend, store)

    try:
        captured_path = capture_plaintext(plaintext_path)
    except OSError as exc:
        _term.emit_warn(f"config.yaml could not be safely captured for reseal: {exc} — leaving it in place.")
        return 0
    if captured_path is None:
        return 0

    try:
        disk_bytes = read_captured_plaintext(captured_path)
        with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
            enrolled = config_name in opened.list_files()
            vault_bytes = opened.read_file(config_name) if enrolled else None
            if disk_bytes != vault_bytes:
                opened.enroll_file(config_name, disk_bytes)
    except BaseException:
        _restore_failed_config_capture(captured_path, plaintext_path)
        raise

    # Enrollment consumed exactly the privately-captured inode. Delete only
    # that name; a writer that recreated live config.yaml is left untouched.
    return _discard_resealed_config_capture(captured_path, plaintext_path)


def install_config_decrypt(*, home: Path | None = None) -> int:
    """Materialize config.yaml at startup and register the reseal for interpreter exit.

    **macOS-only**: the unattended hot path needs a device key store (Secure
    Enclave or its software fallback). On other platforms this is a no-op so Hermes
    runs unchanged. Called from the ``.pth`` startup hook before ``cli.py`` is
    imported. Returns the :func:`materialize_config` result.
    """
    if sys.platform != "darwin":
        return 0
    if home is None:
        home = hermes_home()
    root = default_vault_root()
    n = materialize_config(root=root, home=home)
    if n:
        # Reseal at clean interpreter exit. A hard kill (SIGKILL) cannot run this;
        # the next materialize_config self-heals by re-syncing the leftover plaintext.
        atexit.register(reseal_config, root=root, home=home)
    return n
