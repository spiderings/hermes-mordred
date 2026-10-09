"""Runtime env transparent-decrypt shim (design note §8.2 item 3).

Injects the vault-enrolled ``.env`` into the process environment at startup so an
unattended Hermes process (telegram / gateway / cron) reads secrets from the
at-rest vault instead of plaintext on disk. Opens on the **hot path** (device key
— Secure Enclave or its software fallback, no passphrase) and is **fail-closed**.

Heavy imports (the cryptography-backed vault modules, dotenv) stay function-local
so this module imports on any platform, matching ``wizard/vault_cli.py``.
"""

from __future__ import annotations

import io
import os
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import TYPE_CHECKING

from .._home import hermes_home as _hermes_home
from ._identity import default_vault_root, resolve_backend_store, vault_identity

if TYPE_CHECKING:
    from .anchor import AnchorStore
    from .wrap import NativeBackend

__all__ = ["inject_vault_env", "install_vault_env_decrypt"]

# Opt-out marker: its presence suppresses runtime .env injection even while the
# vault still holds an enrolled ``.env`` (the reversible "disable" state). Mirrors
# the config opt-IN marker in :mod:`._config_bootstrap`, but inverted — env is
# injected by default once enrolled, so the marker turns it OFF.
_ENV_OPTOUT_SUBPATH = ("mordred", "env-vault.optout")


def _env_optout_marker_path(home: Path) -> Path:
    """The env opt-out marker path: ``<home>/mordred/env-vault.optout``."""
    return home.joinpath(*_ENV_OPTOUT_SUBPATH)


def inject_vault_env(
    *,
    root: Path,
    environ: MutableMapping[str, str],
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    name: str = ".env",
) -> int:
    """Decrypt the vault-enrolled ``name`` (``.env``) at ``root`` into ``environ``.

    Opens the vault on the hot path and injects each ``KEY=value`` from the
    enrolled ``name`` into ``environ`` with **override** semantics — matching
    Hermes's own ``load_hermes_dotenv(override=True)``, where ``~/.hermes/.env``
    is authoritative over stale shell values.

    **Fail-closed**: if a vault is present at ``root`` but cannot be opened,
    verified, or read (tamper, wrong/locked key, non-UTF-8 payload), the error
    propagates — the process must not start with unverified secret provisioning.
    If no anchor exists **and** no vault artifacts are on disk, returns 0 (Hermes
    runs unchanged when at-rest encryption is not set up). A missing anchor while
    ``manifest.*.mvmf`` remain on disk is treated as tampering (anchor deletion)
    and raises. A vault present but with no enrolled ``name`` returns 0.

    Values are injected verbatim (no ``${VAR}`` interpolation).

    ``backend`` / ``store`` default to the production implementations; tests
    inject fakes. Returns the number of variables injected.
    """
    from dotenv import dotenv_values

    from . import anchor, vault

    key_id = anchor_label = vault_identity(root)
    backend, store = resolve_backend_store(backend, store)

    # No anchor → no vault here: a clean no-op. BUT if vault artifacts are still
    # on disk while the anchor is gone (vault.artifacts_present), that is
    # anomalous and we fail closed rather than silently no-op. A read *error*
    # (e.g. a locked Keychain) is likewise never swallowed: it propagates
    # fail-closed, since we cannot prove the vault absent. The open's own anchor
    # read doubles as the presence check (AnchorMissing is raised only when the
    # item is absent), so a start reads the Keychain item once, not twice.
    try:
        opened = vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
    except anchor.AnchorMissing as exc:
        if vault.artifacts_present(root):
            raise vault.VaultError(
                f"vault artifacts present at {root} but the device anchor is missing "
                "— refusing to start (possible anchor deletion)."
            ) from exc
        return 0

    with opened:
        if name not in opened.list_files():
            return 0
        plaintext = opened.read_file(name)

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise vault.VaultError(f"enrolled {name!r} is not valid UTF-8 — cannot parse as .env") from exc

    # interpolate=False: secret values are injected verbatim; a value containing
    # ``${...}`` must not be expanded against other vars / os.environ.
    values = dotenv_values(stream=io.StringIO(text), interpolate=False)
    injected = 0
    for env_key, env_value in values.items():
        if env_value is None:  # a bare ``KEY`` with no ``=value`` parses to None — skip it
            continue
        environ[env_key] = env_value
        injected += 1
    return injected


def install_vault_env_decrypt(*, environ: MutableMapping[str, str] | None = None) -> int:
    """Install the runtime env decrypt at startup (called from the plugin ``register()``).

    **macOS-only**: the unattended hot path needs a device key store (Secure
    Enclave or its software fallback), which is macOS-specific. On other platforms
    this is a no-op so Hermes runs unchanged. Injects into ``os.environ`` by
    default. Returns the number of variables injected.

    Honors the env **opt-out marker** (the reversible "disable" state): when
    ``<home>/mordred/env-vault.optout`` is present the vault is never opened and
    nothing is injected, even if ``.env`` is still enrolled — the operator has
    restored a plaintext ``.env`` and wants the runtime to use that.
    """
    if sys.platform != "darwin":
        return 0
    if environ is None:
        environ = os.environ
    if _env_optout_marker_path(_hermes_home()).exists():
        return 0
    return inject_vault_env(root=default_vault_root(), environ=environ)
