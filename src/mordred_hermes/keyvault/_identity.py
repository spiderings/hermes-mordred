"""Shared vault root + identity derivation and production open defaults.

A vault's device-key tag and Keychain anchor account are both derived from its
root path, so every entry point — the operator CLI (``wizard/vault_cli.py``) and
the runtime decrypt shim (``_runtime_env.py``) — opens the **same** vault for a
given root. This lives in ``keyvault`` (not ``wizard``) so the runtime shim,
which ships in this package, needs no upward dependency on ``wizard``.

:func:`resolve_backend_store` extends the same every-entry-point-converges idea
to the hot-path implementations: the startup shims must all default to the one
production Secure-Enclave backend + Keychain anchor store, not each pick their
own.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from .._home import hermes_home as _hermes_home

if TYPE_CHECKING:
    from .anchor import AnchorStore
    from .wrap import NativeBackend

# Default vault root, relative to the Hermes home: ``<home>/mordred/vault``.
_VAULT_SUBDIR = ("mordred", "vault")


def default_vault_root() -> Path:
    """The default vault root: ``<hermes home>/mordred/vault``."""
    return _hermes_home().joinpath(*_VAULT_SUBDIR)


def resolve_root(root: str | None) -> Path:
    """Resolve a vault root, defaulting to :func:`default_vault_root`.

    A user-supplied root is resolved to an absolute, normalized path so the same
    vault yields the same :func:`vault_identity` regardless of spelling (relative
    path, ``..``, cwd). ``default_vault_root`` is already absolute.
    """
    if root is not None:
        return Path(root).resolve()
    return default_vault_root()


def vault_identity(root: Path) -> str:
    """Stable id (device-key tag + Keychain anchor account) for a vault root.

    Derived from the root path so distinct vaults never collide in the shared
    Keychain anchor service. The same root string always maps to the same id.
    """
    digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    return f"mordred-hermes.vault.{digest}"


def resolve_backend(backend: NativeBackend | None) -> NativeBackend:
    """Return ``backend``, or build the production Secure-Enclave backend.

    THE single definition of "``None`` means the production backend" — the
    startup shims, the wizard CLIs (via :mod:`..wizard._defaults`), and the
    privacy_check audit writer all resolve through here so the default cannot
    drift per entry point. The import stays function-local so this module
    remains importable on any platform; tests always inject fakes and never
    reach the production paths.
    """
    if backend is not None:
        return backend
    from ._seckey_backend import _SecKeyBackend

    return _SecKeyBackend()


def resolve_store(store: AnchorStore | None) -> AnchorStore:
    """Return ``store``, or build the production Keychain anchor store.

    Same single-definition contract (and same function-local import rule) as
    :func:`resolve_backend`. The production store is helper-owned when the
    Secure Enclave helper is installed (see
    :func:`._anchor_keychain.default_anchor_store`).
    """
    if store is not None:
        return store
    from ._anchor_keychain import default_anchor_store

    return default_anchor_store()


def resolve_backend_store(
    backend: NativeBackend | None, store: AnchorStore | None
) -> tuple[NativeBackend, AnchorStore]:
    """Default ``backend`` / ``store`` to the production hot-path implementations.

    Shared by the startup shims (:mod:`._runtime_env` / :mod:`._config_bootstrap`);
    composes the per-component resolvers so there is exactly one definition of
    each production default.
    """
    return resolve_backend(backend), resolve_store(store)
