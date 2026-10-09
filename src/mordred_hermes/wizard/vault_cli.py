"""``hermes mordred vault {status,...}`` — at-rest vault CLI.

The path and lifecycle contracts live in ``docs/dev/PATHS.md`` and
``docs/dev/SPEC.md``.

The at-rest vault (``keyvault/{vault,manifest,anchor,file_container}.py``)
generalises secret-at-rest encryption beyond the legacy keyvault. This module
is the ``hermes-mordred vault`` argparse surface: it wires each subcommand to
the command functions, which are split across sibling modules —

* :mod:`mordred_hermes.wizard._vault_open` — shared open / identity helpers
  (``_resolve_root`` / ``_vault_identity`` / ``_open_cold_path`` /
  ``_open_hot_path_or_report`` / ``_build_device_auth`` / ``_display_name``).
* :mod:`mordred_hermes.wizard._vault_lifecycle` — ``init`` / ``ensure_initialised``
  / ``change_passphrase`` / ``recover``.
* :mod:`mordred_hermes.wizard._vault_entries` — ``status`` / ``cat`` / ``add`` /
  ``add_and_verify`` / ``migrate``.

All of those are re-exported here so existing ``from .vault_cli import …``
callers (and tests that patch ``vault_cli.<name>``) keep working unchanged.

Heavy imports (the cryptography-backed vault modules) stay function-local so
this module imports on any platform, matching ``keyvault_cli.py``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .._home import hermes_home as _hermes_home
from ..keyvault import _identity as _identity  # re-exported: tests patch vault_cli._identity._hermes_home
from . import _term
from ._vault_entries import (
    add,
    add_and_verify,
    cat,
    migrate,
    status,
)
from ._vault_lifecycle import (
    change_passphrase,
    ensure_initialised,
    init,
    recover,
)
from ._vault_open import (
    _open_hot_path_or_report as _open_hot_path_or_report,  # re-exported for vault_memory_key + tests
)
from ._vault_open import _resolve_root as _resolve_root  # re-exported for vault_memory_key + tests
from ._vault_open import (
    _vault_identity as _vault_identity,  # re-exported for tests
)

__all__ = [
    "add",
    "add_and_verify",
    "cat",
    "change_passphrase",
    "cli_add",
    "cli_cat",
    "cli_change_passphrase",
    "cli_init",
    "cli_migrate",
    "cli_recover",
    "cli_status",
    "ensure_initialised",
    "init",
    "migrate",
    "recover",
    "status",
]


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_add(args: argparse.Namespace) -> int:
    """argparse handler for ``vault add <name> <source> [--root PATH]``."""
    return add(root=_resolve_root(getattr(args, "root", None)), name=args.name, source=Path(args.source))


def _default_migrate_sources() -> list[Path]:
    """The canonical Hermes plaintext files to import — those that exist.

    The vault's reason for being (design §8.2): the operator's existing
    ``<hermes home>/.env`` and ``<hermes home>/config.yaml``. Absent ones are
    skipped so a no-argument ``vault migrate`` imports whatever is actually
    there. Resolved via this module's :func:`_hermes_home` so tests can
    monkeypatch the home.
    """
    home = _hermes_home()
    # Order is intentional and asserted by tests: .env before config.yaml.
    return [p for p in (home / ".env", home / "config.yaml") if p.is_file()]


def cli_migrate(args: argparse.Namespace) -> int:
    """argparse handler for ``vault migrate [SOURCE ...] [--root PATH]``.

    With explicit ``SOURCE`` paths, migrates exactly those. With none, imports
    the canonical Hermes plaintext set (:func:`_default_migrate_sources`). When
    neither is available, prints guidance and returns 1 rather than silently
    doing nothing.
    """
    explicit = [Path(s) for s in (getattr(args, "source", None) or [])]
    sources = explicit if explicit else _default_migrate_sources()
    if not sources:
        _term.emit_error(
            "Nothing to migrate: no .env or config.yaml under the Hermes home. "
            "Pass file paths explicitly to migrate other files."
        )
        return 1
    return migrate(root=_resolve_root(getattr(args, "root", None)), sources=sources)


def cli_init(args: argparse.Namespace) -> int:
    """argparse handler for ``vault init [--root PATH]``."""
    return init(root=_resolve_root(getattr(args, "root", None)))


def cli_change_passphrase(args: argparse.Namespace) -> int:
    """argparse handler for ``vault change-passphrase [--root PATH]`` (and its
    ``encryption change-passphrase`` alias)."""
    return change_passphrase(root=_resolve_root(getattr(args, "root", None)))


def cli_recover(args: argparse.Namespace) -> int:
    """argparse handler for ``vault recover [--root PATH]``."""
    return recover(root=_resolve_root(getattr(args, "root", None)))


def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``vault status [--root PATH] [--json]``. Never prompts."""
    return status(
        root=_resolve_root(getattr(args, "root", None)),
        as_json=bool(getattr(args, "json", False)),
    )


def cli_cat(args: argparse.Namespace) -> int:
    """argparse handler for ``vault cat <name> [--root PATH]``."""
    return cat(root=_resolve_root(getattr(args, "root", None)), name=args.name)
