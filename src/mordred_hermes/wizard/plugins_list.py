"""``hermes mordred plugins list|migrate`` -- Mordred plugin discovery and identity migration.

Hermes 0.11 silently drops ``ctx.register_cli_command`` from its argparse
build (only ``plugins.memory.discover_plugin_cli_commands`` is consulted);
that leaves users with no built-in way to confirm that Mordred loaded. This
module is the workaround -- a direct ``PluginManager`` query restricted to
the ``mordred`` plugin (plus any leftover pre-0.2.0a0 ``mordred_*`` names),
followed by the per-component registration status.

A YAML fallback reads ``~/.hermes/config.yaml`` ``plugins.enabled`` when
the ``hermes_cli.plugins`` module is unavailable (older / vendored Hermes
or test environments).

``plugins migrate`` rewrites ``plugins.enabled`` / ``plugins.disabled`` from the
six pre-0.2.0a0 plugin names to the single ``mordred`` plugin.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Protocol, cast

from ..__about__ import __version__ as _PACKAGE_VERSION
from .._home import HERMES_BASE
from .._plugin_identity import PLUGIN_NAME
from .._yaml_io import load_yaml_mapping
from . import _term

DEFAULT_CONFIG_PATH = HERMES_BASE / "config.yaml"

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "cli_handler",
    "migrate",
    "migrate_cli_handler",
    "run",
]


def _is_mordred_name(name: object) -> bool:
    """``mordred`` itself, or a leftover pre-0.2.0a0 ``mordred_*`` name."""
    return isinstance(name, str) and (name == PLUGIN_NAME or name.startswith("mordred_"))


class _ManagerLike(Protocol):
    """Minimal surface we depend on -- keeps tests free of hermes_cli."""

    def discover_and_load(self, force: bool = False) -> None: ...
    def list_plugins(self) -> list[dict[str, Any]]: ...


def _get_manager() -> _ManagerLike:
    """Return the Hermes PluginManager singleton.

    Raises :class:`ImportError` (re-raised by callers as the fallback
    trigger) when ``hermes_cli.plugins`` is not installed.
    """
    from hermes_cli.plugins import get_plugin_manager

    return cast(_ManagerLike, get_plugin_manager())


def _print_from_manager(mgr: _ManagerLike) -> int:
    mgr.discover_and_load()
    plugins = [p for p in mgr.list_plugins() if _is_mordred_name(str(p.get("key", "")))]
    if not plugins:
        print("No Mordred plugins discovered.")
        return 0
    for p in plugins:
        enabled = "enabled" if p.get("enabled") else "disabled"
        # Older Hermes builds leave an entry-point plugin's `version` empty,
        # so backfill with the hermes-mordred package version it ships from.
        version = p.get("version") or _PACKAGE_VERSION
        print(f"{p['key']:30s}  {version:10s}  {enabled}")
        if p.get("key") == PLUGIN_NAME and p.get("enabled"):
            _print_components()
    return 0


def _print_components() -> None:
    """Per-component registration status recorded by :mod:`mordred_hermes.plugin`."""
    from .. import plugin as bundle

    errors = bundle.component_errors()
    hooks = bundle.component_hooks()
    for component, _module in bundle.COMPONENTS:
        if component in errors:
            status = f"failed: {errors[component]}"
        elif component in hooks:
            status = "registered"
        else:
            status = "not registered"
        print(f"  {component:28s}  {status}")


def _print_from_yaml_fallback(config_path: Path) -> int:
    """Read ``plugins.enabled`` from config.yaml when PluginManager is absent."""
    print(f"(fallback: hermes_cli.plugins unavailable; reading {config_path})")
    if not config_path.exists():
        print("No Mordred plugins discovered (no config.yaml).")
        return 0
    try:
        # ``catch=()`` -- the shared helper's own default catch (OSError,
        # YAMLError) would swallow a read/parse failure into ``{}`` with only a
        # *logger* warning (no ``log=`` is wired here to a visible destination
        # anyway); this call site instead reports failures to the user via
        # ``_term.emit_error``, so every exception must propagate to the
        # ``except`` below rather than being absorbed inside the helper.
        data = load_yaml_mapping(config_path, catch=())
    except Exception as e:
        _term.emit_error(f"Failed to read {config_path}: {e}")
        return 0
    plugins_section = data.get("plugins")
    if not isinstance(plugins_section, dict):
        print("No Mordred plugins discovered.")
        return 0
    enabled = plugins_section.get("enabled")
    if not isinstance(enabled, list):
        print("No Mordred plugins discovered.")
        return 0
    mordred = [name for name in enabled if _is_mordred_name(name)]
    if not mordred:
        print("No Mordred plugins discovered.")
        return 0
    for name in mordred:
        print(f"{name:30s}  {_PACKAGE_VERSION:10s}  enabled")
    return 0


def run(*, config_path: Path = DEFAULT_CONFIG_PATH) -> int:
    """Print discovered Mordred plugins to stdout. Returns CLI exit code."""
    try:
        mgr = _get_manager()
    except ImportError:
        return _print_from_yaml_fallback(config_path)
    return _print_from_manager(mgr)


def cli_handler(args: argparse.Namespace) -> int:
    return run()


def migrate(*, config_path: Path = DEFAULT_CONFIG_PATH, only_legacy: bool = False) -> int:
    """Switch config.yaml to the single ``mordred`` plugin. Returns CLI exit code.

    ``only_legacy`` (the installer's mode) does nothing, silently, unless the
    config still lists a pre-0.2.0a0 plugin name: it keeps an already-enabled
    Mordred loading after an upgrade and never enables Mordred for a user who
    had not.
    """
    from .._plugin_identity import has_legacy_names
    from .policy_writer import PolicyWriter

    if not config_path.exists():
        if not only_legacy:
            print(f"No {config_path}; nothing to migrate.")
        return 0
    if only_legacy and not has_legacy_names(load_yaml_mapping(config_path, catch=(Exception,)).get("plugins")):
        return 0
    writer = PolicyWriter(config_path=config_path, policy_json_path=config_path.parent / "mordred" / "policy.json")
    migration = writer.migrate_plugin_identity()
    if not migration.changed:
        print(f"plugins.enabled already lists '{PLUGIN_NAME}'; nothing to migrate.")
    for note in migration.notes():
        print(note)
    if migration.changed:
        print("Restart Hermes (and Hermes Desktop) to load the migrated plugin list.")
    return 0


def migrate_cli_handler(args: argparse.Namespace) -> int:
    return migrate(only_legacy=bool(getattr(args, "only_legacy", False)))
