"""``hermes-mordred desktop install|uninstall`` — place the Hermes Desktop half.

Hermes loads a desktop page and its local API only from folders, not from a
pip entry point:

- the page: ``<home>/desktop-plugins/mordred/plugin.js``. Hermes Desktop's
  "disk door" for user plugins, which it loads enabled. (A page shipped as
  ``<home>/plugins/<id>/desktop/`` is copied there by the app but starts
  switched off until the user finds it under Skills & Tools → Plugins, so
  it is not used.)
- the local API: ``<home>/plugins/mordred/dashboard/``, a thin module that
  imports :mod:`.api` from the installed package.

``install`` writes both and enables ``mordred`` in ``plugins.enabled``;
:func:`ensure_page` rewrites only changed files and is called by the plugin at
every start, so any install method (installer, agent, pip) gets the page.

``mordred`` is also the name of Mordred's single entry-point plugin
(:mod:`mordred_hermes.plugin`), so one ``plugins.enabled`` entry turns on both
halves and Hermes Desktop shows them as one plugin row (its hub matches the
dashboard manifest's ``name`` to the agent plugin). The folder has no
``plugin.yaml``, so Hermes' agent-plugin scanner finds no directory plugin
there that could shadow the entry point. For the same reason ``uninstall``
removes only the folder and leaves ``plugins.enabled`` alone: dropping
``mordred`` there would turn every Mordred protection off.
"""

from __future__ import annotations

import argparse
import shutil
from importlib import resources
from pathlib import Path

from ..wizard import _term

PLUGIN_ID = "mordred"
_PAGE_FILE = "desktop/plugin.js"
_API_FILES = ("dashboard/manifest.json", "dashboard/plugin_api.py")
_FILES = (_PAGE_FILE, *_API_FILES)


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def plugin_dir(home: Path | None = None) -> Path:
    return (home or _home()) / "plugins" / PLUGIN_ID


def page_dir(home: Path | None = None) -> Path:
    return (home or _home()) / "desktop-plugins" / PLUGIN_ID


def _targets(base: Path) -> dict[str, Path]:
    targets = {rel: plugin_dir(base) / rel for rel in _API_FILES}
    targets[_PAGE_FILE] = page_dir(base) / "plugin.js"
    return targets


def ensure_page(home: Path | None = None) -> bool:
    """Write the page and API files that are missing or outdated; return whether any changed.

    Never follows a symlinked folder, and never touches ``config.yaml``.
    """
    base = home or _home()
    assets = resources.files("mordred_hermes.desktop").joinpath("assets")
    changed = False
    for rel, destination in _targets(base).items():
        if any(p.is_symlink() for p in (destination.parent, destination.parent.parent)):
            continue
        data = assets.joinpath(rel).read_bytes()
        try:
            if destination.read_bytes() == data:
                continue
        except OSError:
            pass
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = destination.with_name(f".{destination.name}.tmp")
        tmp.write_bytes(data)
        tmp.replace(destination)
        changed = True
    # Earlier builds put the page under plugins/mordred/desktop/, which the app
    # copies out as a second, switched-off "mordred" row. Drop it.
    legacy = plugin_dir(base) / "desktop"
    if legacy.is_dir() and not legacy.is_symlink():
        shutil.rmtree(legacy)
        changed = True
    return changed


def _enable(home: Path) -> None:
    """Add ``mordred`` to ``plugins.enabled`` (round-trip, locked), migrating legacy names."""
    from ..wizard.policy_writer import PolicyWriter

    writer = PolicyWriter(config_path=home / "config.yaml", policy_json_path=home / "mordred" / "policy.json")
    for note in writer.migrate_plugin_identity(create_missing=True).notes():
        _term.emit_warn(note)


def install(home: Path | None = None) -> int:
    base = home or _home()
    ensure_page(base)
    _enable(base)
    print(f"Installed the Mordred desktop page at {page_dir(base)}.")
    print("Next: restart Hermes Desktop, then open “Mordred” in the sidebar")
    print("(or ⌘K → “Mordred: Set up private Telegram”).")
    return 0


def remove_page(home: Path | None = None) -> bool:
    """Remove the page folder; return whether one was removed.

    A symlink at the folder path is left alone (this command never writes one).
    Shared by :func:`uninstall` and ``hermes-mordred uninstall``.
    """
    base = home or _home()
    removed = False
    for target in (page_dir(base), plugin_dir(base)):
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
            removed = True
    return removed


def uninstall(home: Path | None = None) -> int:
    remove_page(home)
    print("Removed the Mordred desktop page. Restart Hermes Desktop.")
    print("The Mordred plugin itself stays enabled; turn it off with `hermes plugins disable mordred`.")
    print("To remove Mordred completely, run `hermes-mordred uninstall`.")
    return 0


def status(home: Path | None = None) -> int:
    base = home or _home()
    missing = [str(path) for path in _targets(base).values() if not path.is_file()]
    if missing:
        _term.emit_warn(f"Mordred desktop page not installed (missing: {', '.join(missing)}).")
        return 1
    print(f"Mordred desktop page installed at {page_dir(base)}.")
    return 0


def cli_desktop(args: argparse.Namespace) -> int:
    command = getattr(args, "desktop_command", None)
    if command == "install":
        return install()
    if command == "uninstall":
        return uninstall()
    return status()
