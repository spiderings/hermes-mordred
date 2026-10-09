"""Mordred's Hermes plugin identity and the legacy-name migration.

Mordred registers with Hermes as ONE entry-point plugin, ``mordred``
(:mod:`mordred_hermes.plugin`). Releases up to 0.1.0a20 registered six separate
entry points instead (``mordred_network``, ``mordred_privacy_check``,
``mordred_llm_guard``, ``mordred_keyvault``, ``mordred_wizard``,
``mordred_e2e``); an existing ``config.yaml`` may still list those names in
``plugins.enabled`` / ``plugins.disabled``, where Hermes now ignores them.

This module owns the identity constants and the pure list migration every
config writer applies. It is stdlib-only and side-effect-free at import.

Note the difference between *plugin identity* and *config sections*: the
``plugins.mordred_network`` / ``plugins.mordred_privacy_check`` /
``plugins.mordred_llm_guard`` mappings in ``config.yaml`` are Mordred's own
settings blocks, read by Mordred directly. They keep their names.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass, field
from typing import Any, Final

PLUGIN_NAME: Final = "mordred"

LEGACY_PLUGIN_NAMES: Final = (
    "mordred_privacy_check",
    "mordred_wizard",
    "mordred_llm_guard",
    "mordred_network",
    "mordred_keyvault",
    "mordred_e2e",
)

MIGRATE_COMMAND: Final = "hermes-mordred plugins migrate"


@dataclass
class PluginListMigration:
    """What :func:`migrate_plugin_lists` changed (empty lists = nothing to do)."""

    removed_enabled: list[str] = field(default_factory=list)
    removed_disabled: list[str] = field(default_factory=list)
    added_enabled: bool = False
    #: ``plugins.enabled`` was missing, not a list, or held non-string / empty entries.
    repaired: bool = False
    #: ``mordred`` itself is in ``plugins.disabled``; left alone (explicit opt-out).
    mordred_disabled: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.removed_enabled or self.removed_disabled or self.added_enabled or self.repaired)

    def notes(self) -> list[str]:
        """Operator-facing lines describing the migration (empty when unchanged)."""
        lines: list[str] = []
        if self.removed_enabled:
            lines.append(
                f"plugins.enabled: replaced the legacy Mordred plugin names {', '.join(self.removed_enabled)} "
                f"with the single plugin '{PLUGIN_NAME}'."
            )
        elif self.added_enabled:
            lines.append(f"plugins.enabled: added '{PLUGIN_NAME}'.")
        if self.removed_disabled:
            lines.append(
                f"plugins.disabled listed {', '.join(self.removed_disabled)}. Mordred is now one plugin and its "
                "parts can no longer be disabled separately, so those entries were removed and every Mordred "
                f"protection is on. To turn Mordred off entirely, add '{PLUGIN_NAME}' to plugins.disabled."
            )
        if self.mordred_disabled:
            lines.append(
                f"plugins.disabled still lists '{PLUGIN_NAME}', so Hermes will not load Mordred; "
                "remove it there to turn Mordred on."
            )
        return lines


def has_legacy_names(plugins: Any) -> bool:
    """Whether a ``plugins`` mapping still lists any legacy Mordred plugin name."""
    if not isinstance(plugins, MutableMapping):
        return False
    for key in ("enabled", "disabled"):
        names = plugins.get(key)
        if isinstance(names, list) and any(name in LEGACY_PLUGIN_NAMES for name in names):
            return True
    return False


def migrate_plugin_lists(plugins: MutableMapping[str, Any]) -> PluginListMigration:
    """Rewrite a ``plugins`` mapping in place to the single ``mordred`` identity.

    - legacy names are removed from ``plugins.enabled`` and ``plugins.disabled``;
    - ``mordred`` is appended to ``plugins.enabled`` (created when absent or not
      a list; a scalar name is kept);
    - ``mordred`` already in ``plugins.disabled`` is an explicit opt-out of the
      whole plugin and is left alone (reported, not overridden).

    A legacy *disabled* entry is not carried over as a disable of ``mordred``:
    disabling one piece used to leave the rest running, so turning everything
    off would be a bigger change than the operator made, and keeping a stale
    name would silently do nothing. The note from :meth:`PluginListMigration.notes`
    tells the operator what happened.
    """
    result = PluginListMigration()
    _migrate_disabled(plugins, result)
    _migrate_enabled(plugins, result)
    return result


def _without_legacy(names: list[Any], removed: list[str]) -> list[Any]:
    """``names`` minus legacy Mordred names, which are appended to ``removed``."""
    kept = []
    for name in names:
        if name in LEGACY_PLUGIN_NAMES:
            removed.append(name)
        else:
            kept.append(name)
    return kept


def _migrate_disabled(plugins: MutableMapping[str, Any], result: PluginListMigration) -> None:
    disabled = plugins.get("disabled")
    if not isinstance(disabled, list):
        return
    kept = _without_legacy(disabled, result.removed_disabled)
    if result.removed_disabled:
        disabled[:] = kept
    result.mordred_disabled = PLUGIN_NAME in disabled


def _migrate_enabled(plugins: MutableMapping[str, Any], result: PluginListMigration) -> None:
    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        # Hermes treats a missing or malformed allow-list as "nothing enabled";
        # keep a scalar plugin name when there is one.
        result.repaired = enabled is not None
        enabled = [enabled] if isinstance(enabled, str) and enabled.strip() else []
        plugins["enabled"] = enabled
    sanitized = [name for name in enabled if isinstance(name, str) and name.strip()]
    if len(sanitized) != len(enabled):
        result.repaired = True
    kept = _without_legacy(sanitized, result.removed_enabled)
    if len(kept) != len(enabled):
        enabled[:] = kept
    if PLUGIN_NAME not in enabled:
        enabled.append(PLUGIN_NAME)
        result.added_enabled = True
