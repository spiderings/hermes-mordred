"""Undo what Mordred wrote into Hermes's own ``config.yaml`` and ``.env``.

Mordred's writers touch a small, known part of Hermes's files:

``config.yaml``
    - ``plugins.enabled`` / ``plugins.disabled``: the ``mordred`` plugin name
      and the six pre-0.2.0a0 names (:mod:`.._plugin_identity`), written by
      :class:`.policy_writer.PolicyWriter`, ``desktop install`` and
      ``plugins migrate``;
    - ``plugins.mordred_*``: Mordred's own settings blocks (policy, LLM guard,
      network, tool egress), written by ``configure`` / ``upgrade`` /
      ``network`` / ``egress``;
    - ``memory.encryption``: a legacy flag older builds wrote (no Hermes
      release reads it).

``.env``
    - ``HERMES_MEMORY_KEY`` (added by ``encryption enable memory``) and
      ``MORDRED_*`` (``network init`` stores the Mullvad account there).

Everything else in both files belongs to Hermes or to the operator and is left
byte-for-byte alone, except that ``config.yaml`` is re-serialized by the same
round-trip writer Mordred used to edit it (comments and key order survive).
Mordred never recorded the values these keys replaced, and ``configure`` does
not change Hermes's ``model`` / provider settings (the ``hermes setup`` it may
launch is Hermes's own wizard), so there is nothing further to restore. Any
remaining reference to Mordred -- for example ``model.provider: mordred-local``
set by hand -- is reported, not guessed at.

The removed ``.env`` lines are saved (mode 0600) under ``<home>/mordred/`` so
nothing is lost; ``uninstall --purge-data`` deletes that directory.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import stat
from collections.abc import Iterator, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .._config_io import DOTENV_LIMIT, CanonicalPaths, canonical_session, read_canonical_snapshot
from .._plugin_identity import LEGACY_PLUGIN_NAMES, PLUGIN_NAME
from .._policy_io import policy_mapping_from_snapshot
from .._private_fs import PrivateFSError
from .._yaml_io import yaml_mapping_from_snapshot
from .policy_writer import _bounded_utf8, _canonical_paths, _checked_policy_edit, _windows, _write_checked_private

__all__ = [
    "ConfigCleanup",
    "EnvCleanup",
    "apply_config_cleanup",
    "apply_env_cleanup",
    "plan_config_cleanup",
    "plan_env_cleanup",
]

_MORDRED_PLUGIN_NAMES = frozenset((PLUGIN_NAME, *LEGACY_PLUGIN_NAMES))
_MEMORY_KEY_ENV = "HERMES_MEMORY_KEY"
_ENV_PREFIX = "MORDRED_"


# -----------------------------------------------------------------------------
# config.yaml
# -----------------------------------------------------------------------------
@dataclass
class ConfigCleanup:
    """What removing Mordred from ``config.yaml`` changes (or would change)."""

    path: Path
    removed: list[str] = field(default_factory=list)
    #: References to Mordred that stay because their previous value is unknown.
    unknowns: list[str] = field(default_factory=list)
    #: Set when the file cannot be read / parsed / edited; nothing is changed then.
    error: str | None = None
    #: The timestamped copy taken before writing (apply only).
    backup: Path | None = None

    @property
    def changed(self) -> bool:
        return bool(self.removed)


def _strip_plugin_lists(plugins: MutableMapping[Any, Any], removed: list[str]) -> None:
    for key in ("enabled", "disabled"):
        names = plugins.get(key)
        if isinstance(names, list):
            gone = [name for name in names if name in _MORDRED_PLUGIN_NAMES]
            if gone:
                names[:] = [name for name in names if name not in _MORDRED_PLUGIN_NAMES]
                removed.extend(f"plugins.{key}: {name}" for name in gone)
        elif isinstance(names, str) and names in _MORDRED_PLUGIN_NAMES:
            plugins[key] = []
            removed.append(f"plugins.{key}: {names}")


def _strip_sections(plugins: MutableMapping[Any, Any], removed: list[str]) -> None:
    for key in [key for key in plugins if isinstance(key, str) and key.startswith("mordred_")]:
        del plugins[key]
        removed.append(f"plugins.{key}")


def _strip_memory_flag(root: MutableMapping[Any, Any], removed: list[str]) -> None:
    """Drop ``memory.encryption`` when it holds nothing but the legacy flag."""
    memory = root.get("memory")
    if not isinstance(memory, MutableMapping):
        return
    encryption = memory.get("encryption")
    if isinstance(encryption, MutableMapping) and set(encryption) <= {"enabled"}:
        del memory["encryption"]
        removed.append("memory.encryption")
        if not memory:
            # Hermes's own config always has other memory settings; an empty
            # block was created by the legacy writer.
            del root["memory"]


def _find_unknowns(node: Any, prefix: str = "") -> list[str]:
    """Paths in ``node`` whose key or string value still mentions Mordred."""
    found: list[str] = []
    if isinstance(node, MutableMapping):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(key, str) and "mordred" in key.lower():
                found.append(path)
            found.extend(_find_unknowns(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_find_unknowns(value, f"{prefix}[{index}]"))
    elif isinstance(node, str) and "mordred" in node.lower():
        found.append(f"{prefix}: {node}")
    return found


def _strip(root: Any) -> tuple[list[str], list[str]]:
    removed: list[str] = []
    if isinstance(root, MutableMapping):
        plugins = root.get("plugins")
        if isinstance(plugins, MutableMapping):
            _strip_plugin_lists(plugins, removed)
            _strip_sections(plugins, removed)
        _strip_memory_flag(root, removed)
    return removed, _find_unknowns(root)


def _load(path: Path) -> tuple[Any, Any, str | None, str | None]:
    """``(yaml, root, text, error)`` for ``path`` via the round-trip loader."""
    from ruamel.yaml.error import YAMLError

    from .policy_writer import _read_regular_text, _round_trip_yaml

    yaml = _round_trip_yaml()
    if _windows():
        pair = read_canonical_snapshot(CanonicalPaths(path.parent, config_name=path.name))
        policy_mapping_from_snapshot(pair)
        root = yaml_mapping_from_snapshot(pair, round_trip=True)
        return yaml, root, pair.config.data.decode("utf-8") if pair.config else None, None
    try:
        text = _read_regular_text(path)
    except (OSError, UnicodeDecodeError) as exc:
        return yaml, None, None, f"cannot read {path}: {exc}"
    if text is None:
        return yaml, None, None, None
    try:
        return yaml, yaml.load(text), text, None
    except YAMLError as exc:
        return yaml, None, text, f"{path} is not valid YAML ({exc.__class__.__name__}); edit it by hand"


def plan_config_cleanup(path: Path) -> ConfigCleanup:
    """What :func:`apply_config_cleanup` would change. Read-only."""
    result = ConfigCleanup(path)
    _yaml, root, _text, error = _load(path)
    if error is not None:
        result.error = error
        return result
    result.removed, result.unknowns = _strip(root)
    return result


@contextlib.contextmanager
def _maybe_policy_lock(lock_dir: Path) -> Iterator[None]:
    """Hold Mordred's config write lock when its directory exists (never create it)."""
    if not lock_dir.is_dir():
        yield
        return
    from .policy_writer import _policy_write_lock

    with _policy_write_lock(lock_dir):
        yield


def apply_config_cleanup(path: Path, *, lock_dir: Path, stamp: str) -> ConfigCleanup:
    """Remove Mordred's entries from ``path``, keeping a timestamped backup first.

    Writes nothing when there is nothing to remove (idempotent). The file mode
    is preserved.
    """
    from .policy_writer import _atomic_write_text

    result = ConfigCleanup(path)
    if _windows():
        _validate_stamp(stamp)
        paths = _canonical_paths(path, lock_dir / "policy.json", lock_dir)
        with _checked_policy_edit(paths) as edit:
            result.removed, result.unknowns = _strip(edit.root)
            if not result.removed:
                return result
            source = edit.session.read_pair().config
            if source is None:
                raise ValueError("config disappeared during cleanup")
            edit.dump_config()
            backup = path.with_name(f"{path.name}.mordred-uninstall-{stamp}.bak")
            edit.session.write_home(backup.name, source.data)
            result.backup = backup
        return result
    with _maybe_policy_lock(lock_dir):
        yaml, root, text, error = _load(path)
        if error is not None:
            result.error = error
            return result
        result.removed, result.unknowns = _strip(root)
        if not result.removed or text is None:
            return result
        backup = path.with_name(f"{path.name}.mordred-uninstall-{stamp}.bak")
        shutil.copy2(path, backup)
        result.backup = backup
        buf = io.StringIO()
        yaml.dump(root, buf)
        _atomic_write_text(path, buf.getvalue(), mode=stat.S_IMODE(path.stat().st_mode))
    return result


# -----------------------------------------------------------------------------
# .env
# -----------------------------------------------------------------------------
@dataclass
class EnvCleanup:
    path: Path
    #: Variable names removed (or that would be removed).
    names: list[str] = field(default_factory=list)
    #: Where the removed lines were saved (apply only).
    saved_to: Path | None = None
    error: str | None = None


def _is_mordred_key(name: str | None) -> bool:
    return name is not None and (name == _MEMORY_KEY_ENV or name.startswith(_ENV_PREFIX))


def _split_env(text: str) -> tuple[str, str, list[str]]:
    """``(kept_text, removed_text, removed_names)`` -- lines are kept verbatim."""
    from dotenv.parser import parse_stream

    kept: list[str] = []
    removed: list[str] = []
    names: list[str] = []
    for binding in parse_stream(io.StringIO(text)):
        if _is_mordred_key(binding.key):
            removed.append(binding.original.string)
            if binding.key not in names:
                names.append(str(binding.key))
        else:
            kept.append(binding.original.string)
    return "".join(kept), "".join(removed), names


def _read_env(path: Path) -> tuple[str | None, str | None]:
    if _windows():
        with canonical_session(CanonicalPaths(path.parent), scope="home") as session:
            source = session.read_home(path.name, max_bytes=DOTENV_LIMIT)
            text = source.data.decode("utf-8") if source else None
        return text, None
    if path.is_symlink():
        return None, f"{path} is a symlink; not editing it"
    try:
        return path.read_text(encoding="utf-8"), None
    except FileNotFoundError:
        return None, None
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"cannot read {path}: {exc}"


def plan_env_cleanup(path: Path) -> EnvCleanup:
    result = EnvCleanup(path)
    text, result.error = _read_env(path)
    if text is not None:
        _kept, _removed, result.names = _split_env(text)
    return result


def apply_env_cleanup(path: Path, *, save_dir: Path, stamp: str) -> EnvCleanup:
    """Move Mordred's variables out of ``path`` into ``save_dir`` (mode 0600)."""
    from .policy_writer import _atomic_write_text

    if _windows():
        return _apply_checked_env_cleanup(path, save_dir=save_dir, stamp=stamp)
    result = EnvCleanup(path)
    text, result.error = _read_env(path)
    if text is None:
        return result
    kept, removed, result.names = _split_env(text)
    if not result.names:
        return result
    save_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    saved = save_dir / f"env-removed-{stamp}.env"
    header = "# Lines hermes-mordred uninstall removed from .env (Mordred-owned variables).\n"
    _atomic_write_text(saved, header + removed + ("" if removed.endswith("\n") else "\n"), mode=0o600)
    result.saved_to = saved
    _atomic_write_text(path, kept, mode=stat.S_IMODE(os.stat(path).st_mode))
    return result


def _validate_stamp(stamp: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9_-]+", stamp) is None:
        raise ValueError("invalid backup stamp")


def _apply_checked_env_cleanup(path: Path, *, save_dir: Path, stamp: str) -> EnvCleanup:
    _validate_stamp(stamp)
    if path.name != ".env":
        raise ValueError("canonical dotenv filename must be .env")
    result = EnvCleanup(path)
    paths = CanonicalPaths(path.parent)
    published = False
    try:
        with canonical_session(paths, scope="policy", create=True) as session:
            source = session.read_home(".env", max_bytes=DOTENV_LIMIT)
            if source is None:
                return result
            kept, removed, result.names = _split_env(source.data.decode("utf-8"))
            if not result.names:
                return result
            header = "# Lines hermes-mordred uninstall removed from .env (Mordred-owned variables).\n"
            backup_data = _bounded_utf8(header + removed + ("" if removed.endswith("\n") else "\n"), DOTENV_LIMIT)
            kept_data = _bounded_utf8(kept, DOTENV_LIMIT)
            saved = save_dir / f"env-removed-{stamp}.env"
            if save_dir == paths.home / paths.mordred_name:
                session.create_policy_backup(saved.name, backup_data)
            else:
                if (
                    not save_dir.is_absolute()
                    or save_dir == paths.home
                    or save_dir in paths.home.parents
                    or any("~" in part for part in save_dir.parts)
                ):
                    raise ValueError("backup directory must be a distinct checked private location")
                published = _write_checked_private(saved, backup_data, backup=True)
            result.saved_to = saved
            session.write_home(".env", kept_data)
    except PrivateFSError as exc:
        if published:
            exc.commit_state = "uncertain"
        raise
    return result
