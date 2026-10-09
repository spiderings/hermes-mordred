"""Shared YAML read helper for config-reading plugin code.

Single-sources the "open ``config.yaml`` and hand back a mapping, or fall
back to empty on any read/parse failure" core that was independently
copy-pasted across five call sites (``network`` x2, ``llm_guard`` x2,
``privacy_check`` x1). Callers that extract something other than a plugin
section (e.g. the ``model.provider`` chain) still own their extraction and
their default; the ``plugins.<section>`` chain itself — which grew its own
copy-paste family across ``network``, ``llm_guard``, ``privacy_check`` and
the wizard — is single-sourced in :func:`load_plugin_section`.

:func:`load_yaml_mapping` keeps the two behaviours that genuinely diverged
across the call sites configurable, so each site's return values and
exception semantics are preserved exactly:

* ``catch`` -- the exception set routed to the degraded "empty mapping"
  path. Most callers narrow this to ``(OSError, YAMLError)`` so that
  programming errors still escape; two callers (``privacy_check._runtime``
  and ``llm_guard.harness_detect``) historically caught bare ``Exception``
  and pass ``catch=(Exception,)`` to preserve that wider net.
* ``log`` -- the caller's own logger, so the warning is attributed to the
  originating module. Passing ``None`` suppresses the warning entirely.

One thing is intentionally *not* preserved: the warning text is normalised
here to ``"could not read ..."``. The two broad-catch sites above previously
logged ``"failed to read ..."``; the wording is asserted by no test and is
not part of the behavioural contract (same normalisation precedent as the
``network/hooks`` audit-log message in #199).

The ``ruamel`` import is local (mirroring the previous per-site code) so
plugin discovery stays cheap and free of a hard ``ruamel`` import at
registration time.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from ._config_io import CanonicalPaths, CanonicalSnapshot

_platform = os.name


def yaml_mapping_from_snapshot(snapshot: CanonicalSnapshot, *, round_trip: bool = False) -> dict[str, Any]:
    """Parse this checked generation; malformed config raises, checked absence is empty."""
    from ruamel.yaml import YAML

    if snapshot.config is None:
        return {}
    yaml = YAML(typ="rt") if round_trip else YAML(typ="safe", pure=True)
    data = yaml.load(snapshot.config.data.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config YAML must contain a mapping")
    return data


def load_yaml_mapping(
    path: Path,
    *,
    catch: tuple[type[BaseException], ...] | None = None,
    log: logging.Logger | None = None,
    round_trip: bool = False,
) -> dict[str, Any]:
    """Load ``path`` as a YAML mapping, collapsing every failure to ``{}``.

    This is a presentation adapter: an empty result cannot authorize a policy
    decision. Canonical Windows config uses checked coordination; custom canonical
    names must use explicit snapshots. Other YAML files retain generic behavior.

    A missing file, an unreadable file, a parse error, or a top-level YAML
    value that is not a mapping all return ``{}`` so callers can apply their
    own defaults without crashing. ``catch`` selects which exceptions route
    to that degraded path (default ``(OSError, YAMLError)``); anything else
    propagates. When ``log`` is supplied, the swallowed error is warned on it.

    ``round_trip`` selects ruamel's ``rt`` loader instead of ``safe``/pure.
    Section-comparison callers (the wizard's upgrade / OpenClaw-migration
    conflict checks) need it: the safe loader *raises* on custom YAML tags,
    which the degraded path would collapse to "no section" and route around
    the caller's conflict handling — the rt loader loads tags as
    ``TaggedScalar`` values that simply compare unequal, so a hand-edited
    section still reaches the conflict prompt instead of being overwritten.
    """
    if _platform == "nt" and path.name.casefold() == "config.yaml":
        from ruamel.yaml.error import YAMLError

        from ._config_io import read_canonical_snapshot

        windows_catch = catch if catch is not None else (OSError, ValueError, YAMLError)
        try:
            return yaml_mapping_from_snapshot(
                read_canonical_snapshot(CanonicalPaths(path.parent, config_name=path.name)), round_trip=round_trip
            )
        except windows_catch as exc:
            if log is not None:
                log.warning("could not read checked config %s: %s", path, exc)
            return {}
    if not path.exists():
        return {}
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    if catch is None:
        catch = (OSError, YAMLError)
    yaml = YAML(typ="rt") if round_trip else YAML(typ="safe", pure=True)
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except catch as e:
        if log is not None:
            log.warning("could not read %s: %s", path, e)
        return {}
    return data if isinstance(data, dict) else {}


def load_plugin_section(
    path: Path,
    plugin: str,
    *,
    catch: tuple[type[BaseException], ...] | None = None,
    log: logging.Logger | None = None,
    round_trip: bool = False,
) -> dict[str, Any] | None:
    """Return the ``plugins.<plugin>`` mapping from ``path``, or ``None``.

    Wraps :func:`load_yaml_mapping` (same ``catch``/``log``/``round_trip``
    semantics) with the ``plugins -> isinstance -> section -> isinstance``
    extraction chain that was previously hand-rolled at each call site.
    ``None`` — rather than ``{}`` — is returned when the file is
    missing/unreadable, when ``plugins`` is absent or not a mapping, or when
    the plugin's section is absent or not a mapping, so callers that
    distinguish "absent" from "present but empty" (e.g. section-comparison
    in the wizard's upgrade path) keep that distinction; callers that don't
    can apply ``or {}``.
    """
    plugins = load_yaml_mapping(path, catch=catch, log=log, round_trip=round_trip).get("plugins")
    if not isinstance(plugins, dict):
        return None
    section = plugins.get(plugin)
    return section if isinstance(section, dict) else None
