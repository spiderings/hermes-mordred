"""Shared ``policy.json`` read helper for config-reading plugin code.

Windows canonical files use checked snapshots. The historical read behavior
described below is retained for POSIX and generic presentation files only.

Single-sources the "open ``policy.json`` and hand back a mapping, or fall
back to empty on any read/parse failure" core that was independently
copy-pasted across four call sites (``network`` x1 whole-dict load,
``llm_guard`` x3: policy mode / enforce settings / local endpoint). Each
caller still owns its own extraction (the ``.get()`` chain) and its own
default; only the load core is shared.

This is the JSON sibling of :mod:`mordred_hermes._yaml_io`. The shape is
deliberately identical: an ``exists()`` pre-check, a narrow ``(OSError,
json.JSONDecodeError)`` catch routed to ``{}``, and a non-mapping root
collapsed to ``{}`` so callers can apply their own defaults without
crashing plugin registration. Unlike ``_yaml_io`` the catch set never
diverged across callers, so there is no ``catch`` parameter.

:func:`read_policy_mode_fail_closed` is the *other* reader this module
hosts: the open-first, fail-CLOSED policy-mode read (M1 security review,
2026-06-11). It exists because collapsing missing-vs-unreadable into a
single ``{}`` (what :func:`load_policy_mapping` does) silently disabled
strict enforcement when ``policy.json`` was corrupted or made unreadable.
An ``exists()`` pre-check would both race the open (TOCTOU) and misread a
stat failure -- e.g. search permission stripped from the parent dir -- as
"absent" -> default, so only a clean ``FileNotFoundError`` keeps the
fresh-install default; every other failure reads as ``"strict"``.
``network.hooks`` (where the M1 fix originally landed) and
``llm_guard._read_policy_mode`` both resolve through it, so the two
enforcement layers reading ``policy.json`` cannot diverge again.

As with ``_yaml_io``, the warning text is normalised here to
``"could not read ..."``. The per-site suffixes ("defaulting to empty",
"using safe defaults", "using default endpoint", "defaulting to <mode>")
are asserted by no test and are not part of the behavioural contract.

``json`` is imported at module scope (unlike the lazy ``ruamel`` import in
``_yaml_io``): it is stdlib and carries no plugin-discovery import cost
worth deferring.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from ._config_io import POLICY_TRANSACTION_MARKER, CanonicalPaths, CanonicalSnapshot
from ._policy_types import VALID_POLICY_MODES

_platform = os.name


def policy_transaction_marker_for_policy(path: Path) -> Path:
    """Return the marker guarding ``policy.json`` and its config mirror."""
    return path.parent / POLICY_TRANSACTION_MARKER


def policy_transaction_marker_for_config(path: Path) -> Path:
    """Return the matching marker for a Hermes ``config.yaml`` path."""
    return path.parent / "mordred" / POLICY_TRANSACTION_MARKER


def _legacy_policy_transaction_pending(marker: Path) -> bool:
    """Treat any marker directory entry—or inability to inspect it—as pending."""
    try:
        marker.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _paths_for_policy(path: Path) -> CanonicalPaths:
    if path.parent.name.casefold() != "mordred":
        raise ValueError("canonical policy must be directly inside home/mordred")
    return CanonicalPaths(path.parent.parent, mordred_name=path.parent.name, policy_name=path.name)


def _checked_marker(marker: Path) -> bytes | None:
    from ._config_io import read_policy_marker

    if marker.name != POLICY_TRANSACTION_MARKER:
        raise ValueError("not the canonical policy marker")
    result = read_policy_marker(_paths_for_policy(marker.with_name("policy.json")))
    return result.data if result is not None else None


def policy_transaction_pending(marker: Path) -> bool:
    """False only for checked Windows absence; every uncertainty is pending."""
    if _platform != "nt":
        return _legacy_policy_transaction_pending(marker)
    try:
        return _checked_marker(marker) is not None
    except (OSError, ValueError):
        return True


def policy_mapping_from_snapshot(snapshot: CanonicalSnapshot) -> dict[str, Any]:
    """Parse checked policy bytes; malformed documents raise, absence is empty."""
    if snapshot.policy is None:
        return {}
    data = json.loads(snapshot.policy.data.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy JSON must contain an object")
    return data


def policy_mode_from_snapshot(snapshot: CanonicalSnapshot, *, default: str) -> str:
    """A single checked generation; malformed/invalid policy always means strict."""
    try:
        data = policy_mapping_from_snapshot(snapshot)
    except (ValueError, UnicodeError):
        return "strict"
    mode = data.get("policy", default)
    return mode if isinstance(mode, str) and mode in VALID_POLICY_MODES else "strict"


def policy_transaction_warning(marker: Path) -> str | None:
    """Operator-facing explanation for a pending marker, or ``None`` if absent.

    A marker left behind by an interrupted write makes every reader fail closed
    to strict mode with empty settings — which refuses all providers. Without a
    surfaced remedy the operator sees only the refusals and has no path back to
    the cause, so every user-facing status surface shares this wording.
    """
    if _platform == "nt":
        try:
            recorded_bytes = _checked_marker(marker)
        except (OSError, ValueError):
            recorded_bytes = b""
        if recorded_bytes is None:
            return None
        detail = f" Marker recorded: {recorded_bytes.decode('utf-8', errors='replace')!r}." if recorded_bytes else ""
        return (
            f"a Mordred policy write is pending or cannot be safely inspected ({marker}).{detail} "
            "Policy reads fail closed. Stop other Mordred processes and run `hermes-mordred configure` "
            "to reconcile readable safe configuration. Unsafe or corrupt files require explicit "
            "inspection and recovery; do not unconditionally remove the marker."
        )
    if not policy_transaction_pending(marker):
        return None
    detail = ""
    try:
        recorded = marker.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        recorded = ""
    if recorded:
        detail = f" Marker recorded: {recorded}."
    return (
        f"a Mordred policy write is marked in progress ({marker}).{detail} "
        "Until it clears, every policy read fails closed to strict mode with empty "
        "settings, which refuses all LLM providers. If no `configure` is currently "
        "running, the previous one was interrupted: re-run `hermes-mordred configure` "
        "to completion, or delete the marker file to restore the on-disk policy."
    )


def load_policy_mapping(
    path: Path,
    *,
    log: logging.Logger | None = None,
    allow_pending_transaction: bool = False,
) -> dict[str, Any]:
    """Load ``path`` as a JSON mapping, collapsing every failure to ``{}``.

    A missing file, an unreadable file, a JSON parse error, or a top-level
    JSON value that is not an object all return ``{}`` so callers can apply
    their own defaults without crashing. When ``log`` is supplied, a
    swallowed read/parse error is warned on it.

    This presentation adapter must never authorize through empty defaults.
    Windows canonical policy reads always coordinate, even when the legacy
    ``allow_pending_transaction`` boolean is true. Custom canonical leaves use
    explicit snapshots. Generic JSON files and POSIX keep their old semantics.

    The legacy branch uses an ``exists()`` pre-check and is therefore unsuitable for
    fail-closed readers that must distinguish "absent" from "unreadable"
    (see the module docstring re ``network.hooks``).
    """
    if _platform == "nt" and path.name.casefold() == "policy.json":
        from ._config_io import read_canonical_snapshot

        try:
            return policy_mapping_from_snapshot(read_canonical_snapshot(_paths_for_policy(path)))
        except (OSError, ValueError, UnicodeError) as exc:
            if log is not None:
                log.warning("could not read checked policy %s: %s", path, exc)
            return {}
    return _load_policy_mapping_legacy(path, log=log, allow_pending_transaction=allow_pending_transaction)


def _load_policy_mapping_legacy(
    path: Path, *, log: logging.Logger | None, allow_pending_transaction: bool
) -> dict[str, Any]:
    marker = policy_transaction_marker_for_policy(path)
    if not allow_pending_transaction and _legacy_policy_transaction_pending(marker):
        if log is not None:
            log.error("policy transaction marker %s is present; using fail-closed empty settings", marker)
        return {}
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        if log is not None:
            log.warning("could not read %s: %s", path, e)
        return {}
    if not allow_pending_transaction and _legacy_policy_transaction_pending(marker):
        if log is not None:
            log.error("policy transaction began while reading %s; using fail-closed empty settings", path)
        return {}
    return data if isinstance(data, dict) else {}


def read_policy_mode_fail_closed(
    path: Path,
    *,
    default: str,
    log: logging.Logger,
) -> str:
    """Open-first, fail-closed read of ``policy`` from ``path`` (M1 contract).

    Windows uses the checked canonical snapshot; any coordination failure is
    strict. On POSIX, only a clean ``FileNotFoundError`` — including a dangling symlink,
    equivalent to deletion — returns ``default`` (the fresh-install mode:
    ``"off"`` for network, ``"lenient"`` for llm_guard). A file that EXISTS
    and cannot be opened, read, or parsed, a non-dict root, and an invalid
    ``policy`` value all read as ``"strict"``: falling back to the default
    meant corrupting policy.json silently disabled strict enforcement.
    ``default`` is also the mode when the file parses but has no ``policy``
    key — an incomplete file is user-authored, not an attack surface, and
    the pre-M1 readers agreed on that.
    """
    if _platform == "nt":
        from ._config_io import read_canonical_snapshot

        try:
            return policy_mode_from_snapshot(read_canonical_snapshot(_paths_for_policy(path)), default=default)
        except (OSError, ValueError, UnicodeError) as exc:
            log.error("could not read checked policy %s (%s); failing closed to strict", path, exc)
            return "strict"
    return _read_policy_mode_legacy(path, default=default, log=log)


def _read_policy_mode_legacy(path: Path, *, default: str, log: logging.Logger) -> str:
    marker = policy_transaction_marker_for_policy(path)
    if policy_transaction_pending(marker):
        log.error("policy transaction marker %s is present; failing closed to strict", marker)
        return "strict"
    try:
        f = path.open(encoding="utf-8")
    except FileNotFoundError:
        if policy_transaction_pending(marker):
            log.error("policy transaction began while opening %s; failing closed to strict", path)
            return "strict"
        return default
    except OSError as e:
        log.error("policy file %s exists but is unreadable (%s); failing closed to strict", path, e)
        return "strict"
    try:
        with f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log.error("policy file %s exists but is unreadable (%s); failing closed to strict", path, e)
        return "strict"
    if policy_transaction_pending(marker):
        log.error("policy transaction began while reading %s; failing closed to strict", path)
        return "strict"
    if not isinstance(data, dict):
        log.error("policy file %s has a non-dict root; failing closed to strict", path)
        return "strict"
    mode = data.get("policy", default)
    # isinstance before frozenset membership — ``in`` on a frozenset raises
    # TypeError for unhashable values like ``[]`` / ``{}`` (Codex round 3 P2).
    if isinstance(mode, str) and mode in VALID_POLICY_MODES:
        return mode
    log.error("invalid policy %r in %s; failing closed to strict", mode, path)
    return "strict"
