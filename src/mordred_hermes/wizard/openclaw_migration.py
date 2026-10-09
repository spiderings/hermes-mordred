"""Story 1.5 -- migrate ``~/.openclaw/mordred/`` into ``~/.hermes/mordred/``.

Per PATHS.md §Migration from legacy OpenClaw paths, the row-level conflict
policy is:

| OpenClaw path | Hermes destination | Conflict policy |
|---|---|---|
| ``audit.log`` | ``audit.log`` (append) | ``--audit-merge={skip,append-all,abort}`` |
| ``keyvault/`` | ``keyvault/`` (copytree) | abort if dest exists |
| ``credentials/`` | ``credentials/`` (copytree) | abort if dest exists |
| ``openclaw.json plugins.entries.mordred-*.config`` | ``config.yaml plugins.mordred_*`` | (see below) |

The policy-section conflict policy (``--policy-conflict``) is resolved
upstream by :func:`upgrade.run` before this module's :func:`migrate` is
invoked.

Idempotency contract: a marker file
``~/.hermes/mordred/.audit-migrated-from-openclaw`` (containing an
ISO-8601 UTC timestamp) is written **last** in the audit step. On
re-runs, marker presence skips audit migration. ``--reset`` overrides
the marker.

Atomicity: every destination write goes through ``<dest>.tmp`` +
``os.replace`` so a crash mid-write leaves the previous file intact.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._audit_io import audit_lock_path, audit_path_stat, exclusive_audit_lock, open_audit_file
from .._log_rotation import utcnow_iso as _utcnow_iso
from .._policy_types import POLICY_MODES
from .._yaml_io import load_plugin_section
from .policy_writer import (
    PolicySnapshot,
    PolicyWriter,
    _atomic_write_text,
    _fsync_durable,
    _fsync_parent,
    _policy_write_lock,
    _preserve_provider_overrides,
    _section_matches_dict,
)

if TYPE_CHECKING:
    from .upgrade import Story1_5Action, UpgradeOptions

_LOG = logging.getLogger("mordred.wizard.openclaw_migration")

MARKER_FILENAME = ".audit-migrated-from-openclaw"


@dataclass(frozen=True, slots=True)
class OpenClawState:
    """Presence flags for the legacy OpenClaw layout. Empty-flag = nothing to do."""

    has_audit: bool
    has_policy_json: bool
    has_keyvault: bool
    has_credentials: bool
    has_openclaw_json: bool


def detect(openclaw_base: Path) -> OpenClawState:
    """Probe the legacy ``~/.openclaw/mordred/`` tree without mutating anything."""
    return OpenClawState(
        has_audit=(openclaw_base / "audit.log").is_file(),
        has_policy_json=(openclaw_base / "policy.json").is_file(),
        has_keyvault=(openclaw_base / "keyvault").is_dir(),
        has_credentials=(openclaw_base / "credentials").is_dir(),
        has_openclaw_json=(openclaw_base.parent / "openclaw.json").is_file(),
    )


# -----------------------------------------------------------------------------
# Audit-log migration -- append-by-timestamp-window + idempotency marker
# -----------------------------------------------------------------------------


def _read_audit_lines(path: Path, *, purpose: str) -> list[str]:
    """Read and validate one plaintext NDJSON audit snapshot without following links."""
    if audit_path_stat(path) is None:
        return []
    fd = open_audit_file(path, os.O_RDONLY)
    try:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    try:
        lines = [line for line in b"".join(chunks).decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError as exc:
        raise SystemExit(f"hermes-mordred upgrade: refusing non-UTF-8 {purpose} audit log at {path}") from exc
    for line in lines:
        try:
            entry = json.loads(line)
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"hermes-mordred upgrade: refusing corrupt {purpose} audit log at {path}") from exc
        timestamp = entry.get("ts") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or entry.get("fmt") == "MRAL"
            or not isinstance(timestamp, str)
            or not timestamp.strip()
        ):
            raise SystemExit(
                f"hermes-mordred upgrade: refusing encrypted or foreign {purpose} audit log at {path}; "
                "plaintext OpenClaw migration cannot transform that format"
            )
    return lines


def _audit_overlap(hermes_lines: list[str], openclaw_lines: list[str]) -> bool:
    """True iff existing Hermes audit and OpenClaw audit timestamp ranges overlap.

    Conservative: any parse failure on either side is treated as overlap
    (caller must then specify ``--audit-merge`` explicitly). The check is
    "does OpenClaw's newest ts come after Hermes's oldest ts?" -- safe append
    requires the OpenClaw range to be entirely older than the Hermes range.
    """
    try:
        hermes_oldest = min(str(json.loads(line)["ts"]) for line in hermes_lines if line)
        openclaw_newest = max(str(json.loads(line)["ts"]) for line in openclaw_lines if line)
    except (KeyError, ValueError, TypeError) as e:
        _LOG.warning("could not parse audit timestamps for overlap check: %s; treating as overlap", e)
        return True
    return openclaw_newest >= hermes_oldest


def _migrate_audit(
    openclaw_base: Path,
    dest_audit: Path,
    marker: Path,
    options: UpgradeOptions,
) -> bool:
    """Migrate audit.log; return True if a real migration happened, False if skipped.

    Skip-vs-migrate decision (in order):
    - marker present + not --reset -> skip (idempotent)
    - openclaw audit absent -> skip (nothing to copy)
    - hermes audit absent -> safe append (no overlap possible)
    - timestamp ranges disjoint (openclaw_newest < hermes_oldest) -> safe append
    - overlap + --audit-merge=skip -> no append, mark migrated
    - overlap + --audit-merge=append-all -> force append duplicates
    - overlap + --audit-merge=abort or unset -> SystemExit
    """
    src_audit = openclaw_base / "audit.log"
    src_metadata = audit_path_stat(src_audit)
    if src_metadata is None:
        return False
    dest_metadata = audit_path_stat(dest_audit)
    if os.path.abspath(src_audit) == os.path.abspath(dest_audit) or (
        dest_metadata is not None
        and (src_metadata.st_dev, src_metadata.st_ino) == (dest_metadata.st_dev, dest_metadata.st_ino)
    ):
        raise SystemExit("hermes-mordred upgrade: source and destination audit logs must be different files")

    # Canonical sidecar order prevents opposing migrations from deadlocking.
    # realpath also collapses parent-directory symlink aliases. Holding both
    # through the marker commit prevents a legacy source writer from appending
    # after our snapshot and prevents a live Hermes writer from losing an
    # append under the destination's atomic replacement.
    lock_order = sorted(
        (src_audit, dest_audit),
        key=lambda path: os.path.normcase(os.path.realpath(os.path.abspath(audit_lock_path(path)))),
    )
    with ExitStack() as locks:
        for audit_path in lock_order:
            locks.enter_context(exclusive_audit_lock(audit_path))
        locked_src_metadata = audit_path_stat(src_audit)
        locked_dest_metadata = audit_path_stat(dest_audit)
        if locked_src_metadata is None or (
            locked_dest_metadata is not None
            and (locked_src_metadata.st_dev, locked_src_metadata.st_ino)
            == (locked_dest_metadata.st_dev, locked_dest_metadata.st_ino)
        ):
            raise SystemExit("hermes-mordred upgrade: source and destination audit logs must be different files")
        return _migrate_audit_locked(
            src_audit=src_audit,
            dest_audit=dest_audit,
            marker=marker,
            options=options,
        )


def _audit_marker_present(marker: Path) -> bool:
    """Inspect the marker as a directory entry while both audit locks are held."""
    try:
        marker.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SystemExit(f"hermes-mordred upgrade: cannot safely inspect audit marker {marker}: {exc}") from exc
    return True


def _migrate_audit_locked(
    *,
    src_audit: Path,
    dest_audit: Path,
    marker: Path,
    options: UpgradeOptions,
) -> bool:
    """Merge one stable plaintext snapshot while source and destination are locked."""
    # Re-check under both locks: two simultaneous upgrade processes must not
    # both observe an absent marker and append the source snapshot twice.
    if _audit_marker_present(marker) and not options.reset:
        _LOG.info("audit migration skipped: marker %s present (use --reset to force)", marker)
        return False

    src_lines = _read_audit_lines(src_audit, purpose="source")
    dest_lines = _read_audit_lines(dest_audit, purpose="destination")
    overlap = bool(dest_lines) and _audit_overlap(dest_lines, src_lines)

    if overlap and options.audit_merge is None:
        raise SystemExit(
            "hermes-mordred upgrade: OpenClaw audit.log overlaps existing "
            "Hermes audit.log timestamps. Re-run with one of "
            "--audit-merge=skip|append-all|abort."
        )
    if overlap and options.audit_merge == "abort":
        raise SystemExit("hermes-mordred upgrade: --audit-merge=abort and overlap detected -- aborting.")
    if overlap and options.audit_merge == "skip":
        _LOG.info("audit migration: overlap detected, skip per --audit-merge=skip")
        # Marker still gets written so re-runs are noops.
        _write_marker(marker)
        return True

    # Safe append (or --audit-merge=append-all forced).
    appended = "\n".join(src_lines)
    if appended:
        appended += "\n"
    existing = "\n".join(dest_lines) + "\n" if dest_lines else ""
    _atomic_write_text(dest_audit, existing + appended, mode=0o600)
    _write_marker(marker)
    return True


def _write_marker(marker: Path) -> None:
    """Write the idempotency marker LAST (so a crashed migration retries safely)."""
    _atomic_write_text(marker, _utcnow_iso() + "\n", mode=0o600)


# -----------------------------------------------------------------------------
# Keyvault / credentials -- never overwrite differing destination data
# -----------------------------------------------------------------------------


def _entries_identical(src_entry: Path, dest_entry: Path) -> bool:
    """Compare one tree entry without relying on stat-only equality."""
    try:
        src_mode = src_entry.lstat().st_mode
        dest_mode = dest_entry.lstat().st_mode
        if stat.S_ISLNK(src_mode) or stat.S_ISLNK(dest_mode):
            return (
                stat.S_ISLNK(src_mode) and stat.S_ISLNK(dest_mode) and os.readlink(src_entry) == os.readlink(dest_entry)
            )
        if stat.S_ISDIR(src_mode) and stat.S_ISDIR(dest_mode):
            return _dirs_identical(src_entry, dest_entry)
        if stat.S_ISREG(src_mode) and stat.S_ISREG(dest_mode):
            if src_entry.stat().st_size != dest_entry.stat().st_size:
                return False
            with src_entry.open("rb") as src_file, dest_entry.open("rb") as dest_file:
                while True:
                    src_chunk = src_file.read(1024 * 1024)
                    dest_chunk = dest_file.read(1024 * 1024)
                    if src_chunk != dest_chunk:
                        return False
                    if not src_chunk:
                        return True
    except OSError:
        return False
    return False


def _dirs_identical(src: Path, dest: Path) -> bool:
    """True iff ``src`` and ``dest`` contain the same file tree byte-for-byte."""
    try:
        src_entries = {entry.name: entry for entry in src.iterdir()}
        dest_entries = {entry.name: entry for entry in dest.iterdir()}
    except OSError:
        return False
    if src_entries.keys() != dest_entries.keys():
        return False
    return all(_entries_identical(src_entry, dest_entries[name]) for name, src_entry in src_entries.items())


def _validate_sensitive_tree(root: Path, kind: str) -> tuple[int, int] | None:
    """Require a real directory containing only real directories/files."""
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SystemExit(f"hermes-mordred upgrade: cannot safely inspect {kind} source {root}: {exc}") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise SystemExit(f"hermes-mordred upgrade: refusing unsafe non-directory {kind} tree at {root}")

    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            raise SystemExit(
                f"hermes-mordred upgrade: cannot safely inspect {kind} tree at {directory}: {exc}"
            ) from exc
        for entry in entries:
            try:
                metadata = entry.lstat()
            except OSError as exc:
                raise SystemExit(f"hermes-mordred upgrade: cannot safely inspect {kind} entry {entry}: {exc}") from exc
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                pending.append(entry)
            elif not stat.S_ISREG(metadata.st_mode):
                raise SystemExit(f"hermes-mordred upgrade: refusing symlink or special entry in {kind} tree: {entry}")
    return root_metadata.st_dev, root_metadata.st_ino


def _tighten_sensitive_directory(directory: Path, kind: str, *, sync: bool = False) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(directory, flags)
    except OSError as exc:
        raise SystemExit(f"hermes-mordred upgrade: cannot secure copied {kind} directory {directory}: {exc}") from exc
    try:
        metadata = os.fstat(directory_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"hermes-mordred upgrade: copied {kind} directory changed type: {directory}")
        os.fchmod(directory_fd, 0o700)
        if sync:
            _fsync_durable(directory_fd)
    finally:
        os.close(directory_fd)


def _tighten_sensitive_file(entry: Path, entry_metadata: os.stat_result, kind: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        file_fd = os.open(entry, flags)
    except OSError as exc:
        raise SystemExit(f"hermes-mordred upgrade: cannot secure copied {kind} file {entry}: {exc}") from exc
    try:
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            entry_metadata.st_dev,
            entry_metadata.st_ino,
        ):
            raise SystemExit(f"hermes-mordred upgrade: copied {kind} file changed while securing: {entry}")
        os.fchmod(file_fd, 0o600)
        _fsync_durable(file_fd)
    finally:
        os.close(file_fd)


def _tighten_sensitive_tree(root: Path, kind: str) -> None:
    """Set private modes and durably flush a copied tree through no-follow fds."""
    pending = [root]
    directories: list[Path] = []
    while pending:
        directory = pending.pop()
        _tighten_sensitive_directory(directory, kind)
        directories.append(directory)

        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            raise SystemExit(
                f"hermes-mordred upgrade: cannot inspect copied {kind} directory {directory}: {exc}"
            ) from exc
        for entry in entries:
            try:
                entry_metadata = entry.lstat()
            except OSError as exc:
                raise SystemExit(f"hermes-mordred upgrade: cannot inspect copied {kind} entry {entry}: {exc}") from exc
            if stat.S_ISDIR(entry_metadata.st_mode) and not stat.S_ISLNK(entry_metadata.st_mode):
                pending.append(entry)
                continue
            if not stat.S_ISREG(entry_metadata.st_mode):
                raise SystemExit(f"hermes-mordred upgrade: refusing symlink or special copied {kind} entry: {entry}")
            _tighten_sensitive_file(entry, entry_metadata, kind)

    # Persist each directory's child entries and mode after every descendant
    # file has been flushed. Reversing preorder gives children-before-parent
    # ordering, so a durable root never points at an unflushed child subtree.
    for directory in reversed(directories):
        _tighten_sensitive_directory(directory, kind, sync=True)


def _migrate_directory(src: Path, dest: Path, kind: str) -> bool:
    """Idempotently copy ``src`` -> ``dest`` (PATHS.md §OpenClaw migration H5).

    Returns True if a copy happened, False if no-op (source absent OR
    dest already contains the same tree byte-for-byte). Raises
    Refuses data conflicts and unsafe or unstable filesystem entries.

    Idempotency rule: if ``dest`` exists AND its contents match ``src``
    exactly, treat as already-migrated (skip silently). Required so that
    a second ``upgrade`` run, or a retry after audit-overlap abort, does
    not crash on the now-existing dest from the first attempt.
    """
    with _policy_write_lock(dest.parent):
        source_identity = _validate_sensitive_tree(src, kind)
        if source_identity is None:
            return False
        if dest.is_symlink():
            raise SystemExit(
                f"hermes-mordred upgrade: refusing to overwrite existing {kind} "
                f"at {dest} -- destination is a symbolic link."
            )
        if dest.exists():
            _validate_sensitive_tree(dest, f"destination {kind}")
            if _dirs_identical(src, dest):
                # Old upgrade versions could have published source modes
                # (including group/world-readable secrets). An idempotent
                # retry repairs those modes after proving the bytes match.
                _tighten_sensitive_tree(dest, kind)
                _LOG.info("%s already migrated (dest matches src byte-for-byte); skipping", kind)
                return False
            raise SystemExit(
                f"hermes-mordred upgrade: refusing to overwrite existing {kind} "
                f"at {dest} -- contents differ from {src}. "
                f"Move or remove the destination manually before re-running upgrade."
            )
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage_root = Path(tempfile.mkdtemp(dir=dest.parent, prefix=f".{dest.name}.migrate-"))
        staged = stage_root / "payload"
        try:
            # Preserve any link planted after the preflight as a link in the
            # staging tree. The validation below then rejects it instead of
            # copytree following it and importing an external target.
            shutil.copytree(src, staged, dirs_exist_ok=False, symlinks=True)
            if _validate_sensitive_tree(staged, f"staged {kind}") is None:
                raise SystemExit(f"hermes-mordred upgrade: staged {kind} tree disappeared before publish")
            _tighten_sensitive_tree(staged, kind)
            # Re-scan the live source after copying, then require the staged
            # bytes and tree shape to match it. Checking only the root inode
            # misses an in-place file rewrite or nested entry replacement and
            # would publish a torn snapshot that future retries call a conflict.
            current_source_identity = _validate_sensitive_tree(src, kind)
            if current_source_identity != source_identity or not _dirs_identical(src, staged):
                raise SystemExit(f"hermes-mordred upgrade: {kind} source changed during migration: {src}")
            try:
                current_source = src.lstat()
            except OSError as exc:
                raise SystemExit(f"hermes-mordred upgrade: {kind} source changed during migration: {src}") from exc
            if (
                not stat.S_ISDIR(current_source.st_mode)
                or (current_source.st_dev, current_source.st_ino) != source_identity
            ):
                raise SystemExit(f"hermes-mordred upgrade: {kind} source changed during migration: {src}")
            if dest.exists() or dest.is_symlink():
                raise SystemExit(
                    f"hermes-mordred upgrade: refusing to overwrite existing {kind} "
                    f"at {dest}; it appeared while the migration copy was being prepared."
                )
            os.rename(staged, dest)
            _fsync_parent(dest)
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)
    return True


# -----------------------------------------------------------------------------
# openclaw.json policy block -- transform + upsert
# -----------------------------------------------------------------------------


def read_policy_snapshot(openclaw_base: Path, policy_writer: PolicyWriter) -> PolicySnapshot | None:
    """Read the legacy policy without mutating Hermes state."""
    src = openclaw_base.parent / "openclaw.json"
    if not src.is_file():
        return None
    try:
        body = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _LOG.warning("could not read %s: %s", src, e)
        return None

    config = _extract_privacy_config(body)
    if config is None:
        return None

    return _preserve_provider_overrides(
        _coerce_snapshot(config),
        policy_writer.policy_json_path,
    )


def _migrate_policy(
    openclaw_base: Path,
    policy_writer: PolicyWriter,
    options: UpgradeOptions,
) -> bool:
    """Transform the legacy policy and write it through ``PolicyWriter``."""
    snapshot = read_policy_snapshot(openclaw_base, policy_writer)
    if snapshot is None:
        return False
    # Apply --policy-conflict against the OpenClaw snapshot (P1-A).
    if not _should_write_policy(policy_writer, snapshot, options):
        return False

    # Write BOTH config.yaml and policy.json mirror (P2).
    policy_writer.write(snapshot)
    return True


def _extract_privacy_config(body: object) -> dict[str, Any] | None:
    """Pull ``plugins.entries.mordred-privacy-check.config`` out of openclaw.json.

    Returns the config dict, or None if any level of the expected nesting is
    absent or the wrong type (no recognisable section to migrate).
    """
    plugins = body.get("plugins") if isinstance(body, dict) else None
    entries = plugins.get("entries") if isinstance(plugins, dict) else None
    if not isinstance(entries, dict):
        return None
    privacy = entries.get("mordred-privacy-check")
    if not isinstance(privacy, dict):
        return None
    config = privacy.get("config")
    if not isinstance(config, dict):
        return None
    return config


def _should_write_policy(
    policy_writer: PolicyWriter,
    snapshot: PolicySnapshot,
    options: UpgradeOptions,
) -> bool:
    """Decide whether to write ``snapshot``, honoring ``options.policy_conflict``.

    Returns True to proceed with the write, False to keep the existing section.
    Raises ``SystemExit`` on an unresolved conflict (``abort``, or an
    interactive prompt that a non-interactive run cannot satisfy).

    The section read mirrors ``upgrade._read_existing_section`` (read-only
    comparison, broad catch, and — load-bearing — ``round_trip=True`` so a
    custom-tagged section compares unequal and reaches conflict resolution
    instead of being collapsed to "no section" and overwritten) but goes
    through the shared root helper directly — importing ``upgrade`` here
    would be cyclic.
    """
    section = load_plugin_section(
        policy_writer.config_path, "mordred_privacy_check", catch=(Exception,), log=_LOG, round_trip=True
    )
    if section is None:
        return True
    # Plain-dict coercion (shallow) mirrors upgrade._read_existing_section —
    # the two conflict checks must return the same shape for the same file.
    existing = dict(section)
    want = snapshot.to_config_yaml_section()
    if _section_matches_dict(existing, want):
        return True
    # Existing section differs from the OpenClaw-derived snapshot. --reset and
    # --policy-conflict=overwrite both proceed to write (reset takes precedence,
    # matching the original elif order).
    if options.reset or options.policy_conflict == "overwrite":
        return True
    if options.policy_conflict == "keep-existing":
        return False
    if options.policy_conflict == "abort":
        raise SystemExit(
            "hermes-mordred upgrade: --policy-conflict=abort and OpenClaw "
            "policy differs from existing config.yaml -- aborting."
        )
    # options.policy_conflict is None
    if options.non_interactive:
        raise SystemExit(
            "hermes-mordred upgrade: --non-interactive set but --policy-conflict "
            "not specified; refusing to overwrite existing mordred section "
            "with OpenClaw migration."
        )
    raise SystemExit(
        "hermes-mordred upgrade: OpenClaw policy differs from existing "
        "config.yaml plugins.mordred_privacy_check. Re-run with one of "
        "--policy-conflict=keep-existing|overwrite|abort or --reset."
    )


def _coerce_snapshot(config: dict[str, Any]) -> PolicySnapshot:
    """Map an OpenClaw ``config`` dict to :class:`PolicySnapshot`.

    Defensive against missing/typo'd fields -- defaults match the wizard's
    ``configure`` defaults so users never end up worse-off than fresh setup.
    """
    raw_policy = config.get("policy", "lenient")
    # POLICY_MODES is the tuple, not the frozenset: foreign JSON can carry
    # unhashable values, and tuple membership returns False instead of
    # raising TypeError (hooks.py Codex round 3 P2).
    policy = raw_policy if raw_policy in POLICY_MODES else "lenient"
    # M2 (security review 2026-06-11): a foreign config's string "false"
    # must not truthy-coerce into an enabled cloud-LLM grant.
    raw_allow_flag = config.get("allow_cloud_llm", False)
    allow = raw_allow_flag if isinstance(raw_allow_flag, bool) else False
    raw_allow = config.get("cloud_provider_allowlist") or []
    allowlist: tuple[str, ...] = (
        tuple(x for x in raw_allow if isinstance(x, str)) if isinstance(raw_allow, list) else ()
    )
    return PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow,
        cloud_provider_allowlist=allowlist,
    )


# -----------------------------------------------------------------------------
# Top-level migrate() orchestrator
# -----------------------------------------------------------------------------


def migrate(
    *,
    openclaw_base: Path,
    policy_writer: PolicyWriter,
    options: UpgradeOptions,
) -> Story1_5Action:
    """Migrate ``openclaw_base`` into the wizard-owned Hermes paths.

    Order matters:
    1. Keyvault / credentials (abort fast on collision -- before any audit
       writes so a refused migration leaves audit.log untouched too).
    2. openclaw.json policy section -> config.yaml via PolicyWriter.
    3. audit.log + marker file (marker is the LAST write so a crashed
       migration safely retries).

    Returns one of: ``noop``, ``migrated``, ``skipped-marker``. ``noop`` covers
    both "no ``openclaw_base`` at all" and "``openclaw_base`` exists but holds
    none of the recognized artifacts" (no audit.log, no keyvault/, no
    credentials/, no sibling openclaw.json, or an openclaw.json with no
    recognisable ``mordred-privacy-check`` section) -- in either case nothing
    was actually copied or written, so reporting ``migrated`` would mislead
    the ``hermes-mordred upgrade`` summary.
    """
    if not openclaw_base.exists():
        return "noop"

    # Resolve destinations from PolicyWriter -- single source of truth for paths.
    dest_audit = policy_writer.mordred_dir / "audit.log"
    dest_keyvault = policy_writer.mordred_dir / "keyvault"
    dest_credentials = policy_writer.mordred_dir / "credentials"
    marker = policy_writer.mordred_dir / MARKER_FILENAME

    state = detect(openclaw_base)

    # 1. Never-overwrite copies (fail fast). Track whether each sub-step
    # actually did something -- an openclaw_base directory that exists but is
    # empty (or an openclaw.json with no recognisable section) must not report
    # "migrated" when nothing was copied or written.
    keyvault_migrated = False
    if state.has_keyvault:
        keyvault_migrated = _migrate_directory(openclaw_base / "keyvault", dest_keyvault, kind="keyvault")
    credentials_migrated = False
    if state.has_credentials:
        credentials_migrated = _migrate_directory(openclaw_base / "credentials", dest_credentials, kind="credentials")

    # 2. Policy transform (idempotent via PolicyWriter compare-and-skip;
    # honors options.policy_conflict against the OpenClaw snapshot per Codex P1-A)
    policy_migrated = False
    if state.has_openclaw_json:
        policy_migrated = _migrate_policy(openclaw_base, policy_writer, options)

    # 3. Audit log -- last, with marker
    audit_migrated = _migrate_audit(openclaw_base, dest_audit, marker, options)
    if not audit_migrated and marker.exists() and state.has_audit:
        return "skipped-marker"
    if keyvault_migrated or credentials_migrated or policy_migrated or audit_migrated:
        return "migrated"
    return "noop"
