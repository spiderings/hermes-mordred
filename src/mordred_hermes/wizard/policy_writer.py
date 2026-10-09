"""Round-trip writer for ``~/.hermes/config.yaml`` and ``~/.hermes/mordred/policy.json``.

Sole writer for the wizard-owned policy files (PATHS.md §Overview).
Preserves user comments, key order, and anchors in ``config.yaml`` via
``ruamel.yaml`` round-trip mode. Writes ``policy.json`` as the
debugger-friendly mirror that other Mordred plugins read directly.

Three core operations:

- :meth:`PolicyWriter.upsert_mordred_sections` — mutate ``plugins.mordred_*``
  blocks in ``~/.hermes/config.yaml``. Also ensures the Mordred entry-point
  plugin names appear in ``plugins.enabled`` (HOOK_PAYLOADS.md §1 mandate
  -- Hermes loader will not invoke ``register()`` otherwise).
- :meth:`PolicyWriter.emit_policy_json` -- serialise the resolved policy
  snapshot to ``policy.json`` (file mode ``0o600``, atomic via tmp + replace).
- :meth:`PolicyWriter.write` -- convenience composition that does both.

Idempotency: if the on-disk content already matches, no write happens
(byte-for-byte compare for both files). Writes use ``<dest>.tmp`` +
``os.replace`` for POSIX-atomic substitution; a crash mid-write leaves
the previous file intact.
"""

from __future__ import annotations

import contextlib
import copy
import errno
import io
import json
import logging
import os
import stat
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, NoReturn, Protocol, runtime_checkable

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .._config_io import CONFIG_LIMIT, POLICY_LIMIT, CanonicalPaths, CanonicalSession, canonical_session
from .._file_lock import private_flock
from .._plugin_identity import PLUGIN_NAME, PluginListMigration, migrate_plugin_lists
from .._policy_io import (
    load_policy_mapping,
    policy_transaction_marker_for_policy,
)
from .._private_fs import PrivateFSError, open_private_directory
from ._runtime import (
    DEFAULT_HERMES_CONFIG_PATH,
    DEFAULT_MORDRED_DIR,
    DEFAULT_POLICY_JSON_PATH,
)

_LOG = logging.getLogger("mordred.wizard.policy_writer")
_POLICY_LOCK_FILENAME = ".policy-write.lock"
_POLICY_THREAD_LOCK = threading.RLock()
_POLICY_LOCK_STATE = threading.local()
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]

#: Names that must be in ``plugins.enabled``: the single ``mordred`` plugin.
MORDRED_PLUGIN_NAMES: Final = (PLUGIN_NAME,)

#: ``plugins.<section>`` settings blocks this writer may edit. These are
#: Mordred's own config keys (named after the pre-0.2.0a0 per-component
#: plugins), not Hermes plugin identities.
MORDRED_CONFIG_SECTIONS: Final = (
    "mordred_privacy_check",
    "mordred_wizard",
    "mordred_llm_guard",
    "mordred_network",
    "mordred_keyvault",
    "mordred_e2e",
)


@runtime_checkable
class _HasConfigYamlSection(Protocol):
    """Structural shape required by :meth:`PolicyWriter.write` for the
    optional ``network_answers`` argument.

    Implemented by :class:`mordred_hermes.wizard.network_cli.NetworkAnswers`.
    Kept as a Protocol (not a concrete import) to avoid the
    ``configure -> policy_writer -> configure`` import cycle while still
    enforcing the contract under ``mypy --strict``. ``runtime_checkable`` so
    callers and tests can ``isinstance``-check at the boundary.
    """

    def to_config_yaml_section(self) -> Mapping[str, Any]: ...


def _windows() -> bool:
    return sys.platform == "win32"


def _canonical_paths(config: Path, policy: Path, mordred: Path) -> CanonicalPaths:
    if policy.parent != mordred or mordred.parent != config.parent:
        raise ValueError("canonical config and policy must share one home")
    return CanonicalPaths(config.parent, config.name, mordred.name, policy.name)


def _bounded_utf8(text: str, limit: int) -> bytes:
    data = text.encode("utf-8")
    if len(data) > limit:
        raise ValueError("configuration exceeds its byte limit")
    return data


@dataclass
class _CheckedPolicyEdit:
    session: CanonicalSession
    yaml: YAML
    root: Any
    policy: dict[str, Any]
    config_present: bool
    config_bytes: bytes | None = None
    policy_bytes: bytes | None = None

    def dump_config(self) -> None:
        buf = io.StringIO()
        self.yaml.dump(self.root, buf)
        self.config_bytes = _bounded_utf8(buf.getvalue(), CONFIG_LIMIT)

    def edit_sections(
        self,
        sections: Mapping[str, Mapping[str, Any]],
        mutator: Callable[[Any, str, Mapping[str, Any]], None],
    ) -> None:
        for name, body in sections.items():
            if name not in MORDRED_CONFIG_SECTIONS:
                raise ValueError(f"PolicyWriter only edits Mordred plugin sections; refusing to touch {name!r}")
            mutator(self.root, name, body)
        _ensure_plugins_enabled(self.root)
        self.dump_config()

    def emit(self, snapshot: PolicySnapshot) -> None:
        if snapshot.provider_overrides == {} and "provider_overrides" in self.policy:
            snapshot = replace(snapshot, provider_overrides=copy.deepcopy(self.policy["provider_overrides"]))
        self.policy_bytes = _bounded_utf8(json.dumps(snapshot.to_json_dict(), indent=2) + "\n", POLICY_LIMIT)


@contextmanager
def _checked_policy_edit(paths: CanonicalPaths, *, recover: bool = False) -> Iterator[_CheckedPolicyEdit]:
    with (
        canonical_session(paths, scope="policy", create=True) as session,
        session.policy_update(recover_pending=recover) as update,
    ):
        pair = session.read_pair()
        yaml = _round_trip_yaml()
        try:
            root = yaml.load(pair.config.data.decode("utf-8")) if pair.config else {}
        except YAMLError as exc:
            raise ValueError("canonical config contains invalid YAML") from exc
        if not isinstance(root, MutableMapping):
            raise ValueError("canonical config must contain a mapping")
        policy = json.loads(pair.policy.data.decode("utf-8")) if pair.policy else {}
        if not isinstance(policy, dict):
            raise ValueError("canonical policy must contain an object")
        edit = _CheckedPolicyEdit(session, yaml, root, policy, pair.config is not None)
        yield edit
        if edit.config_bytes is not None:
            update.put_config(edit.config_bytes)
        elif pair.config is not None:
            update.put_config(pair.config.data)
        if edit.policy_bytes is not None:
            update.put_policy(edit.policy_bytes)
        elif pair.policy is not None:
            update.put_policy(pair.policy.data)
        update.commit()


def _write_checked_private(path: Path, data: bytes, *, backup: bool = False) -> bool:
    """Write a private child with its parents already checked and locked.

    Caller owns canonical home/policy locks and accounts for publication if
    their later cleanup fails. The foundation creates only this final child.
    Backup locks never wait: an explicit destination can belong to a different
    profile, so blocking here could form a cross-profile lock cycle.
    """
    published = False
    try:
        with (
            open_private_directory(path.parent, create=True) as directory,
            directory.transaction(blocking=not backup) as transaction,
        ):
            try:
                before = transaction.stat(path.name)
            except PrivateFSError as exc:
                if exc.reason != "missing" or exc.commit_state != "not_committed":
                    raise
                before = None
            if before is not None and not backup:
                if before.size > CONFIG_LIMIT:
                    raise PrivateFSError("unsafe", "oversize")
                original = transaction.read_bytes(path.name, max_bytes=CONFIG_LIMIT)
                if transaction.stat(path.name) != before:
                    raise PrivateFSError("unsafe", "read_changed")
                if original == data:
                    return False
                transaction.replace_bytes(path.name, data)
            else:
                transaction.create_bytes(path.name, data)
            published = True
            before = transaction.stat(path.name)
            actual = transaction.read_bytes(path.name, max_bytes=CONFIG_LIMIT)
            if actual != data or transaction.stat(path.name) != before:
                raise PrivateFSError("unsafe", "private_write_verification")
        return True
    except PrivateFSError as exc:
        if published:
            exc.commit_state = "uncertain"
        raise


def _round_trip_yaml() -> YAML:
    """ruamel YAML instance configured for round-trip preservation.

    ``typ="rt"`` retains comments, key order, and anchors. Indent settings
    match the Hermes-shipped config style (2-space mapping, 4-space sequence,
    sequences offset 2 from their parent key) so the diff stays minimal
    when we touch unrelated nested keys.
    """
    yaml = YAML(typ="rt")
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    yaml.width = 4096  # don't wrap long values
    return yaml


def _fsync_durable(fd: int) -> None:
    """Flush an fd durably, using F_FULLFSYNC where macOS provides it."""
    full_fsync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_fsync is not None:
        try:
            fcntl.fcntl(fd, full_fsync)
            return
        except OSError as exc:
            if exc.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
                raise
    os.fsync(fd)


def _fsync_parent(path: Path) -> None:
    if os.name != "posix":  # pragma: no cover - Windows directory-open semantics
        return
    fd = os.open(path.parent, os.O_RDONLY | _O_CLOEXEC)
    try:
        _fsync_durable(fd)
    finally:
        os.close(fd)


def _read_regular_text(path: Path) -> str | None:
    """Read an existing regular file without following or blocking on specials."""
    if _windows():
        raise PrivateFSError("unsupported", "generic_configuration_read_requires_checked_consumer")
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, "configuration source must be a regular file", str(path))
    fd = os.open(path, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError(errno.EAGAIN, "configuration source changed while opening", str(path))
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")
    finally:
        os.close(fd)


def _ensure_real_directory(directory: Path) -> None:
    """Create or validate a directory without accepting a symlink endpoint."""
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        with contextlib.suppress(FileExistsError):
            directory.mkdir(mode=0o700, parents=True)
        metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(errno.ENOTDIR, "writer parent must be a real directory", str(directory))


def _reject_unopenable_policy_lock(lock_path: Path, exc: OSError) -> NoReturn:
    """Wrap an ``os.open`` failure on the policy lock as a tagged ``EPERM``."""
    raise OSError(errno.EPERM, "policy writer lock is unsafe or unavailable", str(lock_path)) from exc


def _reject_unsafe_policy_lock(lock_path: Path) -> NoReturn:
    """Fail closed when the policy lock is not a private regular file."""
    raise OSError(errno.EPERM, "policy writer lock must be a mode-0600 regular file", str(lock_path))


@contextmanager
def _policy_write_lock(directory: Path) -> Iterator[None]:
    """Serialize policy/config read-modify-write cycles across threads/processes.

    The descriptor lifecycle is
    :func:`mordred_hermes._file_lock.private_flock`. The reentrancy-depth
    bookkeeping, the ``RLock``, the parent-directory check, and both raises
    stay here: the depth counter is specific to this module's nested
    transactions, and keeping the raises local keeps the tagged ``EPERM``
    :exc:`OSError`\\ s (and the ``from exc`` chaining) byte-identical. ``depth``
    is still set only *after* the flock is held and cleared *before* it is
    released, so a nested caller can never observe the flag without the lock.
    """
    if _windows():
        raise PrivateFSError("unsupported", "legacy_policy_lock_requires_canonical_consumer")
    with _POLICY_THREAD_LOCK:
        depth = getattr(_POLICY_LOCK_STATE, "depth", 0)
        if depth:
            _POLICY_LOCK_STATE.depth = depth + 1
            try:
                yield
            finally:
                _POLICY_LOCK_STATE.depth = depth
            return

        _ensure_real_directory(directory)
        with private_flock(
            directory / _POLICY_LOCK_FILENAME,
            on_unsafe=_reject_unsafe_policy_lock,
            on_open_error=_reject_unopenable_policy_lock,
        ):
            _POLICY_LOCK_STATE.depth = 1
            try:
                yield
            finally:
                _POLICY_LOCK_STATE.depth = 0


def _atomic_write_text(path: Path, text: str, *, mode: int | None = None) -> None:
    """Write ``text`` to ``path`` via tmp + replace.

    Idempotent: if ``path`` already contains ``text`` byte-for-byte, no
    write happens (avoids touching mtime and triggering downstream watchers).

    The tmpfile is created via :func:`tempfile.mkstemp` (atomic
    ``O_CREAT|O_EXCL`` at mode 0o600 with a random suffix). This closes:

    - H3 (review 2026-05-14): for ``mode=0o600`` calls (policy.json,
      .env, credentials JSON) the secret content never lands on disk at
      umask-default — the file is 0o600 from the moment of creation.
    - M5: predictable ``<name>.tmp`` paths could collide under
      concurrent writers; the random suffix removes that.
    - M6: stale ``<name>.tmp`` from a prior crash no longer collides
      with subsequent writes.

    The final file mode after ``os.replace`` is the explicit ``mode``
    argument when provided; otherwise the tmpfile's 0o600 (tightest safe
    default — the parent directory is 0o700 so this doesn't restrict
    legitimate access).

    An existing file must be readable before it can be replaced. A read error
    may hide operator-managed fields or secrets; treating it as merely a failed
    idempotency comparison would allow a writable parent directory to turn a
    transient ACL/ownership problem into silent data loss.
    """
    if _windows():
        raise PrivateFSError("unsupported", "generic_configuration_write_requires_checked_consumer")
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        path_metadata = None
    if path_metadata is not None and stat.S_ISREG(path_metadata.st_mode):
        # Read through a descriptor opened without following symlinks where the
        # platform supports it. O_NONBLOCK plus the post-open fstat also avoids
        # hanging if a regular path is raced into a FIFO between lstat/open.
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        existing_fd = os.open(path, flags)
        try:
            opened_metadata = os.fstat(existing_fd)
            same_object = (path_metadata.st_dev, path_metadata.st_ino) == (
                opened_metadata.st_dev,
                opened_metadata.st_ino,
            )
            if stat.S_ISREG(opened_metadata.st_mode) and same_object:
                with os.fdopen(os.dup(existing_fd), encoding="utf-8") as existing_file:
                    existing = existing_file.read()
                if existing == text:
                    if mode is None or stat.S_IMODE(opened_metadata.st_mode) == mode:
                        return  # no-op -- content and requested metadata match
                    fchmod = getattr(os, "fchmod", None)
                    if callable(fchmod):
                        fchmod(existing_fd, mode)
                        _fsync_durable(existing_fd)
                        return
                    # Windows may not expose fchmod. Fall through to the same
                    # private tmp + atomic replacement used for content changes.
        finally:
            os.close(existing_fd)
    # Symlinks and other non-regular entries are never opened for comparison:
    # following one could disclose another file, while reading a FIFO/device
    # can block forever. The atomic replace below safely replaces the directory
    # entry itself (or fails closed for an unreplaceable directory).

    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # mkstemp returns (fd, name). fd is opened O_RDWR|O_CREAT|O_EXCL at
    # mode 0o600 atomically -- no umask-default window. prefix/suffix
    # combine to keep the path adjacent to its target so os.replace stays
    # within the same filesystem (otherwise replace is non-atomic).
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            _fsync_durable(f.fileno())
        if mode is not None and mode != 0o600:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_parent(path)
    except BaseException:
        # Best-effort cleanup -- if replace already happened the unlink is
        # a no-op (the path no longer points at our tmpfile).
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def _begin_policy_transaction(policy_json_path: Path) -> Path:
    marker = policy_transaction_marker_for_policy(policy_json_path)
    # Record who/when so a marker surviving an interrupted run is diagnosable
    # rather than an unexplained file that silently forces strict mode.
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _atomic_write_text(marker, f"pending pid={os.getpid()} since={stamp}\n", mode=0o600)
    # Even an idempotent pre-existing marker must be re-synchronized. A prior
    # begin may have made the directory entry visible and then failed its
    # parent fsync; simply returning on identical content could otherwise let
    # the two mirrors update while the marker is still non-durable.
    fd = os.open(marker, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise OSError(errno.EPERM, "policy transaction marker must be a mode-0600 regular file", str(marker))
        _fsync_durable(fd)
    finally:
        os.close(fd)
    _fsync_parent(marker)
    return marker


def _finish_policy_transaction(marker: Path) -> None:
    """Clear the marker, failing loudly enough to be actionable if it survives.

    A surviving marker forces every reader closed to strict mode with empty
    settings. Re-raising a bare ``PermissionError`` here would leave the operator
    with refusals and no named cause, so the message states the consequence and
    the remedy.
    """
    try:
        marker.unlink()
    except FileNotFoundError:
        return  # already cleared (concurrent writer finished the transaction)
    except OSError as exc:
        raise OSError(
            errno.EACCES,
            (
                f"the Mordred policy files were written, but the transaction marker {marker} "
                f"could not be removed ({exc}). Every policy read fails closed to strict mode "
                "with empty settings until it is gone — delete it by hand"
            ),
            str(marker),
        ) from exc
    _fsync_parent(marker)


def _ensure_plugins_enabled(root: Any, *, log_notes: bool = True) -> PluginListMigration:
    """Ensure ``mordred`` appears in ``plugins.enabled`` (and migrate legacy names).

    Per HOOK_PAYLOADS.md §1, Hermes's
    entry-point plugins are NOT auto-loaded; their names must be listed
    in ``plugins.enabled`` for ``register()`` to be invoked.

    No-op if the section is already complete. If ``plugins.enabled`` is
    absent we add it; if ``plugins`` itself is absent we add it. Existing
    non-Mordred entries are preserved. The pre-0.2.0a0 per-component names
    (``mordred_network``, ...) are removed from ``plugins.enabled`` and
    ``plugins.disabled``; see :func:`mordred_hermes._plugin_identity.migrate_plugin_lists`.
    The migration notes are logged as warnings unless ``log_notes`` is false
    (callers that print them to the operator themselves).
    """
    plugins = root.get("plugins") if isinstance(root, Mapping) else None
    if not isinstance(plugins, MutableMapping):
        if plugins is not None:
            _LOG.warning(
                "plugins is %s, not a mapping; replacing with fresh enabled list",
                type(plugins).__name__,
            )
        # Use a plain dict -- ruamel will still emit it as a mapping; round-trip
        # treatment of NEW keys is best-effort (we own this section).
        root["plugins"] = {"enabled": list(MORDRED_PLUGIN_NAMES)}
        return PluginListMigration(added_enabled=True)

    enabled = plugins.get("enabled")
    if enabled is not None and not isinstance(enabled, list):
        # Hermes treats a malformed allow-list exactly like a missing one:
        # no entry-point plugin loads.  Leaving it untouched after a successful
        # configure therefore strands every runtime guard. The migration keeps
        # a scalar plugin name when possible and replaces the unusable value.
        _LOG.warning(
            "plugins.enabled is %s, not list; replacing with a valid enabled list",
            type(enabled).__name__,
        )
    elif isinstance(enabled, list) and any(not isinstance(item, str) or not item.strip() for item in enabled):
        _LOG.warning("plugins.enabled contains invalid plugin names; removing non-string or empty entries")

    migration = migrate_plugin_lists(plugins)
    if log_notes:
        for note in migration.notes():
            _LOG.warning("%s", note)
    return migration


def _upsert_mordred_section(root: Any, plugin_name: str, body: Mapping[str, Any]) -> None:
    """Replace ``plugins.<plugin_name>`` with ``body``, leaving siblings alone.

    Whole-section replacement is intentional -- partial merges across
    invocations would leave dangling keys from prior policy modes.
    Non-Mordred plugin sections are preserved.

    Pathological cases (``plugins`` itself is a scalar / list from a hand-edit
    or interrupted write) fall back to whole-replacement of the ``plugins``
    key with a fresh dict — crashing on ``int[str] = ...`` would leave the
    user with an unrecoverable config. Logged at WARNING so the operator
    sees the corruption.
    """
    plugins = root.get("plugins")
    if not isinstance(plugins, MutableMapping):
        if plugins is not None:
            _LOG.warning(
                "plugins is %s, not a mapping; replacing with upsert body",
                type(plugins).__name__,
            )
        root["plugins"] = {plugin_name: dict(body)}
        return
    plugins[plugin_name] = dict(body)


def _merge_mordred_section(root: Any, plugin_name: str, body: Mapping[str, Any]) -> None:
    """In-place merge ``body`` into ``plugins.<plugin_name>``, preserving siblings.

    Unlike :func:`_upsert_mordred_section`, the existing section's sub-fields
    survive: only keys in ``body`` are touched. ruamel.yaml's CommentedMap
    in-place update preserves comments and key order for retained keys; new
    keys are appended at the end of the section.

    Pathological cases (the section is currently a scalar / list / null) fall
    back to whole-replacement -- the on-disk shape is no longer mergeable and
    crashing with ``AttributeError: 'str' has no 'get'`` would leave the user
    with an unrecoverable config. Logged at WARNING so the operator sees it.

    Used by :meth:`PolicyWriter.merge_mordred_sections` (Phase 3 PR3a) to
    drive ``hermes mordred network use <path>`` without dropping Tor /
    Mullvad sub-fields the wizard configure step wrote earlier.
    """
    plugins = root.get("plugins")
    if not isinstance(plugins, MutableMapping):
        if plugins is not None:
            _LOG.warning(
                "plugins is %s, not a mapping; replacing with merge body",
                type(plugins).__name__,
            )
        root["plugins"] = {plugin_name: dict(body)}
        return
    existing = plugins.get(plugin_name)
    # ``MutableMapping`` (not ``Mapping``) so the index-assignment loop below
    # narrows under mypy --strict. ruamel.yaml ``CommentedMap`` is a
    # ``MutableMapping`` so this is exactly the shape we need.
    if not isinstance(existing, MutableMapping):
        if existing is not None:
            _LOG.warning(
                "plugins.%s is %s, not a mapping; replacing with merge body",
                plugin_name,
                type(existing).__name__,
            )
        plugins[plugin_name] = dict(body)
        return
    for key, value in body.items():
        existing[key] = value


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Resolved policy values destined for ``policy.json``.

    Phase 1 + Phase 2 fields. Order of fields matches the JSON serialisation
    order — keep stable for diffability.

    Phase 2 fields (``local_llm_endpoint`` / ``local_llm_model_id`` /
    ``cloud_attempt_action``) are read by ``mordred_llm_guard`` and persisted
    here so future wizard reruns are not required after upgrading from
    Phase 1. They deliberately do NOT appear in
    :meth:`to_config_yaml_section`; ``plugins.mordred_privacy_check`` is
    privacy-check's namespace and Phase 2 fields belong to llm_guard.
    """

    policy: str  # "strict" | "lenient" | "off"
    allow_cloud_llm: bool = False
    cloud_provider_allowlist: tuple[str, ...] = ()
    audit_log_path: str | None = None
    # Phase 2 (Codex M3 — moved from PR2 so Phase 2 has a stable policy input surface).
    local_llm_endpoint: str = "http://localhost:1234/v1"
    local_llm_model_id: str = ""
    cloud_attempt_action: Literal["always-block", "prompt-once"] = "always-block"
    # Phase 2 PR2: config.yaml-only (consumed by harness_detect). Default
    # ``"none"`` is a sentinel that doesn't match any harness regex pattern.
    harness_primary: str = "none"
    # Phase 3 PR3a Task #7: persisted to policy.json so the network reader
    # (mordred_hermes.network.settings.resolve_disable_ipv6) can consume it.
    # Default ``True`` matches the safe-by-default in RuntimeConfig.
    disable_ipv6: bool = True
    # Phase 3 transport facts are an intentionally opaque JSON value here.
    # A valid value is an object keyed by provider id, but keeping the wider
    # ``object`` type is security-significant: if a hand edit leaves a list,
    # scalar, or malformed entry, configure/upgrade must preserve that value
    # so the network gate continues to reject it rather than silently
    # sanitising it to the permissive empty-object default.
    # Exclude the opaque JSON container from the generated hash so adding the
    # field does not make this previously-hashable frozen snapshot unhashable.
    provider_overrides: object = field(default_factory=dict, hash=False)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "allow_cloud_llm": self.allow_cloud_llm,
            "cloud_provider_allowlist": list(self.cloud_provider_allowlist),
            "audit_log_path": self.audit_log_path,
            "local_llm_endpoint": self.local_llm_endpoint,
            "local_llm_model_id": self.local_llm_model_id,
            "cloud_attempt_action": self.cloud_attempt_action,
            "disable_ipv6": self.disable_ipv6,
            # Defensive copy: callers receive a serialisation payload, not a
            # mutable alias to the snapshot's preserved extension value.
            "provider_overrides": copy.deepcopy(self.provider_overrides),
        }

    def to_llm_guard_section(self) -> dict[str, Any]:
        """The body under ``plugins.mordred_llm_guard`` in config.yaml.

        Phase 2 PR2: only ``harness_primary`` for now — wizard is the sole
        writer and ``harness_detect`` is the sole reader. Other Phase 2
        fields stay in policy.json so plugins read through one mirror
        rather than two.
        """
        return {"harness_primary": self.harness_primary}

    def to_config_yaml_section(self) -> dict[str, Any]:
        """The body that lives under ``plugins.mordred_privacy_check`` in config.yaml.

        The same shape is read by ``privacy_check._runtime._load_state``
        (see ``privacy_check/_runtime.py:106``); changing field names here
        requires a coordinated change there. Phase 2 fields are intentionally
        excluded — they belong to ``plugins.mordred_llm_guard`` (PR2) and the
        ``policy.json`` cross-plugin mirror.
        """
        body: dict[str, Any] = {
            "policy": self.policy,
            "allow_cloud_llm": self.allow_cloud_llm,
            "cloud_provider_allowlist": list(self.cloud_provider_allowlist),
        }
        if self.audit_log_path is not None:
            body["audit_log_path"] = self.audit_log_path
        return body


def _preserve_provider_overrides(snapshot: PolicySnapshot, policy_json_path: Path) -> PolicySnapshot:
    """Carry the existing opaque ``provider_overrides`` value into ``snapshot``.

    The wizard owns all other policy.json fields, but provider overrides are
    operator-managed transport evidence. A configure/upgrade rewrite therefore
    preserves that one field verbatim. Crucially, this helper does *not*
    validate or coerce it: invalid types and unknown nested fields must survive
    so ``network.hooks._read_provider_overrides`` retains its fail-closed
    behaviour under strict + Tor.

    A non-empty/non-default value already supplied by the caller is explicit
    and wins. Missing/unreadable/non-object policy files have no preservable
    field and leave the snapshot unchanged.
    """
    if snapshot.provider_overrides != {}:
        return snapshot
    # A recovery write intentionally runs while a stale/pending transaction
    # marker is present. The writer holds the exclusive policy lock, so it may
    # inspect the previous mirror to preserve operator-managed overrides even
    # though runtime readers must treat the same state as fail-closed.
    existing = load_policy_mapping(
        policy_json_path,
        log=_LOG,
        allow_pending_transaction=True,
    )
    if "provider_overrides" not in existing:
        return snapshot
    return replace(
        snapshot,
        provider_overrides=copy.deepcopy(existing["provider_overrides"]),
    )


def _section_matches_dict(existing: Mapping[str, Any], want: Mapping[str, Any]) -> bool:
    """True iff ``existing`` super-set-equals ``want`` field-by-field.

    The idempotency / conflict predicate shared by ``upgrade`` and
    ``openclaw_migration`` for comparing an on-disk ``plugins.mordred_*``
    section against a :meth:`PolicySnapshot.to_config_yaml_section` body:
    every target field must be present with an equal value, while extra
    user-added keys are tolerated (a superset still matches, so an annotated
    config is not flagged as a conflict). Lives beside the snapshot it
    compares against so the two migration callers cannot drift.
    """
    return all(existing.get(k) == v for k, v in want.items()) and set(existing.keys()) >= set(want.keys())


@dataclass
class PolicyWriter:
    """Sole writer for ``~/.hermes/config.yaml plugins.mordred_*`` and ``policy.json``."""

    config_path: Path = DEFAULT_HERMES_CONFIG_PATH
    policy_json_path: Path = DEFAULT_POLICY_JSON_PATH
    mordred_dir: Path = DEFAULT_MORDRED_DIR

    def _checked_edit(self, *, recover: bool = False) -> contextlib.AbstractContextManager[_CheckedPolicyEdit]:
        return _checked_policy_edit(
            _canonical_paths(self.config_path, self.policy_json_path, self.mordred_dir), recover=recover
        )

    def resolve_and_write(self, resolve: Callable[[dict[str, Any]], PolicySnapshot]) -> PolicySnapshot:
        """Resolve pure flag inputs from the locked Windows pair, then publish once.

        The callback must not prompt or perform provider/network operations.
        """
        if not _windows():
            raise PrivateFSError("unsupported", "checked_flag_resolution_is_windows_only")
        with self._checked_edit(recover=True) as edit:
            existing = dict(edit.policy)
            plugins = edit.root.get("plugins")
            guard = plugins.get("mordred_llm_guard") if isinstance(plugins, Mapping) else None
            if isinstance(guard, Mapping) and isinstance(guard.get("harness_primary"), str):
                existing["harness_primary"] = guard["harness_primary"]
            snapshot = resolve(existing)
            edit.emit(snapshot)
            edit.edit_sections(
                {
                    "mordred_privacy_check": snapshot.to_config_yaml_section(),
                    "mordred_llm_guard": snapshot.to_llm_guard_section(),
                },
                _upsert_mordred_section,
            )
        return snapshot

    def transform_config(self, transform: Callable[[MutableMapping[str, Any]], None]) -> None:
        """Apply a pure Windows config transformation to the checked complete pair."""
        if not _windows():
            raise PrivateFSError("unsupported", "checked_config_transform_is_windows_only")
        with self._checked_edit() as edit:
            transform(edit.root)
            edit.dump_config()

    def upsert_mordred_sections(self, sections: Mapping[str, Mapping[str, Any]]) -> None:
        """Round-trip-edit ``config.yaml`` to upsert one or more Mordred plugin sections.

        ``sections`` maps plugin name (e.g. ``"mordred_privacy_check"``) to
        the new section body. Non-listed Mordred plugins and non-Mordred
        plugins in ``config.yaml`` are left untouched.

        Whole-section replacement: any sub-field not in ``body`` is dropped.
        Use :meth:`merge_mordred_sections` for partial writes (e.g.
        ``hermes mordred network use``) that must preserve sub-fields written
        by other code paths or by hand.

        Also ensures all Mordred plugin names appear in ``plugins.enabled``
        (Hermes entry-point loader requires this -- HOOK_PAYLOADS §1).
        """
        if _windows():
            with self._checked_edit() as edit:
                edit.edit_sections(sections, _upsert_mordred_section)
            return
        with _policy_write_lock(self.policy_json_path.parent):
            self._edit_config(sections, _upsert_mordred_section)

    def merge_mordred_sections(self, sections: Mapping[str, Mapping[str, Any]]) -> None:
        """In-place merge sub-fields into ``plugins.<plugin_name>`` sections.

        Unlike :meth:`upsert_mordred_sections`, sub-fields not present in
        ``body`` survive on-disk. Use for partial writers like
        ``hermes mordred network use <path>`` that only know one field and
        must not drop Tor / Mullvad fields set by the wizard configure step.

        Pathological cases (the on-disk value is a scalar / list) fall back
        to whole-replacement -- a corrupted section is no longer mergeable.
        """
        if _windows():
            with self._checked_edit() as edit:
                edit.edit_sections(sections, _merge_mordred_section)
            return
        with _policy_write_lock(self.policy_json_path.parent):
            self._edit_config(sections, _merge_mordred_section)

    def migrate_plugin_identity(self, *, create_missing: bool = False) -> PluginListMigration:
        """Switch ``plugins.enabled`` / ``plugins.disabled`` to the single ``mordred`` plugin.

        Touches nothing but those two lists and writes only when something
        changed. A missing ``config.yaml`` is left missing unless
        ``create_missing`` (nothing to migrate; ``configure`` creates it).
        See :func:`_ensure_plugins_enabled`.
        """
        if _windows():
            with self._checked_edit() as edit:
                if not edit.config_present and not create_missing:
                    return PluginListMigration()
                migration = _ensure_plugins_enabled(edit.root, log_notes=False)
                if migration.changed:
                    edit.dump_config()
            return migration
        with _policy_write_lock(self.policy_json_path.parent):
            existing = _read_regular_text(self.config_path)
            if existing is None and not create_missing:
                return PluginListMigration()
            yaml = _round_trip_yaml()
            root = yaml.load(existing) if existing else None
            if root is None:
                root = {}
            migration = _ensure_plugins_enabled(root, log_notes=False)
            if migration.changed:
                buf = io.StringIO()
                yaml.dump(root, buf)
                _atomic_write_text(self.config_path, buf.getvalue())
            return migration

    def _edit_config(
        self,
        sections: Mapping[str, Mapping[str, Any]],
        section_mutator: Callable[[Any, str, Mapping[str, Any]], None],
    ) -> None:
        """Shared round-trip pipeline for upsert / merge.

        Loads ``config.yaml`` (or starts empty), applies ``section_mutator`` to
        each requested section, runs :func:`_ensure_plugins_enabled`, and
        writes back atomically via :func:`_atomic_write_text`.
        """
        yaml = _round_trip_yaml()
        existing = _read_regular_text(self.config_path)
        if existing is not None:
            root = yaml.load(existing)
            if root is None:
                root = {}
        else:
            root = {}

        for plugin_name, body in sections.items():
            if plugin_name not in MORDRED_CONFIG_SECTIONS:
                raise ValueError(f"PolicyWriter only edits Mordred plugin sections; refusing to touch {plugin_name!r}")
            section_mutator(root, plugin_name, body)

        _ensure_plugins_enabled(root)

        buf = io.StringIO()
        yaml.dump(root, buf)
        _atomic_write_text(self.config_path, buf.getvalue())

    def emit_policy_json(self, snapshot: PolicySnapshot) -> None:
        """Serialise ``snapshot`` to ``policy.json`` (mode 0o600, atomic).

        ``json.dumps`` with ``sort_keys=False`` to honour :class:`PolicySnapshot`
        field order; a 2-space indent for human readability. Idempotent --
        rewrite is skipped if content matches. Existing operator-managed
        ``provider_overrides`` are carried forward verbatim, including invalid
        values that the strict transport gate must continue to reject.
        """
        if _windows():
            with self._checked_edit() as edit:
                edit.emit(snapshot)
            return
        with _policy_write_lock(self.policy_json_path.parent):
            snapshot = _preserve_provider_overrides(snapshot, self.policy_json_path)
            text = json.dumps(snapshot.to_json_dict(), indent=2, sort_keys=False) + "\n"
            _atomic_write_text(self.policy_json_path, text, mode=0o600)

    def write(
        self,
        snapshot: PolicySnapshot,
        *,
        network_answers: _HasConfigYamlSection | None = None,
    ) -> None:
        """Compose: write ``policy.json`` AND the matching config.yaml sections.

        Convenience for ``hermes mordred configure``. Phase 2 PR2 added
        ``mordred_llm_guard`` to the upserted set so ``harness_primary``
        lands in config.yaml. Phase 3 PR3a Task #7 adds an optional
        ``network_answers`` (concretely
        ``mordred_hermes.wizard.network_cli.NetworkAnswers`` but typed here
        via the :class:`_HasConfigYamlSection` Protocol to avoid the
        ``configure -> policy_writer -> configure`` import cycle) which
        lands in ``plugins.mordred_network`` via the Task #1
        :meth:`merge_mordred_sections` so subsequent ``hermes mordred
        network use <path>`` invocations don't clobber the wizard's
        choices.
        """
        if _windows():
            network_section = network_answers.to_config_yaml_section() if network_answers is not None else None
            with self._checked_edit(recover=True) as edit:
                edit.emit(snapshot)
                edit.edit_sections(
                    {
                        "mordred_privacy_check": snapshot.to_config_yaml_section(),
                        "mordred_llm_guard": snapshot.to_llm_guard_section(),
                    },
                    _upsert_mordred_section,
                )
                if network_section is not None:
                    edit.edit_sections({"mordred_network": network_section}, _merge_mordred_section)
            return
        with _policy_write_lock(self.policy_json_path.parent):
            marker = _begin_policy_transaction(self.policy_json_path)
            self.emit_policy_json(snapshot)
            self.upsert_mordred_sections(
                {
                    "mordred_privacy_check": snapshot.to_config_yaml_section(),
                    "mordred_llm_guard": snapshot.to_llm_guard_section(),
                }
            )
            if network_answers is not None:
                self.merge_mordred_sections({"mordred_network": network_answers.to_config_yaml_section()})
            _finish_policy_transaction(marker)
