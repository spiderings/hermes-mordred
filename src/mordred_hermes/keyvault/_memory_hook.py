"""Mordred-owned at-rest encryption for Hermes agent memory.

No hermes-agent release encrypts ``~/.hermes/memories/*.md``, so this module
wraps upstream's private ``tools/memory_tool.py`` seam and seals the bytes on the
way out / opens them on the way in (format: :mod:`.memory_crypto`). Same
defensive posture as :mod:`._env_write_guard`: upstream ships no API stability
guarantee, so the seam is *classified by signature* before anything is wrapped
and an unrecognised shape is refused rather than guessed at.

Three shapes exist in the wild; wrapping the wrong one is a data-loss bug, not a
cosmetic one — a sealed file that a read seam reports as "empty" is overwritten
by the next write:

============  ==================================  ================================
Shape         Read chokepoint                     Drift detection
============  ==================================  ================================
A (0.20+)     ``_read_raw_checked(path)``         ``_detect_external_drift(self, target, raw)``
B (0.16-19)   ``_read_file(path)``                ``_detect_external_drift(self, target)``
C (0.13-15)   ``_read_file(path)``                none
============  ==================================  ================================

Arming is evaluated **per call**, never cached: the operator can pause the
feature (opt-out marker) mid-session, and the key arrives in ``os.environ`` from
the vault shim, which may run after this module is imported.

**Fail-closed on the write side, loud on the read side.** While armed we never
write plaintext, and a sealed file that cannot be decrypted raises
:class:`MemoryEncryptionUnavailable` instead of degrading to "no entries" — in
shapes B/C that degradation would let the next ``add`` overwrite the sealed file
(upstream's own wipe class, issue #26045), and in shape A the operator would
silently see an empty memory.

A read therefore has **three** answers, not two: sealed, plaintext, and *broken
seal* — a file whose first bytes are the magic line but whose structure no longer
parses (appended to, truncated, re-wrapped). Classifying that third state as
plaintext is how AEAD tamper-evidence gets bypassed, so it refuses instead. The
two halves depend on each other: the write guard refuses to create a plaintext
file whose first entry starts with the magic, which is what makes
magic-at-file-start a sound signal for the read side.

**Sealing is sticky.** A write is decided by the file on disk first, the arming
state second:

=====================  ==========  ==================================================
On disk                Armed       Write
=====================  ==========  ==================================================
sealed                 either      seal (key required, else refuse)
plaintext / absent     yes         seal (key required, else refuse)
plaintext / absent     no          plaintext (upstream's own write, verbatim)
=====================  ==========  ==================================================

So a disarmed, safe-mode, or keyless process can never put plaintext back over
sealed bytes: sealed stays sealed until the CLI decrypts it back explicitly.
``HERMES_SAFE_MODE`` therefore means "no NEW sealing and no refusal to start",
not "no protection" — the seams stay wrapped whenever the shape is supported.

Installation happens twice on purpose. The keyvault plugin ``register()`` calls
:func:`install_memory_hook` directly, and :func:`install_memory_import_hook`
registers a ``sys.meta_path`` finder from the ``.pth`` bootstrap, so a process
that never runs plugin discovery — or whose discovery fails, or runs off the main
thread — still gets the seam wrapped the moment upstream imports it. The finder
never imports ``tools.memory_tool`` itself: that import has upstream side effects.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import logging
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from importlib.abc import Loader, MetaPathFinder
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from .._home import hermes_home as _hermes_home
from .._runtime_bootstrap import _SAFE_MODE_TRUTHY
from .memory_crypto import (
    MemoryCryptoError,
    decode_key,
    is_sealed,
    looks_like_magic_line,
    seal,
    unseal,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from importlib.machinery import ModuleSpec
    from types import ModuleType

__all__ = [
    "MemoryEncryptionUnavailable",
    "classify_seam",
    "install_journey_guard",
    "install_memory_hook",
    "install_memory_import_hook",
    "memory_hook_installed",
    "memory_marker_path",
    "memory_optout_marker_path",
    "memory_seam_shape",
    "seam_check",
    "warn_when_memory_is_locked",
]

logger = logging.getLogger(__name__)

#: Opt-IN marker: its presence arms the hook (mirrors ``_config_bootstrap._MARKER_SUBPATH``).
_MEMORY_MARKER_SUBPATH: Final = ("mordred", "memory-vault.marker")
#: Opt-OUT marker: the operator paused the feature (mirrors ``_runtime_env._ENV_OPTOUT_SUBPATH``).
_MEMORY_OPTOUT_SUBPATH: Final = ("mordred", "memory-vault.optout")

_MEMORY_KEY_ENV: Final = "HERMES_MEMORY_KEY"

#: Stamped on every wrapper so a second install is a no-op (idempotent).
_WRAPPED_FLAG: Final = "_mordred_memory_hook_wrapped"

_REMEDY: Final = (
    "run `hermes-mordred encryption enable env` so HERMES_MEMORY_KEY is injected, "
    "or `hermes-mordred encryption disable memory`"
)

#: Paths already reported as plaintext — one warning per path per process.
_PLAINTEXT_SEEN: set[str] = set()

#: Homes already reported as "sealed memory, no usable key" — one warning per process.
_LOCKED_WARNED: set[str] = set()


class MemoryEncryptionUnavailable(RuntimeError):
    """Memory could not be sealed or opened.

    A ``RuntimeError`` on purpose: that is what upstream's memory write path
    already raises for an I/O failure, so callers that catch it report the
    refusal to the model instead of crashing the process.
    """


def memory_marker_path(home: Path) -> Path:
    """The opt-in marker path: ``<home>/mordred/memory-vault.marker``."""
    return home.joinpath(*_MEMORY_MARKER_SUBPATH)


def memory_optout_marker_path(home: Path) -> Path:
    """The opt-out marker path: ``<home>/mordred/memory-vault.optout``."""
    return home.joinpath(*_MEMORY_OPTOUT_SUBPATH)


def _marker_armed(home: Path) -> bool:
    """Opt-in present and not paused — the on-disk half of "armed"."""
    return memory_marker_path(home).exists() and not memory_optout_marker_path(home).exists()


def _live_home() -> Path:
    """Hermes's home resolved at call time (not bound at import: profiles switch)."""
    return _hermes_home()


def _home_factory(home: Path | None) -> Callable[[], Path]:
    """An injected home is fixed; otherwise every call re-resolves it."""
    return _live_home if home is None else (lambda: home)


@dataclass(frozen=True)
class _HookConfig:
    """What the wrappers close over. ``home`` / ``environ`` are injectable for tests."""

    environ: Mapping[str, str]
    delimiter: str
    home_factory: Callable[[], Path] = field(default=_live_home)

    @property
    def home(self) -> Path:
        """Resolved per call unless injected: a profile switch changes it mid-process."""
        return self.home_factory()

    @property
    def armed(self) -> bool:
        """Whether sealing NEW files is on **right now** — re-read per call, never cached."""
        if _safe_mode(self.environ):
            return False
        return _marker_armed(self.home)

    @property
    def key(self) -> bytes | None:
        """The live memory key, or ``None`` when unset / unusable."""
        from ._memory_key import MemoryKeyError, resolve_memory_key

        try:
            return resolve_memory_key(home=self.home, platform=sys.platform, environ=self.environ)
        except MemoryKeyError as exc:
            raise MemoryEncryptionUnavailable(
                "TPM memory key unavailable; restore the original TPM/key material"
            ) from exc


def _decode_env_key(environ: Mapping[str, str]) -> bytes | None:
    """``HERMES_MEMORY_KEY`` as raw bytes, or ``None`` when unset or malformed."""
    value = environ.get(_MEMORY_KEY_ENV)
    if not value:
        return None
    try:
        return decode_key(value)
    except MemoryCryptoError:
        return None


def _safe_mode(environ: Mapping[str, str]) -> bool:
    """Hermes's explicit plugin-recovery escape hatch (same truthy set as the bootstrap)."""
    return environ.get("HERMES_SAFE_MODE", "").strip().casefold() in _SAFE_MODE_TRUTHY


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_key(cfg: _HookConfig, path: Path, *, writing: bool) -> bytes:
    """The live key, or refuse loudly. Never falls back to plaintext."""
    key = cfg.key
    if key is not None:
        return key
    what = (
        f"refusing to write {path} in plaintext: memory encryption is on but" if writing else f"{path} is encrypted but"
    )
    raise MemoryEncryptionUnavailable(f"{what} {_MEMORY_KEY_ENV} is not set or not usable — {_REMEDY}.")


def _require_key_for_sealed(cfg: _HookConfig, path: Path) -> bytes:
    """The live key for a file that is already sealed on disk, or refuse.

    Rewriting it in plaintext would destroy content this process cannot read, so a
    keyless write is a refusal even when the hook is disarmed.
    """
    key = cfg.key
    if key is not None:
        return key
    raise MemoryEncryptionUnavailable(
        f"refusing to overwrite sealed {path} without its key: {_MEMORY_KEY_ENV} is not set or not usable — {_REMEDY}."
    )


def _disk_text(path: Path) -> str | None:
    """The one on-disk view every classifier in this module uses; ``None`` if unreadable.

    ``read_text`` and not ``read_bytes``: it decodes in universal-newline mode,
    exactly like upstream's own readers. Reading the bytes instead would classify a
    CRLF-converted seal as plaintext while the read seam happily decrypted it, and
    the write seam would then publish plaintext over sealed bytes.
    """
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _sealed_on_disk(path: Path) -> bool:
    """Whether the file at ``path`` currently holds a seal (absent / unreadable: no)."""
    text = _disk_text(path)
    return text is not None and is_sealed(text)


def _refuse_broken_seal(text: str, path: Path) -> None:
    """Refuse text that starts with the magic line but is not a whole seal.

    The third state between "sealed" and "plaintext". A seal that was appended to,
    truncated, or re-wrapped fails :func:`is_sealed`, and treating that as plaintext
    would hand the ciphertext to upstream as one entry, keep the locked-memory
    warning silent, and let the next write overwrite what AEAD was supposed to
    protect — tamper-evidence turned into tamper-tolerance.

    Only the *file's first bytes* are classified this way, and only the write guard
    below makes that sound: it refuses to create a plaintext file whose first entry
    starts with the magic, so magic-at-file-start is always a seal or a broken one.
    """
    if not looks_like_magic_line(text) or is_sealed(text):
        return
    raise MemoryEncryptionUnavailable(
        f"{path} looks sealed but its structure is broken (appended to, truncated, or re-wrapped) — "
        f"restore it from a backup or remove it; it cannot be read as memory."
    )


def _refuse_broken_seal_on_disk(entries: Sequence[str], path: Path) -> None:
    """Shapes B/C: the same check, run on the file text upstream just parsed.

    Those shapes only hand back parsed entries, and "one entry that is not a seal"
    is far too broad to refuse on. Re-reading the file (through :func:`_disk_text`,
    the same view upstream used) is the only way to tell a broken seal from a
    plaintext store, and it is worth a stat only when entry 0 carries the magic.
    """
    if not entries or not looks_like_magic_line(entries[0]):
        return
    text = _disk_text(path)
    if text is not None:
        _refuse_broken_seal(text, path)


def _refuse_magic_first_entry(entries: Sequence[str], path: Path) -> None:
    """Refuse a **plaintext** write whose first entry starts with the magic line.

    Written verbatim it would put the magic at the head of the file, which every
    later classification — this hook's own write decision included — reads as a
    seal, or as the broken seal :func:`_refuse_broken_seal` refuses. Narrow on
    purpose: only entry 0 can land at the file's head, and only the plaintext
    branch writes an entry there verbatim. A sealed write is harmless (the blob
    lives inside the ciphertext) and must not be refused, or an already-stored
    impersonation would brick every ``add`` on an encrypted store.
    """
    if not entries or not looks_like_magic_line(entries[0]):
        return
    raise MemoryEncryptionUnavailable(
        f"refusing to write {path} in plaintext: its first memory entry starts with the sealed-memory "
        f"header, which would make the file look sealed — delete that entry first (memory action=remove) "
        f"or enable memory encryption."
    )


def _unseal_text(raw: str, *, path: Path, key: bytes) -> str:
    """Open a sealed memory file's text, or raise :class:`MemoryEncryptionUnavailable`."""
    try:
        return unseal(raw.encode("utf-8"), key=key, name=path.name).decode("utf-8")
    except MemoryCryptoError as exc:
        raise MemoryEncryptionUnavailable(
            f"{path} failed to authenticate — it was sealed with a different key, renamed, or "
            f"modified since. Its contents are not recoverable with the current key; {_REMEDY}."
        ) from exc
    except UnicodeDecodeError as exc:
        raise MemoryEncryptionUnavailable(f"{path} decrypted to bytes that are not valid UTF-8.") from exc


def _split_entries(text: str, delimiter: str) -> list[str]:
    """Upstream's entry split, applied to the plaintext we just recovered."""
    return [entry for entry in (part.strip() for part in text.split(delimiter)) if entry]


def _note_plaintext_seen(path: Path) -> None:
    """Warn once per path that a memory file is still plaintext while armed."""
    if str(path) in _PLAINTEXT_SEEN:
        return
    _PLAINTEXT_SEEN.add(str(path))
    logger.warning("%s is plaintext memory while memory encryption is on — it is sealed on the next write", path)


def _write_private(path: Path, data: bytes) -> None:
    """Atomically publish ``data`` at ``path`` through a same-directory temp file.

    Same directory so the rename stays on one filesystem; ``mkstemp`` creates the
    temp at 0o600, so nothing we write is briefly world-readable. The directory is
    fsynced too — fsyncing the file persists the bytes, only fsyncing the parent
    persists the rename that publishes them.

    Deliberately **not** :func:`mordred_hermes.keyvault._storage.atomic_write`,
    the canonical private writer that ``extension.pairing._write_private``
    delegates to. That helper asserts an *existing* target is already mode
    ``0o600`` and refuses otherwise — correct for keyvault-owned files, fatal
    here: the file this seals is upstream Hermes' ``MEMORY.md``, created by
    ``MemoryStore`` at the process umask (typically ``0o644``), and the very
    first sealing write is the one that would be rejected. This writer takes
    ownership of whatever mode it finds and publishes at ``0o600`` instead. It
    also fsyncs with plain :func:`os.fsync` rather than ``_fsync_durable``'s
    ``F_FULLFSYNC``, which ``test_write_private_fsyncs_the_parent_directory``
    pins by counting exactly two ``os.fsync`` calls. Unifying the two would
    break memory encryption outright, not merely churn it.
    """
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".mordred_mem_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    """Persist a rename in ``directory``. A no-op where directories cannot be opened (Windows)."""
    try:
        dir_fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


# ---------------------------------------------------------------------------
# Seam classification
# ---------------------------------------------------------------------------

#: Every character a sealed file can contain: the magic line plus base64url and
#: its padding, joined by newlines.
_SEALED_BLOB_CHARS: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=\n")


def _params(owner: Any, name: str) -> tuple[str, ...] | None:
    member = getattr(owner, name, None)
    if not callable(member):
        return None
    try:
        return tuple(inspect.signature(member).parameters)
    except (TypeError, ValueError):
        return None


def _check_params(owner: Any, name: str, expected: tuple[str, ...]) -> str:
    """``""`` when ``owner.name`` takes exactly ``expected``, else the reason it does not."""
    found = _params(owner, name)
    if found is None:
        return f"MemoryStore.{name} is missing or not callable"
    if found != expected:
        return f"MemoryStore.{name} takes {found} (expected {expected})"
    return ""


#: What the shape A/B drift wrappers call on the store *besides* the seam they
#: replace. ``_path_for`` is a ``staticmethod(target)`` and ``_char_limit`` an
#: instance method in every reference release (0.13 → 0.20). Unchecked, a variant
#: that renamed either one classified fine and then raised ``AttributeError`` from
#: inside a ``replace`` / ``remove`` — after installation had already promised the
#: seam was understood.
_DRIFT_DEPENDENCIES: Final = (("_path_for", ("target",)), ("_char_limit", ("self", "target")))


def _check_drift_dependencies(store: Any) -> str:
    """``""`` when both drift helpers are upstream's, else the reason they are not."""
    for name, expected in _DRIFT_DEPENDENCIES:
        reason = _check_params(store, name, expected)
        if reason:
            return reason
    return ""


def classify_seam(memory_tool_module: Any) -> tuple[str, str]:
    """Classify the upstream seam by signature: ``("A"|"B"|"C", "")`` or ``("", reason)``.

    Never by version string — a vendored or patched ``memory_tool`` can carry any
    version. Anything that does not match a known shape exactly (a rename, a
    renamed parameter, a non-``str`` delimiter, a mixed shape) is unsupported, so
    the caller can fail closed instead of wrapping a seam it does not understand.
    """
    store = getattr(memory_tool_module, "MemoryStore", None)
    if store is None:
        return "", "tools.memory_tool has no MemoryStore"
    delimiter = getattr(memory_tool_module, "ENTRY_DELIMITER", None)
    if not isinstance(delimiter, str):
        return "", "tools.memory_tool.ENTRY_DELIMITER is missing or not a str"
    if _SEALED_BLOB_CHARS.issuperset(delimiter):
        # Shapes B/C recognise a sealed file by it parsing as exactly one entry.
        # A delimiter drawn only from the blob's own alphabet could occur inside a
        # seal, split it, and leave the sealed halves to be written back as
        # plaintext entries.
        return "", "ENTRY_DELIMITER could occur inside a sealed blob"

    for name, expected in (("_write_file", ("path", "entries")), ("_read_file", ("path",))):
        reason = _check_params(store, name, expected)
        if reason:
            return "", reason

    if getattr(store, "_read_raw_checked", None) is not None:
        reason = (
            _check_params(store, "_read_raw_checked", ("path",))
            or _check_params(store, "_detect_external_drift", ("self", "target", "raw"))
            or _check_drift_dependencies(store)
        )
        return ("", reason) if reason else ("A", "")

    if getattr(store, "_detect_external_drift", None) is None:
        return "C", ""  # no drift wrapper, so no drift dependencies to pin
    reason = _check_params(store, "_detect_external_drift", ("self", "target")) or _check_drift_dependencies(store)
    return ("", reason) if reason else ("B", "")


#: Set while :func:`_load_memory_tool` is importing the seam purely to CLASSIFY it.
#: The import hook's action runs during that import and would otherwise stop the
#: process on an unsupported seam — killing ``seam_check`` / ``memory_seam_shape``
#: / ``--probe``, i.e. exactly the diagnostics an operator runs to find out *why*
#: the seam is unsupported.
#:
#: A plain module-level flag, not a thread-local, and deliberately so: the post-
#: import action always runs on the thread that asked for the import, and a second
#: thread reaching the same module blocks on CPython's per-module import lock and
#: then takes it from ``sys.modules`` without re-running the action. So the flag is
#: never observed by a thread it was not set for, and thread-local machinery would
#: buy nothing. It is restored in a ``finally``, so the window is one
#: ``import_module`` call.
_SUPPRESS_REFUSAL = False


def _load_memory_tool() -> tuple[Any | None, str]:
    """Import the live ``tools.memory_tool`` for classification, or say why it is not there.

    That import has an upstream side effect (it registers the ``memory`` tool in
    the host registry). Acceptable here: ``register()`` runs inside plugin
    discovery, after the host's own tool discovery has already imported it.

    Every classification entry point goes through this function, so all of them
    inherit :data:`_SUPPRESS_REFUSAL`. Nothing else does — an agent process or a
    gateway importing the seam normally still gets the fail-closed refusal, and so
    does :func:`install_memory_hook` itself, which classifies the *returned* module
    after the flag has been restored.
    """
    global _SUPPRESS_REFUSAL

    import importlib

    previous = _SUPPRESS_REFUSAL
    _SUPPRESS_REFUSAL = True
    try:
        # importlib rather than `from tools import memory_tool`: `tools` ships no
        # stubs, so the attribute form does not type-check under --strict.
        return importlib.import_module("tools.memory_tool"), ""
    except Exception as exc:
        return None, f"tools.memory_tool is not importable: {exc!r}"
    finally:
        _SUPPRESS_REFUSAL = previous


def seam_check(memory_tool_module: Any | None = None) -> tuple[bool, str]:
    """``(True, "")`` when the live seam is one we can wrap, else ``(False, reason)``."""
    module, reason = (memory_tool_module, "") if memory_tool_module is not None else _load_memory_tool()
    if module is None:
        return False, reason
    shape, reason = classify_seam(module)
    return (True, "") if shape else (False, reason)


def memory_seam_shape(memory_tool_module: Any | None = None) -> str:
    """``"A"`` / ``"B"`` / ``"C"``, or ``""`` when unsupported — for diagnostics."""
    module = memory_tool_module if memory_tool_module is not None else _load_memory_tool()[0]
    return "" if module is None else classify_seam(module)[0]


def memory_hook_installed(memory_tool_module: Any | None = None) -> bool:
    """Whether **this process** has every seam of the live shape wrapped.

    In-process state, not on-disk. A partially wrapped store is reported as *not*
    installed: with the write seam wrapped but a read seam bare, upstream would
    parse a sealed file as one garbage entry and write it back mangled.
    """
    module = memory_tool_module if memory_tool_module is not None else _load_memory_tool()[0]
    if module is None:
        return False
    shape, _ = classify_seam(module)
    store = getattr(module, "MemoryStore", None)
    if not shape or store is None:
        return False
    return all(_is_wrapped(store, name) for name in _seam_names(shape))


# ---------------------------------------------------------------------------
# Wrappers
# ---------------------------------------------------------------------------


def _is_wrapped(store: Any, name: str) -> bool:
    return bool(getattr(getattr(store, name, None), _WRAPPED_FLAG, False))


def _publish(store: Any, name: str, wrapper: Any, *, static: bool) -> None:
    """Stamp and install ``wrapper``.

    ``static=True`` re-wraps in ``staticmethod``: the upstream seams are static,
    and a plain function assigned back would bind ``self`` to the first argument
    on every instance call.
    """
    setattr(wrapper, _WRAPPED_FLAG, True)
    setattr(store, name, staticmethod(wrapper) if static else wrapper)


@contextlib.contextmanager
def _profile_operation(cfg: _HookConfig, path: Path, *, reading: bool = False) -> Iterator[_HookConfig]:
    """Pin the home and serialize Linux memory I/O with provisioning and purge.

    Even a disarmed write joins the lock: enable may arm the profile while that
    write is in flight. A stale MemoryStore from another profile must refuse.
    """
    if sys.platform != "linux":
        yield cfg
        return
    from ._memory_key import MemoryKeyError, linux_memory_managed, memory_key_lock

    home = cfg.home
    if path.is_symlink() or path.parent.resolve() != (home / "memories").resolve():
        raise MemoryEncryptionUnavailable("memory path does not belong to the active profile")
    bound = _HookConfig(environ=cfg.environ, delimiter=cfg.delimiter, home_factory=lambda: home)
    # Reading an unmanaged profile needs no filesystem mutations. If enable
    # races this read, the reader still validates any seal it observes; it
    # never publishes data. Every writer continues to take the lifecycle lock.
    if reading and not linux_memory_managed(home):
        yield bound
        return
    try:
        with memory_key_lock(home):
            yield bound
    except MemoryKeyError as exc:
        raise MemoryEncryptionUnavailable("TPM memory lifecycle lock or key unavailable") from exc


def _wrap_write_file(store: Any, cfg: _HookConfig) -> None:
    """The single content write of every shape — and the one place plaintext can escape."""
    original = store._write_file

    @functools.wraps(original)
    def _write_file(path: Path, entries: list[str]) -> Any:
        with _profile_operation(cfg, path) as bound:
            if _sealed_on_disk(path):
                key = _require_key_for_sealed(bound, path)  # sealed stays sealed, armed or not
            elif bound.armed:
                key = _require_key(bound, path, writing=True)
            else:
                _refuse_magic_first_entry(entries, path)  # only this branch writes entries verbatim
                return original(path, entries)
            content = bound.delimiter.join(entries) if entries else ""
            sealed = seal(content.encode("utf-8"), key=key, name=path.name)
            # Hand the blob back as a ONE-entry list: `delimiter.join([x]) == x`, so
            # upstream's atomic write and its OSError -> RuntimeError translation are
            # reused verbatim instead of reimplemented here.
            return original(path, [sealed.decode("ascii")])

    _publish(store, "_write_file", _write_file, static=True)


def _wrap_read_raw_checked(store: Any, cfg: _HookConfig) -> None:
    """Shape A: the single checked read every mutation path derives its snapshot from."""
    original = store._read_raw_checked

    @functools.wraps(original)
    def _read_raw_checked(path: Path) -> tuple[str, bool]:
        with _profile_operation(cfg, path, reading=True) as bound:
            raw, read_ok = original(path)
            if not read_ok or not raw:
                return raw, read_ok  # absent / unreadable: upstream's contract is untouched
            if is_sealed(raw):
                return _unseal_text(raw, path=path, key=_require_key(bound, path, writing=False)), True
            _refuse_broken_seal(raw, path)  # `raw` IS the file text here: classify it directly
            if bound.armed:
                _note_plaintext_seen(path)
            return raw, True

    _publish(store, "_read_raw_checked", _read_raw_checked, static=True)


def _wrap_read_file(store: Any, cfg: _HookConfig) -> None:
    """Shapes B/C: ``_read_file`` is the only read, for both loading and mutating.

    Limitation: in B/C upstream returns ``[]`` for both "absent" and "unreadable",
    so a read failure on a *plaintext* file stays indistinguishable from an empty
    store — the hook cannot add a safety net upstream itself lacks. A sealed file
    is covered, because it can never decode to ``[]``.
    """
    original = store._read_file

    @functools.wraps(original)
    def _read_file(path: Path) -> list[str]:
        with _profile_operation(cfg, path, reading=True) as bound:
            entries: list[str] = original(path)
            # A sealed file holds no delimiter, so it always parses as exactly one
            # entry — already stripped by upstream, which `unseal` tolerates.
            if len(entries) == 1 and is_sealed(entries[0]):
                plaintext = _unseal_text(entries[0], path=path, key=_require_key(bound, path, writing=False))
                return _split_entries(plaintext, bound.delimiter)
            _refuse_broken_seal_on_disk(entries, path)
            if entries and bound.armed:
                _note_plaintext_seen(path)
            return entries

    _publish(store, "_read_file", _read_file, static=True)


def _wrap_drift_on_snapshot(store: Any, cfg: _HookConfig) -> None:
    """Shape A: ``raw`` is already plaintext (the read wrapper opened it).

    Upstream writes its ``.bak`` with a bare ``Path.write_text(raw)``, so
    delegating would publish the decrypted memory in the clear and only let us
    re-seal it afterwards — the window is the bug. Replicate upstream's two drift
    signals on ``raw`` instead and write the backup sealed in the first place.
    """
    original = store._detect_external_drift

    @functools.wraps(original)
    def _detect_external_drift(self: Any, target: str, raw: str) -> Any:
        path = Path(self._path_for(target))
        with _profile_operation(cfg, path) as bound:
            if not (bound.armed or _sealed_on_disk(path)):
                return original(self, target, raw)  # plaintext at rest and disarmed: upstream logic intact
            key = _require_key(bound, path, writing=True)
            return _drift_on_plaintext(self, target, path, raw, cfg=bound, key=key)

    _publish(store, "_detect_external_drift", _detect_external_drift, static=False)


def _wrap_drift_self_read(store: Any, cfg: _HookConfig) -> None:
    """Shape B: upstream re-reads the file itself, so it would judge the *sealed* bytes.

    Base64 expansion alone pushes a sealed file past the store's char limit, which
    upstream reads as an oversize entry — every ``replace`` / ``remove`` would be
    refused with a spurious drift error. So for a sealed file we replicate
    upstream's two drift signals on the plaintext, and seal the backup we write.
    """
    original = store._detect_external_drift

    @functools.wraps(original)
    def _detect_external_drift(self: Any, target: str) -> Any:
        path = Path(self._path_for(target))
        with _profile_operation(cfg, path) as bound:
            raw = _sealed_text_at(path)
            if raw is None:
                return original(self, target)  # absent / unreadable / plaintext: upstream logic intact
            key = _require_key(bound, path, writing=False)
            plaintext = _unseal_text(raw, path=path, key=key)
            return _drift_on_plaintext(self, target, path, plaintext, cfg=bound, key=key)

    _publish(store, "_detect_external_drift", _detect_external_drift, static=False)


def _sealed_text_at(path: Path) -> str | None:
    """The file's text when it exists and is sealed, else ``None``."""
    text = _disk_text(path)
    return text if text is not None and is_sealed(text) else None


def _drift_on_plaintext(
    store: Any,
    target: str,
    path: Path,
    plaintext: str,
    *,
    cfg: _HookConfig,
    key: bytes,
) -> str | None:
    """Upstream's drift check, run on the decrypted text; returns its ``.bak`` contract."""
    parsed = _split_entries(plaintext, cfg.delimiter)
    roundtrip = cfg.delimiter.join(parsed)
    max_entry_len = max((len(entry) for entry in parsed), default=0)
    if plaintext.strip() == roundtrip and max_entry_len <= store._char_limit(target):
        return None

    bak_path = path.with_suffix(path.suffix + f".bak.{int(time.time())}")
    try:
        _write_private(bak_path, seal(plaintext.encode("utf-8"), key=key, name=bak_path.name))
    except OSError:
        return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
    return str(bak_path)


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------


#: Every seam of each shape and the wrapper that owns it — the single source of
#: truth for both installing and reporting installation.
_SEAM_WRAPPERS: Final[dict[str, tuple[tuple[str, Callable[[Any, _HookConfig], None]], ...]]] = {
    "A": (
        ("_write_file", _wrap_write_file),
        ("_read_raw_checked", _wrap_read_raw_checked),
        ("_detect_external_drift", _wrap_drift_on_snapshot),
    ),
    "B": (
        ("_write_file", _wrap_write_file),
        ("_read_file", _wrap_read_file),
        ("_detect_external_drift", _wrap_drift_self_read),
    ),
    "C": (
        ("_write_file", _wrap_write_file),
        ("_read_file", _wrap_read_file),
    ),
}


def _seam_names(shape: str) -> tuple[str, ...]:
    return tuple(name for name, _ in _SEAM_WRAPPERS.get(shape, ()))


#: Serialises seam wrapping. Two installers racing (plugin discovery on a worker
#: thread against the import hook on the main one) would both read "not wrapped"
#: and stack a wrapper on a wrapper — and a double-wrapped write hands the inner
#: wrapper's sealed blob to the outer one as a plaintext entry, which then refuses
#: it. Its own lock, not :data:`_IMPORT_HOOK_LOCK`: the import hook calls into here
#: while installing, and a shared non-reentrant lock would deadlock.
_WRAP_LOCK: Final = threading.Lock()


def _wrap_seam(store: Any, shape: str, cfg: _HookConfig) -> None:
    """Wrap every seam of ``shape`` that is not wrapped already."""
    with _WRAP_LOCK:
        for name, wrap in _SEAM_WRAPPERS[shape]:
            if not _is_wrapped(store, name):
                wrap(store, cfg)


def install_memory_hook(
    *,
    home: Path | None = None,
    memory_tool_module: Any | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Wrap the upstream memory seam for this process. Returns whether it is wrapped.

    Called from the keyvault plugin ``register()`` and from the import hook that
    the ``.pth`` bootstrap installs, so it runs before the first disk-touching
    ``MemoryStore`` even when plugin discovery does not. Idempotent.

    * ``HERMES_SAFE_MODE`` truthy → still wrapped when the shape is supported, but
      nothing NEW is sealed and an unsupported seam does not refuse. Unwrapping
      would let upstream truncate the files that are already sealed.
    * Unsupported seam **and not armed** → ``False``: Hermes runs exactly as it
      does today, in plaintext. Nothing is at risk because nothing is sealed.
    * Unsupported seam **while armed** → the process is stopped (see
      :func:`_refuse_or_ignore`). Sealed memories are on disk and we cannot open
      them; starting would let upstream treat them as garbage and overwrite them.
    """
    environ = os.environ if environ is None else environ
    factory = _home_factory(home)

    module, load_reason = (memory_tool_module, "") if memory_tool_module is not None else _load_memory_tool()
    if module is None:
        _refuse_or_ignore(load_reason, home=factory(), environ=environ)
        return False
    shape, reason = classify_seam(module)
    if not shape:
        _refuse_or_ignore(reason, home=factory(), environ=environ)
        return False

    cfg = _HookConfig(environ=environ, delimiter=module.ENTRY_DELIMITER, home_factory=factory)
    _wrap_seam(module.MemoryStore, shape, cfg)
    return True


def _refuse_or_ignore(reason: str, *, home: Path, environ: Mapping[str, str]) -> None:
    """Stop the process on an unsupported seam, but only when memory encryption is on.

    The exit must survive every ``except Exception`` between here and the
    interpreter: upstream only debug-logs what ``register()`` raises, and
    ``threading.excepthook`` swallows a ``SystemExit`` raised off the main thread
    (plugin discovery can run on a worker). So off-main it is ``os._exit``.

    The one exception is a Mordred classification import (:data:`_SUPPRESS_REFUSAL`):
    the caller asked *whether* the seam is supported and is about to be told, so
    stopping the process would only take out the diagnostic. Nothing is wrapped
    either way, and every other importer still refuses.
    """
    if not _marker_armed(home):
        return
    if _SUPPRESS_REFUSAL:
        logger.warning(
            "memory encryption is on but the Hermes memory seam cannot be wrapped: %s "
            "(reported by a Mordred classification call, so this process is not stopped)",
            reason,
        )
        return
    if _safe_mode(environ):
        logger.warning(
            "memory encryption is on but the Hermes memory seam cannot be wrapped: %s "
            "(HERMES_SAFE_MODE is set, so startup continues and nothing new is sealed)",
            reason,
        )
        return
    sys.stderr.write(
        "mordred: refusing to start — memory encryption is on but the Hermes memory seam "
        f"cannot be wrapped: {reason} (set HERMES_SAFE_MODE=1 to bypass for recovery)\n"
    )
    with contextlib.suppress(OSError):
        sys.stderr.flush()
    if threading.current_thread() is threading.main_thread():
        raise SystemExit(1)
    # ``os._exit`` skips interpreter shutdown, so nothing buffered is flushed for
    # us — including whatever the host had already written to stdout.
    with contextlib.suppress(OSError):
        sys.stdout.flush()
    os._exit(1)


# ---------------------------------------------------------------------------
# Post-import installation (sys.meta_path)
# ---------------------------------------------------------------------------


def _on_memory_tool_imported(module: ModuleType) -> None:
    install_memory_hook(memory_tool_module=module)


def _on_learning_mutations_imported(module: ModuleType) -> None:
    install_journey_guard(module)


#: Import of these modules must be followed by an installation. Never imported
#: from here: both carry upstream import-time side effects (tool registration).
_POST_IMPORT_ACTIONS: Final[dict[str, Callable[[ModuleType], None]]] = {
    "tools.memory_tool": _on_memory_tool_imported,
    "agent.learning_mutations": _on_learning_mutations_imported,
}

_IMPORT_HOOK_LOCK: Final = threading.Lock()

#: The one finder this process installed — a second install must not add another.
_IMPORT_HOOK: _PostImportFinder | None = None


class _PostImportLoader(Loader):
    """Delegating loader that runs ``action`` once the module has executed."""

    def __init__(self, inner: Loader, action: Callable[[ModuleType], None]) -> None:
        self._inner = inner
        self._action = action

    def create_module(self, spec: ModuleSpec) -> ModuleType | None:
        return self._inner.create_module(spec)

    def exec_module(self, module: ModuleType) -> None:
        self._inner.exec_module(module)
        try:
            self._action(module)
        except Exception:
            # A bug on our side must not take an upstream module down with it: the
            # module has already executed and is usable, but a raise here leaves it
            # out of ``sys.modules`` and breaks an import we merely observed. Only
            # BaseException — the deliberate ``SystemExit`` refusal — propagates.
            logger.exception("post-import action for %s failed", getattr(module, "__name__", "?"))

    def __getattr__(self, name: str) -> Any:
        # get_source / get_code / is_package / get_resource_reader: whatever the
        # machinery or an inspecting caller asks the real loader for.
        return getattr(self._inner, name)


class _PostImportFinder(MetaPathFinder):
    """First finder on ``sys.meta_path``; observes two module names, stands aside for the rest."""

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        action = _POST_IMPORT_ACTIONS.get(fullname)
        if action is None:
            return None
        spec = self._delegate(fullname, path, target)
        if spec is None or spec.loader is None:
            return spec  # nothing found, or a namespace package: no loader to wrap
        spec.loader = _PostImportLoader(spec.loader, action)
        return spec

    @staticmethod
    def _delegate(fullname: str, path: Sequence[str] | None, target: ModuleType | None) -> ModuleSpec | None:
        """The spec the rest of ``sys.meta_path`` would have produced.

        Every instance of this class is skipped, not just ``self``: two finders
        delegating to each other would recurse forever.
        """
        for finder in list(sys.meta_path):
            if isinstance(finder, _PostImportFinder):
                continue
            find_spec = getattr(finder, "find_spec", None)
            if find_spec is None:
                continue
            spec = find_spec(fullname, path, target)
            if spec is not None:
                return cast("ModuleSpec", spec)
        return None


def install_memory_import_hook() -> bool:
    """Arm the memory seam from interpreter startup, before Hermes imports it.

    ``register()`` only runs for processes that complete plugin discovery, so a
    process that skips it (or whose discovery fails, or runs on a worker thread)
    would drive an UNWRAPPED ``MemoryStore`` over sealed files. Registering the
    finder cannot fail; what it triggers later can, and must — an armed process
    whose seam is unsupported has to stop rather than corrupt.
    """
    global _IMPORT_HOOK
    with _IMPORT_HOOK_LOCK:
        if _IMPORT_HOOK is None:
            _IMPORT_HOOK = _PostImportFinder()
        if _IMPORT_HOOK not in sys.meta_path:
            # Not just "first install": test harnesses and embedded hosts snapshot
            # and restore ``sys.meta_path``, which silently drops the finder. Keying
            # off the module global alone made the re-install a no-op that reported
            # success while the seam was left unarmed.
            sys.meta_path.insert(0, _IMPORT_HOOK)
    for name, action in _POST_IMPORT_ACTIONS.items():
        module = sys.modules.get(name)
        if module is None:
            continue  # not imported yet: find_spec fires later
        try:
            action(module)
        except Exception:
            # Same containment as _PostImportLoader.exec_module: a bug in an
            # action must not refuse startup for every Hermes process via the
            # fail-closed `.pth` bootstrap. The deliberate armed-and-unsupported
            # SystemExit still propagates.
            logger.exception("post-import action for %s failed", name)
    return True


# ---------------------------------------------------------------------------
# Journey guard (agent/learning_mutations)
# ---------------------------------------------------------------------------

#: ``agent/learning_graph._memory_cards`` indexes chunks it reads from the file
#: RAW, while ``delete_node`` / ``edit_node`` mutate by that index through the
#: wrapped — decrypted — seam. Over a sealed file the two views disagree: the UI
#: shows one garbage card and deleting it removes a real entry.
_JOURNEY_SEALED_MESSAGE: Final = (
    "this memory file is sealed by Mordred; edit it through the memory tool or run "
    "`hermes-mordred encryption disable memory` first"
)

#: Node source -> file, replicating ``agent/learning_mutations._MEMORY_FILES`` for
#: the case where upstream stops exposing it.
_JOURNEY_MEMORY_FILES: Final = {"memory": "MEMORY.md", "profile": "USER.md"}

#: The mutations we guard and the exact signature each must have.
_JOURNEY_SEAMS: Final = (("delete_node", ("node_id",)), ("edit_node", ("node_id", "content")))


def install_journey_guard(module: Any, *, home: Path | None = None) -> bool:
    """Refuse journey mutations that would rewrite a sealed memory file by index.

    Returns whether both mutations are wrapped. A signature that is not exactly
    upstream's is left alone (debug-logged): guessing at a renamed parameter is
    how a guard becomes the data-loss bug it exists to prevent. Skill nodes are
    untouched. Idempotent.
    """
    for name, expected in _JOURNEY_SEAMS:
        reason = _journey_signature_mismatch(module, name, expected)
        if reason:
            logger.debug("journey guard not installed: %s", reason)
            return False
    home_factory = _home_factory(home)
    for name, _expected in _JOURNEY_SEAMS:
        if not bool(getattr(getattr(module, name, None), _WRAPPED_FLAG, False)):
            _wrap_journey_mutation(module, name, home_factory)
    return True


def _journey_signature_mismatch(module: Any, name: str, expected: tuple[str, ...]) -> str:
    """``""`` when ``module.name`` takes exactly ``expected``, else the reason it does not."""
    found = _params(module, name)
    if found is None:
        return f"agent.learning_mutations.{name} is missing or not callable"
    if found != expected:
        return f"agent.learning_mutations.{name} takes {found} (expected {expected})"
    return ""


def _wrap_journey_mutation(module: Any, name: str, home_factory: Callable[[], Path]) -> None:
    original = getattr(module, name)

    @functools.wraps(original)
    def _guarded(*args: Any, **kwargs: Any) -> Any:
        node_id = args[0] if args else kwargs.get("node_id")
        path = _journey_memory_path(module, node_id, home_factory) if isinstance(node_id, str) else None
        if path is not None and _sealed_on_disk(path):
            # Upstream's own error shape: {"ok": False, "message": ...}.
            return {"ok": False, "message": _JOURNEY_SEALED_MESSAGE}
        return original(*args, **kwargs)

    setattr(_guarded, _WRAPPED_FLAG, True)
    setattr(module, name, _guarded)


def _journey_memory_path(module: Any, node_id: str, home_factory: Callable[[], Path]) -> Path | None:
    """The memory file a node id names, or ``None`` for a skill node or an id we cannot parse."""
    parse_kind = getattr(module, "parse_node_kind", None)
    if not callable(parse_kind) or parse_kind(node_id) != "memory":
        return None
    parts = node_id.split(":", 2)
    if len(parts) != 3:
        return None
    names = getattr(module, "_MEMORY_FILES", None)
    name = (names if isinstance(names, dict) else _JOURNEY_MEMORY_FILES).get(parts[1])
    if not isinstance(name, str):
        return None
    return _journey_memories_dir(module, home_factory) / name


def _journey_memories_dir(module: Any, home_factory: Callable[[], Path]) -> Path:
    """Upstream's own memories directory when it exposes one, else ``<home>/memories``."""
    resolver = getattr(module, "_memories_dir", None)
    if callable(resolver):
        try:
            return Path(resolver())
        except Exception:
            logger.debug("agent.learning_mutations._memories_dir failed", exc_info=True)
    return home_factory() / "memories"


# ---------------------------------------------------------------------------
# Session-start diagnosis
# ---------------------------------------------------------------------------


def warn_when_memory_is_locked(
    *,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Say so once when memory is sealed and this process cannot open it.

    ``agent/agent_init.py`` wraps ``load_from_disk()`` in ``except Exception:
    pass``, so a sealed memory with no usable key is indistinguishable from an
    empty one — the operator sees an agent that quietly forgot everything. A seal
    whose *structure* is broken is just as silent, and is reported here too.
    Returns whether a warning was written.
    """
    resolved = _home_factory(home)()
    if str(resolved) in _LOCKED_WARNED:
        return False
    from ._memory_key import MemoryKeyError, resolve_memory_key

    try:
        key = resolve_memory_key(
            home=resolved, platform=sys.platform, environ=os.environ if environ is None else environ
        )
    except MemoryKeyError:
        key = None
    for path in sorted((resolved / "memories").glob("*.md")):
        note = _locked_memory_note(path, key)
        if not note:
            continue
        _LOCKED_WARNED.add(str(resolved))
        sys.stderr.write(f"mordred: {note}\n")
        return True
    return False


def _locked_memory_note(path: Path, key: bytes | None) -> str:
    """Why ``path`` cannot be opened as memory, or ``""`` when it can.

    Only files whose first bytes carry the magic are judged (an unreadable or
    plaintext file is not our call). Both failure modes are silent upstream, so
    both get a line: a seal ``key`` does not open, and a seal that is no longer
    structurally whole.
    """
    text = _disk_text(path)
    if text is None or not looks_like_magic_line(text):
        return ""
    if not is_sealed(text):
        return (
            f"agent memory {path.name} looks sealed but its structure is broken (appended to, "
            f"truncated, or re-wrapped), so this session starts with an empty memory; restore it "
            f"from a backup or remove it."
        )
    if _opens_with(text, path, key):
        return ""
    if sys.platform == "linux":
        return f"agent memory {path.name} is sealed but cannot be opened; restore the original TPM and memory key"
    return (
        f"agent memory is sealed but {_MEMORY_KEY_ENV} is not available — {path.name} "
        f"cannot be opened, so this session starts with an empty memory; {_REMEDY}."
    )


def _opens_with(text: str, path: Path, key: bytes | None) -> bool:
    """Whether ``key`` authenticates the seal in ``text`` for ``path``'s basename."""
    if key is None:
        return False
    try:
        unseal(text.encode("utf-8"), key=key, name=path.name)
    except MemoryCryptoError:
        return False
    return True


def _main(argv: Sequence[str] | None = None) -> int:
    """``python -m mordred_hermes.keyvault._memory_hook --probe``.

    Answers "can this interpreter wrap the memory seam?" with an exit code and no
    side effects — no vault access, no prompts. Used by the runtime probe.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if args != ["--probe"]:
        sys.stderr.write("usage: python -m mordred_hermes.keyvault._memory_hook --probe\n")
        return 2
    ok, reason = seam_check()
    if not ok:
        sys.stderr.write(f"{reason}\n")
        return 1
    sys.stdout.write(f"{memory_seam_shape()}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(_main())
