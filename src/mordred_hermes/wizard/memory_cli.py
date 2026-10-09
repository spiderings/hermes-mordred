"""``hermes mordred encryption {enable,disable,purge} memory`` — agent memory at rest.

No Hermes release encrypts ``~/.hermes/memories/*.md``, so Mordred owns the
whole story: the sealing itself is done at runtime by
:mod:`mordred_hermes.keyvault._memory_hook` (wire format:
:mod:`mordred_hermes.keyvault.memory_crypto`), and this module is that hook's
lifecycle — the three pieces that make it real and reversible:

1. ``HERMES_MEMORY_KEY`` in the vault ``.env`` (protected at rest by the device
   key, injected into the environment by the ``.env`` shim at startup),
2. the opt-in marker ``<home>/mordred/memory-vault.marker`` that arms the hook,
   plus the opt-out marker that expresses the reversible *paused* state, and
3. the memory files themselves, migrated in both directions.

- **enable**  — gate, ensure the key, write the marker, then seal every
  plaintext memory file that is already on disk.
- **disable** — decrypt every sealed file back to plaintext, drop the marker and
  write the opt-out marker. The key stays in the vault, so re-enabling is
  immediate. *Refuses* rather than proceeds when a sealed file cannot be
  decrypted — a half-migrated memory directory is worse than a paused one.
- **purge**   — ``disable`` first (never strip a key while sealed files remain),
  then remove the key from the vault ``.env`` and both markers.

``enable`` is fail-closed and writes nothing until every gate passes: this
Hermes' memory tool must expose a seam the hook can wrap, the platform must be
macOS (the shims are), the ``env`` target must be enrolled and injecting (that
is how the key reaches the runtime), and the interpreter that runs ``hermes`` —
plus any gateway running right now — must prove it can open sealed files.

The legacy ``memory.encryption.enabled`` config flag is no longer written: the
marker is the source of truth (no runtime ever read the flag). ``disable`` /
``purge`` still turn a flag an older build left behind off, and ``status``
reports one that is set without a marker.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import io
import os
import sys
from typing import TYPE_CHECKING

from ..keyvault._memory_hook import _write_private, memory_marker_path, memory_optout_marker_path
from ..keyvault.memory_crypto import MAGIC
from . import _term
from ._runtime_gate import runtime_gate
from ._vault_open import _vault_present
from .vault_memory_key import _MEMORY_KEY_ENV

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault._runtime_probe import GatewayRuntime
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO

__all__ = ["disable", "enable", "purge"]

_CONFIG_NAME = "config.yaml"
_DARWIN = "darwin"
#: The sealed-file magic line, under the name ``keyvault/memory_crypto.py``
#: cites when it documents the format's text-safety. That module owns the bytes.
_ENC_HEADER = MAGIC


def _set_encryption_flag(home: Path, *, enabled: bool) -> int:
    """Round-trip ``config.yaml`` and set the legacy ``memory.encryption.enabled``.

    Preserves every other key / comment (``ruamel`` round-trip). Creates the
    nested ``memory.encryption`` block (and the file itself) when absent. Returns
    0 on success, 1 if config.yaml exists but is not a mapping (refuse to clobber
    an unexpected shape).

    Only :func:`_clear_legacy_flag` calls this now: the flag is legacy, so it is
    turned off where an older build set it and never written otherwise.
    """
    from ruamel.yaml.comments import CommentedMap

    from .policy_writer import _atomic_write_text, _round_trip_yaml

    path = home / _CONFIG_NAME
    # Share PolicyWriter's ruamel instance (indent 2/4/2, preserve_quotes,
    # width=4096) instead of a bare YAML() -- a bare instance's default indent
    # settings reformat every sequence in the file (e.g. `plugins.enabled`
    # written by PolicyWriter at offset 2 collapses to offset 0), so a
    # `configure` run right after an `encryption disable memory` run would see
    # gratuitous diff churn on unrelated lists.
    yaml = _round_trip_yaml()
    if path.exists():
        data = yaml.load(path.read_text(encoding="utf-8"))
        if data is None:
            data = CommentedMap()
        elif not isinstance(data, dict):
            _term.emit_error(f"{path} is not a YAML mapping — refusing to edit it.")
            return 1
    else:
        data = CommentedMap()

    # Create missing nodes, but never CLOBBER an existing non-mapping value at
    # ``memory`` / ``memory.encryption`` — that would silently drop the operator's
    # config. Refuse instead.
    memory = data.get("memory")
    if memory is None:
        memory = CommentedMap()
        data["memory"] = memory
    elif not isinstance(memory, dict):
        _term.emit_error(f"{path}: 'memory' is not a mapping — refusing to edit it.")
        return 1
    encryption = memory.get("encryption")
    if encryption is None:
        encryption = CommentedMap()
        memory["encryption"] = encryption
    elif not isinstance(encryption, dict):
        _term.emit_error(f"{path}: 'memory.encryption' is not a mapping — refusing to edit it.")
        return 1
    encryption["enabled"] = enabled

    # Atomic write via PolicyWriter's shared helper (tmpfile + os.replace, plus
    # an idempotent no-write-if-unchanged short-circuit) instead of hand-rolling
    # the same tempfile.mkstemp + os.replace dance again (see
    # PolicyWriter._edit_config for the same io.StringIO() + yaml.dump idiom).
    # Not _storage.atomic_write — that enforces vault mode 0o600; config.yaml is
    # a normal user-readable config file.
    buf = io.StringIO()
    yaml.dump(data, buf)
    _atomic_write_text(path, buf.getvalue())
    return 0


def _clear_legacy_flag(home: Path) -> None:
    """Turn an older build's ``memory.encryption.enabled`` off — never create it.

    A fresh profile must not grow a key no runtime reads just because memory
    encryption was paused, so the flag is only rewritten where it is actually on.
    """
    from .encryption_cli import _memory_flag_enabled

    if _memory_flag_enabled(home):
        _set_encryption_flag(home, enabled=False)


def _strip_memory_key(text: str) -> str:
    """Drop every ``HERMES_MEMORY_KEY`` binding, preserving other lines verbatim.

    Mirrors the removal half of
    :func:`mordred_hermes.wizard.vault_memory_key._env_with_memory_key` but appends
    nothing — used by ``purge`` to take the key out of the vault ``.env``.
    """
    from dotenv.parser import parse_stream

    kept = "".join(
        binding.original.string for binding in parse_stream(io.StringIO(text)) if binding.key != _MEMORY_KEY_ENV
    )
    if kept and not kept.endswith("\n"):
        kept += "\n"
    return kept


def _refuse(verb: str, reason: str) -> int:
    """Print one refusal in the shared ``encryption <verb> memory: …`` shape."""
    _term.emit_error(f"encryption {verb} memory: {reason}")
    return 1


# -----------------------------------------------------------------------------
# Running-gateway diagnostics (shared by enable / disable)
# -----------------------------------------------------------------------------
def _running_gateways(home: Path) -> list[GatewayRuntime]:
    """Every interpreter serving a ``hermes gateway`` right now, best-effort.

    Purely diagnostic here (the fail-closed decision is the runtime gate's), so
    a discovery failure yields no gateways rather than failing the command.
    """
    try:
        from ..keyvault._runtime_probe import discover_running_gateway_runtimes

        return list(discover_running_gateway_runtimes(home=home))
    except Exception:
        # Broad on purpose: a process-table scan must never break the toggle.
        return []


def _restart_hint(gateway: GatewayRuntime) -> str:
    return "restart it" if gateway.pid is None else f"restart it (pid {gateway.pid})"


def _warn_gateways(home: Path, *, enabling: bool) -> None:
    """Tell the operator that a live gateway keeps its old arming until restarted.

    Arming is re-read per call, so a running gateway picks the *marker* change up
    immediately; what it cannot pick up is the hook installation itself (done at
    plugin registration) — hence the asymmetry between the two messages.
    """
    for gateway in _running_gateways(home):
        if enabling:
            _term.emit_warn(
                f"a hermes gateway is running from {gateway.python} — {_restart_hint(gateway)} so it receives "
                "the key; until then its memory reads/writes fail closed (they do NOT write plaintext), and a "
                "session may see an empty memory."
            )
        else:
            _term.emit_warn(
                f"a hermes gateway is running from {gateway.python} — {_restart_hint(gateway)}: it still has the "
                "hook armed in-process, though with the marker gone its per-call arming check stops sealing at "
                "the next memory call."
            )


# -----------------------------------------------------------------------------
# enable — gates first, then key, marker, migration
# -----------------------------------------------------------------------------
def _enable_gate_reason(*, home: Path, root: Path, platform: str) -> str | None:
    """The first reason ``enable`` must refuse, or ``None`` when all three pass.

    Ordered cheapest-and-most-fundamental first, so an operator whose Hermes has
    no wrappable seam is not sent to fix their env target for nothing.
    """
    from .encryption_cli import _env_target_ready, memory_runtime_available

    available, reason = memory_runtime_available()
    if not available:
        return (
            f"{reason} — refusing to arm the hook. Use `hermes-mordred vault set-memory-key` to store the key "
            "anyway (it seals nothing on its own)."
        )
    if platform == "linux":
        return None
    if platform != _DARWIN:
        return f"memory encryption is unsupported on {platform}."
    if not _env_target_ready(home=home, root=root):
        return (
            "memory encryption rides on the env target (the key is injected by the .env shim) — "
            "run `hermes-mordred encryption enable env` first."
        )
    return None


def _default_runtime_probe(*, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
    """Production probe: can that interpreter open a sealed memory file?

    Imported lazily so this module stays import-light; ``runtime_python`` is
    supplied when the gate probes an interpreter running a gateway right now.
    """
    from ..keyvault._runtime_probe import runtime_memory_encryption_available

    return runtime_memory_encryption_available(home=home, runtime_python=runtime_python)


def _runtime_gate(*, home: Path, platform: str, force_runtime_unverified: bool) -> int:
    """Fail-closed check that sealed memories can still be read back at startup.

    Same two-part shape as the ``.env`` seal (:func:`._runtime_gate.runtime_gate`):
    the interpreter that *should* run ``hermes``, then every gateway running now
    from a different environment. Sealing memories a runtime cannot open is not
    recoverable by re-running anything — only by ``disable`` from a runtime that
    can — so the gate refuses instead.
    """
    return runtime_gate(
        home=home,
        platform=platform,
        runtime_probe=None,
        force_runtime_unverified=force_runtime_unverified,
        default_probe=_default_runtime_probe,
        supported_platforms=("darwin", "linux"),
        target="agent memory",
        mechanism=(
            "  Sealed memory files are opened only by the mordred keyvault plugin in the\n"
            "  interpreter that runs `hermes`. That interpreter cannot do it — install the\n"
            "  wheel there, and check its Hermes ships a memory tool mordred can wrap\n"
        ),
        rerun_tail=(
            "  then re-run `encryption enable memory`. To seal anyway (memories stay\n"
            "  unreadable until that runtime can open them), pass --force-runtime-unverified."
        ),
    )


def _ensure_key(
    *,
    root: Path,
    prompt_io: PromptIO | None,
    backend: NativeBackend | None,
    store: AnchorStore | None,
    flow_session: FlowSession | None = None,
) -> tuple[int, bytes | None]:
    """Create the vault if needed, ensure the memory key, and decode it.

    ``ensure_memory_key`` hands the value back from the same vault open that
    enrolled it, so the device key is unlocked once for both the enroll and the
    migration below. The value is never printed.
    """
    from ..keyvault.memory_crypto import MemoryCryptoError, decode_key
    from . import vault_cli, vault_memory_key

    rc = vault_cli.ensure_initialised(
        root=root, prompt_io=prompt_io, backend=backend, store=store, flow_session=flow_session
    )
    if rc != 0:
        return rc, None  # could not create the vault (reason already printed)
    rc, value = vault_memory_key.ensure_memory_key(
        root=root, rotate=False, backend=backend, store=store, flow_session=flow_session
    )
    if rc != 0 or value is None:
        return rc or 1, None
    try:
        return 0, decode_key(value)
    except MemoryCryptoError as exc:
        return _refuse("enable", f"the stored {_MEMORY_KEY_ENV} is unusable: {exc}"), None


def _arm(home: Path) -> None:
    """Write the opt-in marker (0o600 in a 0o700 dir) and clear the opt-out one."""
    from .policy_writer import _atomic_write_text

    _atomic_write_text(memory_marker_path(home), "memory-encryption enabled\n", mode=0o600)
    memory_optout_marker_path(home).unlink(missing_ok=True)


def _seal_plaintext_files(home: Path, *, key: bytes) -> tuple[int, list[str]]:
    """Seal every plaintext memory file in place. Returns ``(sealed, failures)``.

    Per file: read, skip if already sealed, else publish the sealed bytes through
    a same-directory 0o600 temp + ``os.replace`` (the hook's own writer), so a
    failure never leaves a half-written memory file. One file failing does not
    stop the others — the caller reports every failure at once.

    Narrows, but does not close, the scan-to-write TOCTOU: between the first
    read above and the ``os.replace`` below, a concurrently-armed hook (a
    still-running gateway) may have already sealed this same file. Sealing our
    now-stale plaintext over that would silently clobber whatever it just
    wrote. Immediately before writing, the file is re-checked: still a regular
    file (not swapped for a symlink — counted a failure, like the initial
    check), and byte-identical to what was read (else a concurrent writer got
    there first — *skipped*, not failed, since the file is not exposed and
    nothing was lost). A write landing in the instant between that re-check
    and ``os.replace`` itself is still possible — this narrows the window, it
    does not close it.
    """
    from ..keyvault.memory_crypto import MemoryCryptoError, is_sealed, seal
    from .encryption_cli import _memory_file_paths

    sealed = 0
    failures: list[str] = []
    from ..keyvault._memory_key import linux_memory_files

    paths = linux_memory_files(home) if _uses_tpm_memory(home) else _memory_file_paths(home)
    for path in paths:
        if path.is_symlink():
            failures.append(f"{path.name}: is a symlink — refusing to follow it")
            continue
        try:
            data = path.read_bytes()
            if is_sealed(data):
                continue
            blob = seal(data, key=key, name=path.name)
            if path.is_symlink():
                failures.append(f"{path.name}: is a symlink — refusing to follow it")
                continue
            if path.read_bytes() != data:
                continue  # a concurrent writer beat us to it -- their write wins
            _write_private(path, blob)
        except (OSError, MemoryCryptoError) as exc:
            failures.append(f"{path.name}: {exc}")
            continue
        sealed += 1
    return sealed, failures


def _warn_pending_approvals(home: Path) -> None:
    """Warn when approval-gated memory writes are staged as plaintext JSON.

    ``memory.write_approval`` parks pending writes outside the memory files the
    hook wraps, so they are not sealed until they are applied.
    """
    from .._yaml_io import load_yaml_mapping

    memory = load_yaml_mapping(home / _CONFIG_NAME).get("memory")
    if isinstance(memory, dict) and memory.get("write_approval") is True:
        _term.emit_warn(
            "memory.write_approval is on: writes awaiting approval are staged as plaintext JSON under "
            f"{home / 'pending' / 'memory'} until they are applied — that queue is not sealed."
        )


def _finish_enable(*, home: Path, key: bytes) -> int:
    """Migrate what is on disk, then report (the marker is already written)."""
    sealed, failures = _seal_plaintext_files(home, key=key)
    if failures:
        return _refuse(
            "enable",
            "could not seal " + "; ".join(failures) + ". The marker is kept, so the hook seals each file on its "
            "next write and `encryption status` shows `exposed` until then.",
        )
    _warn_pending_approvals(home)
    _warn_gateways(home, enabling=True)
    print(f"Agent-memory encryption enabled ({sealed} file(s) sealed; hook armed at next Hermes start).")
    return 0


def enable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    prompt_io: PromptIO | None = None,
    platform: str | None = None,
    force_runtime_unverified: bool = False,
    flow_session: FlowSession | None = None,
) -> int:
    """Arm the memory hook and seal the memory files already on disk.

    Nothing is written until every gate passes (see the module docstring):
    wrappable seam, macOS, an enrolled-and-injecting ``env`` target, and a
    runtime — including any live gateway — that can open sealed files.
    ``force_runtime_unverified`` skips only that last probe.

    If no vault exists yet, one is created first (prompting once for a recovery
    passphrase), so a fresh install need not run ``vault init`` by hand.
    ``flow_session`` (a guided flow) shares the flow's passphrase, open vault
    and key policy, so enabling memory right after env costs no second unlock
    (see :mod:`._flow_session`).

    Returns 0 on success; 1 when a gate refuses, the vault cannot be created or
    opened, the key is unusable, or the eager migration could not seal a file —
    in that last case the marker is deliberately kept, so the hook seals each
    file on its next write instead of leaving the target off.
    """
    resolved = sys.platform if platform is None else platform

    reason = _enable_gate_reason(home=home, root=root, platform=resolved)
    if reason is not None:
        return _refuse("enable", reason)

    if resolved == "linux" and not force_runtime_unverified:
        from ..keyvault._runtime_probe import discover_running_gateway_runtimes

        if discover_running_gateway_runtimes(home=home):
            return _refuse(
                "enable",
                "stop running Hermes gateways before enabling TPM memory, then restart them; "
                "a new subprocess cannot prove which hook an existing process has loaded",
            )

    gate = _runtime_gate(home=home, platform=resolved, force_runtime_unverified=force_runtime_unverified)
    if gate != 0:
        return gate

    if resolved == "linux":
        return _enable_linux(home=home, backend=backend, force_runtime_unverified=force_runtime_unverified)

    rc, key = _ensure_key(root=root, prompt_io=prompt_io, backend=backend, store=store, flow_session=flow_session)
    if rc != 0 or key is None:
        return rc or 1

    _arm(home)
    return _finish_enable(home=home, key=key)


# -----------------------------------------------------------------------------
# disable — decrypt back (reversible), or refuse
# -----------------------------------------------------------------------------
def _memory_key_from_vault(
    *,
    root: Path,
    backend: NativeBackend | None,
    store: AnchorStore | None,
    flow_session: FlowSession | None = None,
) -> bytes | None:
    """The effective ``HERMES_MEMORY_KEY`` from the vault ``.env``, or ``None``.

    Reads through the hot path (device key, no passphrase) — the same value the
    runtime shim injects, so it is by construction the key the files were sealed
    with. ``None`` covers every "cannot get a usable key" case; the caller turns
    that into one refusal.
    """
    from ..keyvault import anchor, vault
    from ..keyvault.memory_crypto import MemoryCryptoError, decode_key
    from . import vault_cli
    from .vault_memory_key import _effective_memory_key

    if not _vault_present(root):
        return None
    opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store, flow_session=flow_session)
    if opened is None:
        return None
    with opened:
        try:
            if ".env" not in opened.list_files():
                return None
            text = opened.read_file(".env").decode("utf-8")
        except (vault.VaultError, anchor.AnchorError, OSError, UnicodeDecodeError) as exc:
            _term.emit_error(f"cannot read the enrolled .env at {root}: {exc}")
            return None

    value = _effective_memory_key(text)
    if value is None:
        return None
    try:
        return decode_key(value)
    except MemoryCryptoError:
        return None


def _uses_tpm_memory(home: Path) -> bool:
    from ..keyvault._memory_key import memory_key_path

    path = memory_key_path(home)
    return sys.platform == "linux" or path.exists() or path.is_symlink()


def _sealed_memory_files(home: Path) -> list[Path]:
    """Memory files that are sealed right now (mostly the complement of the drift scan).

    A file the drift scan (:func:`encryption_cli._unsealed_memory_files`)
    classifies as plaintext, but whose text still *starts* with the magic line
    (:func:`~..keyvault.memory_crypto.looks_like_magic_line`), is a broken seal
    — truncated or appended to, not a plaintext file that never got sealed —
    and is counted sealed here too, not excluded. Otherwise it would be
    invisible to ``disable``: silently left alone, on disk in an unreadable
    half-state, while ``disable`` reports success and ``purge`` then strips
    the key out from under it (permanent data loss). Routing it through
    ``disable``'s normal ``_unseal_files`` instead makes ``unseal`` fail on it
    loudly and ``disable`` refuse, which is the safe outcome.
    """
    from ..keyvault._memory_key import linux_memory_files
    from ..keyvault.memory_crypto import looks_like_magic_line
    from .encryption_cli import _memory_file_paths, _unsealed_memory_files

    if _uses_tpm_memory(home):
        return [
            path
            for path in linux_memory_files(home)
            if looks_like_magic_line(path.read_bytes().decode("utf-8", "surrogateescape"))
        ]

    plaintext = set(_unsealed_memory_files(home))
    sealed = []
    for path in _memory_file_paths(home):
        if path not in plaintext:
            sealed.append(path)
            continue
        try:
            text = path.read_bytes().decode("utf-8", "surrogateescape")
        except OSError:
            continue
        if looks_like_magic_line(text):
            sealed.append(path)
    return sealed


def _unseal_files(paths: list[Path], *, key: bytes) -> tuple[int, str | None]:
    """Decrypt each file back to plaintext atomically; stop at the first failure.

    Returns ``(decrypted, failure)``. Stopping (rather than continuing) keeps the
    remaining files sealed and readable by the still-armed hook, which is the
    recoverable state: the operator restores the right key and re-runs.

    Narrows, but does not close, the same scan-to-write TOCTOU
    ``_seal_plaintext_files`` narrows: ``paths`` came from an earlier
    ``_sealed_memory_files`` scan, so immediately before writing each file is
    re-read and re-verified still sealed, and it is THAT re-read data which
    gets decrypted — never the classification-time bytes. A file no longer
    sealed at that point (or swapped for a symlink) is reported as a failure
    rather than silently skipped: skipping it here would let ``disable``
    report success while it stays exactly as it was, undecrypted.
    """
    from ..keyvault.memory_crypto import MemoryCryptoError, is_sealed, unseal

    decrypted = 0
    for path in paths:
        if path.is_symlink():
            return decrypted, f"{path.name}: is a symlink — refusing to follow it"
        try:
            current = path.read_bytes()
            if not is_sealed(current):
                return decrypted, f"{path.name}: no longer sealed — a concurrent writer changed it since the scan"
            _write_private(path, unseal(current, key=key, name=path.name))
        except (OSError, MemoryCryptoError) as exc:
            return decrypted, f"{path.name}: {exc}"
        decrypted += 1
    return decrypted, None


def _write_optout_marker(home: Path) -> None:
    from .policy_writer import _atomic_write_text

    _atomic_write_text(memory_optout_marker_path(home), "opt-out\n", mode=0o600)


def disable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> int:
    from ..keyvault._memory_key import MemoryKeyError, memory_key_lock, memory_key_path

    if sys.platform == "linux" or memory_key_path(home).exists() or memory_key_path(home).is_symlink():
        try:
            with memory_key_lock(home):
                return _disable(home=home, root=root, backend=backend, store=store, flow_session=flow_session)
        except MemoryKeyError:
            return _refuse("disable", "TPM memory lifecycle lock unavailable; existing state preserved")
    return _disable(home=home, root=root, backend=backend, store=store, flow_session=flow_session)


def _disable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> int:
    """Decrypt every sealed memory file back and pause the hook (reversible).

    ``flow_session`` (``uninstall``) lends the flow's already open vault, so the
    key read here costs no second unlock.

    The key is kept in the vault, so ``enable`` restores the sealed state without
    re-keying. Returns 0 on success, 1 when sealed files exist and cannot be
    decrypted — in that case nothing is changed: the marker stays, so the armed
    hook can still read the files, and the operator can restore the key and
    re-run rather than face a directory of unreadable blobs.

    The initial scan and the decrypt loop are not one atomic step: a
    still-armed gateway can seal a file — a fresh write, or a re-seal of one
    this run already decrypted — after it was scanned. Before removing the
    marker, ``_sealed_memory_files`` is therefore re-run; if anything comes
    back sealed, the marker removal is refused too, so ``disable`` never
    reports success while a sealed file remains on disk.
    """
    sealed_paths = _sealed_memory_files(home)
    decrypted = 0
    key: bytes | None
    if sealed_paths:
        from ..keyvault._memory_key import MemoryKeyError, load_linux_memory_key, memory_key_path

        if memory_key_path(home).exists() or memory_key_path(home).is_symlink() or sys.platform == "linux":
            try:
                key = load_linux_memory_key(home=home, backend=backend)
            except MemoryKeyError:
                return _refuse("disable", "TPM memory key unavailable; restore the original TPM and wrapped key")
        else:
            key = _memory_key_from_vault(root=root, backend=backend, store=store, flow_session=flow_session)
        if key is None:
            return _refuse(
                "disable",
                f"sealed memory files exist but the vault .env has no usable {_MEMORY_KEY_ENV} — cannot decrypt "
                "them back; restore the key (vault set-memory-key is NOT it — that mints a new one) or keep "
                "encryption enabled.",
            )
        decrypted, failure = _unseal_files(sealed_paths, key=key)
        if failure is not None:
            return _refuse(
                "disable",
                f"cannot decrypt {failure} — stopped. The remaining files stay sealed and memory encryption "
                "stays on, so nothing becomes unreadable.",
            )

    still_sealed = _sealed_memory_files(home)
    if still_sealed:
        names = ", ".join(path.name for path in still_sealed)
        return _refuse(
            "disable",
            f"{len(still_sealed)} file(s) are sealed again after decrypting ({names}) — a gateway is still "
            "armed and wrote to them during this run. Stop every running `hermes gateway`, then re-run "
            "`encryption disable memory`; the marker and key are left untouched so the hook keeps working "
            "meanwhile.",
        )

    memory_marker_path(home).unlink(missing_ok=True)
    _write_optout_marker(home)
    _clear_legacy_flag(home)
    _warn_gateways(home, enabling=False)
    print(
        f"Agent-memory encryption disabled ({decrypted} file(s) decrypted back to plaintext; key kept for re-enable)."
    )
    return 0


def purge(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Disable, then strip the memory key from the vault ``.env`` and clear both markers.

    Destructive: once the key is gone, anything still sealed under it (an old
    backup, a copy outside ``<home>/memories``) can no longer be decrypted. That
    is why the ``disable`` decrypt-back must succeed first — a refusal there
    refuses the purge too. Returns 0 on success, 1 on that refusal or a vault
    open / re-enroll failure.
    """
    from ..keyvault._memory_key import MemoryKeyError, delete_linux_memory_key, memory_key_lock, memory_key_path

    if memory_key_path(home).exists() or memory_key_path(home).is_symlink() or sys.platform == "linux":
        try:
            with memory_key_lock(home):
                rc = disable(home=home, root=root, backend=backend, store=store)
                if rc != 0 or _sealed_memory_files(home):
                    return _refuse("purge", "sealed memory remains; stop running gateways before retrying")
                delete_linux_memory_key(home=home, backend=backend)
                memory_marker_path(home).unlink(missing_ok=True)
                memory_optout_marker_path(home).unlink(missing_ok=True)
            print("TPM memory key purged. Old encrypted backups are no longer recoverable.")
            return 0
        except MemoryKeyError:
            return _refuse("purge", "TPM memory key could not be removed")

    from ..keyvault import anchor, vault
    from . import vault_cli

    rc = disable(home=home, root=root, backend=backend, store=store)
    if rc != 0:
        _term.emit_error(
            "encryption purge memory: refusing to strip the key while sealed memory files remain (see above) — "
            "a purged key cannot decrypt them."
        )
        return rc

    if _vault_present(root):
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        if opened is None:
            return 1
        with opened:
            try:
                if ".env" in opened.list_files():
                    stripped = _strip_memory_key(opened.read_file(".env").decode("utf-8"))
                    opened.enroll_file(".env", stripped.encode("utf-8"))
            except (vault.VaultError, anchor.AnchorError, OSError, UnicodeDecodeError) as exc:
                _term.emit_error(f"cannot strip {_MEMORY_KEY_ENV} from the vault .env: {exc}")
                return 1

    memory_marker_path(home).unlink(missing_ok=True)
    memory_optout_marker_path(home).unlink(missing_ok=True)
    print(
        f"Agent-memory encryption purged ({_MEMORY_KEY_ENV} removed from the vault; config flag off). "
        "Memories encrypted under the old key can no longer be decrypted."
    )
    return 0


def _enable_linux(*, home: Path, backend: NativeBackend | None, force_runtime_unverified: bool) -> int:
    from ..keyvault._memory_key import MemoryKeyError, ensure_linux_memory_key, memory_key_lock, memory_key_path
    from ..keyvault._runtime_probe import runtime_memory_key_available
    from ..keyvault.memory_crypto import MemoryCryptoError, decode_key

    print(
        "Linux memory uses a machine-bound TPM key without per-use user presence. "
        "There is no portable recovery: losing the TPM loses encrypted memory. "
        "Disable encryption while the TPM is usable to restore plaintext first."
    )
    try:
        with memory_key_lock(home):
            path = memory_key_path(home)
            # Ambient input is only for initial adoption, never an existing TPM key.
            value = None if path.exists() or path.is_symlink() else os.environ.get(_MEMORY_KEY_ENV)
            adopted = decode_key(value) if value else None
            key = ensure_linux_memory_key(home=home, adopted_key=adopted, backend=backend)
            # The generic capability gate already ran before provisioning. This second
            # gate proves unwrapping in the installed Hermes and identified gateways.
            gate = runtime_gate(
                home=home,
                platform="linux",
                supported_platforms=("darwin", "linux"),
                runtime_probe=None,
                default_probe=runtime_memory_key_available,
                force_runtime_unverified=force_runtime_unverified,
                target="TPM agent memory",
                mechanism="The Hermes runtime must access this profile's TPM memory key.\n",
                rerun_tail="Install this build in that runtime, restore TPM access and retry.\n",
            )
            if gate:
                return gate
            _arm(home)
            return _finish_enable(home=home, key=key)
    except (MemoryKeyError, MemoryCryptoError):
        return _refuse("enable", "TPM memory key unavailable or invalid; existing memory and markers are preserved")
