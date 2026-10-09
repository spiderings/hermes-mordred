"""mordred_hermes.wizard._encryption_status — the at-rest status model.

Extracted from :mod:`encryption_cli` (the public facade) to keep that module
under the repo's 800-line guideline. What lives here is the *reporting* half
of ``encryption status``: the ``config`` and ``workspace`` detectors (plus
their shared :func:`_os_note` helper), the agent-memory file-scan helpers
(:func:`_memory_file_paths`, :func:`_unsealed_memory_files`,
:func:`_memory_flag_enabled`), and every pure renderer —
:func:`render_json`, :func:`render_text` and the mark vocabulary behind it
(:func:`status_mark`, :func:`_workspace_mark`, :func:`style_mark`,
``_MARK_STYLE``, the three ``*_LEGEND_BODY`` strings) — plus
:func:`_default_workspace_paths`, :func:`_shim_mark`, and
:func:`gateway_runtime_lines`. :class:`TargetStatus`, the value both halves
pass around, moves here too.

What deliberately stays in ``encryption_cli`` is the ``env``/``memory``
detection pair and their aggregator — :func:`encryption_cli._enrolled_names`,
:func:`encryption_cli._env_target_ready`, :func:`encryption_cli.env_status`,
:func:`encryption_cli.memory_runtime_available`,
:func:`encryption_cli.memory_status`, :func:`encryption_cli.collect_status` —
because those are the module's live monkeypatch seams. Tests call
``encryption_cli.env_status(...)`` / ``encryption_cli.memory_status(...)``
directly after ``monkeypatch.setattr(encryption_cli, "_enrolled_names", ...)``
/ ``"memory_runtime_available"``: a moved ``env_status`` or ``memory_status``
would still call the *real* ``_enrolled_names`` / ``memory_runtime_available``
internally (a function's global lookups resolve against the module it was
*defined* in, not the module a caller reached it through), so patching the
facade attribute would stop reaching them. A facade re-export only guarantees
the import path and object identity, not interception — see the
``encryption_cli`` module docstring's "Module layout" section for the
concrete example.

The dependency runs one way (``encryption_cli`` -> this module); nothing here
imports ``encryption_cli``, so there is no load cycle to break.
``encryption_cli`` re-exports every name below, preserving each one's import
path and object identity, which is what keeps ``setup_cli``'s and
``status_cli``'s existing ``from .encryption_cli import ...`` lines resolving
unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..keyvault._config_bootstrap import _marker_path as _config_marker_path
from ..keyvault._config_bootstrap import config_hook_installed
from . import _term
from ._workspace_paths import WorkspacePaths, resolve_workspace_env
from ._workspace_paths import is_mountpoint as _is_mountpoint

_CONFIG_NAME = "config.yaml"
_DARWIN = "darwin"
_MEMORIES_DIR = "memories"
#: Enough of a file to answer "does this even start with the magic line?": the
#: magic line plus room for the BOM and leading whitespace it tolerates. A
#: *quick-reject* optimisation only — the deciding classification always runs
#: ``is_sealed`` on the whole file, never on this truncated head (see
#: :func:`_unsealed_memory_files`).
_SEAL_PROBE_BYTES = 64


@dataclass(frozen=True)
class TargetStatus:
    """The resolved state of one encryption target.

    - ``configured``: the toggle is on (enrolled / marker present / flag true /
      workspace artifacts on disk), independent of the current OS.
    - ``active``: it is *effectively* protecting data on **this** OS right now.
    - ``mounted``: workspace-only rendering hint — ``True`` when the encrypted
      volume is mounted (open / in use), ``False`` when sealed at rest,
      ``None`` for the non-workspace targets. The workspace is encrypted at
      rest whenever it exists and is *unmounted*, so this sealed-vs-open axis,
      not ``on/paused/off``, is what :func:`status_mark` keys on for it.
    """

    target: str
    configured: bool
    active: bool
    detail: str
    mounted: bool | None = None
    drift: bool = False

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "target": self.target,
            "configured": self.configured,
            "active": self.active,
            "detail": self.detail,
        }
        if self.mounted is not None:
            out["mounted"] = self.mounted
        if self.drift:
            out["drift"] = self.drift
        return out


# -----------------------------------------------------------------------------
# Agent-memory file-scan helpers (side-effect-free)
# -----------------------------------------------------------------------------
def _memory_file_paths(home: Path) -> list[Path]:
    """Every agent-memory file the hook seals, sorted.

    The live ``<home>/memories/*.md`` plus upstream's ``*.md.bak.<ts>`` drift
    snapshots: those hold the same content, written by upstream's own
    ``write_text``, so migration and drift detection must both cover them.

    Symlinks are never followed: ``is_file()`` alone follows a link to
    classify it, which would let a planted symlink under ``memories/`` have
    its target read, sealed into the store, and the link itself destroyed by
    the atomic-replace writer. Excluding ``is_symlink()`` entries here is the
    primary guard; ``memory_cli``'s sealer/unsealer re-check it too (defence
    in depth against a link swapped in after this scan).
    """
    memories = home / _MEMORIES_DIR
    if not memories.is_dir():
        return []
    return sorted(
        {p for pattern in ("*.md", "*.md.bak.*") for p in memories.glob(pattern) if p.is_file() and not p.is_symlink()}
    )


def _unsealed_memory_files(home: Path) -> list[Path]:
    """Memory files that are plaintext at rest right now.

    Classification only — no key, no decryption. Reads the WHOLE file before
    calling ``is_sealed`` (memory files are small): classifying off a fixed
    ``_SEAL_PROBE_BYTES`` head made the base64 body's alignment a matter of
    luck across file lengths — a truncated body that happened to still look
    structurally valid read as sealed, one that didn't read as plaintext, so a
    real sealed file could misclassify as plaintext and let ``disable`` report
    success without decrypting it, then ``purge`` strip the key out from under
    it (permanent data loss). The head is still read first as a cheap,
    *prefix-only* reject (:func:`~..keyvault.memory_crypto.looks_like_magic_line`,
    never the full ``is_sealed``): a file that does not even start with the
    magic line cannot be sealed, so the common plaintext case skips the full
    read. A file that cannot be read counts as *not* plaintext: an unreadable
    file is no evidence of exposure, and ``status`` must never raise.
    """
    from ..keyvault.memory_crypto import is_sealed, looks_like_magic_line

    plaintext = []
    for path in _memory_file_paths(home):
        try:
            with path.open("rb") as fh:
                head = fh.read(_SEAL_PROBE_BYTES)
                if not looks_like_magic_line(head.decode("utf-8", "surrogateescape")):
                    plaintext.append(path)
                    continue
                data = head + fh.read()
        except OSError:
            continue
        if not is_sealed(data):
            plaintext.append(path)
    return plaintext


def _memory_flag_enabled(home: Path) -> bool:
    """Whether ``config.yaml`` has the legacy ``memory.encryption.enabled: true``.

    Side-effect-free read. A missing / unreadable / sealed-away config.yaml is
    treated as not-enabled (the flag is simply not observable here). The flag is
    **legacy**: no runtime reads it (the marker arms the hook), and it is
    reported only so a profile carrying it is not silently ignored.
    """
    from .._yaml_io import load_yaml_mapping

    data = load_yaml_mapping(home / _CONFIG_NAME)
    memory = data.get("memory")
    encryption = memory.get("encryption") if isinstance(memory, dict) else None
    enabled = encryption.get("enabled") if isinstance(encryption, dict) else None
    return enabled is True


def _os_note(active: bool, platform: str) -> str:
    return "active" if active else f"enrolled; inactive on this OS ({platform})"


# -----------------------------------------------------------------------------
# Per-target detectors (config / workspace)
# -----------------------------------------------------------------------------
def config_status(*, home: Path, platform: str, hook_installed: bool | None = None) -> TargetStatus:
    """Resolve the ``config`` target's status.

    On macOS the data is enrolled, but it is only *effectively* sealed when the
    startup ``.pth`` hook is installed in this runtime — without it the plaintext
    ``config.yaml`` just stays on disk. ``active`` reflects that (the opt-in
    marker alone used to read as "active" even with no hook). ``hook_installed``
    is injectable for tests; production detects it from the live interpreter.
    """
    configured = _config_marker_path(home).exists()
    if not configured:
        return TargetStatus("config", False, False, "not vault-managed")
    if platform != _DARWIN:
        return TargetStatus("config", True, False, "vault-managed; " + _os_note(False, platform))
    hook = config_hook_installed() if hook_installed is None else hook_installed
    if hook:
        return TargetStatus("config", True, True, "vault-managed; decrypt hook installed (sealed on Hermes exit)")
    detail = "vault-managed; decrypt hook NOT installed — plaintext stays on disk (reinstall the hermes-mordred wheel)"
    return TargetStatus("config", True, False, detail)


def workspace_status(
    *,
    image: Path,
    blob: Path,
    mount: Path,
    platform: str,
    on_path: Callable[[str], bool] | None = None,
) -> TargetStatus:
    """Detect the external ``claude-private`` workspace from on-disk artifacts.

    ``configured`` = the encrypted volume and its wrapped passphrase both exist.
    ``active`` additionally requires macOS (the SE/APFS protection is macOS-only).
    ``on_path`` resolves whether a helper binary is installed (defaults to
    :func:`shutil.which`); injected in tests.
    """
    if on_path is None:
        import shutil

        def on_path(name: str) -> bool:
            return shutil.which(name) is not None

    configured = image.exists() and blob.exists()
    is_macos = platform == _DARWIN
    active = configured and is_macos
    mounted = _is_mountpoint(mount)
    tools_installed = on_path("claude-private") and on_path("claude-vault-key")

    if not is_macos:
        detail = "macOS only — not available on this OS"
    elif not configured:
        detail = "tools installed; volume not set up" if tools_installed else "not installed"
    elif mounted:
        detail = "unlocked & mounted — in use, not sealed"
    else:
        detail = "sealed at rest — protected, not mounted"
    # `mounted` only carries meaning once the volume is set up on this OS;
    # otherwise the mark is plain `off` and the sealed/open distinction is moot.
    return TargetStatus("workspace", configured, active, detail, mounted=mounted if active else None)


# -----------------------------------------------------------------------------
# Rendering
# -----------------------------------------------------------------------------
def render_json(statuses: list[TargetStatus]) -> str:
    return json.dumps([s.to_dict() for s in statuses], indent=2)


#: Human-readable meaning of the env/config/memory marks. Shown as a legend
#: under the target list (both renderers) only when a ``paused`` row is present,
#: so the ``paused`` state is never cryptic and an all-on/off list stays clean.
STATUS_LEGEND_BODY = "on = protecting now | paused = set up but off, data kept | off = not set up"

#: Meaning of the workspace-only marks. The workspace runs on a different axis:
#: its volume is encrypted at rest *whenever it is set up and unmounted*, so it
#: never reports ``on``/``paused``. Shown only when a ``sealed`` / ``open`` row
#: is present (see :func:`_workspace_mark`).
WORKSPACE_LEGEND_BODY = "sealed = encrypted & locked at rest | open = mounted, in use | off = not set up here"

#: Meaning of the ``exposed`` mark. Shown only when an ``exposed`` row is present
#: (drift): the target is protected, yet a plaintext copy is on disk at rest — a
#: host write slipped past the ``.env`` seal, or a memory file was written by a
#: process without the hook. Re-running that target's ``enable`` reconciles it.
#: Target-neutral wording: both ``env`` and ``memory`` can report ``exposed``.
EXPOSED_LEGEND_BODY = (
    "exposed = protected target has a plaintext copy on disk at rest — reseal: encryption enable <target>"
)


def status_mark(status: TargetStatus) -> str:
    """One-word state for the on/off column, keyed on *effective protection*.

    Reflects whether the target is protecting data **right now** (``active``),
    not merely whether it is set up (``configured``) — the prior
    ``configured``-based marker made a disabled-but-still-enrolled ``env`` read
    as ``on``, which is misleading:

    - ``on``     — active: encrypting / protecting on this OS right now.
    - ``paused`` — configured but not active (turned off, or inactive on this
      OS). The encrypted copy is kept, so ``enable`` restores it without
      re-enrolling.
    - ``off``    — not configured: nothing is set up for this target.

    The ``workspace`` target is special-cased onto its own sealed/open/off
    vocabulary by :func:`_workspace_mark`.
    """
    if status.target == "workspace":
        return _workspace_mark(status)
    if status.drift:
        return "exposed"
    if status.active:
        return "on"
    return "paused" if status.configured else "off"


def _workspace_mark(status: TargetStatus) -> str:
    """Workspace mark, keyed on its sealed-vs-mounted axis — not on/paused/off.

    The encrypted volume is protected at rest *whenever it exists and is
    unmounted*, so ``disable`` (which seals it) is the workspace's **most**
    protected state, not its off state. Reusing ``on`` made a freshly-sealed
    workspace read as if ``disable`` had been ignored, which is exactly the
    confusion this avoids:

    - ``sealed`` — set up and unmounted: encrypted & locked at rest (protected).
    - ``open``   — mounted: unlocked and in use this session (not sealed).
    - ``off``    — not set up here (no volume on disk, or not macOS).
    """
    if not status.active:
        return "off"
    return "open" if status.mounted else "sealed"


#: Mark word -> the :mod:`_term` styler that colours it. Shared with
#: ``status_cli`` so the dashboard and the encryption screen colour a mark the
#: same way. ``on``/``sealed`` are protected (green), ``paused`` needs attention
#: (yellow), ``open`` is in-use (cyan), ``off`` is de-emphasised (dim).
_MARK_STYLE: dict[str, Callable[..., str]] = {
    "on": _term.success,
    "sealed": _term.success,
    "paused": _term.warn,
    "open": _term.info,
    "off": _term.dim,
    "exposed": _term.error,
}


def style_mark(mark_word: str, text: str, *, enabled: bool) -> str:
    """Colour *text* by the state *mark_word* names, leaving it unchanged when
    colour is off or the word is unknown.

    *text* is the display cell (often padded), kept separate from the lookup
    *mark_word* so callers can pad first and still colour by state — column
    alignment is preserved because ANSI codes have zero display width.
    """
    if not enabled:
        return text
    styler = _MARK_STYLE.get(mark_word)
    return styler(text, enabled=True) if styler is not None else text


def render_text(statuses: list[TargetStatus], *, color: bool = False) -> str:
    name_w = max(len(s.target) for s in statuses)
    marks = [status_mark(s) for s in statuses]
    # Pad marks to the widest present. With no ``paused`` row the width stays 3
    # (``on``/``off``), so an all-on/off list renders byte-identically to before.
    mark_w = max(len(m) for m in marks)
    lines = [_term.heading("Mordred at-rest encryption:", enabled=color)]
    for s, mark in zip(statuses, marks, strict=True):
        cell = style_mark(mark, mark.ljust(mark_w), enabled=color)
        lines.append(f"  {s.target.ljust(name_w)}  [{cell}]  {s.detail}")
    if "exposed" in marks:
        lines.append(_term.hint(f"  alert: {EXPOSED_LEGEND_BODY}", enabled=color))
    if "paused" in marks:
        lines.append(_term.hint(f"  legend: {STATUS_LEGEND_BODY}", enabled=color))
    if "sealed" in marks or "open" in marks:
        lines.append(_term.hint(f"  workspace: {WORKSPACE_LEGEND_BODY}", enabled=color))
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Default path resolution (production) + gateway runtime diagnostics
# -----------------------------------------------------------------------------
def _default_workspace_paths() -> WorkspacePaths:
    """Resolve the ``claude-private`` artifact locations from env + HOME defaults.

    Delegates to :func:`._workspace_paths.resolve_workspace_env` — the same
    resolver the enable/disable/purge verbs use — so ``status`` reports exactly
    the artifacts those verbs operate on.
    """
    return resolve_workspace_env()


def _shim_mark(ok: bool) -> str:
    return "ok" if ok else "MISSING"


def gateway_runtime_lines(*, home: Path, platform: str) -> list[str]:
    """One line per interpreter currently running a ``hermes gateway``.

    ``gateway runtime: <python> (pid N) — env shim: ok | config hook: MISSING | memory hook: ok``

    The three seals are only as good as the interpreter that actually serves the
    gateway: on 2026-06-25 a gateway running from a repo ``.venv`` without
    mordred could not unseal files the seal had removed, while the *expected*
    runtime looked healthy. This makes that interpreter visible before anything
    is sealed.

    Unlike the rest of ``status`` this spends three short subprocess probes per
    discovered gateway (macOS only, and only when one is actually running). No
    probe opens the vault or prompts for Touch ID — the config probe runs with
    the ``.pth`` hook neutralized. Any failure yields no lines: ``status`` must
    never raise or block.
    """
    if platform != _DARWIN:
        return []
    try:
        from ..keyvault._runtime_probe import (
            discover_running_gateway_runtimes,
            runtime_config_decrypt_available,
            runtime_env_injection_available,
            runtime_memory_encryption_available,
        )

        lines = []
        for gateway in discover_running_gateway_runtimes(home=home):
            env_ok, _ = runtime_env_injection_available(home=home, runtime_python=gateway.python)
            config_ok, _ = runtime_config_decrypt_available(home=home, runtime_python=gateway.python)
            memory_ok, _ = runtime_memory_encryption_available(home=home, runtime_python=gateway.python)
            where = f"{gateway.python}" + (f" (pid {gateway.pid})" if gateway.pid is not None else "")
            lines.append(
                f"  gateway runtime: {where} — env shim: {_shim_mark(env_ok)} "
                f"| config hook: {_shim_mark(config_ok)} | memory hook: {_shim_mark(memory_ok)}"
            )
        return lines
    except Exception:
        # Broad on purpose: a diagnostic line must never make `status` fail.
        return []
