"""``hermes mordred encryption`` — unified at-rest toggle for four targets.

One consistent command surface to turn on/off the at-rest encryption of:

- ``env``       — ``~/.hermes/.env`` enrolled into the vault (runtime-injected)
- ``config``    — ``~/.hermes/config.yaml`` via the ``.pth`` startup decrypt hook
- ``memory``    — ``~/.hermes/memories/*.md`` sealed by Mordred's memory hook
  (:mod:`mordred_hermes.keyvault._memory_hook`), keyed by ``HERMES_MEMORY_KEY``
- ``workspace`` — the external Touch ID/SE Claude Code workspace (``claude-private``)

This module owns the ``status`` reader and the namespace dispatch. ``status`` is
deliberately **side-effect-free**: it never opens the vault cold path (no
passphrase prompt) and never probes the device key store. It reads only on-disk
artifacts —

- enrollment from the *plaintext* manifest body
  (:func:`mordred_hermes.keyvault.manifest.parse_unverified`; the names are
  operational metadata, not secret),
- the config opt-in marker file,
- the memory opt-in / opt-out markers plus the first bytes of each
  ``<home>/memories/*.md`` (sealed or plaintext — no key needed),
- the workspace sparsebundle / wrapped-passphrase / mountpoint.

The one deliberate exception is :func:`gateway_runtime_lines`, appended to the
text output on macOS: it inspects the process table for a running
``hermes gateway`` and probes that interpreter's decrypt shims in a subprocess.
It still opens no vault and prompts for nothing, and it is skipped entirely for
``--json``.

``active`` is the *effective* state on **this** OS. The runtime decrypt shims are
macOS-only (:mod:`mordred_hermes.keyvault._runtime_env`,
:mod:`mordred_hermes.keyvault._config_bootstrap`), so an enrolled-but-off-darwin
target is reported ``active=False`` rather than implying protection that is not
wired here.

Heavy imports stay function-local so this module imports on any platform, like
the other wizard CLI modules.

Module layout
-------------

This module grew past the repo's 800-line guideline and was split; it remains
the single public facade and re-exports every moved name below, so every
``mordred_hermes.wizard.encryption_cli.<name>`` import path keeps resolving to
the same object (``is``-identical) it did before the split:

- :mod:`._encryption_status` — the ``config``/``workspace`` detectors and
  :func:`_os_note`, the agent-memory file-scan helpers
  (:func:`_memory_file_paths`, :func:`_unsealed_memory_files`,
  :func:`_memory_flag_enabled`), :class:`TargetStatus`, and every pure
  renderer (:func:`render_json`, :func:`render_text`, :func:`status_mark`,
  :func:`_workspace_mark`, :func:`style_mark`, :func:`_default_workspace_paths`,
  :func:`_shim_mark`, :func:`gateway_runtime_lines`).

A re-export only guarantees the import path and object identity, not
*interception*. What stays here — :func:`_enrolled_names`,
:func:`_env_target_ready`, :func:`env_status`, :func:`memory_runtime_available`,
:func:`memory_status`, :func:`collect_status`, plus ``status``/``cli_status``
and the enable/disable/purge dispatch — is the module's live monkeypatch
seams: tests call ``env_status(...)`` / ``memory_status(...)`` directly after
``monkeypatch.setattr(encryption_cli, "_enrolled_names", ...)`` /
``"memory_runtime_available"``, and a function's internal calls resolve
against the globals of the module it was *defined* in, not the module a
caller reached it through — so a moved ``env_status`` would keep calling the
*real* ``_enrolled_names`` no matter what the facade attribute was patched to.
Moving ``_enrolled_names``/``env_status`` (or ``memory_runtime_available``/
``memory_status``) apart would silently stop those tests' patches from
reaching the function under test. The same caveat applies to the moved
memory-scan pair: patching ``encryption_cli._memory_file_paths`` no longer
reaches the call *inside* :func:`_unsealed_memory_files` — patch it on
:mod:`._encryption_status` when interception is wanted.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from .._home import hermes_home as _hermes_home
from ..keyvault._identity import resolve_root
from ..keyvault._memory_hook import memory_marker_path, memory_optout_marker_path
from ..keyvault._runtime_env import _env_optout_marker_path
from . import _term
from ._defaults import is_missing_keyvault_stack
from ._encryption_status import _DARWIN as _DARWIN
from ._encryption_status import _SEAL_PROBE_BYTES as _SEAL_PROBE_BYTES
from ._encryption_status import EXPOSED_LEGEND_BODY as EXPOSED_LEGEND_BODY
from ._encryption_status import STATUS_LEGEND_BODY as STATUS_LEGEND_BODY
from ._encryption_status import WORKSPACE_LEGEND_BODY as WORKSPACE_LEGEND_BODY
from ._encryption_status import TargetStatus as TargetStatus
from ._encryption_status import _default_workspace_paths as _default_workspace_paths
from ._encryption_status import _memory_file_paths as _memory_file_paths
from ._encryption_status import _memory_flag_enabled as _memory_flag_enabled
from ._encryption_status import _os_note as _os_note
from ._encryption_status import _shim_mark as _shim_mark
from ._encryption_status import _unsealed_memory_files as _unsealed_memory_files
from ._encryption_status import _workspace_mark as _workspace_mark
from ._encryption_status import config_status as config_status
from ._encryption_status import gateway_runtime_lines as gateway_runtime_lines
from ._encryption_status import render_json as render_json
from ._encryption_status import render_text as render_text
from ._encryption_status import status_mark as status_mark
from ._encryption_status import style_mark as style_mark
from ._encryption_status import workspace_status as workspace_status
from ._flow_session import FlowSession
from ._workspace_paths import WorkspacePaths, resolve_workspace_env

__all__ = [
    "TARGETS",
    "TargetStatus",
    "WorkspacePaths",
    "cli_status",
    "collect_status",
    "config_status",
    "env_status",
    "gateway_runtime_lines",
    "memory_runtime_available",
    "memory_status",
    "render_json",
    "render_text",
    "status",
    "status_mark",
    "style_mark",
    "workspace_status",
]

#: The four toggleable targets, in display order.
TARGETS: tuple[str, ...] = ("env", "config", "memory", "workspace")


# -----------------------------------------------------------------------------
# Side-effect-free detection primitives
# -----------------------------------------------------------------------------
def _enrolled_names(root: Path) -> set[str]:
    """Logical names enrolled in the vault at ``root`` — no device key, no cold path.

    Reads the newest ``manifest.<gen>.mvmf`` and parses its *unverified* body. The
    manifest body is plaintext JSON whose ``files`` keys are the enrolled names
    (operational metadata, not secret), so this needs neither the master key nor a
    passphrase. Returns an empty set when there is no vault / no manifest / the
    manifest is unreadable — status must never raise.
    """
    try:
        from ..keyvault import manifest, vault
    except ModuleNotFoundError as exc:
        # Minimal install (no ``[keyvault]`` extra): ``keyvault.vault`` pulls the
        # crypto stack (argon2 / cryptography / blake3) at import. Nothing can be
        # enrolled without it, so degrade to "nothing enrolled" rather than let
        # ``status`` — an overview command — abort. A genuinely unrelated missing
        # module still propagates (real bug, keeps its traceback).
        if is_missing_keyvault_stack(exc):
            return set()
        raise

    try:
        generation = vault._latest_manifest_generation(root)
        if generation is None:
            return set()
        blob = vault._manifest_path(root, generation).read_bytes()
        parsed = manifest.parse_unverified(blob)
    except (OSError, manifest.ManifestError):
        return set()
    return set(parsed.files)


def _env_target_ready(*, home: Path, root: Path) -> bool:
    """Whether the ``env`` target is enrolled and actually injecting.

    ``.env`` enrolled and not opted out — the state agent-memory encryption
    rides on to get ``HERMES_MEMORY_KEY`` to the runtime (see
    :mod:`mordred_hermes.wizard.memory_cli`'s module docstring): the key is
    carried by the ``.env`` injection shim, so it does not matter that the
    manifest still lists ``.env`` as enrolled if the opt-out marker has
    suppressed the shim. Shared by ``memory_cli._enable_gate_reason`` and
    ``setup_cli``'s memory step so the two do not drift on what "the env
    target is ready" means.
    """
    return ".env" in _enrolled_names(root) and not _env_optout_marker_path(home).exists()


# -----------------------------------------------------------------------------
# Per-target detectors
# -----------------------------------------------------------------------------
def env_status(*, root: Path, home: Path, platform: str) -> TargetStatus:
    enrolled = ".env" in _enrolled_names(root)
    opted_out = _env_optout_marker_path(home).exists()
    configured = enrolled
    # The runtime shim skips injection when the opt-out marker is present, so an
    # enrolled-but-opted-out target is NOT active even on macOS.
    active = enrolled and not opted_out and platform == _DARWIN
    # Drift: the sealed state (active) removed the plaintext, so a plaintext on
    # disk means a host write slipped one past the seal — a secret is exposed at
    # rest and the file is partial (it loses the other enrolled keys until
    # resealed). A plaintext is expected (not drift) when opted-out or off-macOS.
    # Also catch a reseal temp stranded by a crash — a 0o600 plaintext at rest the
    # plain ".env" check would miss; treat it as the same exposed/drift state.
    from .env_decrypt_cli import _RESEAL_TMP_NAME

    stray_plaintext = (home / ".env").exists() or (home / _RESEAL_TMP_NAME).exists()
    drift = active and stray_plaintext
    if not enrolled:
        detail = "not enrolled"
    elif opted_out:
        detail = "disabled — encrypted copy kept; re-enable: encryption enable env"
    elif drift:
        detail = "a plaintext .env copy is on disk at rest while vault-managed — reseal with: encryption enable env"
    else:
        detail = _os_note(active, platform)
    return TargetStatus("env", configured, active, detail, drift=drift)


def memory_runtime_available() -> tuple[bool, str]:
    """Whether **this** interpreter's Hermes has a memory seam Mordred can wrap.

    The in-process half of the capability question, cheap enough for ``status``:
    it classifies the installed ``tools.memory_tool`` by signature (see
    :func:`mordred_hermes.keyvault._memory_hook.seam_check`). The
    cross-interpreter half — can the runtime that actually runs ``hermes``, or a
    gateway running right now, open sealed files? — is answered by
    ``runtime_memory_encryption_available`` at enable time and in
    :func:`gateway_runtime_lines`.

    Fail-closed and total: any import or classification failure is reported as
    unavailable, never raised, because both callers are read-only surfaces.
    """
    try:
        from ..keyvault._memory_hook import seam_check

        return seam_check()
    except Exception as exc:
        # Broad on purpose: `status` must never raise, and an unavailable
        # runtime is exactly what an unexpected failure here means.
        return False, f"the memory-encryption hook is unusable here: {exc!r}"


def _linux_memory_artifact_state(home: Path) -> tuple[bool, str, bool]:
    """Check all local artifacts without unwrapping or accessing the TPM."""
    from ..keyvault._exceptions import WrapError
    from ..keyvault._memory_key import MemoryKeyError, linux_memory_files, memory_key_id, memory_key_path
    from ..keyvault._storage import _check_dir_mode, safe_read
    from ..keyvault.memory_crypto import is_sealed
    from ..keyvault.wrap import _parse_header

    try:
        path = memory_key_path(home)
        _check_dir_mode(path.parent)
        _parse_header(safe_read(path), memory_key_id(home))
        # Read every entry: short-circuiting on the first plaintext file could
        # hide a later traversal/read failure and incorrectly report readiness.
        states = [is_sealed(path.read_bytes()) for path in linux_memory_files(home)]
    except (OSError, ValueError, WrapError, MemoryKeyError):
        return False, "TPM memory key or memory files missing, invalid or unreadable", False
    return True, "", not all(states)


def memory_status(*, home: Path, platform: str) -> TargetStatus:
    """Resolve the ``memory`` target from the Mordred markers and the files on disk.

    ``<home>/mordred/memory-vault.marker`` is what arms the hook, so it — not
    the legacy ``memory.encryption.enabled`` config key — decides ``configured``.
    ``drift`` is a plaintext memory file sitting next to sealed ones while the
    hook is armed (an out-of-process writer, or a migration that could not
    finish): the data is exposed at rest right now, so it renders ``exposed``.
    """
    marker = memory_marker_path(home).exists()
    optout = memory_optout_marker_path(home).exists()
    available, reason = memory_runtime_available()
    configured = marker or optout
    drift = False
    if platform == "linux" and marker and not optout:
        artifact_ok, artifact_reason, drift = _linux_memory_artifact_state(home)
        if not artifact_ok:
            available, reason = False, artifact_reason
    elif marker and not optout:
        drift = bool(_unsealed_memory_files(home))
    active = marker and not optout and available and platform in (_DARWIN, "linux")

    if not configured:
        detail = (
            "legacy config flag set, nothing sealed — run: encryption enable memory"
            if _memory_flag_enabled(home)
            else "not enabled"
        )
    elif optout:
        detail = "disabled — memories are plaintext; re-enable: encryption enable memory"
    elif not available:
        detail = (
            f"enabled, but {reason} — restore access before using encrypted memory"
            if platform == "linux"
            else f"enabled, but {reason} — memories written by this runtime are plaintext"
        )
    elif drift:
        detail = "enabled, but a plaintext memory file is on disk — reseal with: encryption enable memory"
    elif platform == "linux":
        detail = "sealed memory; TPM key configured (live TPM access not checked by status)"
    elif platform != _DARWIN:
        detail = _os_note(False, platform)
    else:
        detail = "sealed memory files; hook armed"
    return TargetStatus("memory", configured, active, detail, drift=drift)


# -----------------------------------------------------------------------------
# Aggregation + rendering
# -----------------------------------------------------------------------------
def collect_status(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    on_path: Callable[[str], bool] | None = None,
) -> list[TargetStatus]:
    return [
        env_status(root=root, home=home, platform=platform),
        config_status(home=home, platform=platform),
        memory_status(home=home, platform=platform),
        workspace_status(
            image=workspace.image,
            blob=workspace.blob,
            mount=workspace.mount,
            platform=platform,
            on_path=on_path,
        ),
    ]


def status(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    as_json: bool = False,
    on_path: Callable[[str], bool] | None = None,
) -> int:
    """Print the state of all four targets. Always returns 0 (read-only).

    Text output is followed by one :func:`gateway_runtime_lines` line per running
    gateway interpreter (macOS only). ``--json`` stays a pure list of target
    objects — and skips the probes entirely, so machine consumers keep the old
    shape and the old cost.
    """
    statuses = collect_status(home=home, root=root, platform=platform, workspace=workspace, on_path=on_path)
    if as_json:
        print(render_json(statuses))
        return 0
    print(render_text(statuses, color=_term.should_color(sys.stdout)))
    for line in gateway_runtime_lines(home=home, platform=platform):
        print(line)
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py
# -----------------------------------------------------------------------------
def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``encryption status [--json]`` — resolves defaults."""
    home = _hermes_home()
    return status(
        home=home,
        root=resolve_root(None),
        platform=sys.platform,
        workspace=_default_workspace_paths(),
        as_json=bool(getattr(args, "json", False)),
    )


# -----------------------------------------------------------------------------
# enable / disable / purge dispatch — routes a (verb, target) to its engine.
# The encryption surface always uses the default vault root (a custom --root would
# not be seen by the macOS startup shims, which read default_vault_root()).
# -----------------------------------------------------------------------------
def _dispatch(
    verb: str, target: str, *, force_runtime_unverified: bool = False, flow_session: FlowSession | None = None
) -> int:
    """Run ``verb`` on one target. ``flow_session`` (a guided multi-target flow)
    reaches the env / config / memory ``enable`` engines so they share one
    passphrase prompt, one vault unlock and one key policy (see
    :mod:`._flow_session`); every other route ignores it."""
    from . import config_decrypt_cli, env_decrypt_cli, memory_cli

    home = _hermes_home()
    root = resolve_root(None)
    platform = sys.platform

    # target -> {verb: action}. enable/disable are explicit; the CLI adapters
    # only ever pass enable/disable/purge, and any non-enable/disable verb
    # resolves to the target's purge (preserves the original if-chain's
    # fall-through). workspace stays lazily imported (macOS-only path).
    # ``force_runtime_unverified`` reaches the env, config, and memory enables
    # (the runtime-gated seals); every other route ignores it.
    routes: dict[str, dict[str, Callable[[], int]]] = {
        "env": {
            "enable": lambda: env_decrypt_cli.enable(
                home=home,
                root=root,
                platform=platform,
                force_runtime_unverified=force_runtime_unverified,
                flow_session=flow_session,
            ),
            "disable": lambda: env_decrypt_cli.disable(home=home, root=root),
            "purge": lambda: env_decrypt_cli.purge(home=home, root=root),
        },
        "config": {
            "enable": lambda: config_decrypt_cli.enable(
                home=home,
                root=root,
                platform=platform,
                force_runtime_unverified=force_runtime_unverified,
                flow_session=flow_session,
            ),
            "disable": lambda: config_decrypt_cli.disable(home=home, root=root),
            "purge": lambda: config_decrypt_cli.purge(home=home, root=root),
        },
        "memory": {
            "enable": lambda: memory_cli.enable(
                home=home,
                root=root,
                platform=platform,
                force_runtime_unverified=force_runtime_unverified,
                flow_session=flow_session,
            ),
            "disable": lambda: memory_cli.disable(home=home, root=root),
            "purge": lambda: memory_cli.purge(home=home, root=root),
        },
    }
    if target in routes:
        actions = routes[target]
        return (actions.get(verb) or actions["purge"])()
    if target == "workspace":
        from . import workspace_cli

        ws: dict[str, Callable[[], int]] = {
            "enable": workspace_cli.cli_enable,
            "disable": workspace_cli.cli_disable,
            "purge": workspace_cli.cli_purge,
        }
        return (ws.get(verb) or ws["purge"])()

    _term.emit_error(f"encryption {verb} {target}: not available in this build.")
    return 2


# -----------------------------------------------------------------------------
# `all` pseudo-target — best-effort fan-out of one verb over every target.
# -----------------------------------------------------------------------------
#: Targets an ``all`` fan-out always attempts, in order. Derived from ``TARGETS``
#: (its leading entries) so the two never drift; ``workspace`` is the trailing
#: entry and is handled separately (eligibility-gated) because it is macOS-only
#: and its ``enable`` drives a heavyweight external setup.
_ALL_CORE_TARGETS: tuple[str, ...] = TARGETS[:-1]


def _default_on_path() -> Callable[[str], bool]:
    """Production ``on_path``: is a helper binary resolvable on ``$PATH``?"""
    import shutil

    return lambda name: shutil.which(name) is not None


def _workspace_eligible(
    verb: str,
    *,
    platform: str,
    on_path: Callable[[str], bool],
    workspace: WorkspacePaths | None = None,
) -> tuple[bool, str]:
    """Decide whether an ``all`` fan-out should touch the workspace target.

    Skipping (rather than failing) keeps ``all`` best-effort: the workspace is
    macOS-only and its ``enable`` builds + mounts an external volume, so a Linux
    host or a Mac without the tooling is reported *skipped*, not failed.

    - non-macOS → never eligible.
    - ``enable`` on macOS → eligible only when both helper binaries are present
      (otherwise ``enable`` would just error — tell the user to set it up first).
    - ``disable`` / ``purge`` on macOS → eligible only when the volume is already
      set up (image + wrapped passphrase on disk); else there is nothing to do.
    """
    if platform != _DARWIN:
        return False, "macOS only"
    if verb == "enable":
        if on_path("claude-private") and on_path("claude-vault-key"):
            return True, ""
        return False, "workspace tooling not installed — run `encryption enable workspace` to set it up"
    ws = workspace if workspace is not None else _default_workspace_paths()
    if ws.image.exists() and ws.blob.exists():
        return True, ""
    return False, "workspace not set up"


def _run_target(
    verb: str, target: str, *, force_runtime_unverified: bool = False, flow_session: FlowSession | None = None
) -> tuple[str, int]:
    """Dispatch one target for an ``all`` fan-out; return ``(status_label, exit_code)``.

    The engine streams its own detail to stdout here; the caller emits the
    one-line per-target status afterwards as a single contiguous summary block.
    """
    rc = _dispatch(verb, target, force_runtime_unverified=force_runtime_unverified, flow_session=flow_session)
    return ("ok" if rc == 0 else f"FAILED (exit {rc})"), rc


def _run_core_target(
    verb: str,
    target: str,
    *,
    platform: str,
    force_runtime_unverified: bool,
    flow_session: FlowSession | None = None,
) -> tuple[str, int, bool]:
    """Run one core (env/config/memory) target; return ``(status_label, exit_code, skipped)``.

    ``memory`` under ``enable`` is special-cased, platform first: off macOS the
    memory-sealing runtime shims do not exist at all (mirrors
    ``setup_cli._resolve_step_memory_encryption``'s ordering), so the engine
    would just refuse — that refusal used to be counted a *failure* here
    because ``_dispatch``/the engine resolve their own ``sys.platform``
    independently of the ``platform`` an ``all`` fan-out was given, so a
    Linux ``enable all`` reported ``memory FAILED`` instead of a clean skip.
    Only once the platform passes is this Hermes' memory seam
    (:func:`memory_runtime_available`) checked; when that is also missing the
    engine would again just refuse, so it is never called — both cases record
    a skip instead of a failure. ``disable`` / ``purge`` still run regardless
    of platform or seam: they clear state and decrypt files back, which is
    exactly what a broken seam or the wrong OS needs.
    """
    if target == "memory" and verb == "enable":
        if platform != _DARWIN:
            return (
                f"skipped (macOS only — the memory sealing runtime is not available on {platform})",
                0,
                True,
            )
        available, reason = memory_runtime_available()
        if not available:
            return f"skipped ({reason})", 0, True
    status, rc = _run_target(verb, target, force_runtime_unverified=force_runtime_unverified, flow_session=flow_session)
    return status, rc, False


def _print_all_summary(verb: str, outcomes: list[tuple[str, str]], *, failed: int, skipped: int) -> None:
    """Print the contiguous result block after all per-target engine output."""
    print(f"encryption {verb} all:")
    for target, status in outcomes:
        print(f"  {target.ljust(9)} {status}")
    ok = len(outcomes) - failed - skipped
    print(f"  {ok} ok, {failed} failed, {skipped} skipped")


def _dispatch_all(
    verb: str,
    *,
    platform: str | None = None,
    on_path: Callable[[str], bool] | None = None,
    force_runtime_unverified: bool = False,
) -> int:
    """Fan ``verb`` out over every target, best-effort. Returns an exit code.

    Core vault targets (env / config / memory) are always attempted; workspace
    is eligibility-gated (see :func:`_workspace_eligible`) and a skip never
    counts as a failure. ``memory`` under ``enable`` is likewise skipped, not
    attempted, off macOS or when this Hermes has no memory seam Mordred can
    wrap (see :func:`_run_core_target`) — the ``platform`` given here (or
    ``sys.platform`` by default) is what decides the former, so the skip is
    accurate even though the per-target engine itself always resolves its own
    ``sys.platform``. Every target runs even if an earlier one
    failed; the exit code is non-zero iff at least one *attempted* target
    failed. Per-target engine output streams inline; the ok/FAILED/skipped
    roll-up prints once at the end as a single block (see
    :func:`_print_all_summary`).

    ``force_runtime_unverified`` is forwarded to every target's dispatch but only
    affects the env and config enables (the runtime-gated seals); see
    :func:`_dispatch`.
    """
    platform = sys.platform if platform is None else platform
    on_path = _default_on_path() if on_path is None else on_path

    outcomes: list[tuple[str, str]] = []
    failed = 0
    skipped = 0
    # One flow for the core targets: `enable all` asks for a new vault's
    # passphrase once and unlocks the vault at most once (the handle is closed,
    # zeroing the master, before the workspace step runs).
    with FlowSession() as flow:
        for target in _ALL_CORE_TARGETS:
            status, rc, was_skipped = _run_core_target(
                verb,
                target,
                platform=platform,
                force_runtime_unverified=force_runtime_unverified,
                flow_session=flow if verb == "enable" else None,
            )
            outcomes.append((target, status))
            if was_skipped:
                skipped += 1
            else:
                failed += rc != 0

    eligible, reason = _workspace_eligible(verb, platform=platform, on_path=on_path)
    if eligible:
        status, rc = _run_target(verb, "workspace", force_runtime_unverified=force_runtime_unverified)
        outcomes.append(("workspace", status))
        failed += rc != 0
    else:
        outcomes.append(("workspace", f"skipped ({reason})"))
        skipped += 1

    _print_all_summary(verb, outcomes, failed=failed, skipped=skipped)
    return 1 if failed else 0


def cli_enable(args: argparse.Namespace) -> int:
    force = bool(getattr(args, "force_runtime_unverified", False))
    if args.target == "all":
        return _dispatch_all("enable", force_runtime_unverified=force)
    return _dispatch("enable", args.target, force_runtime_unverified=force)


def cli_disable(args: argparse.Namespace) -> int:
    if args.target == "all":
        return _dispatch_all("disable")
    return _dispatch("disable", args.target)


def cli_purge(args: argparse.Namespace) -> int:
    """``encryption purge <target> --yes`` — destructive; refuse without --yes."""
    if not bool(getattr(args, "yes", False)):
        scope = (
            "ALL encrypted copies (env, config, memory, workspace)" if args.target == "all" else "the encrypted copy"
        )
        workspace_targets = ""
        if args.target in {"workspace", "all"}:
            workspace = resolve_workspace_env()
            workspace_targets = f" Workspace targets: volume={workspace.image}; key material={workspace.keydir}."
        _term.emit_error(
            f"encryption purge {args.target} is destructive (removes {scope}).{workspace_targets} "
            "Re-run with --yes to confirm."
        )
        return 2
    if args.target == "all":
        return _dispatch_all("purge")
    return _dispatch("purge", args.target)
