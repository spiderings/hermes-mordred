"""``hermes-mordred setup`` -- the one-command orchestrator for a fresh install.

Before this module, getting Mordred fully protected on a new machine meant
running seven separate commands in the right order (``configure``, ``network
init``, ``keyvault enable-se``/``enable-tpm``, ``keyvault init``, ``encryption
enable env``, ``encryption enable memory``) and knowing which ones were
optional. ``setup`` walks that same
sequence for the operator, one step at a time, and is safe to re-run: it never
repeats work that is already done and it never destroys existing state.

State machine
-------------
Seven steps run in a fixed order: **hermes** -> **configure** -> **network** ->
**hardware-helper** -> **keyvault** -> **env-encryption** ->
**memory-encryption**. Each step is a three-stage cycle:

1. **probe** -- a read-only check of on-disk / PATH state, answering "is this
   step already done?". Probes never prompt, never write, and never touch the
   Secure Enclave / TPM.
2. **run** -- only when the probe says the step is incomplete, delegate to
   that subsystem's own command (``configure.run``, ``network_cli.run_init``,
   ``keyvault_native_cli.enable_se``/``enable_tpm``, ``_keyvault_init.init_keyvault``,
   ``env_decrypt_cli.enable``, ``memory_cli.enable``). This module owns no
   persistence of its own -- every write happens inside the command it
   delegates to.
3. **report** -- record one :class:`StepResult` (``name``, ``action``,
   ``detail``) per step, regardless of outcome.

A step's ``action`` is one of:

- ``"done"``        -- the probe already found it complete; nothing ran.
- ``"ran"``          -- it was incomplete and the delegated command completed
  it now.
- ``"skipped"``      -- nothing to do here, by the operator's choice or by
  platform: the ``hermes`` step's ``--skip-hermes-setup`` / a declined prompt,
  and the ``memory-encryption`` step off macOS (its sealing shims are
  macOS-only, and unlike the hardware helper that is no reason to stop a
  perfectly good Linux run).
- ``"manual"``       -- it needs interaction that ``--non-interactive`` cannot
  supply, the operator was told to run a specific command themselves, or a
  build/prerequisite step failed in a way that still leaves the rest of the
  run usable. Hits this for: a non-zero ``hermes setup`` exit; a
  hardware-helper build/install failure (``enable-se`` / ``enable-tpm``); the
  keyvault ceremony itself (passphrase + 24-word seed transcription) and its
  preflight gate (most commonly: the host must be offline); the vault's
  one-time recovery-passphrase prompt, or an OS-level device-key unlock, when
  ``--non-interactive`` would reach either; and any prompt that fails closed
  because stdin is not a TTY, even without ``--non-interactive``.
- ``"blocked"``      -- on-disk state needs manual repair before this step can
  run at all (a corrupt or interrupted keyvault). The repair command is named
  in the detail; this module never runs it.
- ``"failed"``       -- the delegated command ran and returned a real error.
- ``"unsupported"``  -- the host platform cannot run this step at all (a
  hardware keyvault needs macOS Secure Enclave or Linux TPM 2.0).

The run stops immediately -- prints the report so far and exits 1 -- on
``"blocked"``, ``"failed"``, or ``"unsupported"``, and also when the
**keyvault** step itself resolves to ``"manual"``: every step after it
(env-encryption, memory-encryption) and the final status dashboard assume a
keyvault decision has actually been made, so there is nothing useful left to
attempt. Every other ``"manual"`` (network, env-encryption, memory-encryption)
lets the run continue -- those steps are optional / independently re-runnable,
so a missing prompt there should not stop the operator from finishing
everything else.

Re-running ``hermes-mordred setup`` after a partial run (or after fixing
whatever made a step ``"blocked"``/``"failed"``) resumes exactly where it left
off: every already-complete step reports ``"done"`` without touching it again,
because each step's *only* gate for re-running is its own probe.

The never-auto-reset rule
--------------------------
This orchestrator NEVER destroys existing state and NEVER invokes
``hermes-mordred keyvault reset`` on the operator's behalf, no matter what the
keyvault probe finds. A corrupt ``meta.json``, an interrupted native-key
provisioning journal, or residual ownership metadata all resolve to the
``"blocked"`` action: the detail names the exact repair command (``keyvault
reset`` for the journal/residual cases; repair or remove ``meta.json`` by hand
for corruption) and the run stops there. Resetting a keyvault is irreversible
-- it destroys key material -- so it is never something an automated
orchestrator decides on the operator's behalf. The same caution applies to
``configure``/``network init``/``encryption enable env``: each step probe is
the *only* gate for whether the delegated command runs, so a step already
marked complete on disk is never re-run (and, for ``configure`` in
particular, never overwritten) just because ``setup`` was invoked again. The
env-encryption probe extends this to an explicit operator opt-out: once
``encryption disable env`` has written its opt-out marker, re-running
``setup`` reports that step ``"done"`` (paused, by choice) rather than
silently reversing the decision -- a stray plaintext ``.env`` at rest while
still vault-managed (drift) is the opposite case and is deliberately treated
as *incomplete*, so ``enable()``'s reseal path runs instead of a secret being
reported "already done" while it sits exposed on disk. The memory-encryption
probe follows exactly the same two rules on its own markers and its own drift
(a plaintext memory file while the hook is armed).

Keyvault preflight gate
------------------------
Before asking the unattended-keys question, the keyvault step also runs the
ceremony's own fail-closed preflight (``_keyvault_init._preflight_or_refuse``)
once ahead of time, via the module-level ``_keyvault_preflight`` seam. A
refusal there -- most commonly, the host must be fully offline for the
seed-display air-gap check -- resolves straight to ``"manual"`` *before* the
operator is asked anything, rather than asking the unattended-keys question
first and only then discovering the ceremony can't proceed.
``_keyvault_init.init_keyvault`` still re-runs the exact same preflight
internally once the ceremony actually starts; that duplication is
intentional defense in depth (a TOCTOU race between the two checks still
fails closed at the second one), not redundant plumbing to remove.

One passphrase, one vault unlock, one key policy per run
--------------------------------------------------------
:func:`run_setup` owns one in-memory :class:`._flow_session.FlowSession` for
the whole run and hands it to the keyvault, env-encryption and
memory-encryption steps:

- **Passphrase.** A fresh run can create two stores that each need a
  passphrase: the keyvault (its ceremony's Passphrase) and the at-rest vault
  behind env / memory encryption (its recovery passphrase). Whichever step
  creates something first asks the operator to choose and confirm a
  passphrase; every later creation in the same run reuses it without
  prompting. It is never written anywhere except as the Argon2id-wrapped
  material each store already keeps, and it is dropped when the run ends.
- **Vault unlock.** The env and memory steps share one open vault handle, so
  the run unwraps the vault master at most once (one Touch ID / password
  dialog with an attended device key) -- and not at all when the run just
  created the vault. The handle is closed (master zeroed) when the run ends.
- **Key policy.** The answer to "allow background services ..." (or
  ``--unattended-keys`` / ``--attended-keys``) applies to every device key the
  run creates: the keyvault key AND the at-rest vault's key. When the keyvault
  already existed, the question is asked (same precedence) right before the
  vault is created instead.

Probe contract
---------------
Every ``_probe_*`` function in this module:

- reads on-disk / PATH state only (no prompts, no subprocess, no Secure
  Enclave / TPM access, no writes);
- returns a plain tuple (or, for the keyvault step, a three-way
  ``Literal["initialised", "absent", "blocked"]`` plus a detail string) rather
  than raising, mirroring ``status_cli``'s side-effect-free contract;
- is a module-level function (not a closure) precisely so tests can
  monkeypatch it independently of the ``_run_*``/``_resolve_step_*`` seams
  that call it -- the same seam style ``keyvault_native_cli`` uses for
  ``_se_platform_reason`` / ``_missing_build_tools``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .._home import hermes_home as _hermes_home
from ..keyvault._identity import resolve_root
from ..keyvault._memory_hook import memory_marker_path, memory_optout_marker_path
from ..keyvault._runtime_env import _env_optout_marker_path
from . import _term
from ._defaults import resolve_prompt_io
from ._flow_session import FlowSession
from ._prompt_io import NonInteractiveAbort, PromptIO, _RefusingPromptIO
from ._vault_open import _vault_present
from .configure import SetupRunner, SubprocessSetupRunner
from .encryption_cli import (
    WorkspacePaths,
    _default_workspace_paths,
    _env_target_ready,
    _unsealed_memory_files,
    env_status,
)
from .policy_writer import PolicyWriter

__all__ = [
    "SetupOptions",
    "StepResult",
    "cli_setup",
    "render_report",
    "run_setup",
]

#: Step outcomes. See the module docstring's "State machine" section for the
#: meaning of each member.
StepAction = Literal["done", "ran", "skipped", "blocked", "failed", "unsupported", "manual"]

#: Step names, in the fixed run order. Used as the identifier in
#: :class:`StepResult` and by :func:`_stops_run`'s keyvault special-case.
_STEP_HERMES = "hermes"
_STEP_CONFIGURE = "configure"
_STEP_NETWORK = "network"
_STEP_HARDWARE_HELPER = "hardware-helper"
_STEP_KEYVAULT = "keyvault"
_STEP_ENV_ENCRYPTION = "env-encryption"
_STEP_MEMORY_ENCRYPTION = "memory-encryption"

#: Actions that always stop the run immediately (see the module docstring).
_STOPPING_ACTIONS: frozenset[StepAction] = frozenset({"blocked", "failed", "unsupported"})

#: Actions that count as "this step is satisfied" for the overall exit code.
_SUCCESS_ACTIONS: frozenset[StepAction] = frozenset({"done", "ran", "skipped"})


@dataclass(frozen=True, slots=True)
class SetupOptions:
    """CLI flag carrier for ``hermes-mordred setup``.

    Defaults match the interactive, fully-automatic form: prompt when a step
    needs a decision, don't force or skip the upstream ``hermes setup`` step,
    let the keyvault's unattended-key policy be asked about interactively, and
    store the generated seed SE-encrypted for HD derivation (the same default
    ``keyvault init`` itself uses).
    """

    non_interactive: bool = False
    with_hermes_setup: bool = False
    skip_hermes_setup: bool = False
    #: ``None`` = not specified on the CLI; resolved by :func:`_resolve_unattended_keys`.
    unattended_keys: bool | None = None
    store_seed_for_hd: bool = True


@dataclass(frozen=True, slots=True)
class StepResult:
    """One step's outcome -- the unit :func:`render_report` renders."""

    name: str
    action: StepAction
    detail: str


#: Human phrases for each action, shown by :func:`render_report`. A step
#: whose action isn't a key here degrades to the raw token (mirrors
#: ``upgrade.render_report``'s ``.get(..., fallback)`` guard).
_ACTION_PHRASES: dict[StepAction, str] = {
    "done": "already done",
    "ran": "completed now",
    "skipped": "skipped",
    "blocked": "BLOCKED",
    "failed": "FAILED",
    "unsupported": "not supported here",
    "manual": "needs a manual step",
}


def render_report(results: Sequence[StepResult]) -> str:
    """User-facing summary printed after every ``hermes-mordred setup`` run.

    Printed both on a clean finish and on an early stop (see the module
    docstring) -- an operator must always be able to see exactly how far the
    run got and why, never just a bare exit code.
    """
    name_w = max((len(r.name) for r in results), default=0)
    lines = ["Setup summary:"]
    for r in results:
        phrase = _ACTION_PHRASES.get(r.action, r.action)
        lines.append(f"  {r.name.ljust(name_w)} : {phrase} -- {r.detail}")
    return "\n".join(lines)


def _stops_run(result: StepResult) -> bool:
    """Whether ``result`` must stop the run before the next step runs."""
    if result.action in _STOPPING_ACTIONS:
        return True
    # The keyvault decision gates env-encryption's device key and the final
    # status dashboard's "how am I protected" answer; a non-interactive run
    # that cannot complete the ceremony has nothing productive left to do.
    return result.name == _STEP_KEYVAULT and result.action == "manual"


# -----------------------------------------------------------------------------
# Step 1 -- upstream Hermes (`hermes setup`).
# -----------------------------------------------------------------------------


def _probe_hermes(*, home: Path) -> tuple[bool, str]:
    """Read-only: is upstream Hermes already set up?

    Deliberate heuristic: plain ``config.yaml`` existence is NOT sufficient
    signal by itself, because Mordred's own ``configure`` step also creates
    ``config.yaml`` (see :class:`.policy_writer.PolicyWriter`) -- so a fresh
    machine that only ever ran Mordred's ``setup`` (never upstream
    ``hermes setup``) would already have a config.yaml, and reading that alone
    as "upstream ran" would let this probe report ``done`` when it is not.
    ``PolicyWriter`` (and every other Mordred-side writer that touches
    ``config.yaml`` -- ``network_cli``, ``openclaw_migration``, ``upgrade``)
    only ever mutates the top-level ``plugins`` mapping, so any OTHER
    top-level key is real evidence that something outside Mordred wrote to
    this file -- i.e. ``hermes setup`` itself (provider credentials, model
    config, ...). Upstream Hermes therefore counts as set up only when
    ``hermes`` is on PATH AND config.yaml exists AND it has at least one
    top-level key other than ``plugins``.
    """
    import shutil

    from .._yaml_io import load_yaml_mapping

    has_hermes = shutil.which("hermes") is not None
    config_path = home / "config.yaml"
    has_config = config_path.exists()
    has_upstream_evidence = False
    if has_config:
        mapping = load_yaml_mapping(config_path, catch=(Exception,))
        has_upstream_evidence = any(key != "plugins" for key in mapping)

    if has_hermes and has_config and has_upstream_evidence:
        return True, "`hermes` is on PATH and config.yaml has upstream-authored content"
    missing = []
    if not has_hermes:
        missing.append("`hermes` not found on PATH")
    if not has_config:
        missing.append("config.yaml does not exist yet")
    elif not has_upstream_evidence:
        missing.append("config.yaml has no content beyond Mordred's own `plugins` section")
    return False, "; ".join(missing)


def _resolve_step_hermes(
    *,
    home: Path,
    prompt_io: PromptIO,
    setup_runner: SetupRunner,
    options: SetupOptions,
) -> StepResult:
    complete, detail = _probe_hermes(home=home)

    if options.skip_hermes_setup:
        return StepResult(_STEP_HERMES, "skipped", "skipped via --skip-hermes-setup")
    if complete and not options.with_hermes_setup:
        return StepResult(_STEP_HERMES, "done", detail)

    if options.non_interactive:
        rc = setup_runner.run(non_interactive=True)
    else:
        # Only ask when we got here organically (the probe was incomplete);
        # --with-hermes-setup is itself the operator's explicit go-ahead, so
        # asking again would just be a redundant second confirmation.
        if not options.with_hermes_setup:
            try:
                run_now = prompt_io.ask_bool(
                    "Run the upstream `hermes setup` wizard now?",
                    default=True,
                    description=(
                        "`hermes setup` is Hermes's own first-run wizard -- it creates "
                        "~/.hermes/config.yaml and your provider credentials. Mordred setup "
                        "needs that to exist before it can continue."
                    ),
                )
            except NonInteractiveAbort:
                # PromptToolkitIO fails closed on a non-TTY stdin even without
                # --non-interactive (see configure._require_tty) -- an
                # unhandled abort here would skip render_report entirely, so
                # this is caught the same way every other prompt site in this
                # module already handles it.
                return StepResult(
                    _STEP_HERMES,
                    "manual",
                    "stdin is not a TTY; re-run interactively, or use --non-interactive",
                )
            if not run_now:
                return StepResult(_STEP_HERMES, "skipped", "declined at the prompt")
        rc = setup_runner.run(non_interactive=False)

    if rc != 0:
        # Mirrors configure.py's existing tolerance for a non-zero `hermes
        # setup` exit: warn and keep going -- reported as "manual" (not a
        # success) so the overall exit code reflects that upstream Hermes may
        # not actually be configured, but this never stops the rest of
        # Mordred setup from running.
        _term.emit_warn(f"`hermes setup` exited with code {rc}; continuing with Mordred setup anyway")
        return StepResult(
            _STEP_HERMES,
            "manual",
            f"`hermes setup` exited with code {rc}; re-run `hermes setup` yourself, then re-run setup",
        )
    return StepResult(_STEP_HERMES, "ran", "hermes setup completed")


# -----------------------------------------------------------------------------
# Step 2 -- Mordred `configure`.
# -----------------------------------------------------------------------------


def _probe_configure(*, policy_writer: PolicyWriter) -> tuple[bool, str]:
    """Read-only: has ``configure`` already written its output?

    A genuine ``configure`` run always: (1) writes ``policy.json``, (2)
    upserts the ``mordred_privacy_check`` and ``mordred_llm_guard``
    ``config.yaml`` sections together, and (3) -- via
    ``PolicyWriter._ensure_plugins_enabled``, which every wizard write path
    triggers (``configure``, ``upgrade``, even a bare ``network use``) --
    ensures the ``mordred`` plugin (``SIBLING_PLUGINS``) is listed in
    ``plugins.enabled``. Because other wizard commands share that last
    guarantee too, ``plugins.enabled`` membership alone can't tell "configure
    ran" apart from "some other wizard write ran first"; ``policy.json`` and
    the two config.yaml sections are written ONLY by ``configure`` (or
    ``upgrade``), so those three are the real "configure ran" signal. The
    ``plugins.enabled`` check is kept as an extra completeness guard on top
    (a hand-edited config.yaml that dropped ``mordred``, or one still listing
    only the pre-0.2.0a0 per-component names, reads as incomplete).
    """
    if not policy_writer.config_path.exists():
        return False, "config.yaml does not exist yet"
    if not policy_writer.policy_json_path.exists():
        return False, "policy.json does not exist yet"

    from .._yaml_io import load_plugin_section, load_yaml_mapping
    from ..privacy_check._runtime import SIBLING_PLUGINS

    privacy_check = load_plugin_section(policy_writer.config_path, "mordred_privacy_check", catch=(Exception,))
    if privacy_check is None:
        return False, "plugins.mordred_privacy_check section is missing"
    llm_guard = load_plugin_section(policy_writer.config_path, "mordred_llm_guard", catch=(Exception,))
    if llm_guard is None:
        return False, "plugins.mordred_llm_guard section is missing"

    plugins = load_yaml_mapping(policy_writer.config_path, catch=(Exception,)).get("plugins")
    enabled = plugins.get("enabled") if isinstance(plugins, dict) else None
    enabled_names = {name for name in enabled if isinstance(name, str)} if isinstance(enabled, list) else set()
    missing = [name for name in SIBLING_PLUGINS if name not in enabled_names]
    if missing:
        return False, f"plugins.enabled is missing: {', '.join(missing)}"
    return True, "policy.json and config.yaml are configured"


def _run_configure(
    *,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    setup_runner: SetupRunner,
    non_interactive: bool,
) -> None:
    """Run the interactive Mordred prompt sequence. Thin seam over ``configure.run``.

    ``with_hermes_setup=False``: the upstream ``hermes setup`` step already ran
    (or was deliberately skipped) as this orchestrator's own step 1.
    """
    from . import configure

    configure.run(
        setup_runner=setup_runner,
        prompt_io=prompt_io,
        policy_writer=policy_writer,
        non_interactive=non_interactive,
        with_hermes_setup=False,
    )


def _resolve_step_configure(
    *,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    setup_runner: SetupRunner,
    options: SetupOptions,
) -> StepResult:
    from ruamel.yaml.error import YAMLError

    complete, detail = _probe_configure(policy_writer=policy_writer)
    if complete:
        return StepResult(_STEP_CONFIGURE, "done", detail)

    try:
        _run_configure(
            prompt_io=prompt_io,
            policy_writer=policy_writer,
            setup_runner=setup_runner,
            non_interactive=options.non_interactive,
        )
    except NonInteractiveAbort:
        # configure.run() always starts by collecting the Mordred prompts
        # (policy mode, cloud LLM, ...) unconditionally -- there is no
        # flag-driven fallback on this code path, so --non-interactive can
        # never complete it.
        return StepResult(
            _STEP_CONFIGURE,
            "manual",
            "configure cannot complete without prompts; run `hermes-mordred configure --non-interactive` "
            "(with flags) or `hermes-mordred configure` interactively",
        )
    except (OSError, YAMLError) as exc:
        # PolicyWriter.write() round-trip-loads the existing config.yaml
        # (ruamel.yaml) before editing it; a syntactically corrupt file raises
        # YAMLError there, alongside the existing OSError paths (disk full,
        # permission denied).
        return StepResult(_STEP_CONFIGURE, "failed", f"configure failed: {exc}")
    return StepResult(_STEP_CONFIGURE, "ran", "policy.json and config.yaml written")


# -----------------------------------------------------------------------------
# Step 3 -- network privacy path (`network init`).
# -----------------------------------------------------------------------------


def _probe_network(*, config_path: Path) -> tuple[bool, str]:
    """Read-only: is a network privacy path already configured?"""
    from .._yaml_io import load_plugin_section

    # Imported from ``_network_answers`` (the defining module) rather than its
    # re-export in ``_network_init``: the latter re-imports it without an
    # ``__all__``/explicit re-export marker, which ``mypy --strict`` flags.
    from ._network_answers import _VALID_PATHS

    section = load_plugin_section(config_path, "mordred_network", catch=(Exception,))
    if section is None:
        return False, "plugins.mordred_network is not configured"
    path = section.get("default_path")
    if isinstance(path, str) and path in _VALID_PATHS:
        return True, f"default path = {path}"
    return False, "plugins.mordred_network.default_path is missing or invalid"


def _run_network(*, home: Path, prompt_io: PromptIO, policy_writer: PolicyWriter) -> int:
    """Run the network-privacy prompt sequence. Thin seam over ``network_cli.run_init``.

    Passes ``env_path`` / ``credentials_path`` derived from the injected
    ``home`` -- the same relative layout ``network_cli._persist_network``
    falls back to (``<home>/.env`` and
    ``<home>/mordred/credentials/network.json``), just with ``home``
    substituted for that module's import-time ``HERMES_BASE``. Without this,
    ``run_init`` would default both to the real production paths regardless
    of which ``home`` this orchestrator was invoked with.
    """
    from . import network_cli
    from .credentials_writer import JSONCredentialsWriter
    from .env_file_writer import DotEnvFileWriter

    return network_cli.run_init(
        prompt_io=prompt_io,
        policy_writer=policy_writer,
        env_writer=DotEnvFileWriter(),
        credentials_writer=JSONCredentialsWriter(),
        env_path=home / ".env",
        credentials_path=home / "mordred" / "credentials" / "network.json",
    )


def _resolve_step_network(*, home: Path, prompt_io: PromptIO, policy_writer: PolicyWriter) -> StepResult:
    complete, detail = _probe_network(config_path=policy_writer.config_path)
    if complete:
        return StepResult(_STEP_NETWORK, "done", detail)

    try:
        # collect_network_answers() always asks the privacy-path question
        # first -- there is no flag-driven fallback on this code path either
        # -- so a non-interactive prompt_io aborts immediately, before any
        # write. The network path is optional (clearnet is a safe default),
        # so unlike keyvault this must NOT stop the rest of the run.
        rc = _run_network(home=home, prompt_io=prompt_io, policy_writer=policy_writer)
    except NonInteractiveAbort:
        return StepResult(
            _STEP_NETWORK,
            "manual",
            "network privacy path is not configured; run `hermes-mordred network init` to choose Tor / VPN / clearnet",
        )
    if rc != 0:
        return StepResult(_STEP_NETWORK, "failed", "network init failed (see errors above)")
    return StepResult(_STEP_NETWORK, "ran", "network privacy path configured")


# -----------------------------------------------------------------------------
# Step 4 -- hardware keyvault helper (Secure Enclave / TPM 2.0).
# -----------------------------------------------------------------------------


def _probe_se_helper() -> bool:
    """Read-only: is the macOS Secure Enclave helper installed on PATH?"""
    from ..keyvault import _seckey_helper

    # Mirrors status_cli.collect's guard (review 2026-06-12): the PATH/home
    # walk can blow up in odd environments (e.g. Path.home() raising
    # RuntimeError in a container with no passwd entry) -- degrade to "not
    # installed" instead of letting a read-only probe raise.
    try:
        return _seckey_helper._find_helper() is not None
    except Exception:
        return False


def _probe_tpm_helper() -> bool:
    """Read-only: is the Linux TPM 2.0 helper installed on PATH?"""
    from ..keyvault import _seckey_helper

    # See _probe_se_helper's comment -- same rationale, same guard.
    try:
        return _seckey_helper.find_tpmkey_helper() is not None
    except Exception:
        return False


def _run_se_helper(*, home: Path) -> int:
    """Build + install the Secure Enclave helper. Thin seam over ``keyvault_native_cli.enable_se``."""
    from . import keyvault_native_cli

    return keyvault_native_cli.enable_se(home=home)


def _run_tpm_helper(*, home: Path) -> int:
    """Build + install the TPM 2.0 helper. Thin seam over ``keyvault_native_cli.enable_tpm``."""
    from . import keyvault_native_cli

    return keyvault_native_cli.enable_tpm(home=home)


def _probe_winkey_helper(*, home: Path) -> bool:
    from . import keyvault_native_cli

    return keyvault_native_cli._verify_winkey_helper(install_dir=home / "bin")[0]


def _resolve_step_hardware_helper(*, home: Path, platform: str) -> StepResult:
    """Build/install the platform hardware helper. A build failure here (e.g. no
    ``native/`` sources on a wheel install, missing Xcode CLT / Rust toolchain)
    does not by itself make the keyvault unusable, so it resolves to
    ``"manual"`` (never a stopping ``"failed"``) and the run continues to the
    keyvault step:

    - macOS: ``_seckey_backend`` falls back to a software P-256 key when no SE
      helper is installed, so the keyvault remains usable without it.
    - Linux: there is no such fallback -- the TPM backend fails closed without
      a working helper (see ``_seckey_backend``'s platform selection) -- but
      that failure is still better surfaced at the keyvault step itself (where
      it would occur) than guessed at here; stopping the whole run one step
      early, before the keyvault step even gets to try, would hide that detail
      behind a generic "enable-tpm failed" instead.
    """
    if platform == "win32":
        from . import keyvault_native_cli

        if _probe_winkey_helper(home=home):
            return StepResult(_STEP_HARDWARE_HELPER, "done", "Windows TPM helper probe succeeded")
        if keyvault_native_cli.enable_winkey(home=home) != 0:
            return StepResult(
                _STEP_HARDWARE_HELPER,
                "manual",
                "enable-winkey failed; Windows TPM custody fails "
                "closed. Retry `hermes-mordred keyvault enable-winkey` (see errors above).",
            )
        return StepResult(_STEP_HARDWARE_HELPER, "ran", "Windows TPM helper probe succeeded")
    if platform == "darwin":
        if _probe_se_helper():
            return StepResult(_STEP_HARDWARE_HELPER, "done", "Secure Enclave helper installed")
        rc = _run_se_helper(home=home)
        if rc != 0:
            return StepResult(
                _STEP_HARDWARE_HELPER,
                "manual",
                "enable-se failed to build/install (see errors above); the keyvault will use the software "
                "fallback for now -- retry later with `hermes-mordred keyvault enable-se`",
            )
        return StepResult(_STEP_HARDWARE_HELPER, "ran", "Secure Enclave helper installed")

    if platform.startswith("linux"):
        if _probe_tpm_helper():
            return StepResult(_STEP_HARDWARE_HELPER, "done", "TPM 2.0 helper installed")
        rc = _run_tpm_helper(home=home)
        if rc != 0:
            return StepResult(
                _STEP_HARDWARE_HELPER,
                "manual",
                "enable-tpm failed to build/install (see errors above); Linux keyvault operations fail closed "
                "without a working TPM helper (there is no software fallback off macOS) -- retry later with "
                "`hermes-mordred keyvault enable-tpm`",
            )
        return StepResult(_STEP_HARDWARE_HELPER, "ran", "TPM 2.0 helper installed")

    return StepResult(
        _STEP_HARDWARE_HELPER,
        "unsupported",
        f"hardware keyvault requires macOS (Secure Enclave) or Linux (TPM 2.0); {platform!r} is not supported yet",
    )


# -----------------------------------------------------------------------------
# Step 5 -- the keyvault ceremony (`keyvault init`).
# -----------------------------------------------------------------------------

#: The keyvault probe's three-way outcome (distinct from the shared
#: :data:`StepAction` -- "initialised" maps to the step action "done" and
#: "absent" is the "needs a run" case, so this stays its own type).
KeyvaultProbeState = Literal["initialised", "absent", "blocked"]


def _probe_keyvault(*, home: Path) -> tuple[KeyvaultProbeState, str]:
    """Read-only keyvault state probe.

    Uses the same ``_storage`` calls and exception taxonomy as
    ``status_cli._keyvault_state``, plus the residual-ownership check
    ``_keyvault_init._refuse_if_initialised`` performs before starting a new
    ceremony -- so a meta.json with an empty ``keys`` map but leftover
    ownership records (audit-key journal, pending native-key journal) is
    reported ``"blocked"`` rather than misread as ``"absent"``, which would
    let a resume attempt clobber state ``keyvault reset`` needs to clean up
    first. Detail strings are written fresh here (not string-matched from
    ``status_cli``); the "blocked" wording mirrors ``_refuse_if_initialised``'s
    phrasing so the two commands never say two different things about the
    same problem.
    """
    from ..keyvault import _native_key_id, _storage

    root = _storage.resolve_keyvault_dir(home)
    try:
        with _storage.keyvault_read_lock(root) as profile_present:
            if not profile_present:
                return "absent", "not initialised"
            _storage.assert_keyvault_active(root)
            meta = _storage.load_meta(root)
    except _storage.KeyvaultResetInProgressError as exc:
        return (
            "blocked",
            f"Keyvault reset is incomplete ({exc}). "
            "Run `hermes-mordred keyvault reset` before starting a new ceremony.",
        )
    except _storage.KeyvaultCorruptError as exc:
        return "blocked", f"Keyvault meta.json is corrupt -- repair or remove it before init: {exc}"
    except OSError as exc:  # KeyvaultPermissionError (bad mode / not a regular file)
        return "blocked", f"keyvault unreadable -- {exc}"

    if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
        return (
            "blocked",
            "Keyvault has an incomplete native-key provisioning journal. "
            "Run `hermes-mordred keyvault reset` before starting a new ceremony.",
        )

    keys = meta.get("keys") or {}
    if keys:
        count = len(keys)
        return "initialised", f"{count} key" + ("" if count == 1 else "s")

    if _native_key_id.has_native_key_ownership_state(meta):
        return (
            "blocked",
            "Keyvault has residual native-key ownership metadata. "
            "Run `hermes-mordred keyvault reset` before starting a new ceremony.",
        )
    return "absent", "not initialised"


def _resolve_unattended_keys(*, options: SetupOptions, prompt_io: PromptIO) -> bool:
    """Resolve whether newly generated keyvault keys skip the per-use prompt.

    Precedence: an explicit ``--unattended-keys``/``--attended-keys`` flag
    wins outright; otherwise the ``MORDRED_SEKEY_UNATTENDED=1`` env var (the
    exact same parse as ``keyvault._seckey_errors._resolve_unattended``, reused
    directly here so the two can never drift); otherwise, interactively, ask
    (default False -- interactive per-use prompts are the safer default);
    non-interactively with neither a flag nor the env var set, resolve to
    False without prompting.
    """
    if options.unattended_keys is not None:
        return options.unattended_keys

    from ..keyvault._seckey_errors import _resolve_unattended

    if _resolve_unattended(None):
        return True

    if options.non_interactive:
        return False

    return prompt_io.ask_bool(
        "Allow background services (e.g. the extension Gateway) to use Mordred's device "
        "keys (keyvault and encryption vault) without a per-use Touch ID / passcode prompt?",
        default=False,
        description=(
            "Unattended keys let automated callers sign without interrupting you every "
            "time -- convenient, but any process that can reach the key can use it silently. "
            "Interactive keys (the default) prompt for Touch ID / your passcode on every use."
        ),
    )


def _run_keyvault_init(
    *,
    home: Path,
    prompt_io: PromptIO,
    store_seed_for_hd: bool,
    unattended: bool | None,
    flow_session: FlowSession | None = None,
) -> int:
    """Run the keyvault ceremony. Thin seam over ``_keyvault_init.init_keyvault``."""
    from ._keyvault_init import init_keyvault

    return init_keyvault(
        home=home,
        prompt_io=prompt_io,
        store_seed_for_hd=store_seed_for_hd,
        unattended=unattended,
        flow_session=flow_session,
    )


def _keyvault_preflight(*, home: Path) -> int | None:
    """Thin seam over ``_keyvault_init._preflight_or_refuse``'s fail-closed guards.

    Runs the exact same pre-ceremony checks ``init_keyvault`` itself runs first
    (re-init race, air-gap online check, stdout-not-a-tty) -- ``blackout_assert``
    and ``surface`` are passed as ``None`` so this uses the same production
    defaults ``init_keyvault`` would. Returns the refusal exit code (guidance
    already printed) if any guard would refuse, else ``None``.

    Called from :func:`_resolve_step_keyvault` *before* the unattended-keys
    question, purely so an online host (the common failure: the air-gap check
    refuses while a network link is still up) is reported ``"manual"``
    immediately rather than after asking the operator a question whose answer
    would then go nowhere. ``init_keyvault`` still re-runs this exact preflight
    internally when the ceremony actually starts -- that duplication is
    intentional defense in depth (see the module docstring's "Keyvault
    preflight gate" section), not redundant plumbing to remove.
    """
    from ._keyvault_init import _preflight_or_refuse

    return _preflight_or_refuse(home=home, blackout_assert=None, surface=None)


def _resolve_step_keyvault(
    *,
    home: Path,
    prompt_io: PromptIO,
    options: SetupOptions,
    flow_session: FlowSession | None = None,
) -> StepResult:
    state, detail = _probe_keyvault(home=home)
    if state == "initialised":
        return StepResult(_STEP_KEYVAULT, "done", detail)
    if state == "blocked":
        return StepResult(_STEP_KEYVAULT, "blocked", detail)

    # state == "absent". The ceremony needs a typed passphrase and an
    # offline-transcribed 24-word confirmation -- there is no way to complete
    # it without a real prompt, so --non-interactive stops here unconditionally
    # rather than attempting it and discovering that partway through (the
    # ceremony's own pre-checks, notably the air-gap probe, could otherwise
    # fail for an unrelated reason and get misreported as "failed" instead of
    # "manual").
    if options.non_interactive:
        return StepResult(
            _STEP_KEYVAULT,
            "manual",
            "keyvault init is an interactive ceremony (passphrase + 24-word seed transcription) "
            "that --non-interactive cannot complete; run `hermes-mordred keyvault init`",
        )

    # Gate the ceremony's own preflight BEFORE asking the unattended-keys
    # question: a refusal here (most commonly the fail-closed air-gap check
    # while the host is still online) means the ceremony cannot proceed no
    # matter how that question is answered, so there is no point asking it
    # first only to discover this afterward.
    if _keyvault_preflight(home=home) is not None:
        return StepResult(
            _STEP_KEYVAULT,
            "manual",
            "keyvault init preflight refused (see guidance above); commonly the host must be offline for "
            "the ceremony -- disconnect, re-run `hermes-mordred setup`, or run `hermes-mordred keyvault init` "
            "yourself",
        )

    try:
        resolved_unattended = _resolve_unattended_keys(options=options, prompt_io=prompt_io)
        if flow_session is not None:
            # The same answer governs the at-rest vault's device key, created later.
            flow_session.unattended = resolved_unattended
    except NonInteractiveAbort:
        # See _resolve_step_hermes's matching catch: PromptToolkitIO fails
        # closed on a non-TTY stdin even here, where --non-interactive was
        # already ruled out above.
        return StepResult(
            _STEP_KEYVAULT,
            "manual",
            "stdin is not a TTY; re-run interactively, or use --non-interactive",
        )
    rc = _run_keyvault_init(
        home=home,
        prompt_io=prompt_io,
        store_seed_for_hd=options.store_seed_for_hd,
        unattended=resolved_unattended,
        flow_session=flow_session,
    )
    if rc != 0:
        return StepResult(_STEP_KEYVAULT, "failed", "keyvault init failed (see errors above)")
    return StepResult(_STEP_KEYVAULT, "ran", "keyvault initialised")


# -----------------------------------------------------------------------------
# Shared tail for steps 6 and 7 (env / memory encryption).
# -----------------------------------------------------------------------------


def _run_gated_encryption_step(
    *,
    step: str,
    target: str,
    run: Callable[[], int],
    non_interactive: bool,
    non_interactive_detail: str,
    abort_detail: str,
    ran_detail: str,
) -> StepResult:
    """Shared tail of :func:`_resolve_step_env_encryption` and
    :func:`_resolve_step_memory_encryption`, once each has handled its own
    pre-checks (the env step's no-``.env``-file shortcut; the memory step's
    platform gate and its ``_env_target_ready`` gate) and decided there is
    real work left to attempt.

    ``target`` names the ``encryption enable <target>`` command for the two
    generic failure details below; ``run`` is the already-bound
    ``_run_env_encryption``/``_run_memory_encryption`` seam call.

    Both callers can reach interactive machinery that sits outside the
    ``PromptIO`` seam entirely -- a one-time vault recovery-passphrase prompt
    and/or an OS-level device-key unlock (Touch ID / passcode) -- so the
    non-interactive gate is checked unconditionally, before attempting the
    run, rather than discovering it partway through.
    """
    if non_interactive:
        return StepResult(step, "manual", non_interactive_detail)

    try:
        # Interactive from here on (the gate above already returned for
        # --non-interactive); this catch is for PromptToolkitIO's fail-closed
        # non-TTY guard.
        rc = run()
    except NonInteractiveAbort:
        return StepResult(step, "manual", abort_detail)
    except OSError as exc:
        # A disk-write failure (full disk, permission error, read-only
        # ~/.hermes) reports a clean "failed" result instead of an unhandled
        # traceback.
        return StepResult(step, "failed", f"encryption enable {target} failed: {exc}")
    if rc != 0:
        return StepResult(step, "failed", f"encryption enable {target} failed (see errors above)")
    return StepResult(step, "ran", ran_detail)


# -----------------------------------------------------------------------------
# Step 6 -- at-rest `.env` encryption (`encryption enable env`).
# -----------------------------------------------------------------------------


def _probe_env_encryption(*, home: Path, root: Path, platform: str) -> tuple[bool, str]:
    """Read-only: is ``.env`` encryption already fully effective -- or
    deliberately paused by the operator?

    On Linux ``TargetStatus.active`` is gated to macOS (the runtime decrypt
    shim is macOS-only), so an enrolled-and-injecting-nowhere-else target
    still counts as complete there; on macOS it must actually be active.

    Two completeness rules on top of :func:`encryption_cli.env_status` that
    ``env_status`` itself has no reason to make (it is a status *display*, not
    a step-completion gate):

    - **Operator opt-out**: ``encryption disable env`` is a deliberate,
      reversible pause -- it writes an opt-out marker and restores the
      plaintext ``.env`` (see :mod:`env_decrypt_cli`). An enrolled-and-opted-out
      target resolves ``complete=True`` here (action ``"done"``) so setup
      never reverses that explicit operator decision; without this, the
      run would fall through to :func:`_run_env_encryption`, which calls
      ``enable()`` and silently re-enables the very thing that was just
      turned off.
    - **Drift**: a stray plaintext ``.env`` on disk at rest while
      ``env_status`` still reports ``active`` means a host write slipped past
      the seal -- a secret is exposed at rest right now. That must read as
      *incomplete* so ``enable()``'s reseal branch runs, not as "already done"
      while a secret sits exposed.
    """
    st = env_status(root=root, home=home, platform=platform)
    if st.configured and _env_optout_marker_path(home).exists():
        return True, (
            "paused by operator (`encryption disable env`); re-enable with `hermes-mordred encryption enable env`"
        )
    complete = st.configured and not st.drift and (platform != "darwin" or st.active)
    return complete, st.detail


def _run_env_encryption(
    *,
    home: Path,
    root: Path,
    platform: str,
    prompt_io: PromptIO,
    flow_session: FlowSession | None = None,
) -> int:
    """Enroll+seal ``.env``. Thin seam over ``env_decrypt_cli.enable``.

    Deliberately does not expose ``--force-runtime-unverified``: that flag
    seals a file the runtime cannot prove it can decrypt, which is not
    something an automated orchestrator should choose on the operator's
    behalf.
    """
    from . import env_decrypt_cli

    return env_decrypt_cli.enable(
        home=home, root=root, platform=platform, prompt_io=prompt_io, flow_session=flow_session
    )


def _resolve_step_env_encryption(
    *,
    home: Path,
    root: Path,
    platform: str,
    prompt_io: PromptIO,
    options: SetupOptions,
    flow_session: FlowSession | None = None,
) -> StepResult:
    complete, detail = _probe_env_encryption(home=home, root=root, platform=platform)
    if complete:
        return StepResult(_STEP_ENV_ENCRYPTION, "done", detail)

    if not (home / ".env").is_file():
        # Only the genuinely-nothing-to-do case takes this shortcut: not
        # enrolled AND not opted-out. The probe above already ruled out
        # enrolled-and-sealed (already "done") and enrolled-and-opted-out
        # (also "done", paused); what's left here besides "never enrolled" is
        # an opted-out marker with no plaintext to show for it (e.g. a failed
        # restore) -- that is real, incomplete state env_decrypt_cli.enable()
        # must be given a chance to handle, not "nothing to encrypt".
        st = env_status(root=root, home=home, platform=platform)
        if not st.configured and not _env_optout_marker_path(home).exists():
            # env_decrypt_cli.enable() would just report "no .env ... nothing
            # to protect" (rc=1) here. A fresh system genuinely has nothing to
            # encrypt yet; that is a benign outcome, not a failure.
            return StepResult(
                _STEP_ENV_ENCRYPTION,
                "ran",
                "no .env file yet; nothing to encrypt (create one, then re-run `hermes-mordred encryption enable env`)",
            )

    # enable() only prompts (for a one-time vault recovery passphrase) if no
    # vault exists yet; the OS-level device-key unlock (Touch ID / passcode)
    # for add_and_verify() the enrollment sits outside the PromptIO seam
    # entirely. See _run_gated_encryption_step for the shared gate/dispatch
    # logic (mirrors the keyvault step's hardcoded non-interactive gate, see
    # _resolve_step_keyvault).
    def run() -> int:
        if flow_session is not None and flow_session.unattended is None and not _vault_present(root):
            # The keyvault step did not ask (it was already done): resolve the
            # unattended-keys policy now, before this step creates the vault's key.
            flow_session.unattended = _resolve_unattended_keys(options=options, prompt_io=prompt_io)
        return _run_env_encryption(
            home=home, root=root, platform=platform, prompt_io=prompt_io, flow_session=flow_session
        )

    return _run_gated_encryption_step(
        step=_STEP_ENV_ENCRYPTION,
        target="env",
        run=run,
        non_interactive=options.non_interactive,
        non_interactive_detail=(
            "`.env` encryption may need interactive confirmation (a vault recovery passphrase and/or an "
            "OS device-key unlock) that --non-interactive cannot supply; run `hermes-mordred encryption enable env`"
        ),
        abort_detail=(
            "creating the at-rest vault needs a one-time recovery-passphrase prompt, and stdin "
            "is not a TTY; run `hermes-mordred encryption enable env` interactively"
        ),
        ran_detail="`.env` is now vault-managed",
    )


# -----------------------------------------------------------------------------
# Step 7 -- at-rest agent-memory encryption (`encryption enable memory`).
# -----------------------------------------------------------------------------


def _probe_memory_encryption(*, home: Path, platform: str) -> tuple[bool, str]:
    """Read-only: is agent-memory encryption armed -- or deliberately paused?

    Reads the two markers and the first bytes of the memory files; it opens no
    vault and runs no probe, so it costs nothing on a profile that never
    enabled the target. The same two completeness rules as the env step:

    - **Operator opt-out**: ``encryption disable memory`` writes an opt-out
      marker; that is a deliberate, reversible decision setup must not reverse.
    - **Drift**: a plaintext memory file on disk while the hook is armed means
      something wrote outside the hook. That must read as *incomplete* so
      ``enable()`` re-runs its migration, not as "already done" while a memory
      sits readable at rest.

    Platform is not part of completeness: an armed marker stays armed across a
    reboot into another OS. :func:`_resolve_step_memory_encryption` is where the
    macOS-only runtime is accounted for.
    """
    if memory_optout_marker_path(home).exists():
        return True, (
            "paused by operator (`encryption disable memory`); re-enable with `hermes-mordred encryption enable memory`"
        )
    if not memory_marker_path(home).exists():
        return False, "not enabled"
    if _unsealed_memory_files(home):
        return False, "plaintext memory file on disk while enabled"
    return True, "enabled" if platform == "darwin" else "enabled; the sealing runtime is macOS-only"


def _run_memory_encryption(
    *,
    home: Path,
    root: Path,
    platform: str,
    prompt_io: PromptIO,
    flow_session: FlowSession | None = None,
) -> int:
    """Arm memory encryption. Thin seam over ``memory_cli.enable``.

    Like the env step, it deliberately does not expose
    ``--force-runtime-unverified``: sealing files a runtime cannot prove it can
    read back is not a call an orchestrator makes for the operator.
    """
    from . import memory_cli

    return memory_cli.enable(home=home, root=root, platform=platform, prompt_io=prompt_io, flow_session=flow_session)


def _resolve_step_memory_encryption(
    *,
    home: Path,
    root: Path,
    platform: str,
    prompt_io: PromptIO,
    options: SetupOptions,
    flow_session: FlowSession | None = None,
) -> StepResult:
    complete, detail = _probe_memory_encryption(home=home, platform=platform)
    if complete:
        return StepResult(_STEP_MEMORY_ENCRYPTION, "done", detail)

    if platform != "darwin":
        # `enable memory` refuses off macOS (the hook's shims are macOS-only), so
        # attempting it would report a "failure" that is really just the OS. A
        # skip keeps a Linux run clean instead of stopping it, which
        # "unsupported" would do -- this is the last step, not a prerequisite.
        return StepResult(
            _STEP_MEMORY_ENCRYPTION,
            "skipped",
            f"macOS only — the memory sealing runtime is not available on {platform}",
        )

    # Checked on the *state* (env enrolled and not opted out; see
    # `encryption_cli._env_target_ready`, shared with `memory_cli`'s own
    # gate) rather than on the env step's own result: that step reports
    # "ran" for a fresh system with no `.env` to protect at all, which is a
    # success for env and still not a usable carrier for memory.
    if not _env_target_ready(home=home, root=root):
        return StepResult(
            _STEP_MEMORY_ENCRYPTION,
            "manual",
            "requires the env target (`hermes-mordred encryption enable env`) — the memory key reaches the "
            "runtime through the `.env` injection shim",
        )

    # Same reasoning as the env step: enable() can reach an OS-level
    # device-key unlock (Touch ID / passcode) to enroll the key, and that
    # dialog sits outside the PromptIO seam entirely. See
    # _run_gated_encryption_step for the shared gate/dispatch logic.
    return _run_gated_encryption_step(
        step=_STEP_MEMORY_ENCRYPTION,
        target="memory",
        run=lambda: _run_memory_encryption(
            home=home, root=root, platform=platform, prompt_io=prompt_io, flow_session=flow_session
        ),
        non_interactive=options.non_interactive,
        non_interactive_detail=(
            "agent-memory encryption may need interactive confirmation (a vault recovery passphrase and/or an "
            "OS device-key unlock) that --non-interactive cannot supply; run "
            "`hermes-mordred encryption enable memory`"
        ),
        abort_detail=(
            "creating the at-rest vault needs a one-time recovery-passphrase prompt, and stdin is not a TTY; "
            "run `hermes-mordred encryption enable memory` interactively"
        ),
        ran_detail="agent memories are now sealed at rest",
    )


# -----------------------------------------------------------------------------
# Orchestrator.
# -----------------------------------------------------------------------------


def run_setup(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    setup_runner: SetupRunner,
    options: SetupOptions,
) -> int:
    """Run every setup step in order, resuming from whatever is already done.

    Returns 0 iff every step's action is ``"done"``/``"ran"``/``"skipped"``;
    1 if the run stopped early (see :func:`_stops_run`) or finished with any
    step left ``"manual"``. Always prints :func:`render_report`; only prints
    the final ``status`` dashboard when no step stopped the run early (a
    partial run has nothing coherent to summarize yet).

    One :class:`FlowSession` spans the run, so a passphrase is chosen (and
    confirmed) at most once, the vault is unlocked at most once, and one
    unattended-keys answer covers every device key the run creates (see the
    module docstring). It is closed before this function returns.
    """
    with FlowSession(unattended=options.unattended_keys) as session:
        return _run_steps(
            home=home,
            root=root,
            platform=platform,
            workspace=workspace,
            prompt_io=prompt_io,
            policy_writer=policy_writer,
            setup_runner=setup_runner,
            options=options,
            session=session,
        )


def _run_steps(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    setup_runner: SetupRunner,
    options: SetupOptions,
    session: FlowSession,
) -> int:
    """Body of :func:`run_setup`, with the run's shared passphrase holder."""
    results: list[StepResult] = []
    steps: tuple[Callable[[], StepResult], ...] = (
        lambda: _resolve_step_hermes(home=home, prompt_io=prompt_io, setup_runner=setup_runner, options=options),
        lambda: _resolve_step_configure(
            prompt_io=prompt_io, policy_writer=policy_writer, setup_runner=setup_runner, options=options
        ),
        lambda: _resolve_step_network(home=home, prompt_io=prompt_io, policy_writer=policy_writer),
        lambda: _resolve_step_hardware_helper(home=home, platform=platform),
        lambda: _resolve_step_keyvault(home=home, prompt_io=prompt_io, options=options, flow_session=session),
        lambda: _resolve_step_env_encryption(
            home=home, root=root, platform=platform, prompt_io=prompt_io, options=options, flow_session=session
        ),
        lambda: _resolve_step_memory_encryption(
            home=home, root=root, platform=platform, prompt_io=prompt_io, options=options, flow_session=session
        ),
    )

    stopped = False
    for resolve_step in steps:
        result = resolve_step()
        results.append(result)
        if _stops_run(result):
            stopped = True
            break

    print(render_report(results))

    if not stopped:
        from . import status_cli

        status_cli.status(home=home, root=root, platform=platform, workspace=workspace)

    if stopped or not all(r.action in _SUCCESS_ACTIONS for r in results):
        return 1
    return 0


# -----------------------------------------------------------------------------
# CLI adapter wired in cli.py
# -----------------------------------------------------------------------------


def cli_setup(args: argparse.Namespace) -> int:
    """argparse handler for ``setup`` -- resolves production defaults.

    Mirrors ``status_cli.cli_status``'s default resolution
    (``_hermes_home()``, ``resolve_root(None)``, ``sys.platform``,
    ``_default_workspace_paths()``) plus a fresh ``PolicyWriter()`` /
    ``SubprocessSetupRunner()`` and the production ``PromptIO``: the real
    ``prompt_toolkit``-backed implementation in interactive mode (via
    ``_defaults.resolve_prompt_io``, the same resolver ``keyvault init`` uses),
    or ``_RefusingPromptIO`` under ``--non-interactive`` so any step that still
    needs a prompt aborts cleanly instead of blocking.
    """
    non_interactive = bool(getattr(args, "non_interactive", False))
    options = SetupOptions(
        non_interactive=non_interactive,
        with_hermes_setup=bool(getattr(args, "with_hermes_setup", False)),
        skip_hermes_setup=bool(getattr(args, "skip_hermes_setup", False)),
        unattended_keys=getattr(args, "unattended_keys", None),
        store_seed_for_hd=bool(getattr(args, "store_seed_for_hd", True)),
    )
    prompt_io: PromptIO = _RefusingPromptIO() if non_interactive else resolve_prompt_io(None)
    return run_setup(
        home=_hermes_home(),
        root=resolve_root(None),
        platform=sys.platform,
        workspace=_default_workspace_paths(),
        prompt_io=prompt_io,
        policy_writer=PolicyWriter(),
        setup_runner=SubprocessSetupRunner(),
        options=options,
    )
