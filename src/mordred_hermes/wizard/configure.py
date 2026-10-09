"""``hermes mordred configure`` -- interactive Mordred setup.

Two-step flow:

1. Delegate first-run Hermes setup via ``subprocess.run(["hermes", "setup", ...])``
   (Hermes uses its own curses TUI -- ``hermes_cli/main.py:8704``). This step
   is opt-in: it is skipped by default (2026-07-16) so a bare ``configure``
   touches only the Mordred policy, and ``--with-hermes-setup`` runs it before
   step 2. The old ``--skip-hermes-setup`` flag is now a deprecated no-op,
   kept only so existing invocations keep parsing.
2. Collect Mordred-specific prompts (policy mode, cloud allowlist, local LLM
   endpoint, agent harness) via :class:`PromptIO`.
3. Persist via :class:`PolicyWriter` (writes ``~/.hermes/mordred/policy.json``
   and the ``plugins.mordred_privacy_check`` / ``plugins.mordred_llm_guard``
   sections of ``~/.hermes/config.yaml``).

Both side effects -- the Hermes setup spawn AND the prompt collection -- go
through Protocol-typed seams (:class:`SetupRunner`, :class:`PromptIO`) so
tests inject scripted doubles. Production impls (:class:`SubprocessSetupRunner`,
:class:`PromptToolkitIO`) wrap subprocess and prompt_toolkit respectively.

The shared :class:`PromptIO` Protocol and the inline ``prompt_toolkit`` picker
engine ``PromptToolkitIO`` calls live in :mod:`mordred_hermes.wizard._prompt_io`;
they are re-exported here so existing ``from .configure import PromptIO`` /
``PromptToolkitIO`` callers keep working unchanged.

Network-privacy setup (Tor / VPN / clearnet, Mullvad) is NOT part of first-run
configure. It is opt-in via the dedicated, re-runnable
``hermes-mordred network init`` command (see :mod:`mordred_hermes.wizard.network_cli`).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol

from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

from .._policy_types import POLICY_MODES
from . import _term
from ._prompt_io import (
    _CHOICE_NAV_HINT,
    _PROMPT_TOOLKIT_REQUIRED,
    _build_choice_app,
    _build_multichoice_app,
    _choice_values,
    _echo_selection,
    _emit_prompt_help,
    _parse_bool_answer,
)
from ._prompt_io import (
    NonInteractiveAbort as NonInteractiveAbort,
)
from ._prompt_io import (
    PromptIO as PromptIO,
)
from ._prompt_io import (
    _RefusingPromptIO as _RefusingPromptIO,
)
from .policy_writer import PolicySnapshot, PolicyWriter, _preserve_provider_overrides, _windows

#: Cloud providers offered as checkbox choices for the allowlist prompt.
#: Sourced from the network flagger's canonical registry so the wizard and the
#: transport-compat layer never drift. Localhost-only providers
#: (``mordred-local``) are excluded -- a local endpoint is never a *cloud*
#: allowlist entry.
_SELECTABLE_CLOUD_PROVIDERS: Final[tuple[str, ...]] = tuple(
    name for name, entry in KNOWN_PROVIDERS.items() if not entry.localhost_only
)

#: One-line description shown inline next to each policy mode in the
#: ``configure`` radio dialog (UX request 2026-06-15: the bare strict/lenient/off
#: labels gave no hint of what each mode does). Copy mirrors the policy-mode
#: table in ``docs/user/QUICKSTART.md`` so the TUI and the docs never
#: drift. A mode missing here simply renders without a description.
_POLICY_MODE_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "strict": "Blocks cloud LLMs, disables IPv6, refuses known AI harnesses",
    "lenient": "Guards active but stay out of your way (recommended)",
    "off": "Disables all guards entirely",
}

#: One-line description shown inline next to each cloud-attempt action in the
#: ``configure`` radio dialog (UX request 2026-06-15, mirroring the policy-mode
#: descriptions above). ``prompt-once`` now has live enforcement in
#: ``llm_guard.enforce._resolve_cloud_attempt``: under strict mode a
#: non-allowlisted cloud attempt asks the operator once per provider at an
#: interactive terminal, failing closed to a block when no terminal is present
#: (the headless / harness / CI case). Mirrors the Q6 note in
#: ``docs/user/USAGE.md`` so the TUI and the docs never drift.
_CLOUD_ATTEMPT_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "always-block": "Silently refuse the cloud call every time (recommended)",
    "prompt-once": "Ask once per provider at a terminal; blocks if non-interactive",
}

#: One-line description shown inline next to each agent-harness choice in the
#: ``configure`` radio dialog (UX request 2026-06-24: the bare ``acp-claude`` /
#: ``acp-cline`` labels are protocol identifiers with no hint that they mean
#: "driven by an editor/IDE over ACP" -- no user could tell them apart from the
#: terminal ``claude-cli``). The copy makes the terminal-vs-editor distinction
#: explicit so the user can pick the option matching their real setup. Keys
#: mirror the ``choices`` tuple below and the regex allowlist in
#: ``harness_detect._HARNESS_PATTERNS``; a choice missing here renders without a
#: description.
_HARNESS_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "none": "Not driven by an external AI harness (recommended)",
    "codex": "OpenAI Codex CLI (terminal)",
    "claude-cli": "Claude Code in your terminal (the `claude` command)",
    "cursor": "Cursor editor",
    "acp-claude": "Claude driven by an editor/IDE over ACP (e.g. Zed)",
    "acp-cline": "Cline driven by an editor/IDE over ACP (e.g. Zed)",
}

#: Help text shown above the cloud-LLM yes/no prompt. The bare question gave no
#: hint about the privacy trade-off or what answering yes leads to (UX request
#: 2026-06-15, sibling of the policy-mode inline descriptions above). It replaces
#: the old jargon suffix "(passes through provider override)", which named an
#: implementation detail instead of the choice the user is actually making.
_CLOUD_LLM_PROMPT_DESCRIPTION: Final[str] = (
    "Cloud providers (e.g. OpenAI, Anthropic) run models on their own servers, so "
    "your prompts leave this machine. Choose No to stay fully local and private, or "
    "Yes to also permit cloud models — you'll pick which providers at the next prompt."
)

#: Shown once after the recommended policy is selected. The remaining answers
#: are persisted so a later switch to strict already has explicit settings, but
#: they do not block ordinary use while lenient remains active. Calling this
#: out before Q2 keeps users from treating every following prompt as a required
#: up-front decision.
_LENIENT_MODE_NOTE: Final[str] = (
    "Lenient mode selected. The remaining settings only affect strict mode, "
    "so you can press Enter to accept the defaults if unsure."
)


# -----------------------------------------------------------------------------
# Protocols -- production wraps subprocess / prompt_toolkit, tests script.
# -----------------------------------------------------------------------------


class SetupRunner(Protocol):
    """Spawn ``hermes setup``. Return its exit code (0 = success)."""

    def run(self, *, non_interactive: bool) -> int: ...


# -----------------------------------------------------------------------------
# Production implementations.
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SubprocessSetupRunner:
    """Default :class:`SetupRunner` -- shells out to ``hermes setup``.

    Returns the child process exit code on success. Returns ``1`` (with
    a warning printed to the user) if the ``hermes`` binary is missing
    from PATH so that callers do not crash with an unhandled
    :class:`FileNotFoundError` -- the Mordred prompt sequence still runs
    and the user gets a clean exit code rather than a stack trace.
    """

    def run(self, *, non_interactive: bool) -> int:
        cmd = ["hermes", "setup"]
        if non_interactive:
            cmd.append("--non-interactive")
        try:
            completed = subprocess.run(cmd, check=False)
        except FileNotFoundError:
            _term.emit_warn(
                "`hermes` executable not found on PATH; skipping `hermes setup` step. "
                "Install hermes and make sure it's on PATH, then re-run `hermes-mordred configure` "
                "to pick up first-run Hermes setup."
            )
            return 1
        return completed.returncode


# -----------------------------------------------------------------------------
# Interactive PromptIO implementation (prompt_toolkit). The shared PromptIO
# Protocol and the picker builders this calls live in :mod:`._prompt_io`; the
# impl is kept here so tests can monkeypatch the builders (``_build_choice_app``
# / ``_build_multichoice_app``) and ``PromptToolkitIO`` itself through the
# ``configure`` module namespace its methods resolve them from.
# -----------------------------------------------------------------------------


def _require_tty(label: str) -> None:
    """Refuse to prompt when stdin is not a terminal (fail closed).

    prompt_toolkit needs a real terminal on stdin; without one its asyncio
    event loop crashes deep in ``_add_reader`` with ``OSError: [Errno 22]``
    (observed: ``hermes-mordred vault status </dev/null``, 2026-07-09).
    Raising :class:`NonInteractiveAbort` instead routes piped / cron
    invocations through the same clean ``error:`` + exit-2 path
    ``cli.dispatch`` already implements for ``--non-interactive``.
    """
    if not sys.stdin.isatty():
        raise NonInteractiveAbort(f"stdin is not a terminal but prompt required: {label!r}")


class PromptToolkitIO:
    """Default :class:`PromptIO` -- thin wrapper around ``prompt_toolkit``.

    Lazy-imports prompt_toolkit so that the test impl never has to install
    it. Single- and multi-select prompts use the custom dialog builders
    (:func:`_build_choice_app` / :func:`_build_multichoice_app`) instead of
    prompt_toolkit's ``radiolist_dialog`` / ``checkboxlist_dialog`` shortcuts,
    gaining keyboard-confirm affordances and dropping the blue backdrop while
    still rendering well in SSH / Docker / TTY-without-tput environments.

    Every prompt method fail-closes via :func:`_require_tty` when stdin is
    not a terminal.
    """

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        _require_tty(label)
        app = _build_choice_app(
            title=label,
            values=_choice_values(choices, descriptions),
            default=default,
            hint=_CHOICE_NAV_HINT,
        )
        result: str | None = app.run()
        chosen = result if result is not None else default
        # The picker erased itself on exit; echo the resolved choice so the
        # transcript records what was picked (see :func:`_echo_selection`).
        _echo_selection(label, chosen)
        return chosen

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        _require_tty(label)
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        suffix = f" [{default}]" if default else ""
        # An optional help line prints above the question (mirrors ``ask_bool`` /
        # ``ask_choice``) so the label stays short while still explaining the
        # setting. It is emitted separately rather than folded into the prompt()
        # message: a multi-line prompt is repainted in full on accept, which
        # doubled the help text in the scrollback (see :func:`_emit_prompt_help`).
        if description:
            _emit_prompt_help(description)
        answer = prompt(f"{label}{suffix}: ")
        return answer.strip() or default

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        _require_tty(label)
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        suffix = "[Y/n]" if default else "[y/N]"
        # Optional help line above the [y/N] question, printed separately so the
        # prompt stays single-line (see :func:`_emit_prompt_help`).
        if description:
            _emit_prompt_help(description)
        return _parse_bool_answer(prompt(f"{label} {suffix}: "), default=default)

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        """Inline multi-select picker.

        Returns the chosen subset (empty tuple if the user selects nothing).
        Arrows move the highlight, Space toggles the highlighted row, and Enter
        confirms the whole set (see :func:`_build_list_app`). Replaces the old
        free-text comma-separated entry so users pick from known providers
        instead of guessing names (UX request 2026-06-14).
        """
        _require_tty(label)
        app = _build_multichoice_app(
            title=label,
            values=_choice_values(choices, None),
            default_values=default,
        )
        result: list[str] | None = app.run()
        chosen = tuple(result) if result is not None else ()
        _echo_selection(label, ", ".join(chosen) if chosen else "(none)")
        return chosen

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        """Read a secret with shell-history-safe echoing.

        ``is_password=True`` masks the input. Empty input → ``default`` so
        a user who already has the secret set elsewhere can decline to
        re-enter it. An optional ``description`` prints as a help line above
        the prompt (mirrors ``ask_text`` / ``ask_bool``); ``is_password`` masks
        only the typed secret, never the help text or the label.
        """
        _require_tty(label)
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        # Help line printed separately so the masked prompt stays single-line
        # (see :func:`_emit_prompt_help`).
        if description:
            _emit_prompt_help(description)
        answer = prompt(f"{label}: ", is_password=True)
        return answer.strip() or default


# -----------------------------------------------------------------------------
# Mordred-specific prompt sequence + run().
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfigureResult:
    """Resolved answers from the prompt sequence."""

    snapshot: PolicySnapshot


def collect_answers(prompt_io: PromptIO) -> ConfigureResult:
    """Run the Mordred prompt sequence.

    Order matters -- snapshot tests assert on the label / default sequence.
    Network-privacy prompts are NOT collected here; run
    ``hermes-mordred network init`` to set up Tor / VPN / Mullvad on demand.
    """
    policy = prompt_io.ask_choice(
        label="Mordred policy mode",
        choices=POLICY_MODES,
        default="lenient",
        descriptions=_POLICY_MODE_DESCRIPTIONS,
    )
    if policy == "lenient":
        _emit_prompt_help(_LENIENT_MODE_NOTE)
    allow_cloud_llm = prompt_io.ask_bool(
        label="Allow cloud LLM providers?",
        default=False,
        description=_CLOUD_LLM_PROMPT_DESCRIPTION,
    )
    # Only ask *which* providers to permit when cloud is actually allowed. An
    # allowlist is meaningless under "no cloud", and it has no effect at all
    # outside strict mode (see ``llm_guard.enforce``), so skipping it keeps the
    # common local-only flow short (UX request 2026-06-14). The choices come
    # from a checkbox so users pick known provider ids instead of typing them.
    if allow_cloud_llm:
        cloud_provider_allowlist = prompt_io.ask_multi(
            label="Cloud provider allowlist (select which providers to permit)",
            choices=_SELECTABLE_CLOUD_PROVIDERS,
            default=(),
        )
    else:
        cloud_provider_allowlist = ()

    local_llm_endpoint = prompt_io.ask_text(
        label="Local LLM endpoint URL",
        default="http://localhost:1234/v1",
    )
    local_llm_model_id = prompt_io.ask_text(
        label="Local LLM model id",
        default="",
    )
    cloud_attempt_action_raw = prompt_io.ask_choice(
        label="On cloud LLM attempt under strict mode",
        choices=("always-block", "prompt-once"),
        default="always-block",
        descriptions=_CLOUD_ATTEMPT_DESCRIPTIONS,
    )
    cloud_attempt_action = _coerce_cloud_attempt_action(cloud_attempt_action_raw)

    # The declared harness controls strict-mode abort behaviour in
    # ``mordred_llm_guard.harness_detect``. ``"none"`` is the safe default --
    # it doesn't match any harness pattern so existing users don't lose the
    # session. The known choices mirror the regex allowlist in
    # ``harness_detect._HARNESS_PATTERNS``.
    harness_primary = prompt_io.ask_choice(
        label="Agent harness (strict mode refuses if a known harness is detected)",
        choices=("none", "codex", "claude-cli", "cursor", "acp-claude", "acp-cline"),
        default="none",
        descriptions=_HARNESS_DESCRIPTIONS,
    )

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=cloud_provider_allowlist,
        local_llm_endpoint=local_llm_endpoint,
        local_llm_model_id=local_llm_model_id,
        cloud_attempt_action=cloud_attempt_action,
        harness_primary=harness_primary,
        # strict → disable IPv6 by default (mirrors the network settings
        # resolver: strict → True, lenient/off → False).
        disable_ipv6=(policy == "strict"),
    )
    return ConfigureResult(snapshot=snapshot)


def _coerce_cloud_attempt_action(raw: str) -> Literal["always-block", "prompt-once"]:
    """Narrow ``ask_choice``'s ``str`` return to the snapshot Literal.

    The prompt only offers two choices so this never raises in production;
    the explicit check protects against test doubles that script invalid
    answers and satisfies mypy --strict at the construction site.
    """
    if raw == "always-block":
        return "always-block"
    if raw == "prompt-once":
        return "prompt-once"
    raise ValueError(f"invalid cloud_attempt_action: {raw!r}")


def run(
    *,
    setup_runner: SetupRunner,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    non_interactive: bool = False,
    with_hermes_setup: bool = False,
) -> ConfigureResult:
    """Top-level configure entry point.

    Args:
        setup_runner: Spawns ``hermes setup``. Production = :class:`SubprocessSetupRunner`.
        prompt_io: Collects Mordred answers. Tests inject a scripted double.
        policy_writer: Persists the resolved snapshot (policy.json +
            ``plugins.mordred_privacy_check`` / ``plugins.mordred_llm_guard``).
            The ``plugins.mordred_network`` section is intentionally left alone
            -- it is owned by ``hermes-mordred network init``.
        non_interactive: Forwarded to :class:`SetupRunner`. Mordred prompts
            still run -- pass a :class:`_RefusingPromptIO` to abort on any
            prompt requirement.
        with_hermes_setup: Opt-in to spawning ``hermes setup`` before the
            Mordred prompts. Defaults to ``False`` (skip) so a bare
            ``configure`` touches only the Mordred policy.

    Returns:
        :class:`ConfigureResult` holding the resolved :class:`PolicySnapshot`.
    """
    if with_hermes_setup:
        rc = setup_runner.run(non_interactive=non_interactive)
        if rc != 0:
            _term.emit_warn(f"`hermes setup` exited with code {rc}; continuing with Mordred prompts anyway")

    result = collect_answers(prompt_io)
    # ``provider_overrides`` is an operator-managed policy.json extension,
    # not a wizard prompt. Carry it into the resolved snapshot before writing
    # so interactive configure cannot erase it (or turn an invalid value into
    # a permissive empty object).
    result = ConfigureResult(
        snapshot=_preserve_provider_overrides(
            result.snapshot,
            policy_writer.policy_json_path,
        )
    )
    policy_writer.write(result.snapshot)
    return result


def _render_configure_summary(snapshot: PolicySnapshot) -> str:
    """A structured recap printed after a successful ``configure``.

    Shown once all prompts complete (so it survives the full-screen
    dialog prompts, which clear the terminal). Echoes the
    resolved choices and points the user at the on-demand network-privacy
    command, which first-run setup deliberately does not cover.
    """
    cloud = "yes" if snapshot.allow_cloud_llm else "no"
    return "\n".join(
        [
            "",
            "Mordred configured:",
            f"  policy mode       : {snapshot.policy}",
            f"  cloud LLM allowed : {cloud}",
            f"  agent harness     : {snapshot.harness_primary}",
            "",
            "Next: run `hermes-mordred network init` to set up network privacy (Tor / VPN / clearnet).",
        ]
    )


# -----------------------------------------------------------------------------
# Non-interactive (flag-driven) configure — mirrors network init's
# ``network_answers_from_args``: unspecified flags fall back to the existing
# on-disk settings, then to the same defaults the prompts use, so a re-run
# never clobbers prior answers (UX review 2026-06-11 Phase 4).
# -----------------------------------------------------------------------------


def _read_existing_policy_inputs(policy_writer: PolicyWriter) -> dict[str, object]:
    """Best-effort read of the current settings for non-interactive seeding.

    policy.json carries every snapshot field except ``harness_primary``,
    which lives in config.yaml under ``plugins.mordred_llm_guard`` (the
    same split the writers maintain). Any read/parse error collapses to
    ``{}`` — the flags then fall back to the prompt defaults.
    """
    import json

    if _windows():
        from .._config_io import read_canonical_snapshot
        from .._policy_io import policy_mapping_from_snapshot
        from .._yaml_io import yaml_mapping_from_snapshot
        from .policy_writer import _canonical_paths

        pair = read_canonical_snapshot(
            _canonical_paths(
                policy_writer.config_path,
                policy_writer.policy_json_path,
                policy_writer.mordred_dir,
            )
        )
        checked = policy_mapping_from_snapshot(pair)
        root = yaml_mapping_from_snapshot(pair)
        plugins = root.get("plugins")
        guard = plugins.get("mordred_llm_guard") if isinstance(plugins, dict) else None
        if isinstance(guard, dict) and isinstance(guard.get("harness_primary"), str):
            checked["harness_primary"] = guard["harness_primary"]
        return checked

    existing: dict[str, object] = {}
    try:
        body = json.loads(policy_writer.policy_json_path.read_text(encoding="utf-8"))
        if isinstance(body, dict):
            existing.update(body)
    except (OSError, ValueError):
        pass

    from ruamel.yaml.error import YAMLError

    from .._yaml_io import load_plugin_section

    # ValueError joins the shared helper's default catch set — this site has
    # historically swallowed it, and any unreadable config falls back to defaults.
    guard = load_plugin_section(policy_writer.config_path, "mordred_llm_guard", catch=(OSError, ValueError, YAMLError))
    if guard is not None and isinstance(guard.get("harness_primary"), str):
        existing["harness_primary"] = guard["harness_primary"]
    return existing


def snapshot_from_args(
    args: argparse.Namespace,
    *,
    existing: Mapping[str, Any] | None = None,
) -> ConfigureResult:
    """Build a :class:`PolicySnapshot` from CLI flags (no prompts).

    Precedence per field: explicit flag > existing on-disk value > the
    default the interactive prompt would offer. ``disable_ipv6`` mirrors
    :func:`collect_answers`: derived from the resolved policy mode.
    """
    existing = existing or {}

    def _seeded(flag: str, existing_key: str, fallback: object) -> object:
        value = getattr(args, flag, None)
        if value is not None:
            return value
        value = existing.get(existing_key)
        return value if value is not None else fallback

    # Existing values come from a hand-editable policy.json — sanitize the
    # closed-set fields back to their defaults instead of crashing the
    # non-interactive path on a corrupt or downgraded file (review 2026-06-12).
    policy = str(_seeded("policy", "policy", "lenient"))
    if policy not in POLICY_MODES:
        policy = "lenient"
    # M2 (security review 2026-06-11): only a real bool may enable —
    # ``bool(...)`` truthy-coerced a hand-edited ``"allow_cloud_llm": "false"``
    # into a written ``allow_cloud_llm: true``.
    raw_allow_cloud = _seeded("allow_cloud_llm", "allow_cloud_llm", False)
    allow_cloud_llm = raw_allow_cloud if isinstance(raw_allow_cloud, bool) else False
    raw_allowlist = _seeded("cloud_allowlist", "cloud_provider_allowlist", ())
    if isinstance(raw_allowlist, str):
        allowlist = tuple(p.strip() for p in raw_allowlist.split(",") if p.strip())
    elif isinstance(raw_allowlist, (list, tuple)):
        allowlist = tuple(str(p) for p in raw_allowlist)
    else:
        allowlist = ()
    raw_action = str(_seeded("cloud_attempt_action", "cloud_attempt_action", "always-block"))
    if raw_action not in ("always-block", "prompt-once"):
        raw_action = "always-block"
    cloud_attempt_action = _coerce_cloud_attempt_action(raw_action)
    provider_overrides = existing.get("provider_overrides", {})

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=allowlist,
        local_llm_endpoint=str(_seeded("local_llm_endpoint", "local_llm_endpoint", "http://localhost:1234/v1")),
        local_llm_model_id=str(_seeded("local_llm_model_id", "local_llm_model_id", "")),
        cloud_attempt_action=cloud_attempt_action,
        harness_primary=str(_seeded("harness", "harness_primary", "none")),
        disable_ipv6=(policy == "strict"),
        # Do not validate/coerce this operator-managed extension here.
        # Malformed values must remain malformed so strict + Tor continues to
        # fail closed in network.hooks._read_provider_overrides.
        provider_overrides=provider_overrides,
    )
    return ConfigureResult(snapshot=snapshot)


def cli_handler(args: argparse.Namespace) -> int:
    """Adapter from argparse Namespace to :func:`run`. Wired in cli.py.

    Production behavior:
    - ``--non-interactive``: flag-driven, no prompts — answers come from the
      CLI flags, seeded from the existing policy.json / config.yaml (so a
      bare re-run keeps prior settings).
    - Otherwise: real :class:`SubprocessSetupRunner` + :class:`PromptToolkitIO`,
      then a hint pointing the user at the on-demand network-privacy command.
    - ``--with-hermes-setup``: opt-in delegation to the upstream ``hermes
      setup`` wizard in either mode (the Mordred prompts / flag application
      still run either way). A bare ``configure`` touches only the Mordred
      policy. The old ``--skip-hermes-setup`` flag is accepted as a
      deprecated no-op -- it just reaffirms the (now default) skip behavior.
    """
    non_interactive = bool(getattr(args, "non_interactive", False))
    with_hermes_setup = bool(getattr(args, "with_hermes_setup", False))
    if non_interactive:
        if with_hermes_setup:
            setup_rc = SubprocessSetupRunner().run(non_interactive=True)
            if setup_rc != 0:
                _term.emit_warn(f"`hermes setup` exited with code {setup_rc}; continuing with Mordred flags anyway")
        writer = PolicyWriter()
        try:
            if _windows():
                snapshot = writer.resolve_and_write(
                    lambda existing: snapshot_from_args(args, existing=existing).snapshot
                )
                result = ConfigureResult(snapshot=snapshot)
            else:
                result = snapshot_from_args(args, existing=_read_existing_policy_inputs(writer))
                writer.write(result.snapshot)
        except (OSError, ValueError) as e:
            _term.emit_error(f"hermes-mordred configure: failed to write policy: {e}")
            return 1
        print(_render_configure_summary(result.snapshot))
        return 0

    try:
        result = run(
            setup_runner=SubprocessSetupRunner(),
            prompt_io=PromptToolkitIO(),
            policy_writer=PolicyWriter(),
            non_interactive=False,
            with_hermes_setup=with_hermes_setup,
        )
    except OSError as e:
        # cli.dispatch() only catches KeyboardInterrupt / EOFError /
        # NonInteractiveAbort / ModuleNotFoundError, so any OSError from run()
        # (the policy_writer.write(), but also the `hermes setup` subprocess or a
        # prompt_toolkit reader on a broken TTY) would otherwise reach the user
        # as a raw traceback. The message stays generic on purpose — this guard
        # spans the whole interactive flow, not just the write, so it must not
        # claim "failed to write policy" for a subprocess/prompt failure (the
        # --non-interactive branch above IS scoped to the write and says so).
        _term.emit_error(f"hermes-mordred configure failed: {e}")
        return 1
    print(_render_configure_summary(result.snapshot))
    return 0
