"""Phase C tests -- configure flow with scripted PromptIO + SetupRunner doubles.

No subprocess is spawned and no real prompt_toolkit call happens; both
seams go through Protocol-typed doubles. Persistence is verified by
reading the files PolicyWriter actually wrote.

Network-privacy prompts no longer live here: they moved to
``hermes mordred network init`` (see ``test_wizard_network_init.py``) so
first-run setup stays short and privacy is opt-in via an explicit command
(user request 2026-06-05). ``configure`` therefore must NOT touch the
``plugins.mordred_network`` section.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from mordred_hermes.wizard import configure
from mordred_hermes.wizard.configure import (
    ConfigureResult,
    NonInteractiveAbort,
    PromptIO,
    SetupRunner,
    _RefusingPromptIO,
    cli_handler,
    collect_answers,
    run,
)
from mordred_hermes.wizard.policy_writer import PolicySnapshot, PolicyWriter

from ._helpers import _writer

# -----------------------------------------------------------------------------
# Test doubles.
# -----------------------------------------------------------------------------


@dataclass
class _ScriptedPromptIO:
    """Pops a pre-recorded answer per call, in declaration order."""

    answers: list[object]
    seen: list[tuple[str, str, object]] = field(default_factory=list)

    def _pop(self, kind: str, label: str, default: object) -> object:
        if not self.answers:
            raise AssertionError(f"_ScriptedPromptIO ran out of answers at {kind}({label!r})")
        a = self.answers.pop(0)
        self.seen.append((kind, label, a))
        return a

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        return str(self._pop("choice", label, default))

    def ask_text(self, label: str, default: str = "") -> str:
        return str(self._pop("text", label, default))

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return bool(self._pop("bool", label, default))

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        val = self._pop("multi", label, default)
        assert isinstance(val, (list, tuple)), f"ask_multi expects a sequence answer, got {val!r}"
        return tuple(str(v) for v in val)

    def ask_password(self, label: str, default: str = "") -> str:
        """Same FIFO contract as ask_text but kind tag distinguishes for
        diagnostics so a future test can confirm the wizard used password
        prompting for secrets, not plain text."""
        return str(self._pop("password", label, default))


@dataclass
class _SetupRunnerSpy:
    calls: list[bool] = field(default_factory=list)
    returncode: int = 0

    def run(self, *, non_interactive: bool) -> int:
        self.calls.append(non_interactive)
        return self.returncode


# The core prompts collected by ``configure`` after the network split.
# Order: policy, allow_cloud_llm, [allowlist], local endpoint, local model,
# cloud attempt action, agent harness. The allowlist prompt (a checkbox
# multi-select) is ONLY asked when ``allow_cloud`` is True, so the scripted
# FIFO must omit its answer otherwise -- mirroring ``collect_answers``.
def _core_answers(
    *,
    policy: str = "lenient",
    allow_cloud: bool = False,
    allowlist: Sequence[str] = (),
    endpoint: str = "http://x/v1",
    model: str = "",
    cloud_attempt: str = "always-block",
    harness: str = "none",
) -> list[object]:
    answers: list[object] = [policy, allow_cloud]
    if allow_cloud:
        answers.append(tuple(allowlist))
    answers += [endpoint, model, cloud_attempt, harness]
    return answers


# -----------------------------------------------------------------------------
# collect_answers: prompt sequence + snapshot mapping.
# -----------------------------------------------------------------------------


class TestCollectAnswers:
    def test_lenient_explains_that_remaining_prompts_can_keep_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        messages: list[str] = []
        monkeypatch.setattr(configure, "_emit_prompt_help", messages.append)

        collect_answers(_ScriptedPromptIO(answers=_core_answers(policy="lenient")))

        assert messages == [configure._LENIENT_MODE_NOTE]
        note = messages[0].lower()
        assert "strict mode" in note
        assert "enter" in note
        assert "defaults" in note

    @pytest.mark.parametrize("policy", ["strict", "off"])
    def test_non_lenient_modes_do_not_show_lenient_note(self, policy: str, monkeypatch: pytest.MonkeyPatch) -> None:
        messages: list[str] = []
        monkeypatch.setattr(configure, "_emit_prompt_help", messages.append)

        collect_answers(_ScriptedPromptIO(answers=_core_answers(policy=policy)))

        assert messages == []

    def test_strict_with_anthropic_allowlist(self) -> None:
        prompts = _ScriptedPromptIO(
            answers=_core_answers(
                policy="strict",
                allow_cloud=True,
                allowlist=("anthropic", "openai"),
                endpoint="http://example/v1",
                model="llama-3",
                cloud_attempt="prompt-once",
                harness="codex",
            )
        )
        result = collect_answers(prompts)
        assert isinstance(result, ConfigureResult)
        assert result.snapshot == PolicySnapshot(
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic", "openai"),
            local_llm_endpoint="http://example/v1",
            local_llm_model_id="llama-3",
            cloud_attempt_action="prompt-once",
            harness_primary="codex",
        )

    def test_lenient_with_empty_allowlist(self) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers(endpoint="http://localhost:1234/v1"))
        result = collect_answers(prompts)
        assert result.snapshot.policy == "lenient"
        assert result.snapshot.allow_cloud_llm is False
        assert result.snapshot.cloud_provider_allowlist == ()
        assert result.snapshot.harness_primary == "none"

    def test_multi_select_allowlist_stored_verbatim(self) -> None:
        """The checkbox selection is persisted as-is (no parsing)."""
        prompts = _ScriptedPromptIO(
            answers=_core_answers(policy="off", allow_cloud=True, allowlist=("anthropic", "openai"))
        )
        result = collect_answers(prompts)
        assert result.snapshot.cloud_provider_allowlist == ("anthropic", "openai")

    def test_allowlist_prompt_skipped_when_cloud_disallowed(self) -> None:
        """``allow_cloud=No`` must NOT ask the allowlist (UX request 2026-06-14)."""
        prompts = _ScriptedPromptIO(answers=_core_answers(allow_cloud=False))
        result = collect_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert "Cloud provider allowlist (select which providers to permit)" not in labels
        assert len(labels) == 6, "exactly six prompts when cloud is disallowed (no allowlist)"
        assert result.snapshot.cloud_provider_allowlist == ()

    def test_prompt_order_is_stable_and_jargon_free(self) -> None:
        """Order matters for snapshot tests; lock it explicitly. The labels
        must also carry no internal ``(Phase N)`` jargon (user request). Uses
        ``allow_cloud=True`` so the (now gated) allowlist prompt is exercised."""
        prompts = _ScriptedPromptIO(answers=_core_answers(allow_cloud=True, allowlist=("anthropic",)))
        collect_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert labels == [
            "Mordred policy mode",
            "Allow cloud LLM providers?",
            "Cloud provider allowlist (select which providers to permit)",
            "Local LLM endpoint URL",
            "Local LLM model id",
            "On cloud LLM attempt under strict mode",
            "Agent harness (strict mode refuses if a known harness is detected)",
        ]
        for label in labels:
            assert "Phase" not in label, f"user-facing label leaks internal jargon: {label!r}"


# -----------------------------------------------------------------------------
# run(): full flow including SetupRunner spawn + PolicyWriter persistence.
# -----------------------------------------------------------------------------


class TestRun:
    def test_persists_snapshot_to_disk(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(
            answers=_core_answers(
                policy="strict",
                allow_cloud=True,
                allowlist=("anthropic",),
                endpoint="http://x/v1",
                model="qwen",
                cloud_attempt="prompt-once",
                harness="codex",
            )
        )
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        result = run(setup_runner=runner, prompt_io=prompts, policy_writer=w)

        # `hermes setup` delegation is opt-in (default False since 2026-07-16);
        # this test is about policy persistence, not the setup runner.
        assert runner.calls == []
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body == {
            "policy": "strict",
            "allow_cloud_llm": True,
            "cloud_provider_allowlist": ["anthropic"],
            "audit_log_path": None,
            "local_llm_endpoint": "http://x/v1",
            "local_llm_model_id": "qwen",
            "cloud_attempt_action": "prompt-once",
            # strict policy → disable_ipv6=True is computed by collect_answers.
            "disable_ipv6": True,
            "provider_overrides": {},
        }
        ytext = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "mordred_privacy_check" in ytext
        assert "local_llm_endpoint" not in ytext
        assert "cloud_attempt_action" not in ytext
        assert "mordred_llm_guard" in ytext
        assert "harness_primary: codex" in ytext
        # configure must NOT write the network section -- that's `network init`.
        assert "default_path" not in ytext
        assert "tor_binary_path" not in ytext
        assert result.snapshot.policy == "strict"
        assert result.snapshot.local_llm_endpoint == "http://x/v1"
        assert result.snapshot.harness_primary == "codex"

    def test_interactive_rerun_preserves_provider_overrides(self, tmp_path: Path) -> None:
        override = {
            "corp-proxy": {
                "transport": "httpx",
                "respects_proxy": True,
                "respects_socks5h": True,
                "respects_ipv6_proxy": True,
                "unverified_baseline": False,
                "transport_class": "http",
            }
        }
        policy_path = tmp_path / "mordred" / "policy.json"
        policy_path.parent.mkdir(parents=True)
        policy_path.write_text(
            json.dumps(
                {
                    "policy": "off",
                    "provider_overrides": override,
                    "unknown_top_level": "drop",
                }
            ),
            encoding="utf-8",
        )

        result = run(
            setup_runner=_SetupRunnerSpy(),
            prompt_io=_ScriptedPromptIO(answers=_core_answers(policy="strict")),
            policy_writer=_writer(tmp_path),
        )

        body = json.loads(policy_path.read_text(encoding="utf-8"))
        assert result.snapshot.provider_overrides == override
        assert body["provider_overrides"] == override
        assert body["policy"] == "strict"
        assert "unknown_top_level" not in body

    def test_default_does_not_call_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w)
        assert runner.calls == [], "default run() must not invoke `hermes setup` (opt-in since 2026-07-16)"

    def test_non_interactive_default_does_not_call_runner(self, tmp_path: Path) -> None:
        """Crosses the flag matrix at the run() level: the skip default must
        hold regardless of non_interactive (the guard is independent of it)."""
        prompts = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, non_interactive=True)
        assert runner.calls == []

    def test_with_hermes_setup_calls_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, with_hermes_setup=True)
        assert runner.calls == [False]

    def test_setup_failure_warns_but_continues(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers())
        runner = _SetupRunnerSpy(returncode=42)
        w = _writer(tmp_path)

        result = run(setup_runner=runner, prompt_io=prompts, policy_writer=w, with_hermes_setup=True)
        assert result.snapshot.policy == "lenient"
        err = capsys.readouterr().err
        assert "hermes setup" in err and "42" in err

    def test_non_interactive_forwarded_to_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers())
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, non_interactive=True, with_hermes_setup=True)
        assert runner.calls == [True]


class TestConfigureLeavesNetworkSectionIntact:
    """``configure`` is network-free after the split: an existing
    ``plugins.mordred_network`` section (written by ``network init`` or by
    hand) must survive a configure run untouched."""

    def test_existing_network_section_untouched(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n"
            "  mordred_network:\n"
            "    default_path: tor\n"
            "    tor_binary_path: /opt/tor/bin/tor\n"
            "    mullvad_relay_country: jp\n",
            encoding="utf-8",
        )
        prompts = _ScriptedPromptIO(answers=_core_answers(policy="strict"))
        run(setup_runner=_SetupRunnerSpy(), prompt_io=prompts, policy_writer=_writer(tmp_path))

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "tor"
        assert section["tor_binary_path"] == "/opt/tor/bin/tor"
        assert section["mullvad_relay_country"] == "jp"
        # And configure still wrote its own sections alongside.
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "strict"


# -----------------------------------------------------------------------------
# _RefusingPromptIO: --non-interactive guard.
# -----------------------------------------------------------------------------


class TestRefusingPromptIO:
    def test_ask_choice_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort, match="prompt required: 'policy mode'"):
            rp.ask_choice("policy mode", ("a", "b"), "a")

    def test_ask_text_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort):
            rp.ask_text("name", "")

    def test_ask_bool_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort):
            rp.ask_bool("ok?", False)


# -----------------------------------------------------------------------------
# cli_handler: --non-interactive triggers exit code 2.
# -----------------------------------------------------------------------------


def _patch_for_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, prompt_io: PromptIO | None = None) -> None:
    class _ZeroSetup:
        def run(self, *, non_interactive: bool) -> int:
            return 0

    monkeypatch.setattr(configure, "SubprocessSetupRunner", _ZeroSetup)
    monkeypatch.setattr(
        configure,
        "PolicyWriter",
        lambda: PolicyWriter(
            config_path=tmp_path / "config.yaml",
            policy_json_path=tmp_path / "mordred" / "policy.json",
            mordred_dir=tmp_path / "mordred",
        ),
    )
    if prompt_io is not None:
        monkeypatch.setattr(configure, "PromptToolkitIO", lambda: prompt_io)


class TestCliHandler:
    def test_non_interactive_applies_flags_and_defaults(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """UX review 2026-06-11 Phase 4: --non-interactive used to refuse on
        the first prompt unconditionally — a flag that could never succeed.
        It is now flag-driven like `network init --non-interactive`."""
        _patch_for_cli(monkeypatch, tmp_path)
        ns = argparse.Namespace(non_interactive=True, policy="strict", harness="codex")
        rc = cli_handler(ns)
        assert rc == 0
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["policy"] == "strict"
        out = capsys.readouterr().out
        assert "strict" in out

    def test_non_interactive_rerun_keeps_existing_settings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A re-run with no flags must not clobber prior answers (mirrors
        network init's seed-from-disk contract)."""
        _patch_for_cli(monkeypatch, tmp_path)
        first = argparse.Namespace(non_interactive=True, policy="strict", harness="codex")
        assert cli_handler(first) == 0
        rerun = argparse.Namespace(non_interactive=True)
        assert cli_handler(rerun) == 0
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["policy"] == "strict"

    def test_interactive_path_runs_end_to_end(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        ns = argparse.Namespace(non_interactive=False)
        rc = cli_handler(ns)
        assert rc == 0
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["policy"] == "off"

    def test_interactive_path_prints_network_init_hint(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """After configure, the user is pointed at the on-demand privacy command."""
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="lenient"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        cli_handler(argparse.Namespace(non_interactive=False))
        out = capsys.readouterr().out.lower()
        assert "network init" in out

    def test_interactive_skips_hermes_setup_by_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A bare configure (attr absent) must NOT delegate to `hermes setup`
        (default inverted 2026-07-16)."""
        spy = _SetupRunnerSpy()
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        monkeypatch.setattr(configure, "SubprocessSetupRunner", lambda: spy)
        rc = cli_handler(argparse.Namespace(non_interactive=False))
        assert rc == 0
        assert spy.calls == [], "default configure must not delegate to `hermes setup`"

    def test_interactive_with_hermes_setup_runs_runner(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """--with-hermes-setup must spawn `hermes setup`, and the Mordred
        prompts still run and the policy is written."""
        spy = _SetupRunnerSpy()
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        monkeypatch.setattr(configure, "SubprocessSetupRunner", lambda: spy)
        rc = cli_handler(argparse.Namespace(non_interactive=False, with_hermes_setup=True))
        assert rc == 0
        assert spy.calls == [False], "--with-hermes-setup must spawn `hermes setup`"
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["policy"] == "off"

    def test_non_interactive_with_hermes_setup_runs_runner(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """--with-hermes-setup in flag-driven mode still spawns `hermes setup`
        while writing the policy from the CLI flags."""
        spy = _SetupRunnerSpy()
        _patch_for_cli(monkeypatch, tmp_path)
        monkeypatch.setattr(configure, "SubprocessSetupRunner", lambda: spy)
        ns = argparse.Namespace(non_interactive=True, policy="strict", with_hermes_setup=True)
        rc = cli_handler(ns)
        assert rc == 0
        assert spy.calls == [True], "--with-hermes-setup must spawn `hermes setup`"
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["policy"] == "strict"

    def test_non_interactive_default_skips_runner(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Flag-driven mode with no setup attr must not spawn `hermes setup`."""
        spy = _SetupRunnerSpy()
        _patch_for_cli(monkeypatch, tmp_path)
        monkeypatch.setattr(configure, "SubprocessSetupRunner", lambda: spy)
        ns = argparse.Namespace(non_interactive=True, policy="strict")
        rc = cli_handler(ns)
        assert rc == 0
        assert spy.calls == [], "default non-interactive configure must not spawn `hermes setup`"


# -----------------------------------------------------------------------------
# Default subprocess runner -- assert command shape without spawning.
# -----------------------------------------------------------------------------


class TestSubprocessSetupRunner:
    def test_calls_subprocess_run_with_non_interactive_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[list[str]] = []

        class _Completed:
            returncode = 0

        def _fake_run(cmd: list[str], check: bool = False) -> object:
            called.append(cmd)
            return _Completed()

        import subprocess

        monkeypatch.setattr(subprocess, "run", _fake_run)
        rc = configure.SubprocessSetupRunner().run(non_interactive=True)
        assert rc == 0
        assert called == [["hermes", "setup", "--non-interactive"]]

    def test_omits_non_interactive_flag_when_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[list[str]] = []

        class _Completed:
            returncode = 7

        def _fake_run(cmd: list[str], check: bool = False) -> object:
            called.append(cmd)
            return _Completed()

        import subprocess

        monkeypatch.setattr(subprocess, "run", _fake_run)
        rc = configure.SubprocessSetupRunner().run(non_interactive=False)
        assert rc == 7
        assert called == [["hermes", "setup"]]

    def test_missing_hermes_binary_returns_1_and_warns(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``hermes`` not on PATH must not propagate FileNotFoundError."""

        def _raise(cmd: list[str], check: bool = False) -> object:
            raise FileNotFoundError(2, "No such file or directory: 'hermes'")

        import subprocess

        monkeypatch.setattr(subprocess, "run", _raise)
        rc = configure.SubprocessSetupRunner().run(non_interactive=False)
        assert rc == 1
        assert "not found on PATH" in capsys.readouterr().err


# -----------------------------------------------------------------------------
# Protocol structural conformance.
# -----------------------------------------------------------------------------


def test_scripted_prompt_io_matches_protocol() -> None:
    p: PromptIO = _ScriptedPromptIO(answers=[])
    assert p is not None


def test_refusing_prompt_io_matches_protocol() -> None:
    p: PromptIO = _RefusingPromptIO()
    assert p is not None


def test_setup_runner_spy_matches_protocol() -> None:
    r: SetupRunner = _SetupRunnerSpy()
    assert r is not None


# -----------------------------------------------------------------------------
# PromptIO.ask_password remains part of the shared prompt surface (reused by
# `network init` for the Mullvad secret).
# -----------------------------------------------------------------------------


class TestPromptIOAskPassword:
    def test_protocol_has_ask_password(self) -> None:
        import inspect

        sig = inspect.signature(PromptIO.ask_password)  # type: ignore[attr-defined]
        params = list(sig.parameters)
        assert "label" in params
        assert "default" in params

    def test_scripted_prompt_io_supports_ask_password(self) -> None:
        scripted = _ScriptedPromptIO(answers=["secret-123"])
        result = scripted.ask_password("Mullvad account id", default="")
        assert result == "secret-123"

    def test_refusing_prompt_io_ask_password_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort):
            rp.ask_password("secret", default="")


# -----------------------------------------------------------------------------
# Completion summary (UX scope B): a structured recap printed after configure.
# -----------------------------------------------------------------------------


class TestConfigureSummary:
    def test_render_summary_contains_resolved_fields(self) -> None:
        from mordred_hermes.wizard.configure import _render_configure_summary

        snap = PolicySnapshot(policy="strict", allow_cloud_llm=True, harness_primary="codex")
        out = _render_configure_summary(snap)
        assert "strict" in out
        assert "codex" in out
        # cloud-LLM state is shown as a human yes/no, not the raw bool.
        assert "policy" in out.lower()
        assert "cloud" in out.lower()
        # Points the user at the on-demand network privacy command.
        assert "network init" in out

    def test_render_summary_reflects_cloud_disallowed(self) -> None:
        from mordred_hermes.wizard.configure import _render_configure_summary

        out = _render_configure_summary(PolicySnapshot(policy="lenient", allow_cloud_llm=False))
        assert "no" in out.lower()

    def test_cli_handler_prints_summary_with_chosen_values(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="strict", harness="codex"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        rc = cli_handler(argparse.Namespace(non_interactive=False))
        assert rc == 0
        out = capsys.readouterr().out
        assert "strict" in out
        assert "codex" in out
        assert "network init" in out


# -----------------------------------------------------------------------------
# prompt_toolkit guidance (UX review 2026-06-11). The ImportError message used
# to suggest "rerun with --non-interactive" — but configure --non-interactive
# installs _RefusingPromptIO, which aborts on the first prompt, so that advice
# could never succeed. The message must offer only the actionable fix.
# -----------------------------------------------------------------------------


class TestPromptToolkitGuidance:
    def test_missing_prompt_toolkit_message_is_actionable(self) -> None:
        msg = configure._PROMPT_TOOLKIT_REQUIRED
        assert "pip install prompt_toolkit" in msg
        assert "--non-interactive" not in msg
        assert "hermes-mordred configure" in msg


# -----------------------------------------------------------------------------
# Phase 4 (UX review 2026-06-11): flag-driven non-interactive configure +
# robust yes/no parsing.
# -----------------------------------------------------------------------------


class TestSnapshotFromArgs:
    def test_flags_map_to_snapshot_fields(self) -> None:
        ns = argparse.Namespace(
            policy="strict",
            allow_cloud_llm=True,
            cloud_allowlist="anthropic, openai",
            local_llm_endpoint="http://127.0.0.1:8080/v1",
            local_llm_model_id="qwen3",
            cloud_attempt_action="prompt-once",
            harness="codex",
        )
        snapshot = configure.snapshot_from_args(ns).snapshot
        assert snapshot.policy == "strict"
        assert snapshot.allow_cloud_llm is True
        assert snapshot.cloud_provider_allowlist == ("anthropic", "openai")
        assert snapshot.local_llm_endpoint == "http://127.0.0.1:8080/v1"
        assert snapshot.local_llm_model_id == "qwen3"
        assert snapshot.cloud_attempt_action == "prompt-once"
        assert snapshot.harness_primary == "codex"
        assert snapshot.disable_ipv6 is True  # strict => IPv6 off (mirrors prompts)

    def test_defaults_without_flags_match_prompt_defaults(self) -> None:
        snapshot = configure.snapshot_from_args(argparse.Namespace()).snapshot
        assert snapshot.policy == "lenient"
        assert snapshot.allow_cloud_llm is False
        assert snapshot.cloud_provider_allowlist == ()
        assert snapshot.harness_primary == "none"
        assert snapshot.disable_ipv6 is False

    def test_existing_values_seed_unspecified_flags(self) -> None:
        overrides = {"corp-proxy": {"transport": "httpx"}}
        existing = {
            "policy": "strict",
            "allow_cloud_llm": True,
            "cloud_provider_allowlist": ["anthropic"],
            "local_llm_endpoint": "http://10.0.0.2:1234/v1",
            "local_llm_model_id": "llama",
            "cloud_attempt_action": "prompt-once",
            "harness_primary": "cursor",
            "provider_overrides": overrides,
        }
        snapshot = configure.snapshot_from_args(argparse.Namespace(), existing=existing).snapshot
        assert snapshot.policy == "strict"
        assert snapshot.allow_cloud_llm is True
        assert snapshot.cloud_provider_allowlist == ("anthropic",)
        assert snapshot.local_llm_endpoint == "http://10.0.0.2:1234/v1"
        assert snapshot.local_llm_model_id == "llama"
        assert snapshot.cloud_attempt_action == "prompt-once"
        assert snapshot.harness_primary == "cursor"
        assert snapshot.provider_overrides == overrides

    def test_flags_override_existing(self) -> None:
        existing = {"policy": "strict"}
        ns = argparse.Namespace(policy="off")
        snapshot = configure.snapshot_from_args(ns, existing=existing).snapshot
        assert snapshot.policy == "off"

    @pytest.mark.parametrize("raw", ["false", "true", "yes", 1])
    def test_non_bool_allow_cloud_llm_from_policy_json_stays_false(self, raw: object) -> None:
        """M2 (security review 2026-06-11): a hand-edited policy.json holding
        ``"allow_cloud_llm": "false"`` must not truthy-coerce to enabled —
        same sanitize treatment the closed-set fields above already get."""
        existing = {"allow_cloud_llm": raw}
        snapshot = configure.snapshot_from_args(argparse.Namespace(), existing=existing).snapshot
        assert snapshot.allow_cloud_llm is False


class TestParseBoolAnswer:
    @pytest.mark.parametrize("answer", ["y", "yes", "true", "1", "on", "Y", "TRUE"])
    def test_truthy_answers(self, answer: str) -> None:
        assert configure._parse_bool_answer(answer, default=False) is True

    @pytest.mark.parametrize("answer", ["n", "no", "false", "0", "off", "anything-else"])
    def test_falsy_answers(self, answer: str) -> None:
        assert configure._parse_bool_answer(answer, default=True) is False

    @pytest.mark.parametrize("default", [True, False])
    def test_empty_answer_returns_default(self, default: bool) -> None:
        assert configure._parse_bool_answer("", default=default) is default


class TestSnapshotFromArgsHardening:
    """Code-review fixes (2026-06-12): hand-edited / downgraded policy.json
    must not crash the non-interactive path."""

    def test_corrupt_cloud_attempt_action_falls_back_to_default(self) -> None:
        existing = {"cloud_attempt_action": "bogus-value"}
        snapshot = configure.snapshot_from_args(argparse.Namespace(), existing=existing).snapshot
        assert snapshot.cloud_attempt_action == "always-block"

    def test_corrupt_policy_mode_falls_back_to_default(self) -> None:
        existing = {"policy": "bogus-mode"}
        snapshot = configure.snapshot_from_args(argparse.Namespace(), existing=existing).snapshot
        assert snapshot.policy == "lenient"

    def test_no_allow_cloud_llm_flag_overrides_existing_true(self) -> None:
        ns = argparse.Namespace(allow_cloud_llm=False)  # --no-allow-cloud-llm
        snapshot = configure.snapshot_from_args(ns, existing={"allow_cloud_llm": True}).snapshot
        assert snapshot.allow_cloud_llm is False

    @pytest.mark.parametrize("raw", [None, ["bad"], "bad"])
    def test_malformed_provider_overrides_are_not_sanitized(self, raw: object) -> None:
        snapshot = configure.snapshot_from_args(
            argparse.Namespace(),
            existing={"provider_overrides": raw},
        ).snapshot
        assert snapshot.provider_overrides == raw

    def test_non_interactive_write_failure_reports_cleanly(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An unwritable policy dir must yield stderr + rc 1, not a traceback."""
        _patch_for_cli(monkeypatch, tmp_path)

        class _FailingWriter:
            policy_json_path = tmp_path / "mordred" / "policy.json"
            config_path = tmp_path / "config.yaml"

            def write(self, snapshot: object) -> None:
                raise OSError("read-only filesystem")

        monkeypatch.setattr(configure, "PolicyWriter", _FailingWriter)
        rc = cli_handler(argparse.Namespace(non_interactive=True, policy="lenient"))
        assert rc == 1
        assert "read-only filesystem" in capsys.readouterr().err

    def test_interactive_write_failure_reports_cleanly(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Codex review: run()'s policy_writer.write() call was UNGUARDED, unlike
        the --non-interactive branch above -- cli.dispatch() only catches
        KeyboardInterrupt / EOFError / NonInteractiveAbort / ModuleNotFoundError,
        so the same disk-write failure hit during interactive `configure` used to
        surface as a raw traceback instead of this clean error: + rc 1."""
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="lenient"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)

        class _FailingWriter:
            policy_json_path = tmp_path / "mordred" / "policy.json"
            config_path = tmp_path / "config.yaml"

            def write(self, snapshot: object) -> None:
                raise OSError("read-only filesystem")

        monkeypatch.setattr(configure, "PolicyWriter", _FailingWriter)
        rc = cli_handler(argparse.Namespace(non_interactive=False))
        assert rc == 1
        assert "read-only filesystem" in capsys.readouterr().err


# -----------------------------------------------------------------------------
# PromptToolkitIO — the production PromptIO impl, exercised with patched
# prompt_toolkit entry points (no real TTY). The methods import prompt_toolkit
# lazily at call time, so monkeypatching the module attributes (or poisoning
# sys.modules for the ImportError branches) intercepts every call.
# -----------------------------------------------------------------------------


class _FakeApp:
    """Stand-in for the ``Application`` built by ``configure._build_choice_app``
    / ``_build_multichoice_app``; ``run`` yields the scripted result (``None``
    simulates Cancel)."""

    def __init__(self, result: object) -> None:
        self._result = result

    def run(self) -> object:
        return self._result


def test_choice_values_renders_inline_descriptions() -> None:
    # Pure mapping: the value (first element) stays the bare choice; only the
    # label (second) gains an inline "<value> — <desc>" when a description
    # exists. A choice with no description renders bare.
    values = configure._choice_values(
        ("strict", "lenient", "off"),
        {"strict": "Blocks cloud LLMs", "lenient": "Stays out of your way"},
    )
    assert values == [
        ("strict", "strict — Blocks cloud LLMs"),
        ("lenient", "lenient — Stays out of your way"),
        ("off", "off"),
    ]


def test_choice_values_without_descriptions_are_bare() -> None:
    assert configure._choice_values(("a", "b"), None) == [("a", "a"), ("b", "b")]


def _drive_dialog(app: object, keys: str) -> object:
    """Run a real dialog ``Application`` loop against piped keypresses.

    ``DummyOutput`` swallows the rendering. A SIGALRM watchdog turns a regressed
    binding (which would otherwise block waiting for more input) into a fast,
    distinctive failure value instead of a hung test.
    """
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    prev = signal.signal(signal.SIGALRM, lambda *_: app.exit(result="<timeout>"))
    signal.setitimer(signal.ITIMER_REAL, 10)
    try:
        with create_pipe_input() as inp:
            app.input = inp
            app.output = DummyOutput()
            inp.send_text(keys)
            return app.run()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


def _drive_choice_app(values: list[tuple[str, str]], default: str, keys: str) -> object:
    return _drive_dialog(configure._build_choice_app(title="t", values=values, default=default, hint="h"), keys)


def _drive_multichoice_app(values: list[tuple[str, str]], default_values: list[str], keys: str) -> object:
    app = configure._build_multichoice_app(title="t", values=values, default_values=default_values, hint="h")
    return _drive_dialog(app, keys)


class TestPromptToolkitIO:
    @pytest.fixture(autouse=True)
    def _tty_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Make stdin look like a terminal so the ``_require_tty`` guard passes.

        These tests drive the prompt methods with a faked prompt_toolkit;
        under pytest the real stdin is a pipe, which the non-tty guard
        (``TestPromptToolkitIoRequiresTty`` below) would otherwise refuse
        before reaching the behavior under test.
        """
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def test_ask_choice_returns_dialog_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_build(*, title: str, values: object, default: str, hint: str) -> _FakeApp:
            captured.update(title=title, values=values, default=default, hint=hint)
            return _FakeApp("strict")

        monkeypatch.setattr(configure, "_build_choice_app", fake_build)
        io = configure.PromptToolkitIO()
        assert io.ask_choice("mode", ("strict", "lenient"), "lenient") == "strict"
        assert captured["title"] == "mode"
        assert captured["values"] == [("strict", "strict"), ("lenient", "lenient")]
        assert captured["default"] == "lenient"

    def test_ask_choice_cancelled_dialog_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(configure, "_build_choice_app", lambda **kw: _FakeApp(None))
        io = configure.PromptToolkitIO()
        assert io.ask_choice("mode", ("a", "b"), "b") == "b"

    def test_ask_choice_forwards_inline_descriptions_to_builder(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The decorated labels reach the dialog builder while the returned value
        # stays the bare choice -- callers and persisted answers are unaffected.
        captured: dict[str, object] = {}

        def fake_build(*, title: str, values: object, default: str, hint: str) -> _FakeApp:
            captured["values"] = values
            return _FakeApp("strict")

        monkeypatch.setattr(configure, "_build_choice_app", fake_build)
        io = configure.PromptToolkitIO()
        result = io.ask_choice(
            "Mordred policy mode",
            ("strict", "lenient", "off"),
            "lenient",
            descriptions={"strict": "Blocks cloud LLMs", "lenient": "Stays out of your way"},
        )
        assert result == "strict"
        assert captured["values"] == [
            ("strict", "strict — Blocks cloud LLMs"),
            ("lenient", "lenient — Stays out of your way"),
            ("off", "off"),
        ]

    def test_build_choice_app_constructs_keyboard_friendly_dialog(self) -> None:
        # Construction needs no TTY, so exercising the real builder here covers
        # it (the run/cancel tests stub it out). Asserts the dialog is a usable
        # Application with the live-selection radio + key bindings that back the
        # arrows/Enter/Tab navigation.
        from prompt_toolkit.application import Application

        app = configure._build_choice_app(
            title="Mordred policy mode",
            values=[("strict", "strict — x"), ("lenient", "lenient — y")],
            default="lenient",
            hint="hint",
        )
        assert isinstance(app, Application)
        assert app.key_bindings is not None

    @pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="needs SIGALRM watchdog (POSIX)")
    @pytest.mark.parametrize(
        ("keys", "expected"),
        [
            ("\r", "lenient"),  # Enter alone confirms the default-highlighted row
            ("\x1b[B\r", "off"),  # Down arrow moves the live selection, Enter confirms
            ("\x1b[A\r", "strict"),  # Up arrow moves the live selection, Enter confirms
        ],
    )
    def test_choice_dialog_enter_confirms_highlighted_value(self, keys: str, expected: str) -> None:
        # The whole point of the custom dialog: arrows move the selection and a
        # single Enter confirms it -- no Tab/click to the Ok button required.
        result = _drive_choice_app(
            [("strict", "strict — x"), ("lenient", "lenient — y"), ("off", "off")],
            "lenient",
            keys,
        )
        assert result == expected

    def test_build_multichoice_app_constructs_keyboard_friendly_dialog(self) -> None:
        # Construction needs no TTY; exercising the real builder covers the
        # checkbox path of _build_list_app (the run/cancel tests stub it out).
        from prompt_toolkit.application import Application

        app = configure._build_multichoice_app(
            title="Cloud provider allowlist",
            values=[("anthropic", "anthropic"), ("openai", "openai")],
            default_values=("anthropic",),
            hint="hint",
        )
        assert isinstance(app, Application)
        assert app.key_bindings is not None

    @pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="needs SIGALRM watchdog (POSIX)")
    def test_multichoice_dialog_space_toggles_and_enter_confirms(self) -> None:
        # Checkbox semantics: Space toggles the highlighted row, Enter confirms
        # the whole set -- no Tab/click to Ok. Start with anthropic preselected,
        # move down to openai, toggle it on, then confirm.
        result = _drive_multichoice_app(
            [("anthropic", "anthropic"), ("openai", "openai"), ("gemini", "gemini")],
            ["anthropic"],
            "\x1b[B \r",  # Down → openai, Space → toggle on, Enter → confirm
        )
        assert result == ["anthropic", "openai"]

    @pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="needs SIGALRM watchdog (POSIX)")
    def test_choice_dialog_ctrl_c_aborts(self) -> None:
        # Ctrl-C must raise KeyboardInterrupt (abort the whole flow), matching the
        # surrounding prompt() text prompts -- NOT silently return the default and
        # march on through the remaining prompts.
        with pytest.raises(KeyboardInterrupt):
            _drive_choice_app([("strict", "strict"), ("lenient", "lenient")], "lenient", "\x03")

    @pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="needs SIGALRM watchdog (POSIX)")
    def test_multichoice_dialog_ctrl_c_aborts(self) -> None:
        # Same abort contract on the checkbox picker -- Ctrl-C raises rather than
        # confirming whatever happens to be toggled.
        with pytest.raises(KeyboardInterrupt):
            _drive_multichoice_app([("anthropic", "anthropic"), ("openai", "openai")], ["anthropic"], "\x03")

    def test_echo_selection_prints_question_and_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # After the picker erases itself, ask_choice/ask_multi echo a one-line
        # record so the transcript still shows what was answered. Capture the
        # FormattedText (print_formatted_text writes via a cached output that
        # bypasses capsys/capfd) and flatten it to plain text.
        captured: dict[str, str] = {}

        def fake_print(formatted: object, **kwargs: object) -> None:
            captured["text"] = "".join(text for _, text in formatted)

        monkeypatch.setattr("prompt_toolkit.print_formatted_text", fake_print)
        configure._echo_selection("Network privacy path", "clearnet")
        assert "Network privacy path" in captured["text"]
        assert "clearnet" in captured["text"]
        assert captured["text"].lstrip().startswith("?")

    def test_collect_answers_passes_policy_descriptions(self) -> None:
        # The policy-mode, cloud-attempt, and agent-harness prompts are each
        # wired with their own canonical descriptions. Asserting all three carry
        # a *distinct* constant proves the descriptions are wired per-prompt
        # rather than applied globally to every choice dialog.
        seen: dict[str, Mapping[str, str] | None] = {}

        class _RecordingIO(_ScriptedPromptIO):
            def ask_choice(
                self,
                label: str,
                choices: Sequence[str],
                default: str,
                *,
                descriptions: Mapping[str, str] | None = None,
            ) -> str:
                seen[label] = descriptions
                return str(self._pop("choice", label, default))

        configure.collect_answers(_RecordingIO(answers=_core_answers()))
        assert seen["Mordred policy mode"] == configure._POLICY_MODE_DESCRIPTIONS
        assert seen["On cloud LLM attempt under strict mode"] == configure._CLOUD_ATTEMPT_DESCRIPTIONS
        # The agent-harness prompt now carries its own descriptions so the bare
        # ``acp-claude`` / ``acp-cline`` labels read as editor/IDE-driven rather
        # than as opaque protocol identifiers (UX request 2026-06-24).
        assert (
            seen["Agent harness (strict mode refuses if a known harness is detected)"]
            == configure._HARNESS_DESCRIPTIONS
        )

    def test_prompt_once_description_reflects_live_enforcement(self) -> None:
        # prompt-once is no longer a reserved no-op: enforce now asks once per
        # provider at an interactive terminal (llm_guard.enforce). The inline
        # description must stop claiming it is reserved / behaves like always-block.
        desc = configure._CLOUD_ATTEMPT_DESCRIPTIONS["prompt-once"]
        assert "reserved" not in desc.lower()
        assert "once" in desc.lower()

    def test_collect_answers_passes_cloud_llm_description(self) -> None:
        # The cloud-LLM yes/no prompt is wired with the canonical help text so
        # the bare [y/N] question is preceded by a plain-language explanation.
        seen: dict[str, str | None] = {}

        class _RecordingIO(_ScriptedPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                seen[label] = description
                return bool(self._pop("bool", label, default))

        configure.collect_answers(_RecordingIO(answers=_core_answers()))
        assert seen["Allow cloud LLM providers?"] == configure._CLOUD_LLM_PROMPT_DESCRIPTION

    def test_ask_text_strips_and_echoes_default_in_label(self, monkeypatch: pytest.MonkeyPatch) -> None:
        prompts: list[str] = []

        def fake_prompt(message: str, **kwargs: object) -> str:
            prompts.append(message)
            return "  answer  "

        monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
        io = configure.PromptToolkitIO()
        assert io.ask_text("Endpoint", default="http://x") == "answer"
        assert prompts == ["Endpoint [http://x]: "]

    def test_ask_text_empty_answer_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("prompt_toolkit.prompt", lambda message, **kw: "")
        io = configure.PromptToolkitIO()
        assert io.ask_text("Endpoint", default="http://x") == "http://x"

    def test_ask_text_prints_description_above_a_bare_prompt(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The help line prints once, on its own, ABOVE a single-line prompt — it
        # is no longer folded into the prompt() message (prompt_toolkit repaints a
        # multi-line message in full, doubling it in the scrollback). UX 2026-06-16.
        messages: list[str] = []

        def fake_prompt(message: str, **kwargs: object) -> str:
            messages.append(message)
            return "answer"

        monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
        io = configure.PromptToolkitIO()
        assert io.ask_text("Tor binary path", default="tor", description="Where the tor program is.") == "answer"
        # The prompt message is bare — no description, no embedded newline.
        assert messages == ["Tor binary path [tor]: "]
        # The help text was emitted separately, exactly once.
        assert capsys.readouterr().out == "Where the tor program is.\n"

    def test_ask_text_without_description_stays_bare(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No description → the question line is unchanged (regression guard).
        messages: list[str] = []

        def fake_prompt(message: str, **kwargs: object) -> str:
            messages.append(message)
            return ""

        monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
        io = configure.PromptToolkitIO()
        assert io.ask_text("Endpoint", default="http://x") == "http://x"
        assert messages == ["Endpoint [http://x]: "]

    @pytest.mark.parametrize(
        ("answer", "default", "expected"),
        [
            ("", True, True),  # empty input → default (Y/n)
            ("", False, False),  # empty input → default (y/N)
            ("y", False, True),
            ("YES", False, True),  # case-folded
            ("n", True, False),
            ("bogus", True, False),  # anything non-affirmative is False
        ],
    )
    def test_ask_bool_parses_answers(
        self, monkeypatch: pytest.MonkeyPatch, answer: str, default: bool, expected: bool
    ) -> None:
        monkeypatch.setattr("prompt_toolkit.prompt", lambda message, **kw: answer)
        io = configure.PromptToolkitIO()
        assert io.ask_bool("Allow?", default) is expected

    def test_ask_bool_prints_description_above_a_bare_prompt(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The help line prints separately above the [y/N] prompt; the prompt
        # message itself stays single-line.
        messages: list[str] = []

        def fake_prompt(message: str, **kwargs: object) -> str:
            messages.append(message)
            return "y"

        monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
        io = configure.PromptToolkitIO()
        assert io.ask_bool("Allow?", False, description="Cloud sends your prompts away.") is True
        assert messages == ["Allow? [y/N]: "]
        assert capsys.readouterr().out == "Cloud sends your prompts away.\n"

    def test_ask_bool_without_description_stays_bare(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No description → the question line is unchanged (regression guard).
        messages: list[str] = []

        def fake_prompt(message: str, **kwargs: object) -> str:
            messages.append(message)
            return ""

        monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
        io = configure.PromptToolkitIO()
        assert io.ask_bool("Allow?", True) is True
        assert messages == ["Allow? [Y/n]: "]

    def test_ask_multi_returns_selected_tuple(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_build(*, title: str, values: object, default_values: object) -> _FakeApp:
            captured.update(title=title, values=values, default_values=default_values)
            return _FakeApp(["anthropic", "openai"])

        monkeypatch.setattr(configure, "_build_multichoice_app", fake_build)
        io = configure.PromptToolkitIO()
        assert io.ask_multi("Allowlist", ("anthropic", "openai", "gemini"), ()) == ("anthropic", "openai")
        assert captured["title"] == "Allowlist"
        assert captured["values"] == [("anthropic", "anthropic"), ("openai", "openai"), ("gemini", "gemini")]
        assert captured["default_values"] == ()

    def test_ask_multi_cancelled_returns_empty_tuple(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(configure, "_build_multichoice_app", lambda **kw: _FakeApp(None))
        io = configure.PromptToolkitIO()
        assert io.ask_multi("Allowlist", ("anthropic",), ()) == ()

    def test_ask_password_masks_input_and_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen_kwargs: dict[str, object] = {}

        def fake_prompt(message: str, **kwargs: object) -> str:
            seen_kwargs.update(kwargs)
            return ""

        monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
        io = configure.PromptToolkitIO()
        assert io.ask_password("Account number", default="keep-me") == "keep-me"
        # The secret must never echo — is_password masks the input.
        assert seen_kwargs.get("is_password") is True

    def test_ask_password_prints_description_above_a_bare_prompt(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The help line prints separately above the masked prompt; is_password
        # masks only the typed secret, never the help text or label.
        captured: dict[str, object] = {}

        def fake_prompt(message: str, **kwargs: object) -> str:
            captured["message"] = message
            captured.update(kwargs)
            return "secret-1"

        monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
        io = configure.PromptToolkitIO()
        result = io.ask_password("Mullvad account number", description="VPN route only — your account number.")
        assert result == "secret-1"
        # Bare, single-line prompt message; the help text printed separately.
        assert captured["message"] == "Mullvad account number: "
        assert captured.get("is_password") is True
        assert capsys.readouterr().out == "VPN route only — your account number.\n"

    @pytest.mark.parametrize(
        ("method", "args"),
        [
            ("ask_choice", ("label", ("a",), "a")),
            ("ask_text", ("label",)),
            ("ask_bool", ("label", True)),
            ("ask_multi", ("label", ("a", "b"))),
            ("ask_password", ("label",)),
        ],
    )
    def test_methods_raise_runtime_error_without_prompt_toolkit(
        self, monkeypatch: pytest.MonkeyPatch, method: str, args: tuple[object, ...]
    ) -> None:
        # None in sys.modules makes the lazy `from prompt_toolkit import ...`
        # raise ImportError, which each method must translate to the
        # actionable RuntimeError (install hint / --non-interactive escape).
        # Poison the package AND every already-imported submodule: a cached
        # submodule (e.g. prompt_toolkit.application) would otherwise satisfy a
        # `from prompt_toolkit.X import ...` even with the parent poisoned, so
        # this faithfully simulates prompt_toolkit being absent.
        for mod in [m for m in sys.modules if m == "prompt_toolkit" or m.startswith("prompt_toolkit.")]:
            monkeypatch.setitem(sys.modules, mod, None)
        io = configure.PromptToolkitIO()
        with pytest.raises(RuntimeError, match="prompt_toolkit is required"):
            getattr(io, method)(*args)


def test_coerce_cloud_attempt_action_rejects_unknown_value() -> None:
    """The Literal-narrowing guard fails loudly on a scripted bad answer
    instead of letting an invalid action reach the PolicySnapshot."""
    with pytest.raises(ValueError, match="invalid cloud_attempt_action"):
        configure._coerce_cloud_attempt_action("sometimes")


class TestSelectableCloudProviders:
    """The allowlist checkbox is sourced from the network flagger's canonical
    registry so the wizard never drifts from the transport-compat layer."""

    def test_excludes_localhost_provider(self) -> None:
        assert "mordred-local" not in configure._SELECTABLE_CLOUD_PROVIDERS

    def test_includes_known_cloud_providers(self) -> None:
        providers = configure._SELECTABLE_CLOUD_PROVIDERS
        assert "anthropic" in providers
        assert "openai" in providers

    def test_matches_known_providers_minus_localhost(self) -> None:
        from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

        expected = tuple(name for name, e in KNOWN_PROVIDERS.items() if not e.localhost_only)
        assert expected == configure._SELECTABLE_CLOUD_PROVIDERS


# -----------------------------------------------------------------------------
# Non-tty guard on the production prompt layer.
# -----------------------------------------------------------------------------


class TestPromptToolkitIoRequiresTty:
    """Every interactive prompt refuses a non-terminal stdin up front.

    Without the guard, prompt_toolkit's event loop dies deep inside asyncio
    (``OSError: [Errno 22]`` from ``_add_reader``) when stdin is a pipe or
    ``/dev/null`` — observed with ``hermes-mordred vault status </dev/null``
    (2026-07-09). Raising :class:`NonInteractiveAbort` instead routes piped /
    cron invocations through the clean ``error:`` + exit-2 path
    ``cli.dispatch`` already implements for ``--non-interactive``.
    """

    @pytest.mark.parametrize(
        "call",
        [
            pytest.param(lambda io_: io_.ask_choice("Mode", ("a", "b"), "a"), id="ask_choice"),
            pytest.param(lambda io_: io_.ask_text("Name"), id="ask_text"),
            pytest.param(lambda io_: io_.ask_bool("Sure?", True), id="ask_bool"),
            pytest.param(lambda io_: io_.ask_multi("Pick", ("a",)), id="ask_multi"),
            pytest.param(lambda io_: io_.ask_password("Vault passphrase"), id="ask_password"),
        ],
    )
    def test_refuses_before_touching_prompt_toolkit(self, monkeypatch: pytest.MonkeyPatch, call) -> None:
        import io

        monkeypatch.setattr(sys, "stdin", io.StringIO())
        with pytest.raises(NonInteractiveAbort, match="not a terminal"):
            call(configure.PromptToolkitIO())
