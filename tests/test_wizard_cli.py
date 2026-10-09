"""Phase A acceptance tests for the wizard CLI scaffold.

Verifies that ``hermes mordred --help`` exposes every documented
subcommand (SPEC.md §Plugin: ``mordred_wizard``) and that each Phase 0
stub handler raises :class:`NotImplementedError` with the expected
"Phase X not yet landed" marker. Subsequent phases will replace each
stub-targeted test with a real behavioural test.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard import keyvault_native_cli, register, status_cli
from mordred_hermes.wizard.cli import _setup_subparser, dispatch, main


class _CapturingContext:
    """Records the single ``register_cli_command`` invocation."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def register_cli_command(
        self,
        name: str,
        help: str,
        setup_fn: Callable[[argparse.ArgumentParser], None],
        handler_fn: Callable[[argparse.Namespace], Any] | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            {
                "name": name,
                "help": help,
                "setup_fn": setup_fn,
                "handler_fn": handler_fn,
                "description": description,
            }
        )


def _build_parser() -> argparse.ArgumentParser:
    """Build an isolated ``hermes mordred`` parser the same way Hermes would."""
    root = argparse.ArgumentParser(prog="hermes")
    sub = root.add_subparsers(dest="command")
    plugin_parser = sub.add_parser("mordred")
    _setup_subparser(plugin_parser)
    return root


class TestRegister:
    def test_register_calls_register_cli_command_once(self) -> None:
        ctx = _CapturingContext()
        register(ctx)
        assert len(ctx.calls) == 1
        call = ctx.calls[0]
        assert call["name"] == "mordred"
        assert "Mordred privacy layer" in call["help"]
        assert call["setup_fn"] is _setup_subparser
        assert call["description"]  # non-empty description for `--help` discoverability


class TestSubcommandTree:
    """Every documented subcommand must be reachable via ``argparse``."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["mordred", "configure"],
            ["mordred", "configure", "--skip-hermes-setup"],
            ["mordred", "configure", "--with-hermes-setup"],
            ["mordred", "upgrade"],
            ["mordred", "upgrade", "--reset"],
            ["mordred", "upgrade", "--non-interactive"],
            ["mordred", "upgrade", "--audit-merge", "skip"],
            ["mordred", "upgrade", "--policy-conflict", "abort"],
            ["mordred", "install", "some-skill"],
            ["mordred", "network", "use", "tor"],
            ["mordred", "network", "use", "vpn"],
            ["mordred", "network", "use", "clearnet"],
            ["mordred", "network", "status"],
            ["mordred", "network", "init"],
            ["mordred", "network", "init", "--non-interactive"],
            ["mordred", "network", "init", "--clear-mullvad"],
            ["mordred", "network", "init", "--non-interactive", "--path", "tor"],
            ["mordred", "network", "init", "--no-mullvad-killswitch"],
            ["mordred", "network", "init", "--tor-socks-port", "9050"],
            ["mordred", "policy", "show"],
            ["mordred", "policy", "explain", "skill-id"],
            ["mordred", "policy", "dry-run", "/tmp/SKILL.md"],
            ["mordred", "policy", "reload"],
            ["mordred", "audit", "tail"],
            ["mordred", "audit", "tail", "-n", "5"],
            ["mordred", "audit", "grep", "policy.strict"],
            ["mordred", "audit", "decrypt", "--date", "2026-05-10"],
            ["mordred", "audit", "purge", "--before", "2026-01-01"],
            ["mordred", "keyvault", "init"],
            ["mordred", "keyvault", "init", "--store-seed-for-hd"],
            ["mordred", "keyvault", "init", "--paper-only"],
            ["mordred", "keyvault", "list"],
            ["mordred", "keyvault", "verify-digest"],
            ["mordred", "keyvault", "export", "--output", "/tmp/keyvault-backup.mrkv"],
            ["mordred", "keyvault", "recover", "--blob", "/tmp/x"],
            ["mordred", "vault", "migrate"],
            ["mordred", "vault", "migrate", "/tmp/.env", "/tmp/config.yaml"],
            ["mordred", "vault", "migrate", "--root", "/tmp/vault"],
            ["mordred", "plugins", "list"],
        ],
    )
    def test_argv_parses_and_wires_a_handler(self, argv: list[str]) -> None:
        parser = _build_parser()
        ns = parser.parse_args(argv)
        assert hasattr(ns, "func"), f"set_defaults(func=...) missing for {argv!r}"

    def test_keyvault_init_defaults_to_encrypted_seed_storage(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "init"])
        assert ns.store_seed_for_hd is True

    def test_keyvault_init_paper_only_opts_out_of_seed_storage(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "init", "--paper-only"])
        assert ns.store_seed_for_hd is False

    def test_configure_with_hermes_setup_defaults_false(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "configure"])
        assert ns.with_hermes_setup is False

    def test_configure_with_hermes_setup_flag_sets_true(self) -> None:
        # Guards the flag-name -> dest mapping that cli_handler reads via
        # getattr(args, "with_hermes_setup", ...); a rename would break the CLI
        # while leaving the Namespace-based handler tests green.
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "configure", "--with-hermes-setup"])
        assert ns.with_hermes_setup is True

    def test_configure_skip_hermes_setup_parses_as_noop(self) -> None:
        # Deprecated flag (2026-07-16): still parses for backward compat and
        # resolves into the same shared dest as the default (store_false), so
        # it just reaffirms the (now default) skip behavior and leaves no
        # vestigial attribute on the Namespace.
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "configure", "--skip-hermes-setup"])
        assert ns.with_hermes_setup is False
        assert not hasattr(ns, "skip_hermes_setup")

    def test_configure_with_and_skip_hermes_setup_conflict(self) -> None:
        # Mutually exclusive: passing both must error rather than silently
        # picking a winner.
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["mordred", "configure", "--with-hermes-setup", "--skip-hermes-setup"])


class TestUpgradeFlagShape:
    """The H5 conflict-resolution flags must accept their documented choices."""

    def test_audit_merge_choices(self) -> None:
        parser = _build_parser()
        for choice in ("skip", "append-all", "abort"):
            ns = parser.parse_args(["mordred", "upgrade", "--audit-merge", choice])
            assert ns.audit_merge == choice

    def test_audit_merge_rejects_unknown_choice(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["mordred", "upgrade", "--audit-merge", "bogus"])

    def test_policy_conflict_choices(self) -> None:
        parser = _build_parser()
        for choice in ("keep-existing", "overwrite", "abort"):
            ns = parser.parse_args(["mordred", "upgrade", "--policy-conflict", choice])
            assert ns.policy_conflict == choice


class TestDispatchWithoutFunc:
    """Defensive: dispatch on a Namespace lacking ``func`` exits cleanly."""

    def test_missing_func_raises_systemexit(self) -> None:
        with pytest.raises(SystemExit):
            dispatch(argparse.Namespace())


class TestDispatchInterruptGuard:
    """A ^C at any interactive prompt aborts cleanly instead of dumping a
    traceback (UX review 2026-07-07). The prompt layer re-raises
    KeyboardInterrupt on purpose (see ``_prompt_io``); ``dispatch`` is the one
    place every handler funnels through, so the guard lives there.
    """

    def test_keyboard_interrupt_prints_aborted_and_returns_130(self, capsys: pytest.CaptureFixture[str]) -> None:
        def _boom(args: argparse.Namespace) -> int:
            raise KeyboardInterrupt

        rc = dispatch(argparse.Namespace(func=_boom))
        assert rc == 130  # 128 + SIGINT, the shell convention
        captured = capsys.readouterr()
        assert "Aborted." in captured.err
        assert captured.out == ""

    def test_non_interactive_abort_prints_error_and_returns_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.wizard._prompt_io import NonInteractiveAbort

        def _refuse(args: argparse.Namespace) -> int:
            raise NonInteractiveAbort("--non-interactive set but prompt required: 'Passphrase'")

        rc = dispatch(argparse.Namespace(func=_refuse))
        assert rc == 2
        err = capsys.readouterr().err
        assert err.startswith("error:")

    def test_eoferror_prints_aborted_and_returns_130(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Ctrl-D at a prompt — prompt_toolkit raises EOFError — aborts cleanly
        like Ctrl-C instead of dumping a traceback (found via `vault status`,
        2026-07-09)."""

        def _eof(args: argparse.Namespace) -> int:
            raise EOFError

        rc = dispatch(argparse.Namespace(func=_eof))
        assert rc == 130
        captured = capsys.readouterr()
        assert "Aborted" in captured.err
        assert captured.out == ""


class TestDispatchMissingCryptoStack:
    """A ModuleNotFoundError for the optional keyvault crypto stack becomes an
    actionable install hint instead of a raw traceback.

    On a minimal install (no ``[keyvault]`` extra) ``vault status`` died with
    ``ModuleNotFoundError: No module named 'argon2'`` deep inside
    ``_open_cold_path`` (found verifying the 0.1.0a1 TestPyPI wheel,
    2026-07-09). ``dispatch`` is the chokepoint every vault / keyvault /
    encryption handler funnels through, so the translation lives there —
    but ONLY for the known crypto-stack modules; anything else must
    propagate so real import bugs stay visible.
    """

    @pytest.mark.parametrize("missing", ["argon2", "cryptography", "blake3", "argon2.low_level"])
    def test_keyvault_stack_module_becomes_install_hint(self, capsys: pytest.CaptureFixture[str], missing: str) -> None:
        def _boom(args: argparse.Namespace) -> int:
            raise ModuleNotFoundError(f"No module named {missing!r}", name=missing)

        rc = dispatch(argparse.Namespace(func=_boom))
        assert rc == 1
        err = capsys.readouterr().err
        assert err.startswith("error:")
        assert "hermes-mordred[keyvault]" in err
        assert missing.partition(".")[0] in err

    def test_unrelated_module_not_found_propagates(self) -> None:
        def _boom(args: argparse.Namespace) -> int:
            raise ModuleNotFoundError("No module named 'numpy'", name="numpy")

        with pytest.raises(ModuleNotFoundError, match="numpy"):
            dispatch(argparse.Namespace(func=_boom))

    def test_nameless_module_not_found_propagates(self) -> None:
        """A ModuleNotFoundError with no ``name`` attribute (hand-raised) must
        not be misclassified as a missing crypto dependency."""

        def _boom(args: argparse.Namespace) -> int:
            raise ModuleNotFoundError("mystery import failure")

        with pytest.raises(ModuleNotFoundError, match="mystery"):
            dispatch(argparse.Namespace(func=_boom))


class TestMainStandaloneEntry:
    """`hermes-mordred` console-script entry (Codex P1 workaround for Hermes 0.11)."""

    def test_help_exits_cleanly(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "configure" in out
        assert "upgrade" in out
        assert "policy" in out

    def test_no_args_prints_friendly_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        # Bare `hermes-mordred` is a discovery moment, not an error: print the
        # quickstart help and exit 0 instead of an argparse usage error.
        rc = main([])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Quickstart" in out
        assert "configure" in out

    def test_help_lists_no_color_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        assert "--no-color" in capsys.readouterr().out

    def test_no_color_flag_sets_no_color_env(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `--no-color` disables colour by flipping the env var the shared
        # should_color() gate already respects; monkeypatch restores it on teardown.
        monkeypatch.delenv("NO_COLOR", raising=False)
        rc = main(["--no-color"])  # no subcommand -> prints help, returns 0
        assert rc == 0
        assert os.environ.get("NO_COLOR") == "1"

    def test_no_color_flag_applies_with_a_subcommand(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The flag must take effect before dispatch so the command's renderer
        # sees NO_COLOR. Stub the status handler so no real ~/.hermes is touched.
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(status_cli, "cli_status", lambda args: 0)
        rc = main(["--no-color", "status"])
        assert rc == 0
        assert os.environ.get("NO_COLOR") == "1"

    def test_unknown_subcommand_argparse_exits_cleanly(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["bogus-subcommand"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "invalid choice" in err


class TestEnableSEWiring:
    """``hermes mordred keyvault enable-se`` parser wiring + adapter."""

    def test_enable_se_parses_and_wires_handler(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-se"])
        assert hasattr(ns, "func"), "set_defaults(func=...) missing for keyvault enable-se"

    def test_enable_se_install_dir_parses(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-se", "--install-dir", "/tmp/bin"])
        assert ns.install_dir == "/tmp/bin"

    def test_enable_se_rejects_unattended_installer_flag(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["mordred", "keyvault", "enable-se", "--unattended"])
        assert exc.value.code == 2

    def test_cli_enable_se_forwards_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_se(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_native_cli, "enable_se", _fake_enable_se)
        ns = argparse.Namespace(install_dir="/tmp/bin")
        rc = keyvault_native_cli.cli_enable_se(ns)
        assert rc == 0
        assert captured["install_dir"] == Path("/tmp/bin")
        assert "unattended" not in captured

    def test_cli_enable_se_absent_flags_pass_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_se(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_native_cli, "enable_se", _fake_enable_se)
        ns = argparse.Namespace(install_dir=None)
        keyvault_native_cli.cli_enable_se(ns)
        assert captured["install_dir"] is None
        assert "unattended" not in captured

    def test_dispatch_routes_handler_to_native_cli(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # End-to-end: the cli.py handler must import + delegate to
        # keyvault_native_cli (the post-split home), not the old keyvault_cli.
        seen: dict[str, Any] = {}

        def _fake_cli_enable_se(args: argparse.Namespace) -> int:
            seen["args"] = args
            return 7

        monkeypatch.setattr(keyvault_native_cli, "cli_enable_se", _fake_cli_enable_se)
        ns = _build_parser().parse_args(["mordred", "keyvault", "enable-se"])
        assert dispatch(ns) == 7
        assert seen["args"] is ns


class TestEnableTPMWiring:
    """``hermes mordred keyvault enable-tpm`` parser wiring + adapter (v2-OS2 2c).

    The TPM is Tier 2 (machine-bound), so ``enable-tpm`` exposes only
    ``--install-dir`` — there is deliberately no ``--unattended`` per-use gate.
    """

    def test_enable_tpm_parses_and_wires_handler(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-tpm"])
        assert hasattr(ns, "func"), "set_defaults(func=...) missing for keyvault enable-tpm"

    def test_enable_tpm_install_dir_parses(self) -> None:
        parser = _build_parser()
        ns = parser.parse_args(["mordred", "keyvault", "enable-tpm", "--install-dir", "/tmp/bin"])
        assert ns.install_dir == "/tmp/bin"

    def test_enable_tpm_rejects_unattended_flag(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["mordred", "keyvault", "enable-tpm", "--unattended"])

    def test_cli_enable_tpm_forwards_install_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_tpm(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_native_cli, "enable_tpm", _fake_enable_tpm)
        ns = argparse.Namespace(install_dir="/tmp/bin")
        rc = keyvault_native_cli.cli_enable_tpm(ns)
        assert rc == 0
        assert captured["install_dir"] == Path("/tmp/bin")
        assert "unattended" not in captured  # Tier 2: no per-use gate

    def test_cli_enable_tpm_absent_install_dir_passes_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _fake_enable_tpm(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_native_cli, "enable_tpm", _fake_enable_tpm)
        ns = argparse.Namespace(install_dir=None)
        keyvault_native_cli.cli_enable_tpm(ns)
        assert captured["install_dir"] is None

    def test_dispatch_routes_handler_to_native_cli(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # End-to-end: the cli.py handler must import + delegate to
        # keyvault_native_cli (the post-split home), not the old keyvault_cli.
        seen: dict[str, Any] = {}

        def _fake_cli_enable_tpm(args: argparse.Namespace) -> int:
            seen["args"] = args
            return 7

        monkeypatch.setattr(keyvault_native_cli, "cli_enable_tpm", _fake_cli_enable_tpm)
        ns = _build_parser().parse_args(["mordred", "keyvault", "enable-tpm"])
        assert dispatch(ns) == 7
        assert seen["args"] is ns


# -----------------------------------------------------------------------------
# Help information architecture (UX review 2026-06-11, Phase 3).
# -----------------------------------------------------------------------------


def _iter_help_strings(parser: argparse.ArgumentParser) -> list[str]:
    """Every help / description / epilog string in the parser tree."""
    collected: list[str] = [parser.description or "", parser.epilog or ""]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for choice_action in action._choices_actions:
                collected.append(choice_action.help or "")
            for sub in action.choices.values():
                collected.extend(_iter_help_strings(sub))
        else:
            collected.append(action.help or "")
    return collected


class TestHelpHasNoInternalJargon:
    """--help is the product's front door: spec-internal references like
    "Story 1 / Story 1.5", section anchors, or roadmap ids mean nothing to
    a user and crowd out the actual explanation."""

    @pytest.mark.parametrize("jargon", ["Story 1", "§", "v2-F8", "L128"])
    def test_no_jargon_anywhere_in_help_tree(self, jargon: str) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        _setup_subparser(parser)
        offenders = [text for text in _iter_help_strings(parser) if jargon in text]
        assert not offenders, f"internal jargon {jargon!r} leaks into --help: {offenders}"


class TestVersionFlag:
    def test_version_prints_and_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.__about__ import __version__

        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        assert __version__ in capsys.readouterr().out


class TestQuickstartEpilog:
    def test_top_level_help_carries_quickstart_and_group_guide(self) -> None:
        """The epilog must orient a new user: the first-run order of
        commands and how keyvault / vault / encryption relate."""
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        out = buf.getvalue()
        assert "Quickstart" in out
        assert "hermes-mordred configure" in out
        assert "hermes-mordred status" in out
        # The three storage-ish commands confuse users without a map:
        # `encryption` is the recommended switch, `vault` the low-level store.
        assert "encryption" in out


class TestPolicyExitCodeDocumented:
    def test_explain_and_dry_run_helps_mention_exit_2(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        _setup_subparser(parser)
        helps = " ".join(_iter_help_strings(parser))
        assert "exit code 2" in helps


class TestConfigureFlags:
    """Phase 4: configure --non-interactive is flag-driven (like network init)."""

    def test_configure_accepts_policy_flags(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        _setup_subparser(parser)
        ns = parser.parse_args(
            [
                "configure",
                "--non-interactive",
                "--policy",
                "strict",
                "--harness",
                "codex",
                "--cloud-allowlist",
                "anthropic",
            ]
        )
        assert ns.policy == "strict"
        assert ns.harness == "codex"
        assert ns.cloud_allowlist == "anthropic"
