"""Tests for ``hermes-mordred setup`` -- the one-command orchestrator.

Conventions mirror the sibling wizard test suites (``test_wizard_status_cli.py``,
``test_wizard_keyvault_native_cli.py``, ``test_wizard_network_init.py``):
direct function calls with ``home=tmp_path`` (no env vars unless the test is
specifically about one), a scripted :class:`PromptIO` double for interactive
flows, ``_RefusingPromptIO`` for never-prompt assertions, and monkeypatching
the ``setup_cli._probe_*`` / ``_run_*`` / ``_resolve_step_*`` seams so each
concern (orchestration order, a single step's decision logic, a real on-disk
probe) can be tested in isolation.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _identity, _native_key_id, _storage
from mordred_hermes.keyvault._memory_hook import memory_marker_path, memory_optout_marker_path
from mordred_hermes.wizard import cli, configure, encryption_cli, network_cli, setup_cli
from mordred_hermes.wizard._prompt_io import NonInteractiveAbort, _RefusingPromptIO
from mordred_hermes.wizard.encryption_cli import WorkspacePaths
from mordred_hermes.wizard.policy_writer import PolicyWriter

_STEP_HERMES = setup_cli._STEP_HERMES
_STEP_CONFIGURE = setup_cli._STEP_CONFIGURE
_STEP_NETWORK = setup_cli._STEP_NETWORK
_STEP_HARDWARE_HELPER = setup_cli._STEP_HARDWARE_HELPER
_STEP_KEYVAULT = setup_cli._STEP_KEYVAULT
_STEP_ENV_ENCRYPTION = setup_cli._STEP_ENV_ENCRYPTION
_STEP_MEMORY_ENCRYPTION = setup_cli._STEP_MEMORY_ENCRYPTION

_ALL_STEPS = (
    _STEP_HERMES,
    _STEP_CONFIGURE,
    _STEP_NETWORK,
    _STEP_HARDWARE_HELPER,
    _STEP_KEYVAULT,
    _STEP_ENV_ENCRYPTION,
    _STEP_MEMORY_ENCRYPTION,
)

_RESOLVER_BY_STEP = {
    _STEP_HERMES: "_resolve_step_hermes",
    _STEP_CONFIGURE: "_resolve_step_configure",
    _STEP_NETWORK: "_resolve_step_network",
    _STEP_HARDWARE_HELPER: "_resolve_step_hardware_helper",
    _STEP_KEYVAULT: "_resolve_step_keyvault",
    _STEP_ENV_ENCRYPTION: "_resolve_step_env_encryption",
    _STEP_MEMORY_ENCRYPTION: "_resolve_step_memory_encryption",
}

# --------------------------------------------------------------------------- #
# Test doubles + fixtures                                                     #
# --------------------------------------------------------------------------- #


@dataclass
class _DefaultEchoPromptIO:
    """Returns the supplied default for every prompt (simulates pressing Enter)."""

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        return default

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return default

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        return tuple(default)

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default


@dataclass
class _RecordingBoolPromptIO:
    """Records the ``(label, default)`` of every ``ask_bool`` call; other prompts fail the test."""

    answer: bool
    asked: list[tuple[str, bool]] = field(default_factory=list)

    def ask_choice(self, label: str, choices: Any, default: str, **kwargs: Any) -> str:
        raise AssertionError(f"unexpected ask_choice({label!r})")

    def ask_text(self, label: str, default: str = "", **kwargs: Any) -> str:
        raise AssertionError(f"unexpected ask_text({label!r})")

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        self.asked.append((label, default))
        return self.answer

    def ask_multi(self, label: str, choices: Any, default: Any = ()) -> tuple[str, ...]:
        raise AssertionError(f"unexpected ask_multi({label!r})")

    def ask_password(self, label: str, default: str = "", **kwargs: Any) -> str:
        raise AssertionError(f"unexpected ask_password({label!r})")


@dataclass
class _FakeSetupRunner:
    """Records every ``run(non_interactive=...)`` call; returns a fixed ``rc``."""

    rc: int = 0
    calls: list[bool] = field(default_factory=list)

    def run(self, *, non_interactive: bool) -> int:
        self.calls.append(non_interactive)
        return self.rc


class _RaisingSetupRunner:
    """A :class:`configure.SetupRunner` that fails the test if ever invoked."""

    def run(self, *, non_interactive: bool) -> int:
        raise AssertionError("setup_runner.run() must not be called")


def _raiser(message: str) -> Callable[..., Any]:
    """A keyword-only callable that fails the test if invoked -- for asserting a seam is never called."""

    def _fn(**kwargs: object) -> Any:
        raise AssertionError(message)

    return _fn


def _raise_non_interactive_abort(**kwargs: object) -> Any:
    """Simulates a delegated command aborting on a would-be prompt under ``--non-interactive``."""
    raise NonInteractiveAbort("simulated: a prompt would have been required")


def _workspace(tmp_path: Path) -> WorkspacePaths:
    return WorkspacePaths(
        image=tmp_path / "ws" / "img.sparsebundle",
        blob=tmp_path / "ws" / "passphrase.wrapped",
        mount=tmp_path / "ws-mnt",
    )


def _policy_writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )


def _vault_root(home: Path) -> Path:
    """Home-relative encryption *vault* root -- mirrors what
    ``_identity.resolve_root(None)`` (production ``root=``) resolves to when
    ``_hermes_home()`` == ``home`` (see ``test_wizard_vault_cli_inspection.py``'s
    ``TestResolveRoot.test_default_root_under_hermes_home``).

    Deliberately distinct from ``_storage.resolve_keyvault_dir(home)``
    (``<home>/mordred/keyvault``): that is the separate SE/TPM hardware-keyvault
    directory the keyvault step's own probe (``_probe_keyvault``) reads. Using
    the keyvault dir here too would point the env-encryption vault and the
    hardware keyvault at the very same on-disk directory in tests that exercise
    both in the same run.
    """
    return home.joinpath(*_identity._VAULT_SUBDIR)


def _run_setup(
    tmp_path: Path,
    *,
    platform: str = "darwin",
    prompt_io: Any,
    options: setup_cli.SetupOptions,
    policy_writer: PolicyWriter | None = None,
    setup_runner: Any = None,
) -> int:
    return setup_cli.run_setup(
        home=tmp_path,
        root=_vault_root(tmp_path),
        platform=platform,
        workspace=_workspace(tmp_path),
        prompt_io=prompt_io,
        policy_writer=policy_writer if policy_writer is not None else _policy_writer(tmp_path),
        setup_runner=setup_runner if setup_runner is not None else _RaisingSetupRunner(),
        options=options,
    )


def _force_steps_done(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Monkeypatch the given ``_resolve_step_*`` seams to report ``"done"`` immediately.

    Isolates a later step's behaviour from the earlier steps' own decision
    logic -- those are covered by their own dedicated tests.
    """
    for name in names:
        attr = _RESOLVER_BY_STEP[name]

        def _resolve(name: str = name, **kwargs: object) -> setup_cli.StepResult:
            return setup_cli.StepResult(name, "done", "forced done for test isolation")

        monkeypatch.setattr(setup_cli, attr, _resolve)


def _build_keyvault(home: Path, keys: dict[str, bytes]) -> Path:
    """Materialize a keyvault under ``home`` with the given ``{key_id: digest}``."""
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id, digest in keys.items():
        h = hashlib.sha256(key_id.encode("utf-8")).hexdigest()[:16]
        meta["keys"][h] = {"key_id": key_id, "created_at": "2026-06-11T00:00:00Z"}
        _storage.atomic_write(root / "digests" / f"{h}.commit", digest)
    _storage.save_meta(root, meta)
    return root


# --------------------------------------------------------------------------- #
# Orchestration -- run_setup()                                                #
# --------------------------------------------------------------------------- #


class TestRunSetupOrchestration:
    def test_everything_complete_reports_all_done_exit_0_no_runner_called(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(setup_cli, "_probe_hermes", lambda **kw: (True, "hermes ready"))
        monkeypatch.setattr(setup_cli, "_probe_configure", lambda **kw: (True, "configure ready"))
        monkeypatch.setattr(setup_cli, "_probe_network", lambda **kw: (True, "network ready"))
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: True)
        monkeypatch.setattr(setup_cli, "_probe_tpm_helper", lambda: True)
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **kw: ("initialised", "1 key"))
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (True, "env ready"))
        monkeypatch.setattr(setup_cli, "_probe_memory_encryption", lambda **kw: (True, "memory ready"))

        for seam in ("_run_configure", "_run_network", "_run_se_helper", "_run_tpm_helper"):
            monkeypatch.setattr(setup_cli, seam, _raiser(f"{seam} must not be called"))
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))
        monkeypatch.setattr(setup_cli, "_run_env_encryption", _raiser("_run_env_encryption must not be called"))
        monkeypatch.setattr(setup_cli, "_run_memory_encryption", _raiser("_run_memory_encryption must not be called"))

        rc = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 0
        out = capsys.readouterr().out
        for step in _ALL_STEPS:
            assert step in out
        assert "already done" in out
        # The final status dashboard prints too (run wasn't stopped early).
        assert "Mordred status:" in out

    def test_fresh_darwin_system_runs_steps_in_fixed_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        call_order: list[str] = []
        for step, attr in _RESOLVER_BY_STEP.items():

            def _resolve(step: str = step, **kwargs: object) -> setup_cli.StepResult:
                call_order.append(step)
                return setup_cli.StepResult(step, "ran", "mock")

            monkeypatch.setattr(setup_cli, attr, _resolve)

        rc = _run_setup(tmp_path, platform="darwin", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert call_order == list(_ALL_STEPS)
        assert rc == 0

    def test_keyvault_blocked_corrupt_meta_stops_run_without_touching_disk(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # ensure_layout() first (mode 0o700 dir, valid meta.json) so the
        # directory-mode gate passes and the corrupt *body* is what actually
        # trips -- a bare mkdir() leaves the dir at the umask default (0o755),
        # which fails _check_dir_mode's own 0o700 requirement first and would
        # silently test the wrong code path.
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta_path = root / "meta.json"
        meta_path.write_text("{not json", encoding="utf-8")
        meta_path.chmod(0o600)
        before = meta_path.read_bytes()

        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))

        rc = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 1
        assert meta_path.read_bytes() == before
        out = capsys.readouterr().out
        # Corrupt meta.json is repaired by hand (mirrors _refuse_if_initialised's
        # wording); "keyvault reset" is the pending/residual-journal remedy, not this one.
        assert "repair or remove it" in out
        assert _STEP_ENV_ENCRYPTION not in out  # stopped before the next step

    def test_keyvault_blocked_pending_native_key_journal_stops_run_without_touching_disk(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        meta[_native_key_id.PENDING_NATIVE_KEY_FIELD] = {
            "key_id": "interrupted",
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, "interrupted"),
        }
        _storage.save_meta(root, meta)
        before = (root / "meta.json").read_bytes()

        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))

        rc = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 1
        assert (root / "meta.json").read_bytes() == before
        out = capsys.readouterr().out
        assert "keyvault reset" in out

    def test_resume_keyvault_failure_then_success_continues_to_env_step(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        # F5: the real preflight would fail closed here anyway under pytest
        # (capsys leaves stdout non-a-tty), which is not what this test is
        # about -- monkeypatched to "pass" so _run_keyvault_init is actually
        # reached.
        monkeypatch.setattr(setup_cli, "_keyvault_preflight", lambda **kw: None)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", lambda **kw: 1)  # fails
        env_calls: list[bool] = []

        def _env_step(**kwargs: object) -> setup_cli.StepResult:
            env_calls.append(True)
            return setup_cli.StepResult(_STEP_ENV_ENCRYPTION, "ran", "mock")

        monkeypatch.setattr(setup_cli, "_resolve_step_env_encryption", _env_step)
        monkeypatch.setattr(setup_cli, "_probe_memory_encryption", lambda **kw: (True, "memory ready"))

        rc1 = _run_setup(
            tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(unattended_keys=False),
        )
        assert rc1 == 1
        assert env_calls == []  # never reached: the run stopped at the failed keyvault step

        # Second run: keyvault now reports initialised (probe-driven resume).
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **kw: ("initialised", "1 key"))

        rc2 = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())
        assert rc2 == 0
        assert env_calls == [True]  # earlier steps stayed "done"; the run continued past keyvault

    def test_non_interactive_keyvault_absent_exits_1_names_keyvault_init_never_prompts(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))

        # `_RefusingPromptIO` raises on any prompt method; if the keyvault step
        # ever tried to prompt, this call would fail with an unhandled
        # NonInteractiveAbort instead of returning cleanly -- that IS the proof.
        rc = _run_setup(
            tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )

        assert rc == 1
        out = capsys.readouterr().out
        assert "hermes-mordred keyvault init" in out

    def test_unknown_platform_is_unsupported_and_stops_before_keyvault(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK)
        monkeypatch.setattr(setup_cli, "_resolve_step_keyvault", _raiser("keyvault step must not run"))

        rc = _run_setup(tmp_path, platform="freebsd", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 1
        out = capsys.readouterr().out
        assert "not supported" in out.lower()
        # The keyvault step's own report line never appears -- the raiser above
        # already proves _resolve_step_keyvault was never called (it would have
        # failed this test with an AssertionError otherwise). A plain substring
        # check for "keyvault" would false-positive on the hardware-helper
        # step's own detail text ("hardware keyvault requires macOS...").
        assert f"\n  {_STEP_KEYVAULT} " not in out

    def test_network_manual_in_non_interactive_mode_does_not_stop_the_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE)
        # _resolve_step_network is left real: config.yaml has no network section
        # (probe incomplete) and prompt_io refuses -> "manual", must not stop.
        hw_calls: list[bool] = []

        def _hw_step(**kwargs: object) -> setup_cli.StepResult:
            hw_calls.append(True)
            return setup_cli.StepResult(_STEP_HARDWARE_HELPER, "done", "mock")

        monkeypatch.setattr(setup_cli, "_resolve_step_hardware_helper", _hw_step)
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **kw: ("initialised", "1 key"))
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (True, "env ready"))

        rc = _run_setup(
            tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )

        assert hw_calls == [True]  # the run continued past the network "manual" step
        assert rc == 1  # a "manual" step still makes the overall run non-clean

    def test_hardware_helper_failure_is_manual_and_run_continues_to_keyvault(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """F4: a hardware-helper build failure must not hard-stop the run --
        it resolves to "manual" (not the stopping "failed"), so the keyvault
        step still runs afterward."""
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK)
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: False)
        monkeypatch.setattr(setup_cli, "_run_se_helper", lambda **kw: 1)
        keyvault_calls: list[bool] = []

        def _kv_step(**kwargs: object) -> setup_cli.StepResult:
            keyvault_calls.append(True)
            return setup_cli.StepResult(_STEP_KEYVAULT, "done", "mock")

        monkeypatch.setattr(setup_cli, "_resolve_step_keyvault", _kv_step)
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (True, "env ready"))

        rc = _run_setup(tmp_path, platform="darwin", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert keyvault_calls == [True]  # the run continued past the hardware-helper "manual" step
        assert rc == 1  # a "manual" step still makes the overall run non-clean

    def test_non_tty_prompt_abort_still_prints_report(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """F8: run_setup's docstring contract ("always prints render_report")
        must hold even when a prompt fails closed on a non-TTY stdin, in
        interactive mode -- an unhandled NonInteractiveAbort escaping a
        _resolve_step_* would otherwise crash the whole run before the report
        prints."""
        monkeypatch.setattr(setup_cli, "_probe_hermes", lambda **kw: (False, "not set up"))
        _force_steps_done(
            monkeypatch, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER, _STEP_KEYVAULT, _STEP_ENV_ENCRYPTION
        )

        class _AbortingPromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                raise NonInteractiveAbort("stdin is not a terminal")

        rc = _run_setup(
            tmp_path,
            prompt_io=_AbortingPromptIO(),
            options=setup_cli.SetupOptions(),
            setup_runner=_RaisingSetupRunner(),
        )

        assert rc == 1
        out = capsys.readouterr().out
        assert "Setup summary:" in out
        assert _STEP_HERMES in out
        assert "TTY" in out


# --------------------------------------------------------------------------- #
# Step 1 -- hermes                                                            #
# --------------------------------------------------------------------------- #


class TestHermesStep:
    def test_probe_incomplete_when_hermes_missing_from_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        complete, detail = setup_cli._probe_hermes(home=tmp_path)
        assert complete is False
        assert "PATH" in detail

    def test_probe_complete_when_hermes_on_path_and_config_has_upstream_content(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes" if name == "hermes" else None)
        # A non-`plugins` top-level key is the upstream-authored evidence (F3):
        # `model` here stands in for whatever `hermes setup` itself writes.
        (tmp_path / "config.yaml").write_text("model:\n  provider: openai\nplugins: {}\n", encoding="utf-8")
        complete, detail = setup_cli._probe_hermes(home=tmp_path)
        assert complete is True
        assert "upstream" in detail.lower()

    def test_probe_incomplete_with_plugins_only_config_yaml(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """F3 regression: config.yaml containing ONLY Mordred's own `plugins`
        section is not evidence that upstream `hermes setup` ever ran -- Mordred's
        own `configure` step creates exactly this file."""
        monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes" if name == "hermes" else None)
        (tmp_path / "config.yaml").write_text("plugins: {}\n", encoding="utf-8")
        complete, detail = setup_cli._probe_hermes(home=tmp_path)
        assert complete is False
        assert "plugins" in detail.lower()

    def test_skip_flag_skips_without_running(self, tmp_path: Path) -> None:
        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(skip_hermes_setup=True),
        )
        assert result.action == "skipped"

    def test_non_interactive_incomplete_runs_setup_runner_non_interactively(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        runner = _FakeSetupRunner(rc=0)
        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            setup_runner=runner,
            options=setup_cli.SetupOptions(non_interactive=True),
        )
        assert result.action == "ran"
        assert runner.calls == [True]

    def test_non_zero_exit_warns_and_continues_as_manual(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """F2: a non-zero `hermes setup` exit must not silently count as
        success -- it resolves to "manual" (not a _SUCCESS_ACTIONS member) so
        the overall run exits 1, even though the run itself keeps going."""
        monkeypatch.setattr("shutil.which", lambda name: None)
        runner = _FakeSetupRunner(rc=7)
        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            setup_runner=runner,
            options=setup_cli.SetupOptions(non_interactive=True),
        )
        assert result.action == "manual"
        assert "7" in result.detail
        assert result.action not in setup_cli._SUCCESS_ACTIONS

    def test_interactive_declines_prompt_is_skipped(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)

        class _DeclinePromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                return False

        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_DeclinePromptIO(),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "skipped"

    def test_with_hermes_setup_forces_run_without_asking_even_when_done(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes" if name == "hermes" else None)
        (tmp_path / "config.yaml").write_text("plugins: {}\n", encoding="utf-8")
        runner = _FakeSetupRunner(rc=0)

        class _NeverAskPromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                raise AssertionError("must not ask when --with-hermes-setup forces the run")

        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_NeverAskPromptIO(),
            setup_runner=runner,
            options=setup_cli.SetupOptions(with_hermes_setup=True),
        )
        assert result.action == "ran"
        assert runner.calls == [False]

    def test_non_tty_ask_bool_abort_is_manual(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """F8: PromptToolkitIO fails closed with NonInteractiveAbort on a
        non-TTY stdin even in interactive mode (no --non-interactive) -- an
        unhandled abort here would skip render_report entirely, so this must
        be caught and reported as "manual" instead of propagating."""
        monkeypatch.setattr("shutil.which", lambda name: None)

        class _AbortingPromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                raise NonInteractiveAbort("stdin is not a terminal")

        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_AbortingPromptIO(),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "manual"
        assert "TTY" in result.detail


# --------------------------------------------------------------------------- #
# Step 2 -- configure                                                         #
# --------------------------------------------------------------------------- #


class TestConfigureStep:
    def test_probe_incomplete_without_config_yaml(self, tmp_path: Path) -> None:
        complete, _ = setup_cli._probe_configure(policy_writer=_policy_writer(tmp_path))
        assert complete is False

    def test_probe_incomplete_with_config_yaml_but_no_policy_json(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        pw.config_path.parent.mkdir(parents=True, exist_ok=True)
        pw.config_path.write_text("plugins: {}\n", encoding="utf-8")
        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is False
        assert "policy.json" in detail

    def test_probe_is_satisfied_by_a_real_configure_run(self, tmp_path: Path) -> None:
        """Regression guard for the probe/writer alignment: a genuine
        `configure` run (even with every prompt answered by its default) must
        always satisfy the probe -- otherwise `setup` would loop forever
        re-running `configure` on every invocation."""
        pw = _policy_writer(tmp_path)
        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is False, detail

        configure.run(
            setup_runner=_RaisingSetupRunner(),
            prompt_io=_DefaultEchoPromptIO(),
            policy_writer=pw,
            non_interactive=False,
            with_hermes_setup=False,
        )

        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is True, detail

    def test_non_interactive_incomplete_is_manual_and_does_not_write(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        result = setup_cli._resolve_step_configure(
            prompt_io=_RefusingPromptIO(),
            policy_writer=pw,
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )
        assert result.action == "manual"
        assert "configure" in result.detail
        assert not pw.config_path.exists()
        assert not pw.policy_json_path.exists()

    def test_write_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def _boom(**kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(setup_cli, "_run_configure", _boom)
        result = setup_cli._resolve_step_configure(
            prompt_io=_DefaultEchoPromptIO(),
            policy_writer=_policy_writer(tmp_path),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "failed"
        assert "disk full" in result.detail

    def test_yaml_error_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """F6: PolicyWriter.write() round-trip-loads config.yaml (ruamel.yaml)
        before editing it -- a syntactically corrupt file raises YAMLError
        there, which must be caught the same way as the existing OSError
        paths rather than propagating as an unhandled traceback."""
        from ruamel.yaml.error import YAMLError

        def _boom(**kwargs: object) -> None:
            raise YAMLError("bad yaml")

        monkeypatch.setattr(setup_cli, "_run_configure", _boom)
        result = setup_cli._resolve_step_configure(
            prompt_io=_DefaultEchoPromptIO(),
            policy_writer=_policy_writer(tmp_path),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "failed"
        assert "bad yaml" in result.detail

    def test_partial_state_missing_llm_guard_section_is_incomplete(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        pw.config_path.parent.mkdir(parents=True, exist_ok=True)
        pw.config_path.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: lenient\n  enabled: [mordred_privacy_check]\n",
            encoding="utf-8",
        )
        pw.policy_json_path.parent.mkdir(parents=True, exist_ok=True)
        pw.policy_json_path.write_text("{}", encoding="utf-8")
        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is False
        assert "llm_guard" in detail


# --------------------------------------------------------------------------- #
# Step 3 -- network                                                           #
# --------------------------------------------------------------------------- #


class TestNetworkStep:
    def test_probe_incomplete_without_section(self, tmp_path: Path) -> None:
        complete, _ = setup_cli._probe_network(config_path=tmp_path / "config.yaml")
        assert complete is False

    def test_probe_complete_with_valid_default_path(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("plugins:\n  mordred_network:\n    default_path: tor\n", encoding="utf-8")
        complete, detail = setup_cli._probe_network(config_path=tmp_path / "config.yaml")
        assert complete is True
        assert "tor" in detail

    def test_probe_incomplete_with_invalid_default_path_value(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text(
            "plugins:\n  mordred_network:\n    default_path: not-a-real-path\n", encoding="utf-8"
        )
        complete, _ = setup_cli._probe_network(config_path=tmp_path / "config.yaml")
        assert complete is False

    def test_non_interactive_incomplete_is_manual_and_continues(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        result = setup_cli._resolve_step_network(home=tmp_path, prompt_io=_RefusingPromptIO(), policy_writer=pw)
        assert result.action == "manual"
        assert "network init" in result.detail

    def test_run_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_run_network", lambda **kw: 1)
        pw = _policy_writer(tmp_path)
        result = setup_cli._resolve_step_network(home=tmp_path, prompt_io=_DefaultEchoPromptIO(), policy_writer=pw)
        assert result.action == "failed"

    def test_run_network_passes_home_derived_env_and_credentials_paths(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """F7: _run_network must pass env_path/credentials_path derived from
        the injected `home`, not let network_cli.run_init default them to the
        real production HERMES_BASE paths."""
        captured: dict[str, object] = {}

        def _spy(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(network_cli, "run_init", _spy)
        pw = _policy_writer(tmp_path)

        rc = setup_cli._run_network(home=tmp_path, prompt_io=_DefaultEchoPromptIO(), policy_writer=pw)

        assert rc == 0
        assert captured["env_path"] == tmp_path / ".env"
        assert captured["credentials_path"] == tmp_path / "mordred" / "credentials" / "network.json"


# --------------------------------------------------------------------------- #
# Step 4 -- hardware helper                                                   #
# --------------------------------------------------------------------------- #


class TestHardwareHelperStep:
    def test_darwin_probe_true_reports_done_without_running(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: True)
        monkeypatch.setattr(setup_cli, "_run_se_helper", _raiser("must not run enable-se"))
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="darwin")
        assert result.action == "done"

    def test_darwin_probe_false_runs_enable_se(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: False)
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_se_helper", lambda **kw: (calls.append(kw), 0)[-1])
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="darwin")
        assert result.action == "ran"
        assert calls == [{"home": tmp_path}]

    def test_darwin_enable_se_failure_is_manual_and_continues(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """F4: a build/install failure does not make the keyvault unusable (the
        software P-256 fallback still works on macOS), so it resolves to
        "manual" rather than the stopping "failed" action."""
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: False)
        monkeypatch.setattr(setup_cli, "_run_se_helper", lambda **kw: 1)
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="darwin")
        assert result.action == "manual"
        assert "software fallback" in result.detail.lower()
        assert "enable-se" in result.detail

    def test_linux_enable_tpm_failure_is_manual(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """F4 on Linux: still "manual" (never a stopping "failed") so the run
        reaches the keyvault step, where a genuinely TPM-less host fails there
        instead -- but the detail must NOT claim a software fallback exists on
        Linux (there isn't one; the TPM backend fails closed)."""
        monkeypatch.setattr(setup_cli, "_probe_tpm_helper", lambda: False)
        monkeypatch.setattr(setup_cli, "_run_tpm_helper", lambda **kw: 1)
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="linux")
        assert result.action == "manual"
        assert "enable-tpm" in result.detail
        assert "no software fallback" in result.detail.lower()

    def test_linux_dispatches_to_tpm_probe_and_runner(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_probe_tpm_helper", lambda: False)
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_tpm_helper", lambda **kw: (calls.append(kw), 0)[-1])
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="linux")
        assert result.action == "ran"
        assert calls == [{"home": tmp_path}]

    def test_unknown_platform_is_unsupported(self, tmp_path: Path) -> None:
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="freebsd")
        assert result.action == "unsupported"


class TestHelperProbeGuards:
    """F12: Path.home() (walked internally by the PATH/home helper lookups)
    can raise RuntimeError in a container with no passwd entry -- same
    rationale as the guard in status_cli.collect. A probe must degrade to
    "not installed" rather than let that propagate."""

    def test_se_helper_probe_raising_is_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _seckey_helper

        def _boom() -> str | None:
            raise RuntimeError("no passwd entry")

        monkeypatch.setattr(_seckey_helper, "_find_helper", _boom)
        assert setup_cli._probe_se_helper() is False

    def test_tpm_helper_probe_raising_is_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _seckey_helper

        def _boom() -> str | None:
            raise RuntimeError("no passwd entry")

        monkeypatch.setattr(_seckey_helper, "find_tpmkey_helper", _boom)
        assert setup_cli._probe_tpm_helper() is False


# --------------------------------------------------------------------------- #
# Step 5 -- keyvault                                                          #
# --------------------------------------------------------------------------- #


class TestKeyvaultProbe:
    def test_fresh_keyvault_dir_is_absent(self, tmp_path: Path) -> None:
        state, _ = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "absent"

    def test_empty_layout_with_no_keys_is_absent(self, tmp_path: Path) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        state, _ = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "absent"

    def test_keys_present_is_initialised(self, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32, "payments": b"\x02" * 32})
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "initialised"
        assert "2 key" in detail

    def test_corrupt_meta_is_blocked(self, tmp_path: Path) -> None:
        # ensure_layout() first so the dir is mode 0o700 (passing the
        # directory-mode gate) and only the meta.json *body* is corrupt.
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = root / "meta.json"
        meta.write_text("{not json", encoding="utf-8")
        meta.chmod(0o600)
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "corrupt" in detail.lower()

    def test_unreadable_dir_mode_is_blocked(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        root.mkdir(parents=True)  # left at the umask default, not 0o700
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "unreadable" in detail.lower()

    def test_pending_native_key_journal_is_blocked(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        meta[_native_key_id.PENDING_NATIVE_KEY_FIELD] = {
            "key_id": "interrupted",
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, "interrupted"),
        }
        _storage.save_meta(root, meta)
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "keyvault reset" in detail

    @pytest.mark.parametrize("field_name", [_native_key_id.AUDIT_KEY_FIELD, _native_key_id.PENDING_AUDIT_KEY_FIELD])
    def test_residual_ownership_with_empty_keys_is_blocked(self, field_name: str, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        meta[field_name] = {"residual": True}
        _storage.save_meta(root, meta)
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "residual" in detail.lower()

    def test_pending_reset_journal_is_blocked(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b"pending reset")
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "reset" in detail.lower()


class TestResolveUnattendedKeys:
    def test_unattended_flag_wins_regardless_of_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
        options = setup_cli.SetupOptions(unattended_keys=True)
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is True

    def test_attended_flag_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MORDRED_SEKEY_UNATTENDED", "1")
        options = setup_cli.SetupOptions(unattended_keys=False)
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is False

    def test_env_true_without_flag_resolves_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MORDRED_SEKEY_UNATTENDED", "1")
        options = setup_cli.SetupOptions()
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is True

    def test_interactive_no_flag_or_env_asks_with_default_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
        recorder = _RecordingBoolPromptIO(answer=True)
        options = setup_cli.SetupOptions()
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=recorder)
        assert result is True
        assert len(recorder.asked) == 1
        _, default = recorder.asked[0]
        assert default is False

    def test_non_interactive_no_flag_or_env_resolves_false_without_prompting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
        options = setup_cli.SetupOptions(non_interactive=True)
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is False


class TestKeyvaultStep:
    def test_initialised_is_done_without_running(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("must not run init_keyvault"))
        result = setup_cli._resolve_step_keyvault(
            home=tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions()
        )
        assert result.action == "done"

    def test_absent_runs_init_with_resolved_unattended(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # F5: real _keyvault_preflight touches network / stdout-tty state (the
        # air-gap check, the stdout-not-a-tty guard) -- monkeypatched to "pass"
        # so this test stays a pure unit test of the unattended-keys wiring.
        monkeypatch.setattr(setup_cli, "_keyvault_preflight", lambda **kw: None)
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", lambda **kw: (calls.append(kw), 0)[-1])
        result = setup_cli._resolve_step_keyvault(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(unattended_keys=True, store_seed_for_hd=False),
        )
        assert result.action == "ran"
        assert calls == [
            {
                "home": tmp_path,
                "prompt_io": calls[0]["prompt_io"],
                "store_seed_for_hd": False,
                "unattended": True,
                "flow_session": None,
            }
        ]

    def test_absent_run_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_keyvault_preflight", lambda **kw: None)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", lambda **kw: 1)
        result = setup_cli._resolve_step_keyvault(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(unattended_keys=False),
        )
        assert result.action == "failed"

    def test_preflight_refusal_is_manual_and_never_asks_unattended(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """F5: a preflight refusal (most commonly the fail-closed air-gap check
        while the host is online) must be reported "manual" BEFORE the
        unattended-keys question is asked -- order matters, since asking first
        and refusing after would waste the operator's answer."""
        monkeypatch.setattr(setup_cli, "_keyvault_preflight", lambda **kw: 1)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("must not run init_keyvault"))

        class _AskBoolRaisesPromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                raise AssertionError("must not ask the unattended-keys question when preflight refuses first")

        result = setup_cli._resolve_step_keyvault(
            home=tmp_path,
            prompt_io=_AskBoolRaisesPromptIO(),
            options=setup_cli.SetupOptions(),
        )

        assert result.action == "manual"
        assert "preflight" in result.detail.lower()

    def test_unattended_prompt_non_tty_abort_is_manual(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """F8: the unattended-keys ask_bool can also fail closed on a non-TTY
        stdin; must be caught and reported "manual", not propagate."""
        monkeypatch.setattr(setup_cli, "_keyvault_preflight", lambda **kw: None)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("must not run init_keyvault"))

        class _AbortingPromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                raise NonInteractiveAbort("stdin is not a terminal")

        result = setup_cli._resolve_step_keyvault(
            home=tmp_path,
            prompt_io=_AbortingPromptIO(),
            options=setup_cli.SetupOptions(),
        )

        assert result.action == "manual"
        assert "TTY" in result.detail


# --------------------------------------------------------------------------- #
# Step 6 -- env encryption                                                    #
# --------------------------------------------------------------------------- #


class TestEnvEncryptionStep:
    def test_fresh_system_with_no_plaintext_env_is_benign_not_failed(self, tmp_path: Path) -> None:
        root = _vault_root(tmp_path)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path, root=root, platform="darwin", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions()
        )
        assert result.action == "ran"
        assert "nothing to encrypt" in result.detail.lower() or ".env" in result.detail
        assert not (tmp_path / ".env").exists()

    def test_interactive_prompt_abort_creating_vault_is_manual(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # _run_env_encryption is mocked to raise NonInteractiveAbort directly --
        # exactly what a real `enable()` does when it must create the vault (a
        # one-time recovery-passphrase prompt) and the prompt_io fails closed
        # (e.g. stdin is not a TTY, or --non-interactive; both raise the same
        # exception). This isolates _resolve_step_env_encryption's own
        # exception-handling decision from env_decrypt_cli's real
        # device-key-store chain, which needs a real Keychain / pyobjc on
        # macOS to even attempt. options.non_interactive stays False here so
        # the F9 hardcoded gate does not short-circuit before the try/except
        # under test is even reached -- see TestNonInteractiveEnvGate for that
        # separate code path.
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")
        root = _vault_root(tmp_path)
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (False, "not enrolled"))
        monkeypatch.setattr(setup_cli, "_run_env_encryption", _raise_non_interactive_abort)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path, root=root, platform="darwin", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions()
        )
        assert result.action == "manual"
        assert "encryption enable env" in result.detail

    def test_run_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")
        root = _vault_root(tmp_path)
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (False, "not enrolled"))
        monkeypatch.setattr(setup_cli, "_run_env_encryption", lambda **kw: 1)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path,
            root=root,
            platform="darwin",
            prompt_io=_DefaultEchoPromptIO(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "failed"

    def test_os_error_in_run_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")
        root = _vault_root(tmp_path)
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (False, "not enrolled"))

        def _boom(**kwargs: object) -> int:
            raise OSError("disk full")

        monkeypatch.setattr(setup_cli, "_run_env_encryption", _boom)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path,
            root=root,
            platform="darwin",
            prompt_io=_DefaultEchoPromptIO(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "failed"
        assert "disk full" in result.detail

    def test_opted_out_probe_is_done_and_enable_never_called(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """F0/F11: an explicit `encryption disable env` opt-out must read as
        already satisfied ("done", paused) -- setup must never reverse it by
        calling enable() again."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        marker = encryption_cli._env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")
        (home / ".env").write_text("FOO=bar\n", encoding="utf-8")  # disable() restores the plaintext
        root = _vault_root(home)
        monkeypatch.setattr(
            setup_cli, "_run_env_encryption", _raiser("enable() must not be called for an opted-out target")
        )

        result = setup_cli._resolve_step_env_encryption(
            home=home, root=root, platform="darwin", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions()
        )

        assert result.action == "done"
        assert "paused" in result.detail.lower()
        assert marker.exists()  # the opt-out marker survives untouched
        assert (home / ".env").read_text(encoding="utf-8") == "FOO=bar\n"  # plaintext untouched too

    def test_drift_is_incomplete_and_runs_enable(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """F1: a stray plaintext .env at rest while nominally "active" (drift)
        must NOT read as already done -- setup must run enable() so the reseal
        branch merges the plaintext back into the vault."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_text("FOO=bar\n", encoding="utf-8")  # plaintext at rest while "active"
        root = _vault_root(home)
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_env_encryption", lambda **kw: (calls.append(kw), 0)[-1])

        result = setup_cli._resolve_step_env_encryption(
            home=home, root=root, platform="darwin", prompt_io=_DefaultEchoPromptIO(), options=setup_cli.SetupOptions()
        )

        assert len(calls) == 1  # enable()/reseal was actually attempted
        assert result.action == "ran"


class TestNonInteractiveEnvGate:
    """F9: --non-interactive must never reach enable()'s OS-level device-key
    unlock (Touch ID / passcode) when there is real work to do -- the gate is
    checked unconditionally, before the run is even attempted (mirrors the
    keyvault step's hardcoded non-interactive gate)."""

    def test_non_interactive_with_work_to_do_is_manual_without_attempting_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")
        root = _vault_root(tmp_path)
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (False, "not enrolled"))
        monkeypatch.setattr(
            setup_cli, "_run_env_encryption", _raiser("enable() must not be attempted under --non-interactive")
        )

        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path,
            root=root,
            platform="darwin",
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )

        assert result.action == "manual"
        assert "encryption enable env" in result.detail

    def test_non_interactive_with_nothing_to_do_is_still_benign(self, tmp_path: Path) -> None:
        """The non-interactive gate only applies when there IS work to do --
        the ".env"-missing / not-enrolled shortcut still takes priority."""
        root = _vault_root(tmp_path)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path,
            root=root,
            platform="darwin",
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )
        assert result.action == "ran"
        assert "nothing to encrypt" in result.detail.lower() or ".env" in result.detail


# --------------------------------------------------------------------------- #
# Step 7 -- agent-memory encryption                                           #
# --------------------------------------------------------------------------- #


def _arm_memory(home: Path) -> Path:
    marker = memory_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("armed\n", encoding="utf-8")
    return marker


def _pause_memory(home: Path) -> Path:
    marker = memory_optout_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("opt-out\n", encoding="utf-8")
    return marker


def _plaintext_memory(home: Path) -> Path:
    path = home / "memories" / "MEMORY.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# still plaintext\n", encoding="utf-8")
    return path


class TestMemoryEncryptionProbe:
    def test_not_enabled_without_markers(self, tmp_path: Path) -> None:
        complete, detail = setup_cli._probe_memory_encryption(home=tmp_path, platform="darwin")
        assert complete is False
        assert detail == "not enabled"

    def test_marker_is_complete(self, tmp_path: Path) -> None:
        _arm_memory(tmp_path)
        complete, detail = setup_cli._probe_memory_encryption(home=tmp_path, platform="darwin")
        assert complete is True
        assert detail == "enabled"

    def test_operator_optout_is_complete_and_says_paused(self, tmp_path: Path) -> None:
        """`encryption disable memory` is a deliberate pause; setup never reverses it."""
        _pause_memory(tmp_path)
        complete, detail = setup_cli._probe_memory_encryption(home=tmp_path, platform="darwin")
        assert complete is True
        assert "paused by operator" in detail

    def test_plaintext_file_while_armed_is_incomplete(self, tmp_path: Path) -> None:
        _arm_memory(tmp_path)
        _plaintext_memory(tmp_path)
        complete, detail = setup_cli._probe_memory_encryption(home=tmp_path, platform="darwin")
        assert complete is False
        assert "plaintext" in detail


class TestMemoryEncryptionStep:
    def _resolve(
        self, home: Path, *, platform: str = "darwin", prompt_io: Any = None, options: Any = None
    ) -> setup_cli.StepResult:
        return setup_cli._resolve_step_memory_encryption(
            home=home,
            root=_vault_root(home),
            platform=platform,
            prompt_io=prompt_io if prompt_io is not None else _DefaultEchoPromptIO(),
            options=options if options is not None else setup_cli.SetupOptions(),
        )

    def test_already_enabled_is_done_without_running(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _arm_memory(tmp_path)
        monkeypatch.setattr(setup_cli, "_run_memory_encryption", _raiser("enable() must not be called"))
        result = self._resolve(tmp_path)
        assert result.action == "done"

    def test_optout_is_done_and_enable_never_called(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _pause_memory(tmp_path)
        monkeypatch.setattr(
            setup_cli, "_run_memory_encryption", _raiser("enable() must not be called for a paused target")
        )
        result = self._resolve(tmp_path)
        assert result.action == "done"
        assert "paused" in result.detail.lower()
        assert memory_optout_marker_path(tmp_path).exists()

    def test_off_macos_is_skipped_and_never_runs(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """The sealing shims are macOS-only; skipping keeps a Linux run clean."""
        monkeypatch.setattr(setup_cli, "_run_memory_encryption", _raiser("enable() is macOS-only"))
        result = self._resolve(tmp_path, platform="linux")
        assert result.action == "skipped"
        assert "macos" in result.detail.lower()

    def test_manual_when_the_env_target_is_not_ready(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """The key rides on the .env shim, so env must be sealed first."""
        monkeypatch.setattr(setup_cli, "_run_memory_encryption", _raiser("enable() must not be called"))
        result = self._resolve(tmp_path)
        assert result.action == "manual"
        assert "encryption enable env" in result.detail

    def test_manual_under_non_interactive(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        monkeypatch.setattr(
            setup_cli, "_run_memory_encryption", _raiser("enable() must not be attempted under --non-interactive")
        )
        result = self._resolve(
            tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions(non_interactive=True)
        )
        assert result.action == "manual"
        assert "encryption enable memory" in result.detail

    def test_runs_enable_when_env_is_ready(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_memory_encryption", lambda **kw: (calls.append(kw), 0)[-1])

        result = self._resolve(tmp_path)

        assert result.action == "ran"
        assert len(calls) == 1
        assert calls[0]["platform"] == "darwin"

    def test_run_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        monkeypatch.setattr(setup_cli, "_run_memory_encryption", lambda **kw: 1)
        result = self._resolve(tmp_path)
        assert result.action == "failed"

    def test_os_error_in_run_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})

        def _boom(**kwargs: object) -> int:
            raise OSError("disk full")

        monkeypatch.setattr(setup_cli, "_run_memory_encryption", _boom)
        result = self._resolve(tmp_path)
        assert result.action == "failed"
        assert "disk full" in result.detail

    def test_prompt_abort_is_manual(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        monkeypatch.setattr(setup_cli, "_run_memory_encryption", _raise_non_interactive_abort)
        result = self._resolve(tmp_path)
        assert result.action == "manual"
        assert "encryption enable memory" in result.detail


# --------------------------------------------------------------------------- #
# render_report                                                               #
# --------------------------------------------------------------------------- #


class TestRenderReport:
    def test_renders_every_result(self) -> None:
        results = [
            setup_cli.StepResult(_STEP_HERMES, "done", "already there"),
            setup_cli.StepResult(_STEP_KEYVAULT, "blocked", "needs `hermes-mordred keyvault reset`"),
        ]
        text = setup_cli.render_report(results)
        assert "Setup summary:" in text
        assert _STEP_HERMES in text
        assert "already there" in text
        assert "BLOCKED" in text
        assert "keyvault reset" in text

    def test_unknown_action_degrades_to_raw_token(self) -> None:
        result = setup_cli.StepResult("mystery", "future-action", "detail")  # type: ignore[arg-type]
        text = setup_cli.render_report([result])
        assert "future-action" in text


# --------------------------------------------------------------------------- #
# argparse wiring                                                             #
# --------------------------------------------------------------------------- #


class TestCliWiring:
    def test_setup_command_is_wired(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["setup", "--non-interactive"])
        assert ns.non_interactive is True
        assert ns.with_hermes_setup is False
        assert ns.skip_hermes_setup is False
        assert ns.unattended_keys is None
        assert ns.store_seed_for_hd is True
        assert callable(ns.func)

    def test_hermes_setup_flags_are_mutually_exclusive(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["setup", "--with-hermes-setup", "--skip-hermes-setup"])

    def test_unattended_key_flags_are_mutually_exclusive(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["setup", "--unattended-keys", "--attended-keys"])

    def test_seed_storage_flags_are_mutually_exclusive(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["setup", "--store-seed-for-hd", "--paper-only"])

    def test_unattended_keys_flag_resolves_to_explicit_bool(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["setup", "--unattended-keys"])
        assert ns.unattended_keys is True
        ns = parser.parse_args(["setup", "--attended-keys"])
        assert ns.unattended_keys is False


# --------------------------------------------------------------------------- #
# cli_setup() -- the production argparse adapter                             #
# --------------------------------------------------------------------------- #


class TestCliSetupAdapter:
    def test_resolves_production_defaults_and_delegates_to_run_setup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``cli_setup`` must resolve the same production defaults
        ``status_cli.cli_status`` does, build the right :class:`SetupOptions`
        from the parsed flags, and pick ``_RefusingPromptIO`` iff
        ``--non-interactive`` was given."""
        monkeypatch.setattr(setup_cli, "_hermes_home", lambda: tmp_path)
        monkeypatch.setattr(setup_cli, "resolve_root", lambda override: tmp_path / "mordred" / "keyvault")
        monkeypatch.setattr(setup_cli, "_default_workspace_paths", lambda: _workspace(tmp_path))

        captured: dict[str, Any] = {}

        def _fake_run_setup(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(setup_cli, "run_setup", _fake_run_setup)

        args = argparse.Namespace(
            non_interactive=True,
            with_hermes_setup=False,
            skip_hermes_setup=True,
            unattended_keys=True,
            store_seed_for_hd=False,
        )
        rc = setup_cli.cli_setup(args)

        assert rc == 0
        assert captured["home"] == tmp_path
        assert isinstance(captured["prompt_io"], _RefusingPromptIO)
        options = captured["options"]
        assert isinstance(options, setup_cli.SetupOptions)
        assert options.non_interactive is True
        assert options.skip_hermes_setup is True
        assert options.unattended_keys is True
        assert options.store_seed_for_hd is False
        assert isinstance(captured["policy_writer"], PolicyWriter)
