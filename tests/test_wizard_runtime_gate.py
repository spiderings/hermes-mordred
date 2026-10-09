"""Unit tests for the shared fail-closed runtime gate (``wizard._runtime_gate``).

The env / config seals' end-to-end gate behavior stays covered by
``test_wizard_env_decrypt_cli.py`` / ``test_wizard_config_decrypt_cli.py``;
these tests pin the shared core's own contract: the platform / force
short-circuits, injected-over-default probe dispatch, the guidance message
assembly the two seals slot their target-specific text into, and the
running-gateway second check (probe every live gateway interpreter that belongs
to a different environment than the primary one, fail closed on the first
failure, and never block on a discovery that finds nothing).

Gateway discovery is always injected here, so no test reads this host's real
process table.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.wizard._runtime_gate import GatewayDiscovery, RuntimeProbe, runtime_gate

_MECHANISM = "  mechanism line one\n  mechanism line two\n"
_TAIL = "  tail line one\n  tail line two."


def _boom_probe(*, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
    raise AssertionError("probe must not be consulted")


def _boom_discovery(*, home: Path) -> list[GatewayRuntime]:
    raise AssertionError("gateway discovery must not be consulted")


def _no_gateways(*, home: Path) -> list[GatewayRuntime]:
    return []


class _RecordingProbe:
    """Probe that records every call and answers per interpreter.

    ``results`` maps a pinned interpreter (``None`` = the primary check) to the
    ``(ok, detail)`` answer; anything unlisted passes.
    """

    def __init__(self, results: dict[Path | None, tuple[bool, str]] | None = None) -> None:
        self.results = results or {}
        self.calls: list[Path | None] = []

    def __call__(self, *, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
        self.calls.append(runtime_python)
        return self.results.get(runtime_python, (True, "ok"))


def _gate(
    home: Path,
    *,
    platform: str = "darwin",
    runtime_probe: RuntimeProbe | None = None,
    force_runtime_unverified: bool = False,
    default_probe: RuntimeProbe | None = None,
    gateway_discovery: GatewayDiscovery = _no_gateways,
) -> int:
    if default_probe is None:
        default_probe = lambda *, home, runtime_python=None: (True, "ok")  # noqa: E731
    return runtime_gate(
        home=home,
        platform=platform,
        runtime_probe=runtime_probe,
        force_runtime_unverified=force_runtime_unverified,
        default_probe=default_probe,
        target="thing.yaml",
        mechanism=_MECHANISM,
        rerun_tail=_TAIL,
        gateway_discovery=gateway_discovery,
    )


class TestShortCircuits:
    def test_off_macos_never_consults_a_probe(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(
            tmp_path,
            platform="linux",
            runtime_probe=_boom_probe,
            default_probe=_boom_probe,
            gateway_discovery=_boom_discovery,
        )
        assert rc == 0
        out = capsys.readouterr()
        assert out.out == "" and out.err == ""

    def test_force_never_consults_a_probe(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(
            tmp_path,
            force_runtime_unverified=True,
            runtime_probe=_boom_probe,
            default_probe=_boom_probe,
            gateway_discovery=_boom_discovery,
        )
        assert rc == 0
        out = capsys.readouterr()
        assert out.out == "" and out.err == ""


class TestProbeDispatch:
    def test_probe_ok_passes_silently(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(tmp_path, runtime_probe=lambda *, home, runtime_python=None: (True, "ok"))
        assert rc == 0
        assert capsys.readouterr().err == ""

    def test_injected_probe_wins_over_default(self, tmp_path: Path) -> None:
        assert (
            _gate(tmp_path, runtime_probe=lambda *, home, runtime_python=None: (True, "ok"), default_probe=_boom_probe)
            == 0
        )

    def test_default_probe_used_when_none_injected(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = _gate(
            tmp_path,
            default_probe=lambda *, home, runtime_python=None: (False, "shim absent"),
            gateway_discovery=_boom_discovery,  # a failed primary probe never reaches discovery
        )
        assert rc == 1
        assert "shim absent" in capsys.readouterr().err


class TestRefusalMessage:
    def test_message_assembles_target_detail_mechanism_and_tail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Pin runtime discovery to a deterministic interpreter so the uv line
        # is assertable regardless of what this host has on $PATH.
        monkeypatch.setenv("MORDRED_HERMES_RUNTIME_PYTHON", sys.executable)
        rc = _gate(tmp_path, runtime_probe=lambda *, home, runtime_python=None: (False, "no shim"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "refusing to vault-seal thing.yaml — no shim.\n" in err
        assert _MECHANISM in err
        assert "  Install the matching Mordred build into that interpreter:\n" in err
        extra = "macos" if sys.platform == "darwin" else "keyvault,telegram"
        assert (f"    uv pip install --python {sys.executable} 'hermes-mordred[{extra}]'\n") in err
        assert _TAIL in err

    def test_runtime_python_falls_back_under_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # With no override, no managed venv under home, and no `hermes` on
        # $PATH, the guidance still names a concrete interpreter path.
        monkeypatch.delenv("MORDRED_HERMES_RUNTIME_PYTHON", raising=False)
        monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
        rc = _gate(tmp_path, runtime_probe=lambda *, home, runtime_python=None: (False, "no shim"))
        assert rc == 1
        expected = tmp_path / "hermes-agent" / "venv" / "bin" / "python3"
        assert str(expected) in capsys.readouterr().err


class TestRunningGatewayCheck:
    """The second check: probe the interpreters that are running a gateway NOW.

    The 2026-06-25 incident passed the primary probe (the managed venv had
    mordred) while the live gateway ran from a repo ``.venv`` that did not, so
    the seal deleted a plaintext the running process could never unseal.
    """

    def _primary(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """Pin the primary runtime to a concrete interpreter under ``tmp_path``."""
        bindir = tmp_path / "managed" / "bin"
        bindir.mkdir(parents=True)
        python = bindir / "python3"
        python.write_text("")
        monkeypatch.setenv("MORDRED_HERMES_RUNTIME_PYTHON", str(python))
        return python

    def _foreign(self, tmp_path: Path) -> Path:
        bindir = tmp_path / "repo" / ".venv" / "bin"
        bindir.mkdir(parents=True)
        python = bindir / "python"
        python.write_text("")
        return python

    def test_no_gateway_found_costs_a_single_probe(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._primary(tmp_path, monkeypatch)
        probe = _RecordingProbe()
        assert _gate(tmp_path, runtime_probe=probe, gateway_discovery=_no_gateways) == 0
        assert probe.calls == [None]  # only the primary check ran

    def test_identical_interpreter_is_not_reprobed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The gateway is running the very interpreter the primary check just
        # cleared — a second subprocess would answer the same question.
        primary = self._primary(tmp_path, monkeypatch)
        probe = _RecordingProbe()
        rc = _gate(
            tmp_path,
            runtime_probe=probe,
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=4242, python=primary)],
        )
        assert rc == 0
        assert probe.calls == [None]

    def test_sibling_name_in_the_same_bin_is_probed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # `python` next to the primary `python3` is almost certainly the same
        # environment, but the skip key includes the name so that the case below
        # (same bin/, different VERSION) can never be skipped. One redundant
        # probe is the price.
        primary = self._primary(tmp_path, monkeypatch)
        sibling = primary.with_name("python")
        sibling.write_text("")
        probe = _RecordingProbe()
        rc = _gate(
            tmp_path,
            runtime_probe=probe,
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=4242, python=sibling)],
        )
        assert rc == 0
        assert probe.calls == [None, sibling]

    def test_same_bin_different_python_version_is_probed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # /usr/local/bin/python3.11 (primary) and /usr/local/bin/python3.13
        # (gateway) share a directory but NOT a site-packages: skipping on the
        # directory alone would let the gateway through unprobed.
        primary = self._primary(tmp_path, monkeypatch)
        other_version = primary.with_name("python3.13")
        other_version.write_text("")
        probe = _RecordingProbe({other_version: (False, "no mordred in 3.13")})
        rc = _gate(
            tmp_path,
            runtime_probe=probe,
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=4242, python=other_version)],
        )
        assert rc == 1
        assert probe.calls == [None, other_version]
        assert "no mordred in 3.13" in capsys.readouterr().err

    def test_probe_that_raises_is_treated_as_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Fail closed: an exploding probe (non-UTF-8 stderr, a broken injection)
        # proves nothing, so it must refuse — not raise out of the CLI.
        self._primary(tmp_path, monkeypatch)
        foreign = self._foreign(tmp_path)

        def _probe(*, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
            if runtime_python is None:
                return True, "ok"
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

        rc = _gate(
            tmp_path,
            runtime_probe=_probe,
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=4242, python=foreign)],
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "refusing to vault-seal thing.yaml" in err
        assert "raised" in err and str(foreign) in err

    def test_failing_gateway_refuses_and_names_the_interpreter_and_pid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._primary(tmp_path, monkeypatch)
        foreign = self._foreign(tmp_path)
        probe = _RecordingProbe({foreign: (False, "no mordred in that venv")})
        rc = _gate(
            tmp_path,
            runtime_probe=probe,
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=4242, python=foreign)],
        )
        assert rc == 1
        assert probe.calls == [None, foreign]  # primary passed, gateway failed
        err = capsys.readouterr().err
        assert "refusing to vault-seal thing.yaml" in err
        assert "a hermes gateway is RUNNING from a different" in err
        assert f"{foreign} (pid 4242)" in err
        assert "no mordred in that venv" in err
        extra = "macos" if sys.platform == "darwin" else "keyvault,telegram"
        assert f"    uv pip install --python {foreign} 'hermes-mordred[{extra}]'\n" in err
        assert _MECHANISM in err
        assert _TAIL in err  # the force/re-run guidance still closes the message

    def test_refusal_without_a_pid_omits_the_pid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._primary(tmp_path, monkeypatch)
        foreign = self._foreign(tmp_path)
        rc = _gate(
            tmp_path,
            runtime_probe=_RecordingProbe({foreign: (False, "no mordred")}),
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=None, python=foreign)],
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert f"{foreign}.\n" in err
        assert "(pid " not in err  # no pid recorded -> no empty parenthetical

    def test_passing_gateway_proceeds(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._primary(tmp_path, monkeypatch)
        foreign = self._foreign(tmp_path)
        probe = _RecordingProbe()
        rc = _gate(
            tmp_path,
            runtime_probe=probe,
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=7, python=foreign)],
        )
        assert rc == 0
        assert probe.calls == [None, foreign]

    def test_first_failing_gateway_wins_and_stops_probing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._primary(tmp_path, monkeypatch)
        first, second = self._foreign(tmp_path), tmp_path / "other" / "bin" / "python3"
        second.parent.mkdir(parents=True)
        second.write_text("")
        probe = _RecordingProbe({first: (False, "no mordred")})
        rc = _gate(
            tmp_path,
            runtime_probe=probe,
            gateway_discovery=lambda *, home: [
                GatewayRuntime(pid=1, python=first),
                GatewayRuntime(pid=2, python=second),
            ],
        )
        assert rc == 1
        assert probe.calls == [None, first]  # fail closed on the first miss

    def test_discovery_failure_does_not_block_the_seal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # No `ps`, no permission, exotic host: an inconclusive scan must behave
        # exactly like the pre-existing gate, or the seal becomes un-passable.
        self._primary(tmp_path, monkeypatch)
        probe = _RecordingProbe()
        rc = _gate(tmp_path, runtime_probe=probe, gateway_discovery=_boom_discovery)
        assert rc == 0
        assert probe.calls == [None]
        assert capsys.readouterr().err == ""

    def test_unresolvable_primary_still_probes_every_gateway(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With no primary interpreter to compare against, every gateway is
        # "different" — fail closed rather than skip the check.
        monkeypatch.delenv("MORDRED_HERMES_RUNTIME_PYTHON", raising=False)
        monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
        foreign = self._foreign(tmp_path)
        probe = _RecordingProbe({foreign: (False, "no mordred")})
        rc = _gate(
            tmp_path,
            runtime_probe=probe,
            gateway_discovery=lambda *, home: [GatewayRuntime(pid=3, python=foreign)],
        )
        assert rc == 1
        assert probe.calls == [None, foreign]
