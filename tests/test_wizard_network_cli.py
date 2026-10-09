"""Tests for ``hermes mordred network {use,status}`` (Phase 3 PR2-C).

Before PR2 these handlers were ``NotImplementedError`` stubs (see
``test_wizard_cli.py::TestStubHandlersDeferProperly``). PR2-C wires them
to the real surface:

- ``network use <path>``: writes ``plugins.mordred_network.default_path``
  into ``~/.hermes/config.yaml`` for registration-time activation in the next
  Hermes process. If a runtime singleton is already registered, :func:`api.use`
  confirms a same-route no-op or refuses a conflicting frozen route with
  restart guidance.
- ``network status``: prints in-process runtime status if available,
  else falls back to the configured-but-not-active disk state.

The cross-process persistence model is documented inline. Live in-session
switching is deliberately unsupported because provider clients snapshot their
transport when the process starts.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import BringupFailed, PathSwitchRequiresRestart, UnknownPath

# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class _FakeRuntime:
    def __init__(self) -> None:
        self.use_calls: list[str] = []
        self.use_raises: BaseException | None = None
        self._active_path: str = "clearnet"
        self._ready: bool = False
        self.dropped: bool = False

    def use(self, path: str) -> None:
        self.use_calls.append(path)
        if self.use_raises is not None:
            raise self.use_raises
        self._active_path = path
        self._ready = True

    def status(self) -> Any:
        from mordred_hermes.network.api import NetworkStatus

        return NetworkStatus(
            active_path=self._active_path,
            ready=self._ready,
            last_health=True,
        )

    def health(self) -> bool:
        return True

    def stop(self) -> None:
        pass

    def is_dropped(self) -> bool:
        return self.dropped


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset_api() -> Any:
    from mordred_hermes.network import api

    api.reset_runtime_for_tests()
    yield
    api.reset_runtime_for_tests()


def _make_args(**fields: Any) -> argparse.Namespace:
    return argparse.Namespace(**fields)


# --------------------------------------------------------------------------- #
# network use                                                                 #
# --------------------------------------------------------------------------- #


class TestNetworkUseLive:
    """In-process runtime registered - api.use is called directly."""

    def test_use_tor_calls_api_use(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        args = _make_args(
            path="tor",
            config_path=tmp_path / "config.yaml",
        )
        rc = cli._handle_network_use(args)
        assert rc == 0
        assert rt.use_calls == ["tor"]
        out = capsys.readouterr().out
        assert "tor" in out.lower()

    def test_use_vpn_returns_zero(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        args = _make_args(
            path="vpn",
            config_path=tmp_path / "config.yaml",
        )
        assert cli._handle_network_use(args) == 0
        assert rt.use_calls == ["vpn"]

    def test_use_unknown_path_returns_nonzero(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt.use_raises = UnknownPath("bad")
        api.set_runtime(rt)
        args = _make_args(
            path="i2p",
            config_path=tmp_path / "config.yaml",
        )
        rc = cli._handle_network_use(args)
        assert rc != 0

    def test_use_bringup_failure_returns_nonzero(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt.use_raises = BringupFailed("tor timeout")
        api.set_runtime(rt)
        args = _make_args(
            path="tor",
            config_path=tmp_path / "config.yaml",
        )
        rc = cli._handle_network_use(args)
        assert rc != 0

    def test_conflicting_frozen_route_is_saved_and_prints_restart_guidance(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt.use_raises = PathSwitchRequiresRestart("Restart Hermes to apply the saved route.")
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        args = _make_args(path="vpn", config_path=config)

        assert cli._handle_network_use(args) != 0
        assert "restart hermes" in capsys.readouterr().err.lower()
        assert "default_path: vpn" in config.read_text(encoding="utf-8")


class TestNetworkUsePersistence:
    """``use`` always writes ``default_path`` to config.yaml so the next
    Hermes session opens with the user's preferred path."""

    def test_use_writes_default_path_to_config(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"

    def test_use_preserves_other_plugin_sections(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: strict\n  mordred_llm_guard:\n    harness_primary: codex\n"
        )
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "strict"
        assert data["plugins"]["mordred_llm_guard"]["harness_primary"] == "codex"
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"


class TestNetworkUseAtomicity:
    """H1 fix (review 2026-05-14): writes must use PolicyWriter so they
    inherit the canonical ``_atomic_write_text`` (tempfile + os.replace).

    Detection strategy: PolicyWriter's ``_ensure_plugins_enabled`` adds
    the full Mordred-plugin list to ``plugins.enabled`` on every write
    (HOOK_PAYLOADS.md §1). A plain ``Path.write_text``
    would not produce that side effect. Asserting the side effect proves
    the write went through PolicyWriter and therefore got atomic-rename
    semantics — without us having to interrupt a write to test atomicity
    directly.
    """

    def test_use_writes_via_policy_writer_adding_plugins_enabled(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert "enabled" in data["plugins"], (
            "PolicyWriter must add plugins.enabled — network_cli regressed to a non-atomic write path"
        )
        enabled = data["plugins"]["enabled"]
        # The single Mordred plugin must be enabled (PolicyWriter contract).
        assert "mordred" in enabled, "mordred missing from plugins.enabled after network_cli write"

    def test_use_does_not_leave_tmp_artifact(self, tmp_path: Path) -> None:
        """PolicyWriter's ``_atomic_write_text`` writes to ``<name>.tmp``
        and renames; a clean run must not leave the tempfile behind."""
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)
        tmp_artifact = config.with_name(config.name + ".tmp")
        assert not tmp_artifact.exists()


class TestNetworkUseStandalone:
    """No runtime registered - the CLI still writes to disk and reports
    the persistence-only effect to the user."""

    def test_no_runtime_writes_disk_only_and_returns_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import cli

        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        rc = cli._handle_network_use(args)
        assert rc == 0

        assert config.exists()
        out = capsys.readouterr().out
        # The message must communicate the change applies on the next session
        # (not the running process), without the old confusing "deferred" wording.
        assert "next" in out.lower() and "session" in out.lower()

    def test_no_runtime_tor_missing_prints_install_guidance(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.wizard import cli

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        args = _make_args(path="tor", config_path=tmp_path / "config.yaml")
        rc = cli._handle_network_use(args)

        assert rc == 0
        out = capsys.readouterr().out
        assert "Tor is not available yet" in out
        assert "brew install tor" in out
        assert "--tor-binary" in out

    def test_no_runtime_vpn_missing_prints_install_guidance(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.wizard import cli

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        monkeypatch.setattr("pathlib.Path.exists", lambda _self: False)
        args = _make_args(path="vpn", config_path=tmp_path / "config.yaml")
        rc = cli._handle_network_use(args)

        assert rc == 0
        out = capsys.readouterr().out
        assert "Mullvad CLI is not available yet" in out
        assert "mullvad account login" in out
        assert "network init --path vpn" in out


# --------------------------------------------------------------------------- #
# network status                                                              #
# --------------------------------------------------------------------------- #


class TestNetworkStatusLive:
    def test_active_runtime_prints_status(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt._active_path = "tor"
        rt._ready = True
        api.set_runtime(rt)
        args = _make_args(config_path=tmp_path / "config.yaml")
        rc = cli._handle_network_status(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "tor" in out.lower()
        assert "ready" in out.lower()

    def test_status_includes_dropped_warning_when_flagged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt._active_path = "tor"
        rt._ready = True
        rt.dropped = True
        api.set_runtime(rt)
        args = _make_args(config_path=tmp_path / "config.yaml")
        cli._handle_network_status(args)
        out = capsys.readouterr().out
        assert "drop" in out.lower()
        assert "restart hermes" in out.lower()


class TestNetworkStatusStandalone:
    def test_no_runtime_falls_back_to_disk(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.wizard import cli

        config = tmp_path / "config.yaml"
        config.write_text("plugins:\n  mordred_network:\n    default_path: vpn\n")
        args = _make_args(config_path=config)
        rc = cli._handle_network_status(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "vpn" in out.lower()
        assert "not active" in out.lower() or "configured" in out.lower()

    def test_no_runtime_no_config_falls_back_to_clearnet(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import cli

        args = _make_args(config_path=tmp_path / "missing.yaml")
        rc = cli._handle_network_status(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "clearnet" in out.lower()


class TestNetworkInitGuidance:
    def test_init_summary_warns_when_selected_tor_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import network_cli

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        summary = network_cli._init_summary(
            network_cli.NetworkAnswers(
                default_network_path="tor",
                tor_binary_path="tor",
                tor_socks_port=9050,
                mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
                mullvad_relay_country="auto",
                mullvad_killswitch=False,
            ),
            secret_written=False,
        )
        assert "Tor is not available yet" in summary
        assert "--tor-binary" in summary

    def test_init_summary_warns_when_selected_vpn_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import network_cli

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        monkeypatch.setattr("pathlib.Path.exists", lambda _self: False)
        summary = network_cli._init_summary(
            network_cli.NetworkAnswers(
                default_network_path="vpn",
                tor_binary_path="tor",
                tor_socks_port=9050,
                mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
                mullvad_relay_country="auto",
                mullvad_killswitch=False,
            ),
            secret_written=False,
        )
        assert "Mullvad CLI is not available yet" in summary
        assert "mullvad account login" in summary

    def test_init_summary_custom_provider_does_not_warn_about_mullvad(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A custom-provider (e.g. ExpressVPN) user must never be told to
        install Mullvad — the warning must be about *their* CLI."""
        from mordred_hermes.wizard import network_cli

        # Custom CLI resolves on PATH → the vpn route is ready, no warning.
        monkeypatch.setattr(
            "mordred_hermes.network.guidance.shutil.which",
            lambda _name: "/usr/local/bin/expressvpnctl",
        )
        summary = network_cli._init_summary(
            network_cli.NetworkAnswers(
                default_network_path="vpn",
                tor_binary_path="tor",
                tor_socks_port=9050,
                mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
                mullvad_relay_country="auto",
                mullvad_killswitch=False,
                vpn_provider="custom",
                custom_up_cmd=("expressvpnctl", "connect", "smart"),
                custom_down_cmd=("expressvpnctl", "disconnect"),
                custom_health_cmd=("expressvpnctl", "get", "connectionstate"),
            ),
            secret_written=False,
        )
        assert "Mullvad" not in summary

    def test_init_summary_custom_provider_missing_cli_warns_about_custom(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import network_cli

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        monkeypatch.setattr("pathlib.Path.exists", lambda _self: False)
        summary = network_cli._init_summary(
            network_cli.NetworkAnswers(
                default_network_path="vpn",
                tor_binary_path="tor",
                tor_socks_port=9050,
                mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
                mullvad_relay_country="auto",
                mullvad_killswitch=False,
                vpn_provider="custom",
                custom_up_cmd=("expressvpnctl", "connect", "smart"),
            ),
            secret_written=False,
        )
        assert "Mullvad" not in summary
        assert "expressvpnctl" in summary


class TestDependencyWarningProviderAware:
    """``dependency_warning`` must reflect the configured ``vpn_provider`` so a
    non-Mullvad VPN user is not misled into installing Mullvad."""

    def test_vpn_custom_available_no_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.network import guidance

        monkeypatch.setattr(
            "mordred_hermes.network.guidance.shutil.which",
            lambda _name: "/usr/local/bin/expressvpnctl",
        )
        warning = guidance.dependency_warning("vpn", vpn_provider="custom", custom_up_cmd=("expressvpnctl", "connect"))
        assert warning is None

    def test_vpn_custom_missing_names_custom_cli_not_mullvad(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.network import guidance

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        monkeypatch.setattr("pathlib.Path.exists", lambda _self: False)
        warning = guidance.dependency_warning("vpn", vpn_provider="custom", custom_up_cmd=("expressvpnctl", "connect"))
        assert warning is not None
        assert "Mullvad" not in warning
        assert "expressvpnctl" in warning

    def test_vpn_mullvad_still_warns_about_mullvad(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.network import guidance

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        monkeypatch.setattr("pathlib.Path.exists", lambda _self: False)
        warning = guidance.dependency_warning("vpn", vpn_provider="mullvad")
        assert warning is not None
        assert "Mullvad CLI is not available yet" in warning

    def test_vpn_wireguard_missing_names_wireguard_not_mullvad(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from mordred_hermes.network import guidance

        monkeypatch.setattr("mordred_hermes.network.guidance.shutil.which", lambda _name: None)
        warning = guidance.dependency_warning(
            "vpn",
            vpn_provider="wireguard",
            wireguard_config_path=str(tmp_path / "missing.conf"),
        )
        assert warning is not None
        assert "Mullvad" not in warning


# --------------------------------------------------------------------------- #
# network use - merge preservation (Phase 3 PR3a, review-L4 fix)              #
# --------------------------------------------------------------------------- #


class TestNetworkUseMergePreservation:
    """``network use <path>`` must NOT clobber Tor/Mullvad sub-fields.

    PR2 routed through ``upsert_mordred_sections`` which whole-replaces the
    section -- documented at ``network_cli.py:135-141`` as a known caveat to
    be fixed when Phase 3.2 wizard prompts land. PR3a routes through the new
    ``merge_mordred_sections`` so partial writes preserve everything else.
    """

    def test_use_clearnet_preserves_tor_subfields(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard import cli

        seed = """\
plugins:
  mordred_network:
    default_path: tor
    tor_binary_path: /usr/bin/tor
    tor_socks_port: 9050
    mullvad_account_id_env: MORDRED_MULLVAD_ACCOUNT
    mullvad_relay_country: jp
"""
        config = tmp_path / "config.yaml"
        config.write_text(seed, encoding="utf-8")

        args = _make_args(path="clearnet", config_path=config)
        rc = cli._handle_network_use(args)
        assert rc == 0

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "clearnet"
        # All four sub-fields must survive the partial write.
        assert section["tor_binary_path"] == "/usr/bin/tor"
        assert section["tor_socks_port"] == 9050
        assert section["mullvad_account_id_env"] == "MORDRED_MULLVAD_ACCOUNT"
        assert section["mullvad_relay_country"] == "jp"

    def test_use_tor_then_use_clearnet_preserves_tor_subfields_across_runs(self, tmp_path: Path) -> None:
        """Two-step regression: configure persists Tor sub-fields, then a
        subsequent ``network use clearnet`` must not drop them."""
        from mordred_hermes.wizard import cli

        seed = """\
plugins:
  mordred_network:
    tor_binary_path: /opt/tor/bin/tor
    tor_socks_port: 19050
"""
        config = tmp_path / "config.yaml"
        config.write_text(seed, encoding="utf-8")

        # First switch to tor.
        rc1 = cli._handle_network_use(_make_args(path="tor", config_path=config))
        assert rc1 == 0
        # Then back to clearnet.
        rc2 = cli._handle_network_use(_make_args(path="clearnet", config_path=config))
        assert rc2 == 0

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "clearnet"
        assert section["tor_binary_path"] == "/opt/tor/bin/tor"
        assert section["tor_socks_port"] == 19050


# --------------------------------------------------------------------------- #
# Error channel + exit codes (UX review 2026-06-11). network_cli was the only #
# wizard module printing errors to stdout (0 uses of stderr vs 22-24 in the   #
# others), and used an ad hoc exit code 3 for a write failure.                #
# --------------------------------------------------------------------------- #


class TestUseErrorChannel:
    def test_write_failure_reports_to_stderr_with_rc_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import network_cli

        def _boom(config_path: Path, default_path: str) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(network_cli, "_write_default_path_to_config", _boom)
        args = _make_args(path="tor", config_path=tmp_path / "config.yaml")
        rc = network_cli.handle_use(args)
        assert rc == 1
        captured = capsys.readouterr()
        assert "disk full" in captured.err
        assert captured.out == ""

    def test_bringup_failure_reports_to_stderr(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import network_cli

        rt = _FakeRuntime()
        rt.use_raises = BringupFailed("tor timeout")
        api.set_runtime(rt)
        args = _make_args(path="tor", config_path=tmp_path / "config.yaml")
        rc = network_cli.handle_use(args)
        assert rc == 1
        captured = capsys.readouterr()
        assert "tor timeout" in captured.err


class TestOutputHasNoPythonRepr:
    """UX review 2026-06-11 Phase 3: enum values and paths must not be
    rendered through ``!r`` — users see Python quoting ('tor') leak into
    what should be plain CLI output."""

    def test_use_deferred_message_is_plain(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.wizard import network_cli

        args = _make_args(path="tor", config_path=tmp_path / "config.yaml")
        rc = network_cli.handle_use(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "'tor'" not in out
        assert "tor" in out

    def test_live_status_message_is_plain(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import network_cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        rt.use("tor")
        rc = network_cli.handle_status(_make_args(config_path=tmp_path / "config.yaml"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "'tor'" not in out
        assert "tor" in out

    def test_disk_status_message_is_plain(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.wizard import network_cli

        rc = network_cli.handle_status(_make_args(config_path=tmp_path / "config.yaml"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "'clearnet'" not in out
        assert "clearnet" in out


class TestStatusJson:
    """Phase 5 (UX review 2026-06-11): read commands need --json for scripting."""

    def test_live_status_json(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        import json

        from mordred_hermes.network import api
        from mordred_hermes.wizard import network_cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        rt.use("tor")
        rc = network_cli.handle_status(_make_args(config_path=tmp_path / "config.yaml", json=True))
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["live"] is True
        assert body["active_path"] == "tor"
        assert body["ready"] is True
        assert body["dropped"] is False

    def test_disk_status_json(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        import json

        from mordred_hermes.wizard import network_cli

        rc = network_cli.handle_status(_make_args(config_path=tmp_path / "config.yaml", json=True))
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["live"] is False
        assert body["configured_path"] == "clearnet"

    def test_status_json_flag_is_wired(self) -> None:
        from mordred_hermes.wizard import cli

        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["network", "status", "--json"])
        assert ns.json is True


class TestErrorColour:
    """`network use` errors route through _term.emit_error: red on a tty, plain off it."""

    def test_unknown_path_error_is_red_when_forced(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import network_cli

        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        rc = network_cli.handle_use(argparse.Namespace(path="bogus"))
        assert rc == 2
        err = capsys.readouterr().err
        assert "\033[31m" in err  # red `error:` label
        assert "unknown network path" in err

    def test_unknown_path_error_plain_and_prefixed_off_tty(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Off a tty the output stays byte-identical to the old manual `error:` print.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        from mordred_hermes.wizard import network_cli

        rc = network_cli.handle_use(argparse.Namespace(path="bogus"))
        assert rc == 2
        err = capsys.readouterr().err
        assert err.startswith("error: unknown network path")
        assert "\033" not in err

    def test_dependency_warning_is_styled_yellow_on_a_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The post-set dependency advisory stays on stdout (intentional — it
        # follows the route-set success lines; existing tests assert it there)
        # but now reads as a warning: yellow on a tty.
        from mordred_hermes.wizard import network_cli

        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        monkeypatch.setattr(network_cli, "_runtime_registered", lambda: False)
        monkeypatch.setattr(
            network_cli, "_dependency_warning_for_configured_path", lambda *a, **k: "tor is not installed"
        )
        rc = network_cli.handle_use(_make_args(config_path=tmp_path / "config.yaml", path="tor"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "tor is not installed" in out
        assert "\033[33m" in out  # styled yellow when colour is on
