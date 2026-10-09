"""Tests for ``hermes mordred network init`` -- on-demand network privacy setup.

The six network prompts (default path, Tor binary/port, Mullvad
account/relay/killswitch) used to live inside ``hermes mordred configure``.
They now live behind this dedicated command so first-run setup stays short and
privacy is opt-in via an explicit command (user request 2026-06-05).

Contract:
- ``collect_network_answers`` always asks the privacy-path question first,
  then only the prompts the selected route needs: ``clearnet`` asks nothing
  further, ``tor`` asks the Tor binary/port prompts, and ``vpn`` asks the VPN
  provider prompt plus the selected provider's settings (route-gated prompts,
  UX request 2026-08-12). Every prompt seeds its default from the existing
  on-disk ``plugins.mordred_network`` section so a re-run with Enter keeps
  current values, and every setting a given route does NOT ask about is still
  preserved from that same existing section (or the static safe default),
  never blanked.
- The Mullvad secret never lands in :class:`NetworkAnswers` (env-var REFERENCE
  only) and is redacted from the transient inputs object's repr.
- A blank Mullvad answer KEEPS the existing secret (re-run safe) rather than
  stripping the ``.env`` line.
- ``run_init`` merges (never whole-replaces) ``plugins.mordred_network`` so
  unrelated user fields survive, routes the secret to the env writer, and the
  relay/killswitch indirection to the credentials writer.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard._network_init import (
    _MULLVAD_ACCOUNT_DESCRIPTION,
    _MULLVAD_KILLSWITCH_DESCRIPTION,
    _MULLVAD_RELAY_DESCRIPTION,
    _NETWORK_PATH_DESCRIPTIONS,
    _TOR_BINARY_DESCRIPTION,
    _TOR_SOCKS_PORT_DESCRIPTION,
)
from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter
from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter
from mordred_hermes.wizard.network_cli import (
    _VALID_PATHS,
    NetworkAnswers,
    collect_network_answers,
    handle_init,
    run_init,
)

from ._helpers import _writer

# --------------------------------------------------------------------------- #
# Test doubles                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class _ScriptedPromptIO:
    """Pops a pre-recorded answer per call; records (kind, label, default).

    ``help_by_label`` captures the inline ``descriptions`` (choice) or the
    ``description`` help line (text/bool/password) passed alongside each prompt,
    so tests can assert ``network init`` now explains every prompt (UX request
    2026-06-15) without coupling to the dialog rendering.
    """

    answers: list[object]
    seen: list[tuple[str, str, object]] = field(default_factory=list)
    help_by_label: dict[str, object] = field(default_factory=dict)

    def _pop(self, kind: str, label: str, default: object, help_text: object = None) -> object:
        if not self.answers:
            raise AssertionError(f"_ScriptedPromptIO ran out of answers at {kind}({label!r})")
        a = self.answers.pop(0)
        self.seen.append((kind, label, default))
        self.help_by_label[label] = help_text
        return a

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        return str(self._pop("choice", label, default, descriptions))

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return str(self._pop("text", label, default, description))

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return bool(self._pop("bool", label, default, description))

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return str(self._pop("password", label, default, description))


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

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default


class _SpyEnvFileWriter:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, str, str]] = []

    def upsert(self, path: Path, *, key: str, value: str) -> None:
        self.calls.append((path, key, value))


class _SpyCredentialsWriter:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, str, str, bool]] = []

    def write_network(
        self,
        path: Path,
        *,
        mullvad_account_id_env: str,
        mullvad_relay_country: str,
        mullvad_killswitch: bool,
    ) -> None:
        self.calls.append((path, mullvad_account_id_env, mullvad_relay_country, mullvad_killswitch))


# Per-route scripted answer sets, in prompt order. Prompts are gated on the
# selected privacy path (UX request 2026-08-12): the wizard only asks the
# questions the chosen route needs, so each list below is exactly what that
# route's run consumes -- nothing more, nothing less.
_ANSWERS_CLEARNET: list[object] = ["clearnet"]
_ANSWERS_TOR: list[object] = ["tor", "/usr/bin/tor", "9150"]
# vpn + mullvad, in prompt order: path, VPN provider, mullvad secret (blank =
# keep current), relay country, killswitch.
_ANSWERS_VPN_MULLVAD: list[object] = ["vpn", "mullvad", "MULL-secret-99", "jp", True]
_ANSWERS_VPN_WIREGUARD: list[object] = ["vpn", "wireguard", "/etc/wireguard/wg0.conf"]
_ANSWERS_VPN_CUSTOM: list[object] = [
    "vpn",
    "custom",
    "expressvpn connect",
    "expressvpn disconnect",
    "expressvpn status",
]


# --------------------------------------------------------------------------- #
# collect_network_answers                                                     #
# --------------------------------------------------------------------------- #


class TestCollectNetworkAnswers:
    def test_collects_vpn_mullvad_prompts_into_network_answers(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        inputs = collect_network_answers(prompts)
        na = inputs.network_answers
        assert isinstance(na, NetworkAnswers)
        assert na.default_network_path == "vpn"
        assert na.mullvad_account_id_env == "MORDRED_MULLVAD_ACCOUNT"
        assert na.mullvad_relay_country == "jp"
        assert na.mullvad_killswitch is True
        assert prompts.answers == [], "the vpn+mullvad answer list must be fully consumed"

    def test_secret_captured_separately_not_in_network_answers(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        inputs = collect_network_answers(prompts)
        # The secret rides the transient inputs object, never NetworkAnswers.
        import dataclasses

        na_values = [getattr(inputs.network_answers, f.name) for f in dataclasses.fields(inputs.network_answers)]
        assert "MULL-secret-99" not in na_values
        assert inputs._mullvad_account_secret == "MULL-secret-99"

    def test_tor_socks_port_coerced_to_int(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_TOR))
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.tor_socks_port == 9150
        assert isinstance(inputs.network_answers.tor_socks_port, int)

    def test_invalid_tor_socks_port_falls_back_to_default(self) -> None:
        prompts = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "not-a-port"])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.tor_socks_port == 9050

    def test_out_of_range_tor_socks_port_falls_back_to_default(self) -> None:
        prompts = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "70000"])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.tor_socks_port == 9050

    def test_65535_falls_back_because_control_port_needs_plus_one(self) -> None:
        prompts = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "65535"])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.tor_socks_port == 9050

    def test_invalid_relay_country_falls_back_to_auto(self) -> None:
        # Relay coercion only happens on the vpn+mullvad route, so the path
        # must be "vpn" (not "clearnet") for the relay prompt to fire at all.
        prompts = _ScriptedPromptIO(answers=["vpn", "mullvad", "", "unitedstates", False])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.mullvad_relay_country == "auto"

    def test_2letter_relay_country_lowercased(self) -> None:
        prompts = _ScriptedPromptIO(answers=["vpn", "mullvad", "", "JP", False])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.mullvad_relay_country == "jp"

    def test_prompt_labels_carry_no_phase_jargon(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        collect_network_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert len(labels) == 5
        for label in labels:
            assert "Phase" not in label, f"user-facing label leaks internal jargon: {label!r}"

    def test_prompt_secret_false_skips_password_prompt(self) -> None:
        # With provider=mullvad but the password prompt off, the consumed
        # slots are path, provider, relay, killswitch (4 total).
        prompts = _ScriptedPromptIO(answers=["vpn", "mullvad", "auto", False])
        inputs = collect_network_answers(prompts, prompt_secret=False)
        assert inputs._mullvad_account_secret == ""
        kinds = [k for k, _, _ in prompts.seen]
        assert "password" not in kinds
        assert len(kinds) == 4

    def test_every_prompt_carries_an_explanation(self) -> None:
        """UX request 2026-06-15: each ``network init`` prompt must explain
        itself — what the setting does and which route it applies to — the way
        keyvault init and the configure policy-mode dialog already do.

        Prompts are now route-gated (UX request 2026-08-12), so no single run
        visits every prompt; this drives four separate runs (tor; vpn+mullvad;
        vpn+wireguard; vpn+custom) on the same ``PromptIO`` to accumulate help
        text for every prompt that exists.
        """
        prompts = _ScriptedPromptIO(answers=[])
        for answers in (_ANSWERS_TOR, _ANSWERS_VPN_MULLVAD, _ANSWERS_VPN_WIREGUARD, _ANSWERS_VPN_CUSTOM):
            prompts.answers = list(answers)
            collect_network_answers(prompts)
        help_by_label = prompts.help_by_label

        # The privacy-path radio carries an inline description for every route.
        path_desc = help_by_label["Network privacy path"]
        assert path_desc == _NETWORK_PATH_DESCRIPTIONS
        # Parity with the source of truth: a route added to _VALID_PATHS without
        # a description would render bare in the dialog — fail here instead.
        assert set(_NETWORK_PATH_DESCRIPTIONS) == set(_VALID_PATHS)

        # The five plain-text / secret / yes-no prompts each get a help line.
        assert help_by_label["Tor binary path"] == _TOR_BINARY_DESCRIPTION
        assert help_by_label["Tor SOCKS port"] == _TOR_SOCKS_PORT_DESCRIPTION
        assert (
            help_by_label["Mullvad account number (blank = keep current; stored in ~/.hermes/.env)"]
            == _MULLVAD_ACCOUNT_DESCRIPTION
        )
        assert help_by_label["Mullvad relay country (`auto` or 2-letter code)"] == _MULLVAD_RELAY_DESCRIPTION
        assert help_by_label["Mullvad killswitch (lockdown-mode)"] == _MULLVAD_KILLSWITCH_DESCRIPTION

        # Regression guard: no prompt is left bare.
        assert all(help_by_label.values()), f"a network-init prompt has no explanation: {help_by_label}"

    def test_route_only_prompts_name_their_route(self) -> None:
        """Each Tor/Mullvad help line names the route it matters for, so a
        clearnet user knows every one of these can be Enter'd straight through."""
        for desc in (_TOR_BINARY_DESCRIPTION, _TOR_SOCKS_PORT_DESCRIPTION):
            assert "Tor route only" in desc
        for desc in (_MULLVAD_ACCOUNT_DESCRIPTION, _MULLVAD_RELAY_DESCRIPTION, _MULLVAD_KILLSWITCH_DESCRIPTION):
            assert "VPN route only" in desc


class TestCollectNetworkAnswersSeedsDefaults:
    """Re-run safety: each prompt's default comes from the existing on-disk
    section, so pressing Enter keeps the current value. Split across the
    route that actually prompts for each field, since prompts are now
    route-gated (UX request 2026-08-12)."""

    def test_tor_route_seeds_prompt_defaults(self) -> None:
        """Seeded defaults are observed on the tor route, which is the one
        that actually asks the Tor binary/port prompts."""
        existing: Mapping[str, Any] = {
            "default_path": "tor",
            "tor_binary_path": "/opt/tor/bin/tor",
            "tor_socks_port": 19050,
        }
        echo = _DefaultEchoPromptIO()
        inputs = collect_network_answers(echo, existing=existing)
        na = inputs.network_answers
        assert na.default_network_path == "tor"
        assert na.tor_binary_path == "/opt/tor/bin/tor"
        assert na.tor_socks_port == 19050

    def test_vpn_route_seeds_mullvad_prompt_defaults(self) -> None:
        """Seeded defaults are observed on the vpn route, which is the one
        that actually asks the Mullvad relay/killswitch prompts."""
        existing: Mapping[str, Any] = {
            "default_path": "vpn",
            "vpn_provider": "mullvad",
            "mullvad_relay_country": "se",
            "mullvad_killswitch": True,
        }
        echo = _DefaultEchoPromptIO()
        inputs = collect_network_answers(echo, existing=existing)
        na = inputs.network_answers
        assert na.default_network_path == "vpn"
        assert na.mullvad_relay_country == "se"
        assert na.mullvad_killswitch is True

    def test_no_existing_section_uses_safe_defaults(self) -> None:
        echo = _DefaultEchoPromptIO()
        inputs = collect_network_answers(echo, existing=None)
        na = inputs.network_answers
        assert na.default_network_path == "clearnet"
        assert na.tor_binary_path == "tor"
        assert na.tor_socks_port == 9050
        assert na.mullvad_relay_country == "auto"
        assert na.mullvad_killswitch is False

    def test_hand_edited_string_false_killswitch_seed_is_false(self) -> None:
        """A hand-edited quoted ``"false"`` must not flip the killswitch default
        to True on a re-run (plain ``bool("false")`` would). Codex review 2026-06-05."""
        echo = _DefaultEchoPromptIO()
        inputs = collect_network_answers(echo, existing={"mullvad_killswitch": "false"})
        assert inputs.network_answers.mullvad_killswitch is False


class TestNetworkInitInputsRedactsSecret:
    """The transient inputs object must not leak the Mullvad secret through
    ``repr``/``str`` (tracebacks, --showlocals, debuggers call repr)."""

    def test_repr_does_not_contain_secret(self) -> None:
        prompts = _ScriptedPromptIO(answers=["vpn", "mullvad", "DO-NOT-LEAK-XYZ", "auto", True])
        inputs = collect_network_answers(prompts)
        assert "DO-NOT-LEAK-XYZ" not in repr(inputs)
        assert "DO-NOT-LEAK-XYZ" not in str(inputs)


# --------------------------------------------------------------------------- #
# NetworkAnswers dataclass (rehomed into network_cli)                         #
# --------------------------------------------------------------------------- #


class TestNetworkAnswersDataclass:
    def test_fields_present(self) -> None:
        import dataclasses

        names = {f.name for f in dataclasses.fields(NetworkAnswers)}
        assert names == {
            "default_network_path",
            "tor_binary_path",
            "tor_socks_port",
            "mullvad_account_id_env",
            "mullvad_relay_country",
            "mullvad_killswitch",
            "vpn_provider",
            "wireguard_config_path",
            "custom_up_cmd",
            "custom_down_cmd",
            "custom_health_cmd",
        }

    def test_to_config_yaml_section_shape(self) -> None:
        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/opt/tor/bin/tor",
            tor_socks_port=19050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=True,
        )
        assert na.to_config_yaml_section() == {
            "default_path": "vpn",
            "tor_binary_path": "/opt/tor/bin/tor",
            "tor_socks_port": 19050,
            "mullvad_account_id_env": "MORDRED_MULLVAD_ACCOUNT",
            "mullvad_relay_country": "jp",
            "mullvad_killswitch": True,
            "vpn_provider": "mullvad",
        }

    def test_is_frozen(self) -> None:
        import dataclasses

        na = NetworkAnswers(
            default_network_path="clearnet",
            tor_binary_path="tor",
            tor_socks_port=9050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            na.default_network_path = "tor"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# run_init: persistence routing                                              #
# --------------------------------------------------------------------------- #


class TestRunInitPersistsConfig:
    def test_merges_network_section_into_config(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        w = _writer(tmp_path)
        rc = run_init(
            prompt_io=prompts,
            policy_writer=w,
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert rc == 0

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "vpn"
        # The vpn route never asks the Tor prompts; the section still carries
        # the base Tor keys, seeded from the safe static defaults (no
        # existing config to preserve here).
        assert section["tor_binary_path"] == "tor"
        assert section["tor_socks_port"] == 9050
        assert section["mullvad_relay_country"] == "jp"
        assert section["mullvad_killswitch"] is True
        # Atomic-write contract: PolicyWriter enables the Mordred plugin.
        assert "mordred" in data["plugins"]["enabled"]

    def test_merge_preserves_unrelated_fields(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n"
            "  mordred_privacy_check:\n    policy: strict\n"
            "  mordred_network:\n    default_path: tor\n    custom_user_field: keep-me\n",
            encoding="utf-8",
        )
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        w = _writer(tmp_path)
        run_init(
            prompt_io=prompts,
            policy_writer=w,
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "strict"
        # The custom field the user hand-added must survive the merge.
        assert data["plugins"]["mordred_network"]["custom_user_field"] == "keep-me"
        assert data["plugins"]["mordred_network"]["default_path"] == "vpn"


class TestRunInitRoutesSecret:
    def test_env_writer_receives_secret(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        env_w = _SpyEnvFileWriter()
        env_path = tmp_path / ".env"
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=env_w,
            credentials_writer=_SpyCredentialsWriter(),
            env_path=env_path,
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert env_w.calls == [(env_path, "MORDRED_MULLVAD_ACCOUNT", "MULL-secret-99")]

    def test_credentials_writer_receives_relay_and_killswitch(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        cred_w = _SpyCredentialsWriter()
        creds_path = tmp_path / "credentials" / "network.json"
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=cred_w,
            env_path=tmp_path / ".env",
            credentials_path=creds_path,
        )
        assert cred_w.calls == [(creds_path, "MORDRED_MULLVAD_ACCOUNT", "jp", True)]

    def test_blank_secret_does_not_touch_env_writer(self, tmp_path: Path) -> None:
        """Re-run safety: a blank Mullvad answer keeps the existing secret
        instead of stripping the .env line (Codex review 2026-06-05)."""
        prompts = _ScriptedPromptIO(answers=["vpn", "mullvad", "", "auto", False])
        env_w = _SpyEnvFileWriter()
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=env_w,
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert env_w.calls == [], "blank secret must NOT call the env writer (would wipe the existing line)"

    def test_blank_secret_preserves_existing_env_line(self, tmp_path: Path) -> None:
        env_path = tmp_path / ".env"
        env_path.write_text("MORDRED_MULLVAD_ACCOUNT=OLD-SECRET-KEEP\n", encoding="utf-8")
        prompts = _ScriptedPromptIO(answers=["vpn", "mullvad", "", "auto", False])
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=DotEnvFileWriter(),
            credentials_writer=JSONCredentialsWriter(),
            env_path=env_path,
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert "MORDRED_MULLVAD_ACCOUNT=OLD-SECRET-KEEP" in env_path.read_text(encoding="utf-8")


class TestRunInitSeedsDefaultsFromDisk:
    """End-to-end re-run: with values already on disk, pressing Enter on every
    prompt must leave the config unchanged."""

    def test_enter_on_every_prompt_keeps_existing_values(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n"
            "  mordred_network:\n"
            "    default_path: tor\n"
            "    tor_binary_path: /opt/tor/bin/tor\n"
            "    tor_socks_port: 19050\n"
            "    mullvad_relay_country: se\n"
            "    mullvad_killswitch: true\n",
            encoding="utf-8",
        )
        run_init(
            prompt_io=_DefaultEchoPromptIO(),
            policy_writer=_writer(tmp_path),
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "tor"
        assert section["tor_binary_path"] == "/opt/tor/bin/tor"
        assert section["tor_socks_port"] == 19050
        assert section["mullvad_relay_country"] == "se"
        assert section["mullvad_killswitch"] is True


# --------------------------------------------------------------------------- #
# handle_init: CLI adapter                                                    #
# --------------------------------------------------------------------------- #


class TestInitSummary:
    """UX scope B: the post-init summary echoes the resolved settings so the
    user can confirm what was saved (and whether the Mullvad secret changed)."""

    def _na(self, *, path: str = "tor", killswitch: bool = True) -> NetworkAnswers:
        return NetworkAnswers(
            default_network_path=path,
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9150,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=killswitch,
        )

    def test_summary_echoes_tor_settings_when_path_is_tor(self) -> None:
        """Tor summary gating (UX request 2026-08-12): tor lines appear, but
        no Mullvad/provider lines leak in."""
        from mordred_hermes.wizard.network_cli import _init_summary

        out = _init_summary(self._na(path="tor"), secret_written=False)
        assert "tor" in out
        assert "/usr/bin/tor" in out
        assert "9150" in out
        assert "mullvad" not in out.lower()

    def test_summary_echoes_vpn_settings_when_path_is_vpn(self) -> None:
        """VPN summary gating: provider lines appear, but no Tor lines leak in."""
        from mordred_hermes.wizard.network_cli import _init_summary

        out = _init_summary(self._na(path="vpn"), secret_written=True)
        assert "jp" in out
        assert "enabled" in out.lower()  # killswitch True
        assert "stored" in out.lower()  # secret written
        assert "tor binary" not in out.lower()
        assert "tor socks port" not in out.lower()

    def test_summary_clearnet_shows_note_only(self) -> None:
        """Clearnet summary gating: neither Tor nor VPN/Mullvad lines apply,
        since clearnet skips both prompt blocks entirely."""
        from mordred_hermes.wizard.network_cli import _init_summary

        out = _init_summary(self._na(path="clearnet", killswitch=False), secret_written=False)
        assert "clearnet" in out.lower()
        assert "no anonymising layer" in out.lower()
        assert "tor binary" not in out.lower()
        assert "mullvad" not in out.lower()

    def test_summary_marks_secret_cleared(self) -> None:
        """The stored/unchanged secret status is a VPN/Mullvad-route detail
        and only surfaces there; *cleared* is the exception (tested below)."""
        from mordred_hermes.wizard.network_cli import _init_summary

        out = _init_summary(self._na(path="vpn"), secret_written=False, secret_cleared=True)
        assert "cleared" in out.lower()

    def test_summary_marks_secret_cleared_outside_the_vpn_route(self) -> None:
        """``--clear-mullvad`` is route-independent: the cleared confirmation
        must surface even on a route that shows no other Mullvad lines,
        otherwise the clear would happen silently."""
        from mordred_hermes.wizard.network_cli import _init_summary

        out = _init_summary(self._na(path="clearnet"), secret_written=False, secret_cleared=True)
        assert "cleared" in out.lower()

    def test_summary_marks_secret_cleared_for_non_mullvad_vpn_provider(self) -> None:
        """A wireguard/custom provider summary has no Mullvad account line of
        its own, so the cleared confirmation must still be appended."""
        from mordred_hermes.wizard.network_cli import _init_summary

        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9150,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=False,
            vpn_provider="wireguard",
            wireguard_config_path="/etc/wireguard/wg0.conf",
        )
        out = _init_summary(na, secret_written=False, secret_cleared=True)
        assert "cleared" in out.lower()

    def test_summary_shows_custom_provider_and_commands(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A custom-provider summary echoes the provider + its up/down/health
        commands, and drops the Mullvad relay/account lines that don't apply."""
        from mordred_hermes.wizard.network_cli import _init_summary

        # Custom CLI resolves so the summary carries no dependency warning.
        monkeypatch.setattr(
            "mordred_hermes.network.guidance.shutil.which",
            lambda _name: "/usr/local/bin/expressvpnctl",
        )
        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9150,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=True,
            vpn_provider="custom",
            custom_up_cmd=("expressvpnctl", "connect", "smart"),
            custom_down_cmd=("expressvpnctl", "disconnect"),
            custom_health_cmd=("expressvpnctl", "get", "connectionstate"),
        )
        out = _init_summary(na, secret_written=False)
        assert "custom" in out
        assert "expressvpnctl connect smart" in out
        assert "expressvpnctl disconnect" in out
        assert "expressvpnctl get connectionstate" in out
        # Mullvad-specific detail lines must not appear for a custom provider.
        assert "mullvad relay" not in out.lower()
        assert "mullvad account" not in out.lower()

    def test_run_init_prints_resolved_settings(self, tmp_path: Path) -> None:
        """End-to-end: run_init's printed summary reflects the saved path."""
        import io
        from contextlib import redirect_stdout

        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_init(
                prompt_io=prompts,
                policy_writer=_writer(tmp_path),
                env_writer=_SpyEnvFileWriter(),
                credentials_writer=_SpyCredentialsWriter(),
                env_path=tmp_path / ".env",
                credentials_path=tmp_path / "credentials" / "network.json",
            )
        out = buf.getvalue()
        assert "vpn" in out  # _ANSWERS_VPN_MULLVAD default_path
        assert "jp" in out  # _ANSWERS_VPN_MULLVAD relay country
        assert "stored" in out.lower()  # _ANSWERS_VPN_MULLVAD has a non-blank secret


class TestNetworkAnswersFromArgs:
    """Non-interactive flag surface: build NetworkAnswers from CLI args,
    seeding unspecified fields from the existing config. The Mullvad secret is
    NEVER taken from a flag (would leak via ps / shell history)."""

    def _args(self, **kw: Any) -> argparse.Namespace:
        base = dict(path=None, tor_binary=None, tor_socks_port=None, mullvad_relay=None, mullvad_killswitch=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_builds_from_flags(self) -> None:
        from mordred_hermes.wizard.network_cli import network_answers_from_args

        args = self._args(
            path="tor", tor_binary="/usr/bin/tor", tor_socks_port=9150, mullvad_relay="jp", mullvad_killswitch=True
        )
        inputs = network_answers_from_args(args, existing={})
        na = inputs.network_answers
        assert na.default_network_path == "tor"
        assert na.tor_binary_path == "/usr/bin/tor"
        assert na.tor_socks_port == 9150
        assert na.mullvad_relay_country == "jp"
        assert na.mullvad_killswitch is True
        assert inputs._mullvad_account_secret == ""  # never from a flag

    def test_unspecified_flags_seed_from_existing(self) -> None:
        from mordred_hermes.wizard.network_cli import network_answers_from_args

        existing = {
            "default_path": "vpn",
            "tor_binary_path": "/opt/tor/bin/tor",
            "tor_socks_port": 19050,
            "mullvad_relay_country": "se",
            "mullvad_killswitch": True,
        }
        inputs = network_answers_from_args(self._args(), existing=existing)
        na = inputs.network_answers
        assert na.default_network_path == "vpn"
        assert na.tor_binary_path == "/opt/tor/bin/tor"
        assert na.tor_socks_port == 19050
        assert na.mullvad_relay_country == "se"
        assert na.mullvad_killswitch is True

    def test_no_flags_no_existing_uses_safe_defaults(self) -> None:
        from mordred_hermes.wizard.network_cli import network_answers_from_args

        na = network_answers_from_args(self._args(), existing={}).network_answers
        assert na.default_network_path == "clearnet"
        assert na.tor_binary_path == "tor"
        assert na.tor_socks_port == 9050
        assert na.mullvad_relay_country == "auto"
        assert na.mullvad_killswitch is False

    def test_port_and_relay_coerced(self) -> None:
        from mordred_hermes.wizard.network_cli import network_answers_from_args

        na = network_answers_from_args(
            self._args(path="clearnet", tor_socks_port=70000, mullvad_relay="unitedstates"), existing={}
        ).network_answers
        assert na.tor_socks_port == 9050  # out of range -> default
        assert na.mullvad_relay_country == "auto"  # invalid -> auto


class TestClearMullvad:
    """``--clear-mullvad`` removes the stored secret (env line), overriding the
    blank=keep default, and the summary reports it as cleared."""

    def _args(self, **kw: Any) -> argparse.Namespace:
        base = dict(path="clearnet", tor_binary=None, tor_socks_port=None, mullvad_relay=None, mullvad_killswitch=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_clear_calls_env_writer_with_empty_value(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.network_cli import _persist_network, network_answers_from_args

        env_w = _SpyEnvFileWriter()
        env_path = tmp_path / ".env"
        inputs = network_answers_from_args(self._args(), existing={})
        rc = _persist_network(
            inputs,
            policy_writer=_writer(tmp_path),
            env_writer=env_w,
            credentials_writer=_SpyCredentialsWriter(),
            env_path=env_path,
            credentials_path=tmp_path / "credentials" / "network.json",
            clear_mullvad=True,
        )
        assert rc == 0
        assert env_w.calls == [(env_path, "MORDRED_MULLVAD_ACCOUNT", "")]

    def test_clear_strips_existing_env_line(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.network_cli import _persist_network, network_answers_from_args

        env_path = tmp_path / ".env"
        env_path.write_text("MORDRED_MULLVAD_ACCOUNT=OLD\nOTHER=keep\n", encoding="utf-8")
        inputs = network_answers_from_args(self._args(), existing={})
        _persist_network(
            inputs,
            policy_writer=_writer(tmp_path),
            env_writer=DotEnvFileWriter(),
            credentials_writer=JSONCredentialsWriter(),
            env_path=env_path,
            credentials_path=tmp_path / "credentials" / "network.json",
            clear_mullvad=True,
        )
        text = env_path.read_text(encoding="utf-8")
        assert "MORDRED_MULLVAD_ACCOUNT" not in text
        assert "OTHER=keep" in text

    def test_clear_summary_says_cleared(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.wizard.network_cli import _persist_network, network_answers_from_args

        inputs = network_answers_from_args(self._args(), existing={})
        _persist_network(
            inputs,
            policy_writer=_writer(tmp_path),
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
            clear_mullvad=True,
        )
        assert "cleared" in capsys.readouterr().out.lower()


class TestHandleInitNonInteractive:
    """``network init --non-interactive`` is flag-driven (no abort). The secret
    is left unchanged unless ``--clear-mullvad`` removes it."""

    def _ns(self, tmp_path: Path, **kw: Any) -> argparse.Namespace:
        base = dict(
            non_interactive=True,
            clear_mullvad=False,
            config_path=tmp_path / "config.yaml",
            path=None,
            tor_binary=None,
            tor_socks_port=None,
            mullvad_relay=None,
            mullvad_killswitch=None,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_flag_driven_persists_without_prompt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from mordred_hermes.wizard import network_cli as nc

        monkeypatch.setattr(nc, "HERMES_BASE", tmp_path)
        rc = handle_init(self._ns(tmp_path, path="tor", tor_binary="/usr/bin/tor", tor_socks_port=9050))
        assert rc == 0
        from ruamel.yaml import YAML

        data = YAML(typ="safe", pure=True).load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"

    def test_keeps_existing_secret(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from mordred_hermes.wizard import network_cli as nc

        monkeypatch.setattr(nc, "HERMES_BASE", tmp_path)
        (tmp_path / ".env").write_text("MORDRED_MULLVAD_ACCOUNT=KEEP\n", encoding="utf-8")
        assert handle_init(self._ns(tmp_path, path="tor")) == 0
        assert "MORDRED_MULLVAD_ACCOUNT=KEEP" in (tmp_path / ".env").read_text(encoding="utf-8")

    def test_clear_mullvad_strips_secret(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from mordred_hermes.wizard import network_cli as nc

        monkeypatch.setattr(nc, "HERMES_BASE", tmp_path)
        (tmp_path / ".env").write_text("MORDRED_MULLVAD_ACCOUNT=GONE\n", encoding="utf-8")
        assert handle_init(self._ns(tmp_path, path="clearnet", clear_mullvad=True)) == 0
        assert "MORDRED_MULLVAD_ACCOUNT" not in (tmp_path / ".env").read_text(encoding="utf-8")


class TestPersistNetworkErrorChannel:
    """``_persist_network`` (used by both ``run_init`` and non-interactive
    ``handle_init``) must guard OSError the same way ``handle_use`` already
    does around its single PolicyWriter write (network_cli.py). Before this
    fix, a disk-write failure during ``network init`` surfaced as an
    unhandled traceback instead of the ``error:`` + exit-1 convention the
    rest of the CLI uses."""

    def test_policy_writer_failure_reports_to_stderr_with_rc_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class _BoomPolicyWriter:
            config_path = tmp_path / "config.yaml"

            def merge_mordred_sections(self, sections: object) -> None:
                raise OSError("disk full")

        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        rc = run_init(
            prompt_io=prompts,
            policy_writer=_BoomPolicyWriter(),  # type: ignore[arg-type]
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
        )
        assert rc == 1
        captured = capsys.readouterr()
        assert "disk full" in captured.err
        assert captured.out == ""

    def test_env_writer_failure_reports_to_stderr_with_rc_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class _BoomEnvWriter:
            def upsert(self, path: Path, *, key: str, value: str) -> None:
                raise OSError("permission denied")

        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        rc = run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=_BoomEnvWriter(),  # type: ignore[arg-type]
            credentials_writer=_SpyCredentialsWriter(),
        )
        assert rc == 1
        captured = capsys.readouterr()
        assert "permission denied" in captured.err

    def test_credentials_writer_failure_reports_to_stderr_with_rc_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class _BoomCredentialsWriter:
            def write_network(
                self,
                path: Path,
                *,
                mullvad_account_id_env: str,
                mullvad_relay_country: str,
                mullvad_killswitch: bool,
            ) -> None:
                raise OSError("read-only filesystem")

        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        rc = run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_BoomCredentialsWriter(),  # type: ignore[arg-type]
        )
        assert rc == 1
        captured = capsys.readouterr()
        assert "read-only filesystem" in captured.err

    def test_handle_init_non_interactive_surfaces_same_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The non-interactive ``handle_init`` path routes through the same
        ``_persist_network`` -- the guard must cover it too, not just the
        interactive ``run_init`` caller."""
        from mordred_hermes.wizard import network_cli as nc

        def _boom(self: object, sections: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(nc.PolicyWriter, "merge_mordred_sections", _boom)
        ns = argparse.Namespace(
            non_interactive=True,
            clear_mullvad=False,
            config_path=tmp_path / "config.yaml",
            path="tor",
            tor_binary=None,
            tor_socks_port=None,
            mullvad_relay=None,
            mullvad_killswitch=None,
        )
        rc = handle_init(ns)
        assert rc == 1
        assert "disk full" in capsys.readouterr().err


class TestHandleInit:
    def test_interactive_path_persists_and_prints(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """End-to-end production wiring: real writers, scripted prompts, with
        ``.env`` / credentials paths resolved from a patched HERMES_BASE."""
        from mordred_hermes.wizard import network_cli as nc

        # vpn+mullvad is used (rather than a tor script) so this end-to-end
        # test still exercises the Mullvad secret write; the tor route no
        # longer visits any VPN prompt (UX request 2026-08-12).
        scripted = _ScriptedPromptIO(answers=["vpn", "mullvad", "MULL-xyz", "jp", True])
        monkeypatch.setattr(nc, "PromptToolkitIO", lambda: scripted)
        monkeypatch.setattr(nc, "HERMES_BASE", tmp_path)

        ns = argparse.Namespace(non_interactive=False, config_path=tmp_path / "config.yaml")
        rc = handle_init(ns)
        assert rc == 0

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "vpn"
        # Secret + credentials resolved relative to the patched HERMES_BASE.
        assert "MORDRED_MULLVAD_ACCOUNT=MULL-xyz" in (tmp_path / ".env").read_text(encoding="utf-8")
        assert (tmp_path / "mordred" / "credentials" / "network.json").exists()
        assert "default path" in capsys.readouterr().out.lower()


class TestCollectVpnProvider:
    """The VPN provider selector + provider-specific prompts (Phase 5):
    Mullvad stays the default; wireguard / custom let any VPN be used.
    """

    def test_wireguard_selection_collects_config_path(self) -> None:
        # Provider is asked before the Mullvad trio, and wireguard gates that
        # trio out entirely: no Mullvad account / relay / killswitch slots here.
        # The vpn route also never sees the Tor prompts (UX request 2026-08-12).
        na = collect_network_answers(_ScriptedPromptIO(answers=list(_ANSWERS_VPN_WIREGUARD))).network_answers
        assert na.vpn_provider == "wireguard"
        assert na.wireguard_config_path == "/etc/wireguard/wg0.conf"
        section = na.to_config_yaml_section()
        assert section["vpn_provider"] == "wireguard"
        assert section["wireguard_config_path"] == "/etc/wireguard/wg0.conf"

    def test_custom_selection_collects_commands_as_argv(self) -> None:
        na = collect_network_answers(_ScriptedPromptIO(answers=list(_ANSWERS_VPN_CUSTOM))).network_answers
        assert na.vpn_provider == "custom"
        assert na.custom_up_cmd == ("expressvpn", "connect")
        assert na.custom_down_cmd == ("expressvpn", "disconnect")
        assert na.custom_health_cmd == ("expressvpn", "status")
        # Persisted as YAML lists.
        assert na.to_config_yaml_section()["custom_up_cmd"] == ["expressvpn", "connect"]

    def test_mullvad_default_omits_provider_specific_keys(self) -> None:
        na = collect_network_answers(_ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))).network_answers
        section = na.to_config_yaml_section()
        assert section["vpn_provider"] == "mullvad"
        assert "wireguard_config_path" not in section
        assert "custom_up_cmd" not in section

    def test_non_mullvad_provider_never_asks_for_mullvad_account(self) -> None:
        """The 2026-06-16 fix: now that any VPN may be used, a WireGuard user is
        never prompted for a Mullvad account number / relay / killswitch — those
        prompts are gated behind ``provider == "mullvad"``."""
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_WIREGUARD))
        collect_network_answers(prompts)
        kinds = [k for k, _, _ in prompts.seen]
        labels = [label for _, label, _ in prompts.seen]
        assert "password" not in kinds, "a non-Mullvad provider must not trigger the secret prompt"
        assert not any("Mullvad" in label for label in labels), f"Mullvad prompt leaked for wireguard: {labels}"

    def test_provider_question_precedes_the_mullvad_prompts(self) -> None:
        """Ordering guard: the provider is asked before the Mullvad trio, which
        is what lets the provider choice gate them."""
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        collect_network_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        account_label = "Mullvad account number (blank = keep current; stored in ~/.hermes/.env)"
        assert labels.index("VPN provider") < labels.index(account_label)

    def test_mullvad_account_help_line_does_not_restate_the_label(self) -> None:
        """Dedup (2026-06-16): the label already says "Mullvad account number",
        so the help line must not just repeat it."""
        assert "account number" not in _MULLVAD_ACCOUNT_DESCRIPTION.lower()
        assert "VPN route only" in _MULLVAD_ACCOUNT_DESCRIPTION


# --------------------------------------------------------------------------- #
# Route-gated prompts (UX request 2026-08-12)                                 #
# --------------------------------------------------------------------------- #


class TestRouteGatedPrompts:
    """``network init`` now asks only the prompts the selected privacy path
    needs: ``clearnet`` asks nothing further, ``tor`` asks only the Tor
    prompts, and ``vpn`` asks only the VPN prompts. Every skipped setting is
    preserved from ``existing`` (or falls back to the static safe default)
    instead of being blanked, so a re-run on a different route stays
    non-destructive -- the same contract :func:`_collect_vpn_settings` already
    applies one level down when a non-Mullvad provider is chosen."""

    def test_clearnet_run_asks_exactly_one_prompt(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_CLEARNET))
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.default_network_path == "clearnet"
        assert len(prompts.seen) == 1
        assert prompts.answers == [], "the clearnet answer list must be fully consumed"

    def test_tor_run_never_issues_vpn_prompts(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_TOR))
        collect_network_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert "VPN provider" not in labels
        assert not any("Mullvad" in label for label in labels)
        assert prompts.answers == [], "the tor answer list must be fully consumed"

    def test_vpn_run_never_issues_tor_prompts(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_VPN_MULLVAD))
        collect_network_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert "Tor binary path" not in labels
        assert "Tor SOCKS port" not in labels
        assert prompts.answers == [], "the vpn+mullvad answer list must be fully consumed"

    def test_clearnet_rerun_preserves_existing_tor_and_vpn_settings(self) -> None:
        """A clearnet re-run must not wipe a previously configured Tor path or
        VPN provider config -- it just doesn't ask about them this time."""
        existing: Mapping[str, Any] = {
            "tor_binary_path": "/opt/tor",
            "tor_socks_port": 9150,
            "vpn_provider": "wireguard",
            "wireguard_config_path": "/etc/wg.conf",
            "mullvad_relay_country": "se",
            "mullvad_killswitch": True,
        }
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_CLEARNET))
        inputs = collect_network_answers(prompts, existing=existing)
        na = inputs.network_answers
        assert na.default_network_path == "clearnet"
        assert na.tor_binary_path == "/opt/tor"
        assert na.tor_socks_port == 9150
        assert na.vpn_provider == "wireguard"
        assert na.wireguard_config_path == "/etc/wg.conf"
        assert na.mullvad_relay_country == "se"
        assert na.mullvad_killswitch is True
        assert prompts.answers == [], "only the path question should have been asked"

    def test_tor_rerun_preserves_saved_custom_provider_config(self) -> None:
        """A tor re-run must not wipe a previously configured custom VPN
        provider's up/down/health commands -- it just doesn't ask about the
        VPN block this time."""
        existing: Mapping[str, Any] = {
            "default_path": "tor",
            "tor_binary_path": "/opt/tor",
            "tor_socks_port": 9150,
            "vpn_provider": "custom",
            "custom_up_cmd": ["expressvpnctl", "connect"],
            "custom_down_cmd": ["expressvpnctl", "disconnect"],
            "custom_health_cmd": ["expressvpnctl", "status"],
        }
        prompts = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "9150"])
        inputs = collect_network_answers(prompts, existing=existing)
        na = inputs.network_answers
        assert na.default_network_path == "tor"
        assert na.vpn_provider == "custom"
        assert na.custom_up_cmd == ("expressvpnctl", "connect")
        assert na.custom_down_cmd == ("expressvpnctl", "disconnect")
        assert na.custom_health_cmd == ("expressvpnctl", "status")
        assert prompts.answers == [], "only the two Tor prompts should have been asked"
