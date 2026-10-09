"""Phase B tests -- ruamel.yaml round-trip preservation + policy.json mirror.

Snapshot strategy: comments / anchors / key-order are checked in inline
inside this file (deliberately weird YAML to stress ruamel round-trip).
After :class:`PolicyWriter` rewrites, the result is asserted via simple
substring checks -- a real diff is easier to debug than a pickle blob.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from mordred_hermes.wizard.policy_writer import (
    MORDRED_CONFIG_SECTIONS,
    MORDRED_PLUGIN_NAMES,
    PolicySnapshot,
    _atomic_write_text,
)

from ._helpers import _writer


class TestEmitPolicyJson:
    def test_writes_snapshot_with_0600_mode(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.emit_policy_json(PolicySnapshot(policy="lenient"))
        path = tmp_path / "mordred" / "policy.json"
        assert path.exists()
        body = json.loads(path.read_text(encoding="utf-8"))
        # Phase 2 fields (local_llm_endpoint / local_llm_model_id /
        # cloud_attempt_action) land here with defaults so llm_guard can
        # read them without needing wizard rerun. Phase 3 PR3a Task #7
        # added ``disable_ipv6`` so the network reader doesn't have to
        # rerun the mode-default heuristic. See POLICY.md §Phase 2 / §Phase 3.
        assert body == {
            "policy": "lenient",
            "allow_cloud_llm": False,
            "cloud_provider_allowlist": [],
            "audit_log_path": None,
            "local_llm_endpoint": "http://localhost:1234/v1",
            "local_llm_model_id": "",
            "cloud_attempt_action": "always-block",
            "disable_ipv6": True,
            "provider_overrides": {},
        }
        st_mode = stat.S_IMODE(os.stat(path).st_mode)
        assert st_mode == 0o600, f"expected 0o600, got 0o{st_mode:o}"

    def test_field_order_preserved(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic", "openai"),
        )
        w.emit_policy_json(snap)
        text = (tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8")
        assert (
            text.index('"policy"')
            < text.index('"allow_cloud_llm"')
            < text.index('"cloud_provider_allowlist"')
            < text.index('"audit_log_path"')
            < text.index('"local_llm_endpoint"')
            < text.index('"local_llm_model_id"')
            < text.index('"cloud_attempt_action"')
            < text.index('"disable_ipv6"')
            < text.index('"provider_overrides"')
        )

    def test_idempotent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="off")
        w.emit_policy_json(snap)
        path = tmp_path / "mordred" / "policy.json"
        first_mtime = path.stat().st_mtime_ns
        w.emit_policy_json(snap)
        assert path.stat().st_mtime_ns == first_mtime, "no-op write must not touch mtime"

    def test_idempotent_write_repairs_secret_file_mode(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="strict")
        w.emit_policy_json(snap)
        path = tmp_path / "mordred" / "policy.json"
        path.chmod(0o644)

        w.emit_policy_json(snap)

        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_atomic_write_never_replaces_an_unreadable_existing_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = tmp_path / "secret.json"
        original = b'{"operator_managed": true}\n'
        path.write_bytes(original)
        from mordred_hermes.wizard import policy_writer as pw

        real_open = pw.os.open

        def deny_target_read(candidate: object, *args: object, **kwargs: object) -> int:
            if os.fspath(candidate) == os.fspath(path):
                raise PermissionError("simulated ACL denial")
            return real_open(candidate, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(pw.os, "open", deny_target_read)

        with pytest.raises(PermissionError, match="ACL denial"):
            _atomic_write_text(path, '{"replacement": true}\n', mode=0o600)
        assert path.read_bytes() == original

    def test_preserves_hand_edited_provider_overrides_only(self, tmp_path: Path) -> None:
        """Configure-owned fields update, while the opaque extension survives."""
        w = _writer(tmp_path)
        path = tmp_path / "mordred" / "policy.json"
        path.parent.mkdir(parents=True)
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
        path.write_text(
            json.dumps(
                {
                    "policy": "off",
                    "allow_cloud_llm": True,
                    "provider_overrides": override,
                    "unknown_top_level": "scrub me",
                }
            ),
            encoding="utf-8",
        )

        w.emit_policy_json(
            PolicySnapshot(
                policy="strict",
                allow_cloud_llm=False,
                local_llm_model_id="qwen",
                disable_ipv6=False,
            )
        )

        body = json.loads(path.read_text(encoding="utf-8"))
        assert body["provider_overrides"] == override
        assert body["policy"] == "strict"
        assert body["allow_cloud_llm"] is False
        assert body["local_llm_model_id"] == "qwen"
        assert body["disable_ipv6"] is False
        # policy.json remains a scrubbed wizard snapshot: preservation is
        # deliberately scoped to provider_overrides, not arbitrary root keys.
        assert "unknown_top_level" not in body

    @pytest.mark.parametrize(
        "malformed",
        [
            None,
            ["not", "an", "object"],
            {"corp-proxy": {"transport": "httpx", "future_unsafe_fact": True}},
        ],
    )
    def test_preserves_malformed_overrides_for_fail_closed_reader(
        self,
        tmp_path: Path,
        malformed: object,
    ) -> None:
        """Never repair malformed evidence into an allowed empty mapping."""
        from mordred_hermes.network.hooks import _read_provider_overrides

        w = _writer(tmp_path)
        path = tmp_path / "mordred" / "policy.json"
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps({"policy": "strict", "provider_overrides": malformed}),
            encoding="utf-8",
        )

        w.emit_policy_json(PolicySnapshot(policy="strict"))

        body = json.loads(path.read_text(encoding="utf-8"))
        assert body["provider_overrides"] == malformed
        with pytest.raises(ValueError):
            _read_provider_overrides(path)


class TestPolicySnapshotPhase2Fields:
    """Phase 2 fields persisted into policy.json (Codex M3, moved from PR2).

    The fields are kw-only with defaults so existing positional callers
    (``PolicySnapshot(policy="strict")``) keep working. They are read by
    ``mordred_llm_guard`` (Phase 2 PR2 enforce + local_adapter) — wizard
    is the sole writer.
    """

    def test_custom_values_round_trip(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(
            policy="strict",
            local_llm_endpoint="http://127.0.0.1:11434/v1",
            local_llm_model_id="llama3.1:70b",
            cloud_attempt_action="prompt-once",
        )
        w.emit_policy_json(snap)
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["local_llm_endpoint"] == "http://127.0.0.1:11434/v1"
        assert body["local_llm_model_id"] == "llama3.1:70b"
        assert body["cloud_attempt_action"] == "prompt-once"

    def test_snapshot_is_frozen(self) -> None:
        """Defensive copy guarantee — llm_guard reads, never mutates."""
        snap = PolicySnapshot(policy="strict")
        with pytest.raises((AttributeError, TypeError)):
            snap.local_llm_endpoint = "http://evil.example.com"  # type: ignore[misc]

    def test_config_yaml_section_omits_phase2_fields(self) -> None:
        """``plugins.mordred_privacy_check`` config body must NOT carry llm_guard fields.

        privacy_check reads its own section from config.yaml (see
        ``privacy_check/_runtime.py:_load_state``). Polluting that section
        with Phase 2 fields would cross plugin boundaries — they belong in
        ``plugins.mordred_llm_guard`` (added in PR2) instead, or in
        ``policy.json`` (the cross-plugin mirror) here.
        """
        snap = PolicySnapshot(
            policy="strict",
            local_llm_endpoint="http://localhost:1234/v1",
            local_llm_model_id="qwen2.5",
            cloud_attempt_action="always-block",
        )
        section = snap.to_config_yaml_section()
        assert "local_llm_endpoint" not in section
        assert "local_llm_model_id" not in section
        assert "cloud_attempt_action" not in section

    def test_back_compat_positional_construction(self) -> None:
        """Existing call-sites (``PolicySnapshot("strict")``) keep working.

        Phase 1 tests construct snapshots with positional + a small kw-only
        set; the Phase 2 extension must not reorder existing parameters.
        """
        snap = PolicySnapshot(policy="strict")
        # Defaults pinned so a wizard-less consumer can rely on them.
        assert snap.local_llm_endpoint == "http://localhost:1234/v1"
        assert snap.local_llm_model_id == ""
        assert snap.cloud_attempt_action == "always-block"
        assert snap.provider_overrides == {}
        assert isinstance(hash(snap), int)

    def test_explicit_provider_overrides_round_trip(self) -> None:
        override = {"corp-proxy": {"transport": "httpx"}}
        snap = PolicySnapshot(policy="strict", provider_overrides=override)
        assert snap.to_json_dict()["provider_overrides"] == override

    def test_cloud_attempt_action_only_accepts_known_values(self) -> None:
        """No validation at the dataclass level — schema is documented but
        not enforced (matches Phase 1 pattern). This test just guards the
        Literal type hint so mypy --strict catches typos at compile time.

        The runtime test below ensures we did not silently widen the type.
        """
        from typing import get_type_hints

        from mordred_hermes.wizard.policy_writer import PolicySnapshot as Snap

        hints = get_type_hints(Snap)
        # ``Literal['always-block', 'prompt-once']`` -> __args__ exposes the values
        action_hint = hints["cloud_attempt_action"]
        args = getattr(action_hint, "__args__", ())
        assert set(args) == {"always-block", "prompt-once"}, args


class TestUpsertMordredSections:
    def test_creates_config_yaml_when_absent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.upsert_mordred_sections(
            {
                "mordred_privacy_check": {
                    "policy": "lenient",
                    "allow_cloud_llm": False,
                    "cloud_provider_allowlist": [],
                }
            }
        )
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "mordred_privacy_check" in text
        assert "policy: lenient" in text
        for name in MORDRED_PLUGIN_NAMES:
            assert name in text

    def test_preserves_user_comments_and_anchors(self, tmp_path: Path) -> None:
        seed = """\
# Hermes user config (do not delete this comment)
profile: default  # inline comment

defaults: &defs
  retries: 3
  timeout: 30  # seconds

plugins:
  enabled:
    - my_other_plugin
    - mordred_privacy_check
  mordred_privacy_check:
    policy: strict
    allow_cloud_llm: false
    cloud_provider_allowlist: []

  my_other_plugin:
    <<: *defs
    custom: value
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.upsert_mordred_sections(
            {
                "mordred_privacy_check": {
                    "policy": "lenient",
                    "allow_cloud_llm": False,
                    "cloud_provider_allowlist": ["anthropic"],
                }
            }
        )

        result = config_path.read_text(encoding="utf-8")
        assert "# Hermes user config (do not delete this comment)" in result
        assert "# seconds" in result
        assert "&defs" in result
        assert "<<: *defs" in result
        assert "my_other_plugin:" in result
        assert "custom: value" in result
        assert "policy: lenient" in result
        assert "anthropic" in result
        for name in MORDRED_PLUGIN_NAMES:
            assert name in result

    def test_refuses_non_mordred_plugin_section(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        with pytest.raises(ValueError, match="refusing to touch 'random_plugin'"):
            w.upsert_mordred_sections({"random_plugin": {"key": "value"}})

    def test_does_not_duplicate_in_plugins_enabled(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        body = {"policy": "lenient", "allow_cloud_llm": False, "cloud_provider_allowlist": []}
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        for name in MORDRED_PLUGIN_NAMES:
            list_occurrences = sum(1 for line in text.splitlines() if line.strip() == f"- {name}")
            assert list_occurrences == 1, f"{name} listed {list_occurrences} times"

    def test_idempotent_when_state_unchanged(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        body = {"policy": "lenient", "allow_cloud_llm": False, "cloud_provider_allowlist": []}
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        config_path = tmp_path / "config.yaml"
        first_mtime = config_path.stat().st_mtime_ns
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        assert config_path.stat().st_mtime_ns == first_mtime

    def test_existing_plugins_enabled_extended_not_replaced(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  enabled:
    - some_user_plugin
    - mordred_wizard
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.upsert_mordred_sections(
            {"mordred_privacy_check": {"policy": "off", "allow_cloud_llm": False, "cloud_provider_allowlist": []}}
        )
        result = config_path.read_text(encoding="utf-8")
        assert "some_user_plugin" in result, "non-Mordred entries must be preserved"
        for name in MORDRED_PLUGIN_NAMES:
            assert name in result

    @pytest.mark.parametrize(
        "raw_enabled,preserved",
        [
            ("some_user_plugin", "some_user_plugin"),
            ("{broken: true}", None),
        ],
    )
    def test_malformed_plugins_enabled_is_repaired(
        self,
        tmp_path: Path,
        raw_enabled: str,
        preserved: str | None,
    ) -> None:
        """A successful configure must not leave Hermes's opt-in list unusable."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(f"plugins:\n  enabled: {raw_enabled}\n", encoding="utf-8")

        w = _writer(tmp_path)
        w.upsert_mordred_sections({"mordred_privacy_check": {"policy": "strict", "allow_cloud_llm": False}})

        from ruamel.yaml import YAML

        with config_path.open(encoding="utf-8") as f:
            data = YAML(typ="safe", pure=True).load(f)
        enabled = data["plugins"]["enabled"]
        assert isinstance(enabled, list)
        if preserved is not None:
            assert preserved in enabled
        for name in MORDRED_PLUGIN_NAMES:
            assert name in enabled

    def test_unhashable_enabled_items_are_removed_before_real_hermes_discovery(
        self,
        tmp_path: Path,
    ) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            """\
plugins:
  enabled:
    - {broken: true}
    - [also, broken]
    - ""
    - some_user_plugin
""",
            encoding="utf-8",
        )

        w = _writer(tmp_path)
        w.upsert_mordred_sections({"mordred_privacy_check": {"policy": "strict", "allow_cloud_llm": False}})

        from ruamel.yaml import YAML

        with config_path.open(encoding="utf-8") as f:
            data = YAML(typ="safe", pure=True).load(f)
        enabled = data["plugins"]["enabled"]
        assert enabled == ["some_user_plugin", *MORDRED_PLUGIN_NAMES]

        source_path = str(Path(__file__).resolve().parent.parent / "src")
        env = os.environ.copy()
        env["HERMES_HOME"] = str(tmp_path)
        env.pop("HERMES_SAFE_MODE", None)
        prior_pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = source_path if not prior_pythonpath else source_path + os.pathsep + prior_pythonpath
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                """\
import json
from hermes_cli.plugins import PluginManager, _get_enabled_plugins
enabled = _get_enabled_plugins()
manager = PluginManager()
manager.discover_and_load(force=True)
print(json.dumps({
    "enabled": sorted(enabled) if enabled is not None else None,
    "wizard_discovered": "mordred" in manager._plugins,
}))
""",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        assert completed.returncode == 0, completed.stderr
        result = json.loads(completed.stdout.splitlines()[-1])
        assert result["enabled"] == sorted(["some_user_plugin", *MORDRED_PLUGIN_NAMES])
        assert result["wizard_discovered"] is True


class TestMergeMordredSections:
    """Partial-update merge API (Phase 3 PR3a, review-L4 fix from PR #18).

    ``upsert_mordred_sections`` does whole-section replacement -- correct for
    ``hermes mordred configure`` writing a full ``PolicySnapshot``, but
    destructive for partial writers like ``hermes mordred network use`` that
    only know about ``default_path``. The merge variant preserves on-disk
    sub-fields (Tor binary path, Mullvad account ref, etc.) that other code
    paths or hand-edits established.
    """

    def test_merge_preserves_existing_sub_fields(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  enabled:
    - mordred_network
  mordred_network:
    default_path: tor
    tor_binary_path: /usr/bin/tor
    tor_socks_port: 9050
    mullvad_account_id_env: MORDRED_MULLVAD_ACCOUNT
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "clearnet"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "clearnet"
        assert section["tor_binary_path"] == "/usr/bin/tor"
        assert section["tor_socks_port"] == 9050
        assert section["mullvad_account_id_env"] == "MORDRED_MULLVAD_ACCOUNT"

    def test_merge_idempotent(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  mordred_network:
    default_path: tor
    tor_binary_path: /usr/bin/tor
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})
        first_mtime = config_path.stat().st_mtime_ns
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})
        assert config_path.stat().st_mtime_ns == first_mtime, "no-op merge must not touch mtime"

    def test_merge_preserves_comments_and_anchors(self, tmp_path: Path) -> None:
        seed = """\
# user-owned config (preserve this comment)
profile: default  # inline

defaults: &defs
  retries: 3

plugins:
  enabled:
    - my_other_plugin
  mordred_network:
    default_path: tor  # set by `hermes mordred network use tor`
    tor_binary_path: /usr/bin/tor

  my_other_plugin:
    <<: *defs
    custom: value
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "clearnet"}})

        result = config_path.read_text(encoding="utf-8")
        assert "# user-owned config (preserve this comment)" in result
        assert "# inline" in result
        assert "&defs" in result
        assert "<<: *defs" in result
        assert "custom: value" in result
        assert "tor_binary_path: /usr/bin/tor" in result
        assert "default_path: clearnet" in result

    def test_merge_refuses_non_mordred_plugin(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        with pytest.raises(ValueError, match="refusing to touch 'random_plugin'"):
            w.merge_mordred_sections({"random_plugin": {"key": "value"}})

    def test_merge_creates_section_when_absent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "default_path: tor" in text
        for name in MORDRED_PLUGIN_NAMES:
            assert name in text, f"plugins.enabled must list {name}"

    def test_merge_creates_section_with_existing_unrelated_plugins(self, tmp_path: Path) -> None:
        """Fresh ``plugins.mordred_network`` section under an existing ``plugins`` block."""
        seed = """\
plugins:
  enabled:
    - my_other_plugin
  my_other_plugin:
    custom: value
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "vpn"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "vpn"
        assert data["plugins"]["my_other_plugin"]["custom"] == "value"

    def test_merge_overwrites_non_mapping_section(self, tmp_path: Path) -> None:
        """If ``plugins.mordred_network`` is pathologically a scalar / list, we
        replace it entirely with the merge body (no in-place merge possible)
        instead of crashing."""
        seed = """\
plugins:
  mordred_network: "string-instead-of-mapping"
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"] == {"default_path": "tor"}


class TestPolicySnapshotDisableIPv6Field:
    """Phase 3 PR3a Task #7: PolicySnapshot gains ``disable_ipv6`` so the
    wizard can persist it to ``policy.json``. The network reader (Task #2)
    consumes it through ``network.settings.resolve_disable_ipv6``; PolicyWriter is the
    sole writer side.
    """

    def test_default_is_true(self) -> None:
        """Safe-by-default mirrors RuntimeConfig.disable_ipv6 default."""
        snap = PolicySnapshot(policy="lenient")
        assert snap.disable_ipv6 is True

    def test_field_round_trips_through_policy_json(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="strict", disable_ipv6=False)
        w.emit_policy_json(snap)
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["disable_ipv6"] is False

    def test_field_omitted_from_privacy_check_section(self) -> None:
        """``disable_ipv6`` lives in policy.json + plugins.mordred_network, NOT
        in plugins.mordred_privacy_check (cross-plugin discipline)."""
        snap = PolicySnapshot(policy="strict", disable_ipv6=True)
        section = snap.to_config_yaml_section()
        assert "disable_ipv6" not in section


class TestNetworkAnswersToConfigYamlSection:
    """``NetworkAnswers.to_config_yaml_section()`` returns the body upserted
    into ``plugins.mordred_network`` so PolicyWriter.write can persist it
    alongside snapshot fields."""

    def test_to_config_yaml_section_shape(self) -> None:
        from mordred_hermes.wizard.network_cli import NetworkAnswers

        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/opt/tor/bin/tor",
            tor_socks_port=19050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=True,
        )
        section = na.to_config_yaml_section()
        assert section == {
            "default_path": "vpn",
            "tor_binary_path": "/opt/tor/bin/tor",
            "tor_socks_port": 19050,
            "mullvad_account_id_env": "MORDRED_MULLVAD_ACCOUNT",
            "mullvad_relay_country": "jp",
            "mullvad_killswitch": True,
            "vpn_provider": "mullvad",
        }


class TestPolicyWriterWritesNetworkSection:
    """Task #7: ``PolicyWriter.write`` accepts an optional
    ``network_answers`` and upserts ``plugins.mordred_network`` in
    config.yaml via :meth:`merge_mordred_sections`. The merge variant is
    used (not whole-replace) so future writers like ``hermes mordred
    network use`` don't clobber the wizard's choices when only the path
    changes (Task #1 contract)."""

    def test_write_upserts_network_section_when_answers_provided(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.network_cli import NetworkAnswers

        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="strict")
        na = NetworkAnswers(
            default_network_path="tor",
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=True,
        )
        w.write(snap, network_answers=na)
        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "tor"
        assert section["mullvad_killswitch"] is True
        assert section["tor_socks_port"] == 9050

    def test_write_without_network_answers_omits_section(self, tmp_path: Path) -> None:
        """Backward compat: existing call sites passing only ``snapshot``
        must not write a (probably-wrong-default-valued) mordred_network."""
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="lenient"))
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        # mordred_network may appear in plugins.enabled, but its section
        # body should be absent (no default_path / tor_binary_path / ...).
        assert "default_path" not in text
        assert "tor_binary_path" not in text

    def test_write_uses_merge_not_whole_replace(self, tmp_path: Path) -> None:
        """When a prior network section exists (e.g., from a previous
        configure run that the user partially edited), the wizard must
        merge -- not clobber -- per the Task #1 contract."""
        from mordred_hermes.wizard.network_cli import NetworkAnswers

        config_path = tmp_path / "config.yaml"
        seed = """\
plugins:
  mordred_network:
    default_path: tor
    custom_user_field: keep-me
"""
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        w.write(PolicySnapshot(policy="strict"), network_answers=na)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "vpn"
        assert section["custom_user_field"] == "keep-me", "merge must preserve unknown user fields"


class TestCorruptedPluginsScalarRecovery:
    """H1 (review 2026-05-14): when ``config.yaml`` has a corrupted
    ``plugins: <scalar>`` (e.g. a string, list, or None from a hand-edit
    or a half-finished crash recovery), both merge and upsert helpers
    must not crash with AttributeError / TypeError. They should treat
    the corrupted section as ``{}`` and rebuild it.
    """

    def test_merge_recovers_from_plugins_scalar(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("plugins: a-string\n", encoding="utf-8")

        w = _writer(tmp_path)
        # Must not crash with AttributeError.
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"

    def test_upsert_recovers_from_plugins_scalar(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("plugins: 42\n", encoding="utf-8")

        w = _writer(tmp_path)
        # Must not crash with TypeError on int subscript.
        w.upsert_mordred_sections(
            {"mordred_privacy_check": {"policy": "lenient", "allow_cloud_llm": False, "cloud_provider_allowlist": []}}
        )

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "lenient"

    def test_merge_recovers_from_plugins_list(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("plugins:\n  - item1\n  - item2\n", encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "vpn"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "vpn"


class TestUpsertMordredSectionsStillReplaces:
    """Regression guard: ``upsert_mordred_sections`` (whole-replace) must keep
    its full-snapshot semantics so ``configure`` rewrites stay clean.

    The merge variant is the new partial-update API. The whole-replace one is
    NOT deprecated — it is the right behaviour when the caller has computed
    every field of the section from scratch.
    """

    def test_upsert_clobbers_unspecified_sub_fields(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  mordred_network:
    default_path: tor
    tor_binary_path: /usr/bin/tor
    tor_socks_port: 9050
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.upsert_mordred_sections({"mordred_network": {"default_path": "clearnet"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section == {"default_path": "clearnet"}, "whole-replace must drop unspecified sub-fields"


class TestWriteCompose:
    def test_writes_both_files(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict", allow_cloud_llm=True, cloud_provider_allowlist=("anthropic",)))
        json_path = tmp_path / "mordred" / "policy.json"
        yaml_path = tmp_path / "config.yaml"
        assert json_path.exists()
        assert yaml_path.exists()
        body = json.loads(json_path.read_text(encoding="utf-8"))
        assert body["policy"] == "strict"
        assert body["allow_cloud_llm"] is True
        ytext = yaml_path.read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "anthropic" in ytext

    def test_no_lingering_tmp_files_on_success(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="lenient"))
        leftovers = sorted(p.name for p in tmp_path.rglob("*.tmp"))
        assert leftovers == [], f"unexpected .tmp leftovers: {leftovers}"

    def test_begin_resynchronizes_an_idempotent_existing_marker(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.wizard import policy_writer as pw

        w = _writer(tmp_path)
        marker = pw.policy_transaction_marker_for_policy(w.policy_json_path)
        marker.parent.mkdir(parents=True)
        marker.write_text("pending\n", encoding="utf-8")
        marker.chmod(0o600)
        synced_fds: list[int] = []
        synced_parents: list[Path] = []

        monkeypatch.setattr(pw, "_atomic_write_text", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(pw, "_fsync_durable", lambda fd: synced_fds.append(fd))
        monkeypatch.setattr(pw, "_fsync_parent", lambda path: synced_parents.append(path))

        assert pw._begin_policy_transaction(w.policy_json_path) == marker
        assert len(synced_fds) == 1
        assert synced_parents == [marker]

    @pytest.mark.parametrize(
        ("old_mode", "new_mode"),
        [("strict", "off"), ("off", "strict")],
    )
    def test_second_file_failure_leaves_fail_closed_marker_until_reconciled(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        old_mode: str,
        new_mode: str,
    ) -> None:
        from mordred_hermes import _policy_io
        from mordred_hermes.privacy_check import _runtime as privacy_runtime
        from mordred_hermes.wizard import policy_writer as pw

        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy=old_mode))  # type: ignore[arg-type]
        real_atomic_write = pw._atomic_write_text

        def fail_config_write(path: Path, text: str, *, mode: int | None = None) -> None:
            if path == w.config_path:
                raise OSError("injected config write failure")
            real_atomic_write(path, text, mode=mode)

        monkeypatch.setattr(pw, "_atomic_write_text", fail_config_write)

        with pytest.raises(OSError, match="injected config write failure"):
            w.write(PolicySnapshot(policy=new_mode))  # type: ignore[arg-type]

        marker = _policy_io.policy_transaction_marker_for_policy(w.policy_json_path)
        assert marker.is_file()
        assert json.loads(w.policy_json_path.read_text(encoding="utf-8"))["policy"] == new_mode
        assert _policy_io.load_policy_mapping(w.policy_json_path) == {}
        assert (
            _policy_io.read_policy_mode_fail_closed(
                w.policy_json_path,
                default="lenient",
                log=logging.getLogger("test.policy.transaction"),
            )
            == "strict"
        )
        assert privacy_runtime.get_active_policy_mode(config_path=w.config_path) == "strict"

        # A later successful configure reconciles both mirrors and is the only
        # operation allowed to clear the stale marker.
        monkeypatch.setattr(pw, "_atomic_write_text", real_atomic_write)
        w.write(PolicySnapshot(policy=new_mode))  # type: ignore[arg-type]
        assert not marker.exists()
        assert (
            _policy_io.read_policy_mode_fail_closed(
                w.policy_json_path,
                default="lenient",
                log=logging.getLogger("test.policy.transaction"),
            )
            == new_mode
        )
        assert privacy_runtime.get_active_policy_mode(config_path=w.config_path) == new_mode


class TestHasConfigYamlSectionProtocol:
    """H2 (review 2026-05-14): ``PolicyWriter.write`` accepted
    ``network_answers: object | None`` and called ``.to_config_yaml_section()``
    behind a ``# type: ignore[attr-defined]``. The structural shape is now
    described by a ``runtime_checkable`` Protocol exposed from the module so
    callers and tests can verify conformance and mypy --strict can drop the
    type ignore.
    """

    def test_protocol_is_runtime_checkable_and_importable(self) -> None:
        from mordred_hermes.wizard.policy_writer import _HasConfigYamlSection

        class _Stub:
            def to_config_yaml_section(self) -> dict[str, object]:
                return {"default_path": "tor"}

        class _NotStub:
            pass

        assert isinstance(_Stub(), _HasConfigYamlSection)
        assert not isinstance(_NotStub(), _HasConfigYamlSection)

    def test_write_accepts_protocol_shape_without_type_ignore(self, tmp_path: Path) -> None:
        """Duck-type compliance: any object implementing the Protocol works."""

        class _MinimalNetworkAnswers:
            def to_config_yaml_section(self) -> dict[str, object]:
                return {"default_path": "tor", "tor_socks_port": 9050}

        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"), network_answers=_MinimalNetworkAnswers())

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"
        assert data["plugins"]["mordred_network"]["tor_socks_port"] == 9050


class TestAtomicWriteHardening:
    """H3+M5+M6 (review 2026-05-14): the canonical ``_atomic_write_text``
    writes the tmpfile via ``Path.write_text``, which creates the file at
    the process umask (typically 0o644). For writes that specify
    ``mode=0o600`` (policy.json, .env, credentials JSON) the secret content
    lands on disk in the umask-default mode and a co-tenant on the same
    host can read it during the gap between ``write_text`` and ``os.chmod``.

    The tmpfile name is also predictable (``<path>.tmp``), so concurrent
    writers collide on the same path and a stale ``.tmp`` from a prior
    crash can break subsequent writes.

    Hardening: switch to ``tempfile.mkstemp`` (atomic ``O_CREAT|O_EXCL`` at
    0o600 with a random suffix). Closes H3 (umask window), M5 (predictable
    name), M6 (stale-collision).
    """

    def test_tmpfile_at_replace_time_matches_target_mode(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The tmpfile written by ``_atomic_write_text(..., mode=0o600)``
        must already be 0o600 (or tighter) at every observable point during
        its on-disk lifetime — not just after a post-write ``os.chmod``.

        We monitor every observable transition: the file's mode at the
        moment of the first stat after creation, at the moment of
        ``os.replace``, and at the moment of every ``os.chmod`` call. None
        of them may exceed the target mode. The current ``Path.write_text``
        approach leaves the file at umask-default (0o644) between
        ``write_text`` and ``os.chmod``; with ``tempfile.mkstemp`` the file
        is at 0o600 from the moment of creation.
        """
        from mordred_hermes.wizard import policy_writer as pw

        target = tmp_path / "policy.json"
        captured_pre_chmod: list[int] = []
        real_chmod = os.chmod

        def capturing_chmod(path: object, mode: int, *args: object, **kwargs: object) -> None:
            with contextlib.suppress(FileNotFoundError):
                if str(path).startswith(str(tmp_path)) and str(path) != str(target):
                    captured_pre_chmod.append(stat.S_IMODE(os.stat(str(path)).st_mode))
            real_chmod(path, mode, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "chmod", capturing_chmod)
        pw._atomic_write_text(target, "secret-payload\n", mode=0o600)

        too_broad = [oct(m) for m in captured_pre_chmod if m > 0o600]
        assert not too_broad, (
            f"tmpfile observed at mode wider than 0o600 before chmod: {too_broad}; "
            "umask-default window leaks secret content to co-tenants (H3)"
        )

    def test_tmpfile_name_is_randomized_per_invocation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Consecutive writes to the same target must use distinct tmpfile
        names — predictable ``<name>.tmp`` paths collide under concurrent
        writers (M5) and leave stale-collision footguns after a crash (M6).
        """
        from mordred_hermes.wizard import policy_writer as pw

        target = tmp_path / "policy.json"
        tmpfiles_seen: list[str] = []
        real_replace = os.replace

        def capturing_replace(src: object, dst: object, *args: object, **kwargs: object) -> None:
            tmpfiles_seen.append(os.path.basename(str(src)))
            real_replace(src, dst, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "replace", capturing_replace)
        pw._atomic_write_text(target, "first-payload\n", mode=0o600)
        # second write must produce a different content so idempotent-skip
        # doesn't short-circuit (and thus skip the tmpfile rotation).
        pw._atomic_write_text(target, "second-payload\n", mode=0o600)

        assert len(tmpfiles_seen) == 2, f"expected 2 replace calls, got {tmpfiles_seen}"
        assert tmpfiles_seen[0] != tmpfiles_seen[1], (
            f"tmpfile names must be randomized to avoid predictable collisions; "
            f"got the same name {tmpfiles_seen[0]!r} twice"
        )

    def test_matching_symlink_is_replaced_instead_of_treated_as_idempotent(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard import policy_writer as pw

        victim = tmp_path / "victim.txt"
        victim.write_text("same\n", encoding="utf-8")
        target = tmp_path / "policy.json"
        target.symlink_to(victim)

        pw._atomic_write_text(target, "same\n", mode=0o600)

        assert target.is_file() and not target.is_symlink()
        assert target.read_text(encoding="utf-8") == "same\n"
        assert victim.read_text(encoding="utf-8") == "same\n"

    def test_matching_content_rewrites_atomically_when_fchmod_is_unavailable(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.wizard import policy_writer as pw

        target = tmp_path / "policy.json"
        target.write_text("same\n", encoding="utf-8")
        target.chmod(0o644)
        replacements: list[tuple[object, object]] = []
        real_replace = pw.os.replace

        def record_replace(src: object, dst: object) -> None:
            replacements.append((src, dst))
            real_replace(src, dst)  # type: ignore[arg-type]

        monkeypatch.delattr(pw.os, "fchmod", raising=False)
        monkeypatch.setattr(pw.os, "replace", record_replace)

        pw._atomic_write_text(target, "same\n", mode=0o600)

        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert len(replacements) == 1

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
    def test_fifo_is_replaced_without_attempting_to_read_it(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.wizard import policy_writer as pw

        target = tmp_path / "policy.json"
        os.mkfifo(target, mode=0o600)
        real_read_text = Path.read_text

        def reject_fifo_read(candidate: Path, *args: object, **kwargs: object) -> str:
            if candidate == target:
                pytest.fail("atomic writer must not read a FIFO")
            return real_read_text(candidate, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", reject_fifo_read)

        pw._atomic_write_text(target, "replacement\n", mode=0o600)

        assert stat.S_ISREG(target.lstat().st_mode)
        assert target.read_bytes() == b"replacement\n"


class TestSinglePluginIdentity:
    """Mordred is one Hermes plugin, ``mordred``. Config writers enable it and
    migrate the six pre-0.2.0a0 per-component names (``mordred_e2e`` once went
    missing from the enable list and left E2E inert; one name removes that
    class of bug)."""

    def test_only_mordred_is_enabled_and_sections_keep_their_names(self) -> None:
        assert MORDRED_PLUGIN_NAMES == ("mordred",)
        assert "mordred_e2e" in MORDRED_CONFIG_SECTIONS
        assert "mordred_privacy_check" in MORDRED_CONFIG_SECTIONS

    def test_fresh_write_enables_mordred(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="lenient"))

        from ruamel.yaml import YAML

        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = YAML(typ="safe", pure=True).load(f)
        assert data["plugins"]["enabled"] == ["mordred"]

    def test_write_migrates_legacy_names(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            """\
# operator comment
plugins:
  enabled:
    - mordred_privacy_check
    - other_plugin
    - mordred_network
  disabled:
    - mordred_keyvault
    - unrelated
""",
            encoding="utf-8",
        )
        w = _writer(tmp_path)
        with caplog.at_level("WARNING", logger="mordred.wizard.policy_writer"):
            w.upsert_mordred_sections({"mordred_privacy_check": {"policy": "lenient", "allow_cloud_llm": False}})

        from ruamel.yaml import YAML

        text = config_path.read_text(encoding="utf-8")
        data = YAML(typ="safe", pure=True).load(text)
        assert "# operator comment" in text
        assert data["plugins"]["enabled"] == ["other_plugin", "mordred"]
        assert data["plugins"]["disabled"] == ["unrelated"]
        assert "can no longer be disabled separately" in caplog.text

    def test_migrate_plugin_identity_only_touches_the_lists(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        seed = """\
model:
  provider: local  # keep
plugins:
  enabled:
    - mordred_e2e
    - mordred_wizard
  mordred_network:
    default_path: tor
"""
        config_path.write_text(seed, encoding="utf-8")
        w = _writer(tmp_path)

        migration = w.migrate_plugin_identity()

        assert migration.changed
        assert migration.removed_enabled == ["mordred_e2e", "mordred_wizard"]
        text = config_path.read_text(encoding="utf-8")
        assert "provider: local  # keep" in text
        assert "default_path: tor" in text
        assert "- mordred\n" in text and "mordred_e2e" not in text
        assert not (tmp_path / "mordred" / "policy.json").exists()

        # Idempotent: a second run changes nothing and does not rewrite the file.
        before = config_path.stat().st_mtime_ns
        assert not w.migrate_plugin_identity().changed
        assert config_path.stat().st_mtime_ns == before

    def test_migrate_plugin_identity_leaves_a_missing_config_missing(self, tmp_path: Path) -> None:
        assert not _writer(tmp_path).migrate_plugin_identity().changed
        assert not (tmp_path / "config.yaml").exists()

    def test_explicitly_disabled_mordred_is_respected_and_reported(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("plugins:\n  enabled: [mordred]\n  disabled: [mordred]\n", encoding="utf-8")

        migration = _writer(tmp_path).migrate_plugin_identity()

        assert not migration.changed
        assert migration.mordred_disabled
        assert any("still lists 'mordred'" in note for note in migration.notes())
        assert "disabled: [mordred]" in config_path.read_text(encoding="utf-8")
