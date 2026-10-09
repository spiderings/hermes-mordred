"""Phase E tests -- `hermes mordred upgrade` Story 1 (idempotent migration).

RED phase 1: dataclass shape + minimum dispatch -- proves the file
imports and exposes the documented surface. Story 1.5 OpenClaw tests
live in `test_openclaw_migration.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mordred_hermes.wizard import upgrade
from mordred_hermes.wizard.policy_writer import PolicySnapshot

from ._helpers import _writer

# -----------------------------------------------------------------------------
# UpgradeOptions dataclass
# -----------------------------------------------------------------------------


class TestUpgradeOptions:
    def test_defaults(self) -> None:
        opts = upgrade.UpgradeOptions()
        assert opts.reset is False
        assert opts.non_interactive is False
        assert opts.audit_merge is None
        assert opts.policy_conflict is None

    def test_frozen(self) -> None:
        opts = upgrade.UpgradeOptions()
        with pytest.raises((AttributeError, Exception)):
            opts.reset = True  # type: ignore[misc]

    def test_audit_merge_accepts_known_values(self) -> None:
        for v in ("skip", "append-all", "abort"):
            assert upgrade.UpgradeOptions(audit_merge=v).audit_merge == v

    def test_policy_conflict_accepts_known_values(self) -> None:
        for v in ("keep-existing", "overwrite", "abort"):
            assert upgrade.UpgradeOptions(policy_conflict=v).policy_conflict == v


# -----------------------------------------------------------------------------
# upgrade.run() -- Story 1 happy paths
# -----------------------------------------------------------------------------


class TestRunNoOp:
    """Re-running upgrade against an already-migrated config is a no-op."""

    def test_returns_noop_when_no_existing_state_and_no_openclaw(self, tmp_path: Path) -> None:
        """Empty target = no Hermes config + no OpenClaw = nothing to do."""
        w = _writer(tmp_path)
        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "noop"
        assert report.story1_5_action == "noop"
        assert (tmp_path / "config.yaml").exists() is False, "noop must not create files"

    def test_existing_matching_section_is_noop(self, tmp_path: Path) -> None:
        """If config.yaml already has the snapshot the wizard would write, no rewrite."""
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="lenient")
        # First write seeds disk
        w.write(snap)
        first_mtime = (tmp_path / "config.yaml").stat().st_mtime_ns

        # Run upgrade with the same target snapshot -- must not touch the file
        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "noop"
        assert (tmp_path / "config.yaml").stat().st_mtime_ns == first_mtime


class TestRunStory1Apply:
    """Story 1: existing Hermes config but missing/different mordred section."""

    def test_writes_snapshot_when_section_absent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        # Pre-existing config with no mordred section
        config = tmp_path / "config.yaml"
        config.write_text("profile: default\n", encoding="utf-8")

        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="lenient"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "applied"
        text = config.read_text(encoding="utf-8")
        assert "mordred_privacy_check" in text
        assert "policy: lenient" in text
        # User's pre-existing profile key is preserved (round-trip)
        assert "profile: default" in text

    def test_apply_preserves_existing_provider_overrides(self, tmp_path: Path) -> None:
        """Upgrade back-fill must not erase operator transport evidence."""
        w = _writer(tmp_path)
        w.config_path.write_text("profile: default\n", encoding="utf-8")
        override = {"corp-proxy": {"transport": "httpx", "future_unsafe_fact": True}}
        w.policy_json_path.parent.mkdir(parents=True)
        w.policy_json_path.write_text(
            json.dumps(
                {
                    "policy": "off",
                    "provider_overrides": override,
                    "unknown_top_level": "drop",
                }
            ),
            encoding="utf-8",
        )

        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="lenient"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )

        assert report.story1_action == "applied"
        body = json.loads(w.policy_json_path.read_text(encoding="utf-8"))
        assert body["provider_overrides"] == override
        assert body["policy"] == "lenient"
        assert "unknown_top_level" not in body

    def test_integrated_openclaw_policy_is_resolved_before_default_backfill(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.config_path.write_text("profile: default\n", encoding="utf-8")
        openclaw_base = tmp_path / "openclaw" / "mordred"
        openclaw_base.mkdir(parents=True)
        (openclaw_base.parent / "openclaw.json").write_text(
            json.dumps(
                {
                    "plugins": {
                        "entries": {
                            "mordred-privacy-check": {
                                "config": {
                                    "policy": "strict",
                                    "allow_cloud_llm": False,
                                    "cloud_provider_allowlist": [],
                                }
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            openclaw_base=openclaw_base,
        )

        assert report.story1_action == "applied"
        assert report.story1_5_action == "migrated"
        assert "policy: strict" in w.config_path.read_text(encoding="utf-8")
        assert json.loads(w.policy_json_path.read_text(encoding="utf-8"))["policy"] == "strict"


class TestRunPolicyConflict:
    """When config.yaml has a different mordred section, --policy-conflict drives behaviour."""

    def test_keep_existing_does_not_overwrite(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        # Seed with strict
        w.write(PolicySnapshot(policy="strict"))

        report = upgrade.run(
            options=upgrade.UpgradeOptions(policy_conflict="keep-existing"),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="lenient"),  # different
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "kept-existing"
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in text  # not overwritten
        assert "policy: lenient" not in text

    def test_overwrite_replaces_section(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        report = upgrade.run(
            options=upgrade.UpgradeOptions(policy_conflict="overwrite"),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="off"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "overwritten"
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: off" in text

    def test_abort_raises_systemexit(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        with pytest.raises(SystemExit):
            upgrade.run(
                options=upgrade.UpgradeOptions(policy_conflict="abort"),
                policy_writer=w,
                target_snapshot=PolicySnapshot(policy="lenient"),
                openclaw_base=tmp_path / "no-openclaw-here",
            )

    def test_non_interactive_without_policy_conflict_aborts(self, tmp_path: Path) -> None:
        """--non-interactive without --policy-conflict must fail closed."""
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        with pytest.raises(SystemExit, match=r"policy-conflict"):
            upgrade.run(
                options=upgrade.UpgradeOptions(non_interactive=True),
                policy_writer=w,
                target_snapshot=PolicySnapshot(policy="lenient"),
                openclaw_base=tmp_path / "no-openclaw-here",
            )

    def test_custom_tagged_section_reaches_conflict_path(self, tmp_path: Path) -> None:
        """A custom YAML tag in the mordred section must not bypass conflict handling.

        Regression: the section read uses the rt loader (``round_trip=True``)
        precisely because the safe loader raises on custom tags — the broad
        catch would collapse that to "no section" and the upgrade would
        silently overwrite the operator's hand-edited section instead of
        honoring --policy-conflict.
        """
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))
        config = tmp_path / "config.yaml"
        config.write_text(
            config.read_text(encoding="utf-8").replace("policy: strict", "policy: !keep strict"),
            encoding="utf-8",
        )

        report = upgrade.run(
            options=upgrade.UpgradeOptions(policy_conflict="keep-existing"),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="strict"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "kept-existing"
        assert "policy: !keep strict" in config.read_text(encoding="utf-8")  # untouched

    def test_custom_tag_outside_section_stays_idempotent(self, tmp_path: Path) -> None:
        """A custom tag elsewhere in config.yaml must not break the noop path.

        The safe loader rejects the whole document on any tag; the rt read
        must still see the (plain, matching) mordred section and report noop.
        """
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))
        config = tmp_path / "config.yaml"
        config.write_text(
            config.read_text(encoding="utf-8") + "unrelated: !custom value\n",
            encoding="utf-8",
        )

        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="strict"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "noop"

    def test_reset_overrides_policy_conflict(self, tmp_path: Path) -> None:
        """--reset forces overwrite regardless of --policy-conflict."""
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        report = upgrade.run(
            options=upgrade.UpgradeOptions(reset=True, policy_conflict="keep-existing"),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="off"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "overwritten"
        assert "policy: off" in (tmp_path / "config.yaml").read_text(encoding="utf-8")


# -----------------------------------------------------------------------------
# Idempotency -- second run of the same upgrade is a no-op
# -----------------------------------------------------------------------------


class TestIdempotency:
    def test_second_run_is_noop_after_apply(self, tmp_path: Path) -> None:
        """Realistic: existing Hermes user runs `upgrade` to back-fill mordred,
        then re-runs -- second call must be a no-op (no rewrite, no mtime bump)."""
        w = _writer(tmp_path)
        # Pre-seed Hermes config (mordred section absent)
        (tmp_path / "config.yaml").write_text("profile: default\n", encoding="utf-8")
        snap = PolicySnapshot(policy="lenient")

        first = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert first.story1_action == "applied"
        first_mtime = (tmp_path / "config.yaml").stat().st_mtime_ns

        second = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert second.story1_action == "noop"
        assert (tmp_path / "config.yaml").stat().st_mtime_ns == first_mtime


# -----------------------------------------------------------------------------
# UpgradeReport shape
# -----------------------------------------------------------------------------


class TestReport:
    def test_report_has_story1_and_story1_5_fields(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert hasattr(report, "story1_action")
        assert hasattr(report, "story1_5_action")
        # Action values are documented strings
        assert report.story1_action in {"noop", "applied", "kept-existing", "overwritten"}
        assert report.story1_5_action in {"noop", "migrated", "skipped-marker"}


# -----------------------------------------------------------------------------
# render_report -- `hermes-mordred upgrade` must say what it did. UX review
# 2026-06-11: the CLI handler used to discard the report and print nothing,
# leaving a migration command silent even after migrating ~/.openclaw.
# -----------------------------------------------------------------------------


class TestRenderReport:
    @pytest.mark.parametrize(
        ("action", "phrase"),
        [
            ("noop", "already up to date"),
            ("applied", "applied"),
            ("kept-existing", "kept existing"),
            ("overwritten", "overwritten"),
        ],
    )
    def test_story1_actions_render_human_phrases(self, action: str, phrase: str) -> None:
        report = upgrade.UpgradeReport(story1_action=action, story1_5_action="noop")  # type: ignore[arg-type]
        assert phrase in upgrade.render_report(report)

    @pytest.mark.parametrize(
        ("action", "phrase"),
        [
            # "no OpenClaw install detected" was a false statement once migrate()
            # started returning "noop" ALSO when the base dir exists but holds
            # nothing to migrate -- the phrase changed accordingly.
            ("noop", "nothing to migrate"),
            ("migrated", "migrated"),
            ("skipped-marker", "already migrated"),
        ],
    )
    def test_story1_5_actions_render_human_phrases(self, action: str, phrase: str) -> None:
        report = upgrade.UpgradeReport(story1_action="noop", story1_5_action=action)  # type: ignore[arg-type]
        assert phrase in upgrade.render_report(report)

    def test_cli_handler_prints_summary(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The argparse handler must surface the report, not swallow it."""
        import argparse

        from mordred_hermes.wizard import cli

        report = upgrade.UpgradeReport(story1_action="applied", story1_5_action="noop")
        monkeypatch.setattr(upgrade, "run", lambda **_kwargs: report)
        ns = argparse.Namespace(reset=False, non_interactive=False, audit_merge=None, policy_conflict=None)
        rc = cli._handle_upgrade(ns)
        assert rc == 0
        out = capsys.readouterr().out
        assert "applied" in out
        assert "OpenClaw" in out


class TestPluginIdentityMigration:
    """``upgrade`` switches the pre-0.2.0a0 plugin names to the single ``mordred``."""

    def test_migrates_legacy_names_even_when_the_policy_is_unchanged(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="lenient")
        w.write(snap)
        config = tmp_path / "config.yaml"
        legacy = "    - mordred_network\n    - mordred_e2e\n"
        config.write_text(config.read_text(encoding="utf-8").replace("    - mordred\n", legacy), encoding="utf-8")

        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )

        assert report.story1_action == "noop"
        after = config.read_text(encoding="utf-8")
        assert "- mordred\n" in after and "mordred_network\n" not in after.split("mordred_privacy_check:")[0]
        assert report.plugin_notes
        rendered = upgrade.render_report(report)
        assert "single 'mordred' plugin" in rendered
        assert "mordred_network" in rendered

    def test_nothing_to_migrate_adds_no_report_line(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="lenient")
        w.write(snap)

        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )

        assert report.plugin_notes == ()
        assert "Hermes plugin" not in upgrade.render_report(report)
