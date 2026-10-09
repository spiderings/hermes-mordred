"""Tests for Story 1.5 OpenClaw migration conflict resolution.

Row policy (PATHS.md §Migration from legacy OpenClaw paths):

| OpenClaw path | New path | Conflict policy |
|---|---|---|
| audit.log | append-by-timestamp-window; marker last | --audit-merge=skip|append-all|abort |
| keyvault/ | never overwrite | abort if dest exists |
| credentials/ | never overwrite | abort if dest exists |
| openclaw.json plugins | upsert via PolicyWriter | --policy-conflict=keep-existing|overwrite|abort |

Idempotency marker: `~/.hermes/mordred/.audit-migrated-from-openclaw`
holds an ISO-8601 UTC timestamp; presence skips audit migration on
re-runs (use --reset to force).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import threading
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.privacy_check.audit import NDJSONWriter
from mordred_hermes.wizard import openclaw_migration, upgrade
from mordred_hermes.wizard.policy_writer import PolicyWriter


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "hermes" / "config.yaml",
        policy_json_path=tmp_path / "hermes" / "mordred" / "policy.json",
        mordred_dir=tmp_path / "hermes" / "mordred",
    )


def _seed_openclaw(
    base: Path,
    *,
    audit_lines: list[str] | None = None,
    policy: dict[str, Any] | None = None,
    keyvault: bool = False,
    credentials: bool = False,
    openclaw_json: dict[str, Any] | None = None,
) -> None:
    """Create a synthetic ~/.openclaw/mordred/ tree under ``base``.

    ``base`` is the OpenClaw root (e.g. ``tmp_path / "openclaw" / "mordred"``).
    The sibling ``openclaw.json`` lives at ``base.parent / "openclaw.json"``.
    """
    base.mkdir(parents=True, exist_ok=True)
    if audit_lines:
        (base / "audit.log").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
    if policy is not None:
        (base / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    if keyvault:
        (base / "keyvault").mkdir(exist_ok=True)
        (base / "keyvault" / "key1.bin").write_bytes(b"opaque-keyvault-bytes")
    if credentials:
        (base / "credentials").mkdir(exist_ok=True)
        (base / "credentials" / "network.json").write_bytes(b'{"x": 1}')
    if openclaw_json is not None:
        (base.parent / "openclaw.json").write_text(json.dumps(openclaw_json), encoding="utf-8")


# -----------------------------------------------------------------------------
# detect() -- presence flags only, no migration
# -----------------------------------------------------------------------------


class TestDetect:
    def test_all_absent(self, tmp_path: Path) -> None:
        state = openclaw_migration.detect(tmp_path / "openclaw" / "mordred")
        assert state.has_audit is False
        assert state.has_policy_json is False
        assert state.has_keyvault is False
        assert state.has_credentials is False
        assert state.has_openclaw_json is False

    def test_all_present(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
            policy={"policy": "strict"},
            keyvault=True,
            credentials=True,
            openclaw_json={"plugins": {"entries": {}}},
        )
        state = openclaw_migration.detect(base)
        assert state.has_audit is True
        assert state.has_policy_json is True
        assert state.has_keyvault is True
        assert state.has_credentials is True
        assert state.has_openclaw_json is True


# -----------------------------------------------------------------------------
# migrate() -- top-level dispatch returns Story1_5Action
# -----------------------------------------------------------------------------


class TestMigrateNoOp:
    def test_returns_noop_when_base_missing(self, tmp_path: Path) -> None:
        result = openclaw_migration.migrate(
            openclaw_base=tmp_path / "no-such-base",
            policy_writer=_writer(tmp_path),
            options=upgrade.UpgradeOptions(),
        )
        assert result == "noop"

    def test_returns_noop_when_base_exists_but_empty(self, tmp_path: Path) -> None:
        """Codex review: `openclaw_base` existing as a bare directory with NONE
        of the recognized artifacts (no audit.log, no keyvault/, no
        credentials/, no sibling openclaw.json) must report "noop" -- nothing
        was actually copied or written, so "migrated" would mislead the
        `hermes-mordred upgrade` summary line."""
        base = tmp_path / "openclaw" / "mordred"
        base.mkdir(parents=True)
        result = openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=_writer(tmp_path),
            options=upgrade.UpgradeOptions(),
        )
        assert result == "noop"


# -----------------------------------------------------------------------------
# Audit log migration (H5: append-by-timestamp-window + marker file)
# -----------------------------------------------------------------------------


class TestAuditMigration:
    def test_safe_append_when_no_existing_audit(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=[
                '{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow","skill_id":"a"}',
                '{"ts":"2026-05-02T00:00:00.000Z","event":"pre_install","decision":"allow","skill_id":"b"}',
            ],
        )
        w = _writer(tmp_path)
        result = openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(),
        )
        assert result == "migrated"
        # Hermes audit.log exists with both lines
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        assert hermes_audit.exists()
        lines = [line for line in hermes_audit.read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 2
        assert "skill_id" in lines[0]

    def test_hardlinked_source_and_destination_are_refused_before_locking(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        source_line = '{"ts":"2026-05-01T00:00:00.000Z","event":"legacy","decision":"allow"}\n'
        _seed_openclaw(base, audit_lines=[source_line.strip()])
        writer = _writer(tmp_path)
        dest = writer.mordred_dir / "audit.log"
        dest.parent.mkdir(parents=True)
        os.link(base / "audit.log", dest)

        with pytest.raises(SystemExit, match="must be different files"):
            openclaw_migration.migrate(
                openclaw_base=base,
                policy_writer=writer,
                options=upgrade.UpgradeOptions(),
            )

        assert (base / "audit.log").read_text(encoding="utf-8") == source_line
        assert dest.read_text(encoding="utf-8") == source_line
        assert not (writer.mordred_dir / openclaw_migration.MARKER_FILENAME).exists()

    def test_marker_written_after_successful_migration(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(),
        )
        marker = tmp_path / "hermes" / "mordred" / ".audit-migrated-from-openclaw"
        assert marker.exists()
        content = marker.read_text(encoding="utf-8").strip()
        assert content.endswith("Z")
        assert "T" in content

    def test_marker_skips_re_migration(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        lines_after_first = hermes_audit.read_text(encoding="utf-8")

        result = openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        assert result == "skipped-marker"
        assert hermes_audit.read_text(encoding="utf-8") == lines_after_first

    def test_reset_overrides_marker(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        result = openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(reset=True, audit_merge="append-all"),
        )
        assert result == "migrated"
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        lines = [line for line in hermes_audit.read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 2

    def test_overlap_aborts_without_audit_merge_flag(self, tmp_path: Path) -> None:
        """Existing Hermes audit overlaps OpenClaw audit -> needs explicit policy."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-05T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        hermes_audit.parent.mkdir(parents=True, exist_ok=True)
        hermes_audit.write_text(
            '{"ts":"2026-05-04T00:00:00.000Z","event":"pre_install","decision":"allow"}\n',
            encoding="utf-8",
        )
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"audit-merge"):
            openclaw_migration.migrate(
                openclaw_base=base,
                policy_writer=w,
                options=upgrade.UpgradeOptions(),
            )

    def test_overlap_skip_does_not_append(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-05T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        hermes_audit.parent.mkdir(parents=True, exist_ok=True)
        original = '{"ts":"2026-05-04T00:00:00.000Z","event":"pre_install","decision":"allow"}\n'
        hermes_audit.write_text(original, encoding="utf-8")
        w = _writer(tmp_path)
        openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(audit_merge="skip"),
        )
        assert hermes_audit.read_text(encoding="utf-8") == original

    def test_live_destination_append_waits_for_migration_and_is_preserved(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"legacy","decision":"allow"}'],
        )
        writer = _writer(tmp_path)
        dest = writer.mordred_dir / "audit.log"
        publish_entered = threading.Event()
        release_publish = threading.Event()
        append_done = threading.Event()
        failures: list[BaseException] = []
        from mordred_hermes.wizard.policy_writer import _atomic_write_text as real_atomic_write

        def blocked_publish(path: Path, text: str, *, mode: int | None = None) -> None:
            if path == dest:
                publish_entered.set()
                if not release_publish.wait(timeout=5):
                    raise RuntimeError("test publish release timed out")
            real_atomic_write(path, text, mode=mode)

        monkeypatch.setattr(
            "mordred_hermes.wizard.openclaw_migration._atomic_write_text",
            blocked_publish,
        )

        def migrate_audit() -> None:
            try:
                openclaw_migration.migrate(
                    openclaw_base=base,
                    policy_writer=writer,
                    options=upgrade.UpgradeOptions(),
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        def append_live_entry() -> None:
            try:
                NDJSONWriter(dest).append({"event": "live", "decision": "allow"})
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)
            finally:
                append_done.set()

        migration_thread = threading.Thread(target=migrate_audit)
        append_thread = threading.Thread(target=append_live_entry)
        migration_thread.start()
        assert publish_entered.wait(timeout=5)
        append_thread.start()
        assert not append_done.wait(timeout=0.1), "live writer bypassed the destination sidecar lock"
        release_publish.set()
        migration_thread.join(timeout=5)
        append_thread.join(timeout=5)

        assert not migration_thread.is_alive() and not append_thread.is_alive()
        assert failures == []
        entries = [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines()]
        assert [entry["event"] for entry in entries] == ["legacy", "live"]

    def test_encrypted_destination_is_refused_without_mutation(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        source_line = '{"ts":"2026-05-01T00:00:00.000Z","event":"legacy","decision":"allow"}\n'
        _seed_openclaw(base, audit_lines=[source_line.strip()])
        writer = _writer(tmp_path)
        dest = writer.mordred_dir / "audit.log"
        dest.parent.mkdir(parents=True)
        original_dest = b'{"fmt":"MRAL","v":1,"key_id":"mordred.audit-log"}\nopaque-ciphertext\n'
        dest.write_bytes(original_dest)

        with pytest.raises(SystemExit, match="encrypted or foreign destination audit log"):
            openclaw_migration.migrate(
                openclaw_base=base,
                policy_writer=writer,
                options=upgrade.UpgradeOptions(audit_merge="append-all"),
            )

        assert dest.read_bytes() == original_dest
        assert (base / "audit.log").read_text(encoding="utf-8") == source_line
        assert not (writer.mordred_dir / openclaw_migration.MARKER_FILENAME).exists()

    @pytest.mark.parametrize("foreign_side", ["source", "destination"])
    def test_missing_timestamp_is_refused_as_foreign_without_mutation(
        self,
        tmp_path: Path,
        foreign_side: str,
    ) -> None:
        base = tmp_path / "openclaw" / "mordred"
        valid_source = '{"ts":"2026-05-01T00:00:00.000Z","event":"legacy","decision":"allow"}\n'
        _seed_openclaw(base, audit_lines=[valid_source.strip()])
        writer = _writer(tmp_path)
        dest = writer.mordred_dir / "audit.log"
        dest.parent.mkdir(parents=True)
        valid_dest = '{"ts":"2026-05-02T00:00:00.000Z","event":"current","decision":"allow"}\n'
        dest.write_text(valid_dest, encoding="utf-8")
        foreign = '{"event":"not-an-audit-entry"}\n'
        foreign_path = base / "audit.log" if foreign_side == "source" else dest
        foreign_path.write_text(foreign, encoding="utf-8")

        with pytest.raises(SystemExit, match=f"foreign {foreign_side} audit log"):
            openclaw_migration.migrate(
                openclaw_base=base,
                policy_writer=writer,
                options=upgrade.UpgradeOptions(audit_merge="append-all"),
            )

        expected_source = foreign if foreign_side == "source" else valid_source
        expected_dest = foreign if foreign_side == "destination" else valid_dest
        assert (base / "audit.log").read_text(encoding="utf-8") == expected_source
        assert dest.read_text(encoding="utf-8") == expected_dest
        assert not (writer.mordred_dir / openclaw_migration.MARKER_FILENAME).exists()

    def test_concurrent_migrations_append_source_only_once(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"legacy","decision":"allow"}'],
        )
        writer = _writer(tmp_path)
        ready = threading.Barrier(2)
        results: list[str] = []
        failures: list[BaseException] = []

        def migrate_once() -> None:
            try:
                ready.wait(timeout=5)
                results.append(
                    openclaw_migration.migrate(
                        openclaw_base=base,
                        policy_writer=writer,
                        options=upgrade.UpgradeOptions(),
                    )
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        threads = [threading.Thread(target=migrate_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        assert all(not thread.is_alive() for thread in threads)
        assert failures == []
        assert sorted(results) == ["migrated", "skipped-marker"]
        dest = writer.mordred_dir / "audit.log"
        entries = [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines()]
        assert [entry["event"] for entry in entries] == ["legacy"]


# -----------------------------------------------------------------------------
# Keyvault / credentials -- never overwrite
# -----------------------------------------------------------------------------


class TestKeyvaultCredentialsNeverOverwrite:
    def test_keyvault_copied_when_dest_absent(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        dest_keyvault = tmp_path / "hermes" / "mordred" / "keyvault"
        assert dest_keyvault.is_dir()
        assert (dest_keyvault / "key1.bin").read_bytes() == b"opaque-keyvault-bytes"

    def test_keyvault_collision_aborts(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        hermes_kv = tmp_path / "hermes" / "mordred" / "keyvault"
        hermes_kv.mkdir(parents=True)
        (hermes_kv / "existing.bin").write_bytes(b"do-not-touch")
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"keyvault"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        assert (hermes_kv / "existing.bin").read_bytes() == b"do-not-touch"

    def test_credentials_collision_aborts(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, credentials=True)
        hermes_creds = tmp_path / "hermes" / "mordred" / "credentials"
        hermes_creds.mkdir(parents=True)
        (hermes_creds / "x.json").write_bytes(b"{}")
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"credentials"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())

    def test_keyvault_idempotent_when_already_migrated(self, tmp_path: Path) -> None:
        """Codex P1-B: second `upgrade` after a successful first run must not abort.

        First run copies keyvault. Second run sees dest exists with identical
        content -- treat as already migrated and skip (NOT abort).
        """
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        # Second run -- must not crash even though dest now exists
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        # Existing dest content unchanged
        dest_keyvault = tmp_path / "hermes" / "mordred" / "keyvault"
        assert (dest_keyvault / "key1.bin").read_bytes() == b"opaque-keyvault-bytes"

    def test_idempotent_retry_repairs_existing_destination_modes(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        source_nested = src / "nested"
        source_nested.mkdir(parents=True)
        source_file = source_nested / "key.bin"
        source_file.write_bytes(b"secret")
        dest = tmp_path / "dest"
        shutil.copytree(src, dest)
        os.chmod(dest, 0o777)
        os.chmod(dest / "nested", 0o775)
        os.chmod(dest / "nested" / "key.bin", 0o644)

        assert openclaw_migration._migrate_directory(src, dest, "keyvault") is False

        assert stat.S_IMODE(dest.stat().st_mode) == 0o700
        assert stat.S_IMODE((dest / "nested").stat().st_mode) == 0o700
        assert stat.S_IMODE((dest / "nested" / "key.bin").stat().st_mode) == 0o600
        assert source_file.read_bytes() == b"secret"

    def test_keyvault_content_collision_still_aborts(self, tmp_path: Path) -> None:
        """Idempotency must NOT swallow real data conflicts -- different content
        at dest still aborts (data-loss protection per PATHS.md H5)."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        # Pre-existing Hermes keyvault with DIFFERENT content
        hermes_kv = tmp_path / "hermes" / "mordred" / "keyvault"
        hermes_kv.mkdir(parents=True)
        (hermes_kv / "key1.bin").write_bytes(b"different-content")
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"keyvault"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        # Existing data must remain untouched
        assert (hermes_kv / "key1.bin").read_bytes() == b"different-content"

    def test_dangling_destination_symlink_is_never_replaced(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "key.bin").write_bytes(b"secret")
        dest = tmp_path / "dest"
        dest.symlink_to(tmp_path / "missing-target", target_is_directory=True)

        with pytest.raises(SystemExit, match="refusing to overwrite"):
            openclaw_migration._migrate_directory(src, dest, "keyvault")

        assert dest.is_symlink()

    def test_symlinked_source_root_is_refused(self, tmp_path: Path) -> None:
        actual = tmp_path / "actual"
        actual.mkdir()
        (actual / "key.bin").write_bytes(b"secret")
        src = tmp_path / "src"
        src.symlink_to(actual, target_is_directory=True)
        dest = tmp_path / "dest"

        with pytest.raises(SystemExit, match="unsafe non-directory"):
            openclaw_migration._migrate_directory(src, dest, "keyvault")

        assert not dest.exists()

    def test_nested_source_symlink_is_refused(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"outside-secret")
        src = tmp_path / "src"
        src.mkdir()
        (src / "linked.bin").symlink_to(outside)
        dest = tmp_path / "dest"

        with pytest.raises(SystemExit, match="symlink or special"):
            openclaw_migration._migrate_directory(src, dest, "credentials")

        assert not dest.exists()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
    def test_nested_source_fifo_is_refused(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        os.mkfifo(src / "pipe", mode=0o600)
        dest = tmp_path / "dest"

        with pytest.raises(SystemExit, match="symlink or special"):
            openclaw_migration._migrate_directory(src, dest, "credentials")

        assert not dest.exists()

    def test_staged_tree_is_revalidated_before_publish(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "key.bin").write_bytes(b"secret")
        outside = tmp_path / "outside"
        outside.write_bytes(b"outside-secret")
        dest = tmp_path / "dest"

        def inject_staged_symlink(_src: Path, staged: Path, **_kwargs: object) -> None:
            staged.mkdir(parents=True)
            (staged / "linked.bin").symlink_to(outside)

        monkeypatch.setattr(openclaw_migration.shutil, "copytree", inject_staged_symlink)

        with pytest.raises(SystemExit, match="symlink or special"):
            openclaw_migration._migrate_directory(src, dest, "keyvault")

        assert not dest.exists()
        assert not list(tmp_path.glob(".dest.migrate-*"))

    def test_source_mutation_during_copy_is_refused_without_publishing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        src = tmp_path / "src"
        src.mkdir()
        source_file = src / "key.bin"
        source_file.write_bytes(b"before")
        dest = tmp_path / "dest"
        real_copytree = shutil.copytree

        def copy_then_mutate(source: Path, staged: Path, **kwargs: object) -> Path:
            result = real_copytree(source, staged, **kwargs)
            source_file.write_bytes(b"after!")
            return result

        monkeypatch.setattr(
            "mordred_hermes.wizard.openclaw_migration.shutil.copytree",
            copy_then_mutate,
        )

        with pytest.raises(SystemExit, match="source changed during migration"):
            openclaw_migration._migrate_directory(src, dest, "keyvault")

        assert not dest.exists()
        assert source_file.read_bytes() == b"after!"
        assert not list(tmp_path.glob(".dest.migrate-*"))

    def test_published_sensitive_tree_has_private_modes_without_changing_source(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        nested = src / "nested"
        nested.mkdir(parents=True)
        source_file = nested / "key.bin"
        source_file.write_bytes(b"secret")
        os.chmod(src, 0o777)
        os.chmod(nested, 0o775)
        os.chmod(source_file, 0o644)
        dest = tmp_path / "dest"

        assert openclaw_migration._migrate_directory(src, dest, "keyvault") is True

        assert stat.S_IMODE(dest.stat().st_mode) == 0o700
        assert stat.S_IMODE((dest / "nested").stat().st_mode) == 0o700
        assert stat.S_IMODE((dest / "nested" / "key.bin").stat().st_mode) == 0o600
        assert stat.S_IMODE(src.stat().st_mode) == 0o777
        assert stat.S_IMODE(nested.stat().st_mode) == 0o775
        assert stat.S_IMODE(source_file.stat().st_mode) == 0o644

    def test_sensitive_tree_flushes_files_then_directories_bottom_up(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "copied"
        nested = root / "nested"
        nested.mkdir(parents=True)
        copied_file = nested / "key.bin"
        copied_file.write_bytes(b"secret")
        labels = {
            (path.stat().st_dev, path.stat().st_ino): label
            for path, label in ((root, "root"), (nested, "nested"), (copied_file, "file"))
        }
        sync_order: list[str] = []

        def observe_sync(fd: int) -> None:
            metadata = os.fstat(fd)
            sync_order.append(labels[(metadata.st_dev, metadata.st_ino)])

        monkeypatch.setattr(openclaw_migration, "_fsync_durable", observe_sync)

        openclaw_migration._tighten_sensitive_tree(root, "keyvault")

        assert sync_order == ["file", "nested", "root"]

    def test_parent_fsync_failure_after_publish_is_not_reported_as_success(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "key.bin").write_bytes(b"secret")
        dest = tmp_path / "dest"

        def fail_parent_sync(path: Path) -> None:
            assert path == dest
            raise OSError("forced destination parent fsync failure")

        monkeypatch.setattr(openclaw_migration, "_fsync_parent", fail_parent_sync)

        with pytest.raises(OSError, match="forced destination parent fsync failure"):
            openclaw_migration._migrate_directory(src, dest, "keyvault")

        # rename already committed in this process, but the caller was not told
        # migration succeeded without a durable destination directory entry.
        assert (dest / "key.bin").read_bytes() == b"secret"
        assert not list(tmp_path.glob(".dest.migrate-*"))

    def test_same_size_and_mtime_with_different_bytes_is_not_identical(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dest = tmp_path / "dest"
        src.mkdir()
        dest.mkdir()
        src_file = src / "key.bin"
        dest_file = dest / "key.bin"
        src_file.write_bytes(b"AAAA")
        dest_file.write_bytes(b"BBBB")
        timestamp = 1_700_000_000_000_000_000
        os.utime(src_file, ns=(timestamp, timestamp))
        os.utime(dest_file, ns=(timestamp, timestamp))

        assert openclaw_migration._dirs_identical(src, dest) is False

    def test_directory_comparison_does_not_reuse_stale_filecmp_cache(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dest = tmp_path / "dest"
        src.mkdir()
        dest.mkdir()
        src_file = src / "key.bin"
        dest_file = dest / "key.bin"
        src_file.write_bytes(b"AAAA")
        dest_file.write_bytes(b"AAAA")
        timestamp = 1_700_000_000_000_000_000
        os.utime(src_file, ns=(timestamp, timestamp))
        os.utime(dest_file, ns=(timestamp, timestamp))

        assert openclaw_migration._dirs_identical(src, dest) is True

        dest_file.write_bytes(b"BBBB")
        os.utime(dest_file, ns=(timestamp, timestamp))

        assert openclaw_migration._dirs_identical(src, dest) is False

    def test_failed_copy_leaves_no_partial_destination(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = tmp_path / "src"
        dest = tmp_path / "dest"
        src.mkdir()
        (src / "key.bin").write_bytes(b"secret")

        def partial_then_fail(_src: Path, staged: Path, **_kwargs: object) -> None:
            staged.mkdir(parents=True)
            (staged / "partial.bin").write_bytes(b"partial")
            raise OSError("simulated copy failure")

        monkeypatch.setattr(openclaw_migration.shutil, "copytree", partial_then_fail)
        with pytest.raises(OSError, match="copy failure"):
            openclaw_migration._migrate_directory(src, dest, "keyvault")

        assert not dest.exists()
        assert not list(tmp_path.glob(".dest.migrate-*"))

    def test_partial_failure_retry_after_audit_overlap(self, tmp_path: Path) -> None:
        """Codex P1-B (sub-case): keyvault copies, then audit step aborts on
        overlap -- a retry with --audit-merge=skip must succeed, not crash on
        the now-existing keyvault dest."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            keyvault=True,
            audit_lines=['{"ts":"2026-05-05T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        # Pre-seed Hermes audit with overlapping ts (forces overlap abort)
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        hermes_audit.parent.mkdir(parents=True, exist_ok=True)
        hermes_audit.write_text(
            '{"ts":"2026-05-04T00:00:00.000Z","event":"pre_install","decision":"allow"}\n',
            encoding="utf-8",
        )
        w = _writer(tmp_path)

        # First run: keyvault copies, audit aborts (overlap, no merge flag)
        with pytest.raises(SystemExit, match=r"audit-merge"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())

        # Retry with --audit-merge=skip: must NOT crash on already-copied keyvault
        result = openclaw_migration.migrate(
            openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions(audit_merge="skip")
        )
        assert result == "migrated"


# -----------------------------------------------------------------------------
# Codex P1-A + P2 -- conflict resolver applies to OpenClaw snapshot too;
# policy.json mirror must be emitted when policy is migrated.
# -----------------------------------------------------------------------------


class TestCodexFindings:
    def test_openclaw_policy_respects_policy_conflict_keep_existing(self, tmp_path: Path) -> None:
        """Codex P1-A: --policy-conflict=keep-existing must protect the
        existing Hermes section even from OpenClaw migration overwrites."""
        # Pre-seed Hermes config with strict
        config = tmp_path / "hermes" / "config.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: strict\n"
            "    allow_cloud_llm: false\n    cloud_provider_allowlist: []\n",
            encoding="utf-8",
        )
        # OpenClaw wants to migrate "off"
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {"policy": "off", "allow_cloud_llm": False, "cloud_provider_allowlist": []},
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(policy_conflict="keep-existing"),
        )
        # Existing strict policy preserved
        assert "policy: strict" in config.read_text(encoding="utf-8")

    def test_openclaw_policy_respects_policy_conflict_abort(self, tmp_path: Path) -> None:
        """Codex P1-A: --policy-conflict=abort must SystemExit on OpenClaw policy mismatch."""
        config = tmp_path / "hermes" / "config.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: strict\n"
            "    allow_cloud_llm: false\n    cloud_provider_allowlist: []\n",
            encoding="utf-8",
        )
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {"policy": "off"},
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"policy-conflict"):
            openclaw_migration.migrate(
                openclaw_base=base,
                policy_writer=w,
                options=upgrade.UpgradeOptions(policy_conflict="abort"),
            )

    def test_openclaw_policy_emits_policy_json_mirror(self, tmp_path: Path) -> None:
        """Codex P2: policy.json mirror must be written when OpenClaw policy migrates."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {
                                "policy": "strict",
                                "allow_cloud_llm": True,
                                "cloud_provider_allowlist": ["anthropic"],
                            },
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        policy_json = tmp_path / "hermes" / "mordred" / "policy.json"
        assert policy_json.exists(), "policy.json mirror must be emitted by OpenClaw migration"
        import json as _json

        body = _json.loads(policy_json.read_text(encoding="utf-8"))
        assert body["policy"] == "strict"
        assert body["allow_cloud_llm"] is True
        assert body["cloud_provider_allowlist"] == ["anthropic"]

    def test_openclaw_policy_preserves_hermes_provider_overrides(self, tmp_path: Path) -> None:
        """The Story 1.5 writer shares configure/upgrade preservation semantics."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {"policy": "strict"},
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        override = {"corp-proxy": {"transport": "httpx", "future_unsafe_fact": True}}
        w.policy_json_path.parent.mkdir(parents=True)
        w.policy_json_path.write_text(
            json.dumps({"policy": "off", "provider_overrides": override}),
            encoding="utf-8",
        )

        openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(),
        )

        body = json.loads(w.policy_json_path.read_text(encoding="utf-8"))
        assert body["policy"] == "strict"
        assert body["provider_overrides"] == override


# -----------------------------------------------------------------------------
# openclaw.json policy block -- transform + upsert via PolicyWriter
# -----------------------------------------------------------------------------


class TestPolicyTransform:
    def test_transforms_openclaw_policy_into_config_yaml(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {
                                "policy": "strict",
                                "allow_cloud_llm": True,
                                "cloud_provider_allowlist": ["anthropic"],
                            },
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        ytext = (tmp_path / "hermes" / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "anthropic" in ytext
        assert "allow_cloud_llm: true" in ytext.lower()

    def test_string_false_allow_cloud_llm_migrates_to_false(self, tmp_path: Path) -> None:
        """M2 (security review 2026-06-11): a foreign OpenClaw config holding
        ``"allow_cloud_llm": "false"`` (string) must not truthy-coerce to an
        enabled cloud-LLM grant in the migrated config.yaml."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {
                                "policy": "strict",
                                "allow_cloud_llm": "false",
                            },
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        ytext = (tmp_path / "hermes" / "config.yaml").read_text(encoding="utf-8")
        assert "allow_cloud_llm: false" in ytext.lower()

    def test_missing_openclaw_policy_section_is_handled(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, openclaw_json={"plugins": {"entries": {}}})
        w = _writer(tmp_path)
        result = openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        # openclaw.json is present but carries no recognisable
        # mordred-privacy-check section -- and there's no audit/keyvault/
        # credentials either, so nothing was actually migrated: "noop", not
        # the misleading "migrated" (Codex review, see TestMigrateNoOp above).
        assert result == "noop"
