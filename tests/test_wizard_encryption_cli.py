"""Tests for ``hermes mordred encryption`` — the unified at-rest toggle surface.

Phase 0: the namespace skeleton + a **side-effect-free** ``status`` that reports
the state of all four targets (``env`` / ``config`` / ``memory`` / ``workspace``)
without ever opening the vault cold path (no passphrase prompt) or probing the
device key store. Enrollment is read from the plaintext manifest body
(:func:`mordred_hermes.keyvault.manifest.parse_unverified`); the config opt-in is
the marker file; memory is its own opt-in / opt-out marker pair plus the sealed
state of ``<home>/memories/*.md``; the workspace is on-disk artifact +
mountpoint detection.

``active`` is the *effective* state on this OS: the runtime decrypt shims are
macOS-only (see :mod:`mordred_hermes.keyvault._runtime_env`), so an enrolled
target is reported inactive off ``darwin`` rather than implying protection that
is not actually wired.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, memory_crypto, vault
from mordred_hermes.keyvault._config_bootstrap import _marker_path
from mordred_hermes.keyvault._memory_hook import memory_marker_path, memory_optout_marker_path
from mordred_hermes.keyvault.memory_crypto import seal
from mordred_hermes.wizard import encryption_cli

from ._helpers import _init_empty_vault
from ._keyvault_fakes import FakeAnchorStore, FakeBackend

#: Any 32 bytes: these tests only care whether a file *looks* sealed.
_MEMORY_KEY = b"\x07" * 32


# --- shared vault helpers (mirror test_wizard_config_decrypt_cli) -------------
def _enroll(root: Path, name: str, data: bytes, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        opened.enroll_file(name, data)


# -----------------------------------------------------------------------------
# _enrolled_names — side-effect-free enrollment read (no device key, no cold path)
# -----------------------------------------------------------------------------
class TestEnrolledNames:
    def test_empty_for_missing_vault(self, tmp_path: Path) -> None:
        assert encryption_cli._enrolled_names(tmp_path / "nope") == set()

    def test_lists_enrolled_names_without_keys(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        _enroll(root, ".env", b"A=1\n", backend, store)

        # No backend / store / passphrase passed — purely reads the plaintext manifest body.
        assert ".env" in encryption_cli._enrolled_names(root)

    def test_degrades_without_crypto_stack_in_subprocess(self) -> None:
        """Minimal install (no ``[keyvault]`` extra): the lazy keyvault import
        raises ``ModuleNotFoundError`` for argon2 — ``_enrolled_names`` must
        degrade to the empty set (its never-raise contract) and the whole
        ``status`` overview must still exit 0, not abort with the install hint.

        Found in the 2026-07-09 CLI sweep: ``hermes-mordred status`` exited 1
        with the keyvault hint instead of printing policy / network state.

        Runs in a subprocess: blocking the crypto imports in-process would race
        the copies other tests have already imported (mirrors
        ``test_audit_cli.TestMinimalInstallImport``).
        """
        import subprocess
        import sys
        import textwrap

        script = textwrap.dedent(
            """
            import argparse, os, sys, tempfile
            from pathlib import Path

            class _Blocker:
                BLOCKED = ("cryptography", "blake3", "argon2")
                def find_spec(self, name, path=None, target=None):
                    if name.split(".")[0] in self.BLOCKED:
                        raise ModuleNotFoundError(f"No module named {name!r} (blocked by test)", name=name)
                    return None

            sys.meta_path.insert(0, _Blocker())
            os.environ["HERMES_HOME"] = tempfile.mkdtemp()

            from mordred_hermes.wizard import encryption_cli
            assert encryption_cli._enrolled_names(Path("/nonexistent/vault")) == set()

            from mordred_hermes.wizard._cli_parsers import _handle_status
            rc = _handle_status(argparse.Namespace(json=False))
            assert rc == 0, f"status must degrade cleanly, got rc={rc}"
            print("OK")
            """
        )
        proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=False)
        assert proc.returncode == 0, f"status crashed without crypto stack:\n{proc.stderr}"
        assert "OK" in proc.stdout


# -----------------------------------------------------------------------------
# _env_target_ready — shared by memory_cli._enable_gate_reason and setup_cli's
# memory step (W6): both used to duplicate ".env enrolled and no env opt-out".
# -----------------------------------------------------------------------------
class TestEnvTargetReady:
    def test_false_when_not_enrolled(self, tmp_path: Path) -> None:
        assert encryption_cli._env_target_ready(home=tmp_path / "home", root=tmp_path / "v") is False

    def test_true_when_enrolled_and_not_opted_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        assert encryption_cli._env_target_ready(home=tmp_path / "home", root=tmp_path / "v") is True

    def test_false_when_enrolled_but_opted_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        marker = encryption_cli._env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")
        assert encryption_cli._env_target_ready(home=home, root=tmp_path / "v") is False


# -----------------------------------------------------------------------------
# Per-target detectors — configured / active / detail
# -----------------------------------------------------------------------------
class TestEnvStatus:
    def test_not_enrolled(self, tmp_path: Path) -> None:
        st = encryption_cli.env_status(root=tmp_path / "v", home=tmp_path / "home", platform="darwin")
        assert st.target == "env"
        assert st.configured is False
        assert st.active is False

    def test_enrolled_active_on_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        st = encryption_cli.env_status(root=tmp_path / "v", home=tmp_path / "home", platform="darwin")
        assert st.configured is True
        assert st.active is True

    def test_enrolled_inactive_off_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        st = encryption_cli.env_status(root=tmp_path / "v", home=tmp_path / "home", platform="linux")
        assert st.configured is True
        assert st.active is False  # enrolled but the runtime shim is a no-op off darwin

    def test_enrolled_but_opted_out_is_inactive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        marker = encryption_cli._env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.configured is True  # still enrolled
        assert st.active is False  # but injection is suppressed by the opt-out marker
        assert "disabled" in st.detail.lower()

    def test_plaintext_present_while_active_is_drift(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A plaintext .env on disk while sealed (active, no opt-out, macOS) is drift:
        a host write slipped a partial plaintext past the seal — surface it loudly."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_text("FOO=bar\n", encoding="utf-8")
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.active is True
        assert st.drift is True
        assert encryption_cli.status_mark(st) == "exposed"
        assert "plaintext" in st.detail.lower()
        assert st.to_dict()["drift"] is True

    def test_plaintext_off_macos_is_not_drift(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Off macOS the plaintext is kept intentionally (inactive), so it is not drift."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_text("FOO=bar\n", encoding="utf-8")
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="linux")
        assert st.drift is False
        assert encryption_cli.status_mark(st) != "exposed"

    def test_no_plaintext_while_active_is_clean(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sealed with no plaintext on disk is the healthy state — `on`, not `exposed`."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.drift is False
        assert encryption_cli.status_mark(st) == "on"

    def test_stray_reseal_temp_is_drift(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A reseal temp stranded by a crash is a plaintext at rest the plain ".env"
        check would miss — env_status must still flag it as exposed."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env.reseal.tmp").write_text("FOO=bar\n", encoding="utf-8")  # only the temp, no .env
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.drift is True
        assert encryption_cli.status_mark(st) == "exposed"
        assert st.to_dict()["drift"] is True


class TestConfigStatus:
    def test_marker_absent(self, tmp_path: Path) -> None:
        st = encryption_cli.config_status(home=tmp_path, platform="darwin")
        assert st.target == "config"
        assert st.configured is False

    def test_marker_present_with_hook_active_on_macos(self, tmp_path: Path) -> None:
        marker = _marker_path(tmp_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        st = encryption_cli.config_status(home=tmp_path, platform="darwin", hook_installed=True)
        assert st.configured is True
        assert st.active is True
        assert "hook installed" in st.detail

    def test_marker_present_no_hook_inactive_on_macos(self, tmp_path: Path) -> None:
        # Marker set but the decrypt .pth hook absent: nothing reseals, so the
        # plaintext stays on disk — configured but NOT active, and the detail says so.
        marker = _marker_path(tmp_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        st = encryption_cli.config_status(home=tmp_path, platform="darwin", hook_installed=False)
        assert st.configured is True
        assert st.active is False
        assert "NOT installed" in st.detail

    def test_marker_present_inactive_off_macos(self, tmp_path: Path) -> None:
        marker = _marker_path(tmp_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        st = encryption_cli.config_status(home=tmp_path, platform="linux")
        assert st.configured is True
        assert st.active is False


class TestMemoryStatus:
    """The memory target is keyed on the Mordred markers, not the legacy flag.

    ``<home>/mordred/memory-vault.marker`` is what arms the hook; the
    ``memory.encryption.enabled`` config key is a legacy flag no runtime reads
    (an old profile carrying it is reported, never treated as protection).
    """

    @pytest.fixture(autouse=True)
    def _runtime_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default to a wrappable seam; the unavailable case overrides this."""
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, "seam A"))

    def _arm(self, home: Path) -> Path:
        marker = memory_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("armed\n", encoding="utf-8")
        return marker

    def _opt_out(self, home: Path) -> Path:
        marker = memory_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")
        return marker

    def _memory_file(self, home: Path, name: str, data: bytes) -> Path:
        path = home / "memories" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_no_marker_is_not_configured(self, tmp_path: Path) -> None:
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.target == "memory"
        assert st.configured is False
        assert st.active is False
        assert st.detail == "not enabled"

    def test_legacy_flag_without_marker_says_so(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("memory:\n  encryption:\n    enabled: true\n", encoding="utf-8")
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.configured is False  # the flag never sealed anything
        assert "legacy" in st.detail
        assert "encryption enable memory" in st.detail

    def test_marker_active_on_macos(self, tmp_path: Path) -> None:
        self._arm(tmp_path)
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.configured is True
        assert st.active is True
        assert encryption_cli.status_mark(st) == "on"
        assert "hook armed" in st.detail

    def test_linux_marker_without_key_is_inactive(self, tmp_path: Path) -> None:
        self._arm(tmp_path)
        st = encryption_cli.memory_status(home=tmp_path, platform="linux")
        assert st.configured is True
        assert st.active is False
        assert "TPM memory key" in st.detail

    def test_optout_is_paused(self, tmp_path: Path) -> None:
        self._opt_out(tmp_path)
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.configured is True
        assert st.active is False
        assert encryption_cli.status_mark(st) == "paused"
        assert "re-enable" in st.detail

    def test_marker_without_runtime_is_inactive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (False, "no wrappable seam"))
        self._arm(tmp_path)
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.active is False
        assert "no wrappable seam" in st.detail
        assert "plaintext" in st.detail

    def test_plaintext_file_while_armed_is_drift(self, tmp_path: Path) -> None:
        self._arm(tmp_path)
        self._memory_file(tmp_path, "MEMORY.md", b"# plaintext notes\n")
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.drift is True
        assert encryption_cli.status_mark(st) == "exposed"
        assert st.to_dict()["drift"] is True
        assert "reseal" in st.detail

    def test_plaintext_backup_snapshot_is_drift_too(self, tmp_path: Path) -> None:
        """Upstream writes `<file>.bak.<ts>` next to the live file on drift."""
        self._arm(tmp_path)
        self._memory_file(tmp_path, "MEMORY.md", seal(b"sealed\n", key=_MEMORY_KEY, name="MEMORY.md"))
        self._memory_file(tmp_path, "MEMORY.md.bak.20260819", b"# plaintext snapshot\n")
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.drift is True

    def test_sealed_files_only_is_clean(self, tmp_path: Path) -> None:
        self._arm(tmp_path)
        self._memory_file(tmp_path, "MEMORY.md", seal(b"sealed\n", key=_MEMORY_KEY, name="MEMORY.md"))
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.drift is False
        assert encryption_cli.status_mark(st) == "on"

    def test_plaintext_while_paused_is_not_drift(self, tmp_path: Path) -> None:
        """After `disable memory` the plaintext is the intended state."""
        self._opt_out(tmp_path)
        self._memory_file(tmp_path, "MEMORY.md", b"# plaintext notes\n")
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.drift is False
        assert encryption_cli.status_mark(st) == "paused"


# -----------------------------------------------------------------------------
# _memory_file_paths — the single glob every enable/disable/status walk shares.
# Symlinks must never reach it (W2): `is_file()` alone follows a link, which
# would let a planted symlink under `memories/` have its target read, sealed,
# and the link itself destroyed by the atomic-replace writer.
# -----------------------------------------------------------------------------
class TestMemoryFilePathsSymlinks:
    def _memories(self, home: Path) -> Path:
        path = home / "memories"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def test_symlink_is_excluded_from_the_scan(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        memories = self._memories(home)
        outside = tmp_path / "outside.md"
        outside.write_text("plaintext outside the memories dir\n", encoding="utf-8")
        link = memories / "linked.md"
        link.symlink_to(outside)
        real = memories / "MEMORY.md"
        real.write_text("real file\n", encoding="utf-8")

        paths = encryption_cli._memory_file_paths(home)

        assert link not in paths
        assert real in paths

    def test_symlinked_backup_snapshot_is_also_excluded(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        memories = self._memories(home)
        outside = tmp_path / "outside.bak"
        outside.write_text("plaintext outside\n", encoding="utf-8")
        (memories / "MEMORY.md.bak.20260819").symlink_to(outside)

        assert encryption_cli._memory_file_paths(home) == []

    def test_symlink_is_ignored_by_the_drift_scan(self, tmp_path: Path) -> None:
        """A symlink whose target "looks" plaintext must never influence
        `status` -- it is invisible, not classified either way (W2)."""
        home = tmp_path / "home"
        memories = self._memories(home)
        outside = tmp_path / "outside.md"
        outside.write_text("plaintext outside\n", encoding="utf-8")
        (memories / "linked.md").symlink_to(outside)

        assert encryption_cli._unsealed_memory_files(home) == []


# -----------------------------------------------------------------------------
# _unsealed_memory_files — classification must run on the WHOLE file, never a
# fixed-size head (W4). A truncated buffer's base64 alignment is a matter of
# luck across file lengths: a real sealed file could misclassify as plaintext,
# and `disable`/`purge` would then treat it as already-plain and strip the key
# while it stayed encrypted -- permanent data loss.
# -----------------------------------------------------------------------------
class TestUnsealedMemoryFilesFullFileClassification:
    def _memories(self, home: Path) -> Path:
        path = home / "memories"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def test_a_5kb_sealed_file_is_classified_sealed(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        memories = self._memories(home)
        blob = seal(b"x" * 5000, key=_MEMORY_KEY, name="MEMORY.md")
        assert len(blob) > encryption_cli._SEAL_PROBE_BYTES  # actually exercises the fix
        (memories / "MEMORY.md").write_bytes(blob)

        assert encryption_cli._unsealed_memory_files(home) == []

    def test_head_probe_agrees_with_the_full_check_across_many_sizes(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        memories = self._memories(home)
        rng = random.Random(20260819)
        for i in range(100):
            size = rng.randint(0, 4096)
            plaintext = bytes(rng.randrange(256) for _ in range(size))
            path = memories / f"MEMORY{i}.md"
            path.write_bytes(seal(plaintext, key=_MEMORY_KEY, name=path.name))

        unsealed = encryption_cli._unsealed_memory_files(home)

        assert unsealed == []  # every real seal, whatever its length, reads sealed

    def test_classification_runs_on_the_full_file_not_the_truncated_head(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        memories = self._memories(home)
        blob = seal(b"y" * 1000, key=_MEMORY_KEY, name="MEMORY.md")
        (memories / "MEMORY.md").write_bytes(blob)
        assert len(blob) > encryption_cli._SEAL_PROBE_BYTES

        seen_lengths: list[int] = []
        real_is_sealed = memory_crypto.is_sealed

        def _spy(data: bytes) -> bool:
            seen_lengths.append(len(data))
            return real_is_sealed(data)

        monkeypatch.setattr(memory_crypto, "is_sealed", _spy)

        assert encryption_cli._unsealed_memory_files(home) == []
        assert seen_lengths == [len(blob)]  # the FULL file, not a 64-byte head

    def test_plaintext_that_does_not_even_look_sealed_skips_the_full_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The head probe is a cheap, safe *reject*: a file that never even
        starts with the magic line short-circuits before the full read."""
        home = tmp_path / "home"
        memories = self._memories(home)
        (memories / "MEMORY.md").write_text("just some notes, not sealed at all\n", encoding="utf-8")

        def _boom(_data: bytes) -> bool:
            raise AssertionError("is_sealed must not run on an obviously-unsealed file")

        monkeypatch.setattr(memory_crypto, "is_sealed", _boom)

        assert encryption_cli._unsealed_memory_files(home) == [memories / "MEMORY.md"]


class TestMemoryRuntimeAvailable:
    """The single seam every memory decision routes through (status + enable)."""

    def test_reports_the_live_seam(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _memory_hook

        monkeypatch.setattr(_memory_hook, "seam_check", lambda *_a, **_k: (True, "seam A"))
        assert encryption_cli.memory_runtime_available() == (True, "seam A")

    def test_failure_is_reported_not_raised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _memory_hook

        def _boom(*_a: object, **_k: object) -> tuple[bool, str]:
            raise RuntimeError("importing tools blew up")

        monkeypatch.setattr(_memory_hook, "seam_check", _boom)
        ok, reason = encryption_cli.memory_runtime_available()
        assert ok is False
        assert "importing tools blew up" in reason


class TestWorkspaceStatus:
    def test_no_artifacts(self, tmp_path: Path) -> None:
        st = encryption_cli.workspace_status(
            image=tmp_path / "img.sparsebundle",
            blob=tmp_path / "passphrase.wrapped",
            mount=tmp_path / "mnt",
            platform="darwin",
            on_path=lambda _name: False,
        )
        assert st.target == "workspace"
        assert st.configured is False

    def test_image_and_blob_present_is_configured(self, tmp_path: Path) -> None:
        image = tmp_path / "img.sparsebundle"
        blob = tmp_path / "passphrase.wrapped"
        image.mkdir()  # sparsebundle is a directory bundle
        blob.write_bytes(b"wrapped")
        st = encryption_cli.workspace_status(
            image=image,
            blob=blob,
            mount=tmp_path / "mnt",
            platform="darwin",
            on_path=lambda _name: True,
        )
        assert st.configured is True
        assert st.active is True

    def test_macos_only_off_darwin(self, tmp_path: Path) -> None:
        image = tmp_path / "img.sparsebundle"
        blob = tmp_path / "passphrase.wrapped"
        image.mkdir()
        blob.write_bytes(b"wrapped")
        st = encryption_cli.workspace_status(
            image=image,
            blob=blob,
            mount=tmp_path / "mnt",
            platform="linux",
            on_path=lambda _name: True,
        )
        assert st.active is False
        assert "macos" in st.detail.lower()


# -----------------------------------------------------------------------------
# Aggregation + rendering
# -----------------------------------------------------------------------------
class TestRender:
    def test_collect_returns_all_four_targets(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        statuses = encryption_cli.collect_status(
            home=home,
            root=tmp_path / "v",
            platform="darwin",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )
        assert [s.target for s in statuses] == list(encryption_cli.TARGETS)

    def test_render_json_is_machine_readable(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        statuses = encryption_cli.collect_status(
            home=home,
            root=tmp_path / "v",
            platform="darwin",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )
        payload = json.loads(encryption_cli.render_json(statuses))
        assert {row["target"] for row in payload} == set(encryption_cli.TARGETS)
        for row in payload:
            assert set(row) >= {"target", "configured", "active", "detail"}

    def test_render_text_lists_every_target(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        statuses = encryption_cli.collect_status(
            home=home,
            root=tmp_path / "v",
            platform="linux",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )
        text = encryption_cli.render_text(statuses)
        for target in encryption_cli.TARGETS:
            assert target in text

    def test_status_mark_reflects_active_not_just_configured(self) -> None:
        on = encryption_cli.TargetStatus("env", configured=True, active=True, detail="active")
        paused = encryption_cli.TargetStatus("env", configured=True, active=False, detail="disabled")
        off = encryption_cli.TargetStatus("env", configured=False, active=False, detail="not enrolled")
        assert encryption_cli.status_mark(on) == "on"
        # configured but not active -> 'paused', NOT 'on' (the misleading old behavior)
        assert encryption_cli.status_mark(paused) == "paused"
        assert encryption_cli.status_mark(off) == "off"

    def test_render_text_marks_disabled_target_paused_with_legend(self) -> None:
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=False, detail="disabled"),
            encryption_cli.TargetStatus("config", configured=False, active=False, detail="not vault-managed"),
        ]
        text = encryption_cli.render_text(statuses)
        assert "[paused]" in text  # the disabled-but-enrolled target reads paused
        assert "legend:" in text  # legend explains 'paused' whenever it appears

    def test_render_text_unchanged_when_nothing_paused(self) -> None:
        # No paused row -> marks stay width 3 (on/off) and no legend, so existing
        # docs/tests that show `[on ]` / `[off]` keep rendering identically.
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=True, detail="active"),
            encryption_cli.TargetStatus("config", configured=False, active=False, detail="not vault-managed"),
        ]
        text = encryption_cli.render_text(statuses)
        assert "[on ]" in text
        assert "[off]" in text
        assert "legend:" not in text

    def test_exposed_legend_is_target_neutral(self) -> None:
        """`exposed` is now reachable for env *and* memory, so the alert line
        must not name a single target's reseal command."""
        body = encryption_cli.EXPOSED_LEGEND_BODY
        assert "encryption enable <target>" in body
        assert "encryption enable env" not in body

    def test_render_text_shows_the_exposed_alert_for_any_target(self) -> None:
        statuses = [
            encryption_cli.TargetStatus("memory", configured=True, active=True, detail="plaintext file", drift=True),
        ]
        text = encryption_cli.render_text(statuses)
        assert "[exposed]" in text
        assert encryption_cli.EXPOSED_LEGEND_BODY in text

    def test_workspace_mark_is_sealed_when_set_up_and_unmounted(self) -> None:
        # The workspace is encrypted at rest whenever it is set up and sealed,
        # so `disable` (= seal) must NOT read as the others' `on`/`off`.
        sealed = encryption_cli.TargetStatus(
            "workspace", configured=True, active=True, detail="sealed at rest", mounted=False
        )
        assert encryption_cli.status_mark(sealed) == "sealed"

    def test_workspace_mark_is_open_when_mounted(self) -> None:
        mounted = encryption_cli.TargetStatus(
            "workspace", configured=True, active=True, detail="unlocked & mounted", mounted=True
        )
        assert encryption_cli.status_mark(mounted) == "open"

    def test_workspace_mark_is_off_when_not_set_up_or_off_os(self) -> None:
        not_set_up = encryption_cli.TargetStatus("workspace", configured=False, active=False, detail="not installed")
        off_os = encryption_cli.TargetStatus("workspace", configured=True, active=False, detail="macOS only")
        assert encryption_cli.status_mark(not_set_up) == "off"
        assert encryption_cli.status_mark(off_os) == "off"

    def test_render_text_explains_workspace_marks_below(self) -> None:
        # The exact shape of `encryption disable all`: env paused, workspace
        # sealed. The sealed workspace must read `[sealed]`, not the others'
        # `on`, and the explanation line must be rendered below.
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=False, detail="disabled"),
            encryption_cli.TargetStatus(
                "workspace", configured=True, active=True, detail="sealed at rest", mounted=False
            ),
        ]
        text = encryption_cli.render_text(statuses)
        assert "[sealed]" in text  # sealed, not the misleading `on`
        assert "workspace:" in text  # the explanation line is rendered below
        assert encryption_cli.WORKSPACE_LEGEND_BODY in text

    def test_to_dict_serializes_mounted_only_for_workspace(self) -> None:
        # `mounted` is a workspace-only rendering hint: it appears in JSON for an
        # active workspace (so consumers can tell sealed from open) and is absent
        # for the core targets and for an off workspace (where it is `None`).
        env = encryption_cli.TargetStatus("env", configured=True, active=True, detail="active")
        assert "mounted" not in env.to_dict()

        sealed = encryption_cli.TargetStatus(
            "workspace", configured=True, active=True, detail="sealed at rest", mounted=False
        )
        assert sealed.to_dict()["mounted"] is False

        off = encryption_cli.TargetStatus("workspace", configured=False, active=False, detail="not installed")
        assert "mounted" not in off.to_dict()


# -----------------------------------------------------------------------------
# Colour — opt-in styling; plain output stays byte-identical (above tests assert it)
# -----------------------------------------------------------------------------
class TestColor:
    def test_style_mark_colours_by_state(self) -> None:
        assert "\033[32m" in encryption_cli.style_mark("on", "on", enabled=True)  # green
        assert "\033[32m" in encryption_cli.style_mark("sealed", "sealed", enabled=True)  # green
        assert "\033[33m" in encryption_cli.style_mark("paused", "paused", enabled=True)  # yellow
        assert "\033[36m" in encryption_cli.style_mark("open", "open", enabled=True)  # cyan
        assert "\033[2m" in encryption_cli.style_mark("off", "off", enabled=True)  # dim

    def test_style_mark_plain_when_disabled(self) -> None:
        # The padded cell passes through unchanged so column alignment is preserved.
        assert encryption_cli.style_mark("on", "on ", enabled=False) == "on "

    def test_style_mark_unknown_word_passes_through(self) -> None:
        assert encryption_cli.style_mark("mystery", "mystery", enabled=True) == "mystery"

    def test_render_text_default_has_no_ansi(self) -> None:
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=True, detail="active"),
            encryption_cli.TargetStatus("config", configured=True, active=False, detail="disabled"),
        ]
        assert "\033" not in encryption_cli.render_text(statuses)

    def test_render_text_color_emits_ansi_and_keeps_words(self) -> None:
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=True, detail="active"),
            encryption_cli.TargetStatus("config", configured=True, active=False, detail="disabled"),
        ]
        text = encryption_cli.render_text(statuses, color=True)
        assert "\033[" in text  # styled
        assert "\033[1m" in text  # heading is bold
        assert "on" in text and "paused" in text  # mark words still present

    def _run_status(self, tmp_path: Path) -> int:
        return encryption_cli.status(
            home=tmp_path,
            root=tmp_path / "v",
            platform="linux",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "pp.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )

    def test_status_wiring_no_ansi_when_not_a_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The capsys stdout is not a tty, so the live should_color gate in status()
        # must yield plain text — guards the `encryption status` colour wiring.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert self._run_status(tmp_path) == 0
        assert "\033" not in capsys.readouterr().out

    def test_status_wiring_colours_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # FORCE_COLOR drives colour through the same wiring even off a tty.
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert self._run_status(tmp_path) == 0
        assert "\033[" in capsys.readouterr().out


# -----------------------------------------------------------------------------
# CLI wiring — `encryption status` parses and runs end to end (non-prompting)
# -----------------------------------------------------------------------------
class TestCliWiring:
    def test_status_command_runs_and_returns_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import cli

        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)
        monkeypatch.setattr(
            encryption_cli,
            "_default_workspace_paths",
            lambda: encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
        )

        rc = cli.main(["encryption", "status", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert {row["target"] for row in payload} == set(encryption_cli.TARGETS)


# -----------------------------------------------------------------------------
# CLI dispatch — enable / disable / purge route to the right per-target engine
# -----------------------------------------------------------------------------
class TestCliDispatch:
    def _patch_home(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)

    def test_enable_env_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, env_decrypt_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        seen: dict[str, object] = {}

        def _spy(*, home: Path, root: Path, platform: str, **_: object) -> int:
            seen.update(home=home, root=root, platform=platform)
            return 0

        monkeypatch.setattr(env_decrypt_cli, "enable", _spy)
        assert cli.main(["encryption", "enable", "env"]) == 0
        assert seen["home"] == tmp_path / "home"

    def test_disable_config_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, config_decrypt_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        called = {"n": 0}

        def _spy(**_: object) -> int:
            called["n"] += 1
            return 0

        monkeypatch.setattr(config_decrypt_cli, "disable", _spy)
        assert cli.main(["encryption", "disable", "config"]) == 0
        assert called["n"] == 1

    def test_purge_requires_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, memory_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        called = {"n": 0}
        monkeypatch.setattr(memory_cli, "purge", lambda **_: called.__setitem__("n", called["n"] + 1) or 0)

        # without --yes: refuse (non-zero) and never touch the engine
        assert cli.main(["encryption", "purge", "memory"]) != 0
        assert called["n"] == 0

    def test_purge_with_yes_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, memory_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        called = {"n": 0}
        monkeypatch.setattr(memory_cli, "purge", lambda **_: called.__setitem__("n", called["n"] + 1) or 0)

        assert cli.main(["encryption", "purge", "memory", "--yes"]) == 0
        assert called["n"] == 1


# -----------------------------------------------------------------------------
# `all` pseudo-target — best-effort fan-out over every target, workspace gated.
# -----------------------------------------------------------------------------
class TestCliDispatchAll:
    def _patch_home(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)

    def _spy_engines(
        self,
        monkeypatch: pytest.MonkeyPatch,
        verb: str,
        *,
        rc_for: dict[str, int] | None = None,
    ) -> dict[str, int]:
        """Replace every per-target engine ``verb`` with a counting spy.

        Returns a dict mapping target -> call count (a target absent from the
        dict was never invoked). ``rc_for`` overrides the exit code a given
        target's spy returns (default 0). The spies are silent so stdout
        assertions see only the ``all`` summary block.
        """
        from mordred_hermes.wizard import config_decrypt_cli, env_decrypt_cli, memory_cli, workspace_cli

        rc_for = rc_for or {}
        calls: dict[str, int] = {}

        def make(name: str) -> object:
            def _spy(*_a: object, **_k: object) -> int:
                calls[name] = calls.get(name, 0) + 1
                return rc_for.get(name, 0)

            return _spy

        monkeypatch.setattr(env_decrypt_cli, verb, make("env"))
        monkeypatch.setattr(config_decrypt_cli, verb, make("config"))
        monkeypatch.setattr(memory_cli, verb, make("memory"))
        # workspace dispatch goes through the cli_<verb> wrappers, not <verb>.
        monkeypatch.setattr(workspace_cli, f"cli_{verb}", make("workspace"))
        return calls

    def test_enable_all_runs_core_and_workspace_on_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, ""))
        calls = self._spy_engines(monkeypatch, "enable")
        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: True)
        assert rc == 0
        assert calls == {"env": 1, "config": 1, "memory": 1, "workspace": 1}

    def test_enable_all_skips_workspace_off_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        # A wrappable seam does not matter here -- off macOS `memory` is skipped
        # on the platform check alone, before the seam is ever consulted (W1).
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, ""))
        calls = self._spy_engines(monkeypatch, "enable")
        rc = encryption_cli._dispatch_all("enable", platform="linux", on_path=lambda _n: True)
        assert rc == 0
        assert calls == {"env": 1, "config": 1}  # workspace AND memory skipped, not failed

    def test_enable_all_skips_memory_without_runtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A Hermes whose memory tool this build cannot wrap: the engine would
        # only refuse, so the fan-out records a skip instead of a failure. Kept
        # on darwin (with workspace tooling absent) so this specifically
        # exercises the seam-availability skip, not the platform skip (W1) that
        # `test_enable_all_skips_workspace_off_macos` already covers.
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (False, "no wrappable seam"))
        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable")
        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: False)
        assert rc == 0  # a skip never fails the batch
        assert "memory" not in calls  # the engine is never called — it would just refuse
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert any("memory" in ln and "skipped" in ln and "no wrappable seam" in ln for ln in lines)
        assert "  2 ok, 0 failed, 2 skipped" in lines  # env+config ok; memory+workspace skipped

    def test_enable_all_skips_memory_off_macos_before_the_seam_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """W1: off macOS `memory` is skipped on the platform alone -- the fan-out
        used to resolve platform independently inside the per-target dispatch
        (always `sys.platform`), so a Linux `enable all` reported `memory FAILED`
        instead of a skip even though `setup`'s own step skips it cleanly."""

        def _never(*_a: object, **_k: object) -> tuple[bool, str]:
            raise AssertionError("the platform gate must short-circuit before the seam check")

        monkeypatch.setattr(encryption_cli, "memory_runtime_available", _never)
        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable")

        rc = encryption_cli._dispatch_all("enable", platform="linux", on_path=lambda _n: True)

        assert rc == 0
        assert "memory" not in calls  # _dispatch (and therefore memory_cli.enable) is never reached
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert any("memory" in ln and "skipped" in ln and "macOS only" in ln and "linux" in ln for ln in lines)

    def test_enable_all_attempts_memory_on_darwin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The darwin half of the W1 fix: the platform gate must not skip memory
        when it does not need to."""
        self._patch_home(monkeypatch, tmp_path / "home")
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, ""))
        calls = self._spy_engines(monkeypatch, "enable")

        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: False)

        assert rc == 0
        assert calls["memory"] == 1

    def test_enable_all_skips_workspace_when_tooling_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable")
        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: False)
        assert rc == 0
        assert "workspace" not in calls
        assert calls["env"] == 1

    def test_all_continues_past_failure_and_reports_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, ""))
        calls = self._spy_engines(monkeypatch, "enable", rc_for={"memory": 1})
        # darwin + no workspace tooling: memory is actually attempted (and fails)
        # while workspace is skipped for a reason unrelated to the failure below.
        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: False)
        assert rc == 1  # a target failed
        assert calls == {"env": 1, "config": 1, "memory": 1}  # every core target still attempted

    def test_enable_all_prints_contiguous_summary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, ""))
        self._spy_engines(monkeypatch, "enable")  # silent spies → output is only the summary
        encryption_cli._dispatch_all("enable", platform="linux", on_path=lambda _n: True)
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        # Header + one line per target + a trailing, indented totals line — together.
        assert "encryption enable all:" in lines
        assert any("workspace" in ln and "skipped" in ln for ln in lines)
        assert any("memory" in ln and "skipped" in ln and "macOS only" in ln for ln in lines)
        assert "  2 ok, 0 failed, 2 skipped" in lines  # env+config ok; memory+workspace skipped off macOS

    def test_enable_all_via_cli_accepts_all_choice(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli

        self._patch_home(monkeypatch, tmp_path / "home")
        # `_dispatch_all` defaults `platform` from `sys.platform` when `cli_enable`
        # does not pass one -- pin it so `memory`'s platform gate (W1) does not
        # depend on the real OS running the test suite.
        monkeypatch.setattr(encryption_cli.sys, "platform", "darwin")
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, ""))
        calls = self._spy_engines(monkeypatch, "enable")
        monkeypatch.setattr(encryption_cli, "_workspace_eligible", lambda *_a, **_k: (False, "test"))
        assert cli.main(["encryption", "enable", "all"]) == 0
        assert calls == {"env": 1, "config": 1, "memory": 1}

    def test_purge_all_requires_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli

        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "purge")
        monkeypatch.setattr(encryption_cli, "_workspace_eligible", lambda *_a, **_k: (False, "test"))
        assert cli.main(["encryption", "purge", "all"]) != 0  # gate refuses
        assert calls == {}  # never reached the engines

    def test_purge_all_with_yes_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli

        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "purge")
        monkeypatch.setattr(encryption_cli, "_workspace_eligible", lambda *_a, **_k: (False, "test"))
        assert cli.main(["encryption", "purge", "all", "--yes"]) == 0
        assert calls == {"env": 1, "config": 1, "memory": 1}


# -----------------------------------------------------------------------------
# `_workspace_eligible` — the workspace gate for `all` (M1: direct unit coverage)
# -----------------------------------------------------------------------------
class TestWorkspaceEligible:
    def test_non_macos_never_eligible(self) -> None:
        ok, reason = encryption_cli._workspace_eligible("enable", platform="linux", on_path=lambda _n: True)
        assert ok is False
        assert "macOS" in reason

    def test_enable_eligible_with_tooling(self) -> None:
        ok, _ = encryption_cli._workspace_eligible("enable", platform="darwin", on_path=lambda _n: True)
        assert ok is True

    def test_enable_skipped_without_tooling(self) -> None:
        ok, reason = encryption_cli._workspace_eligible("enable", platform="darwin", on_path=lambda _n: False)
        assert ok is False
        assert "tooling" in reason

    def test_purge_eligible_when_volume_set_up(self, tmp_path: Path) -> None:
        image = tmp_path / "claude-private.sparsebundle"
        image.write_text("x")
        blob = tmp_path / "passphrase.wrapped"
        blob.write_text("y")
        ws = encryption_cli.WorkspacePaths(image=image, blob=blob, mount=tmp_path / "mnt")
        # on_path is irrelevant for purge — only on-disk artifacts decide eligibility.
        ok, _ = encryption_cli._workspace_eligible("purge", platform="darwin", on_path=lambda _n: False, workspace=ws)
        assert ok is True

    def test_purge_skipped_when_not_set_up(self, tmp_path: Path) -> None:
        ws = encryption_cli.WorkspacePaths(
            image=tmp_path / "absent.sparsebundle",
            blob=tmp_path / "absent.wrapped",
            mount=tmp_path / "mnt",
        )
        ok, reason = encryption_cli._workspace_eligible(
            "purge", platform="darwin", on_path=lambda _n: True, workspace=ws
        )
        assert ok is False
        assert "not set up" in reason


def test_all_core_targets_derived_from_targets() -> None:
    """L1: ``_ALL_CORE_TARGETS`` is the leading slice of ``TARGETS`` (no drift)."""
    assert encryption_cli.TARGETS[-1] == "workspace"
    assert encryption_cli._ALL_CORE_TARGETS == ("env", "config", "memory")
    assert encryption_cli.TARGETS[:-1] == encryption_cli._ALL_CORE_TARGETS


class TestGatewayRuntimeLines:
    """``encryption status`` surfaces the interpreter serving a running gateway.

    That interpreter — not the one the seal *expects* — is what has to unseal
    ``.env`` / ``config.yaml`` at startup, and on 2026-06-25 it was a repo
    ``.venv`` without mordred. The line makes the mismatch visible before an
    operator seals anything.
    """

    def _patch_probe(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        gateways: object,
        env_ok: bool = True,
        config_ok: bool = True,
        memory_ok: bool = True,
    ) -> None:
        from mordred_hermes.keyvault import _runtime_probe

        monkeypatch.setattr(_runtime_probe, "discover_running_gateway_runtimes", gateways)
        monkeypatch.setattr(_runtime_probe, "runtime_env_injection_available", lambda **_kw: (env_ok, "detail"))
        monkeypatch.setattr(_runtime_probe, "runtime_config_decrypt_available", lambda **_kw: (config_ok, "detail"))
        monkeypatch.setattr(_runtime_probe, "runtime_memory_encryption_available", lambda **_kw: (memory_ok, "detail"))

    def test_reports_each_gateway_with_every_shim_result(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault._runtime_probe import GatewayRuntime

        python = tmp_path / "repo" / ".venv" / "bin" / "python"
        self._patch_probe(
            monkeypatch,
            gateways=lambda **_kw: [GatewayRuntime(pid=4242, python=python)],
            env_ok=False,
            config_ok=True,
            memory_ok=False,
        )
        lines = encryption_cli.gateway_runtime_lines(home=tmp_path, platform="darwin")
        assert lines == [
            f"  gateway runtime: {python} (pid 4242) — env shim: MISSING | config hook: ok | memory hook: MISSING"
        ]

    def test_omits_the_pid_when_unknown(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault._runtime_probe import GatewayRuntime

        python = tmp_path / "bin" / "python3"
        self._patch_probe(monkeypatch, gateways=lambda **_kw: [GatewayRuntime(pid=None, python=python)])
        assert encryption_cli.gateway_runtime_lines(home=tmp_path, platform="darwin") == [
            f"  gateway runtime: {python} — env shim: ok | config hook: ok | memory hook: ok"
        ]

    def test_no_lines_off_macos_and_no_discovery(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _never(**_kw: object) -> list[object]:
            raise AssertionError("the shims are macOS-only; do not scan elsewhere")

        self._patch_probe(monkeypatch, gateways=_never)
        assert encryption_cli.gateway_runtime_lines(home=tmp_path, platform="linux") == []

    def test_no_gateway_running_yields_no_lines(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_probe(monkeypatch, gateways=lambda **_kw: [])
        assert encryption_cli.gateway_runtime_lines(home=tmp_path, platform="darwin") == []

    def test_discovery_failure_is_swallowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(**_kw: object) -> list[object]:
            raise RuntimeError("ps exploded")

        self._patch_probe(monkeypatch, gateways=_boom)
        assert encryption_cli.gateway_runtime_lines(home=tmp_path, platform="darwin") == []

    def test_status_prints_the_line_and_json_stays_a_pure_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(encryption_cli, "gateway_runtime_lines", lambda **_kw: ["  gateway runtime: X"])
        ws = encryption_cli.WorkspacePaths(
            image=tmp_path / "img.sparsebundle", blob=tmp_path / "pp.wrapped", mount=tmp_path / "mnt"
        )
        assert (
            encryption_cli.status(
                home=tmp_path, root=tmp_path / "v", platform="darwin", workspace=ws, on_path=lambda _n: False
            )
            == 0
        )
        assert "  gateway runtime: X" in capsys.readouterr().out

        assert (
            encryption_cli.status(
                home=tmp_path,
                root=tmp_path / "v",
                platform="darwin",
                workspace=ws,
                as_json=True,
                on_path=lambda _n: False,
            )
            == 0
        )
        out = capsys.readouterr().out
        assert "gateway runtime" not in out  # --json keeps the old shape and cost
        assert isinstance(json.loads(out), list)
