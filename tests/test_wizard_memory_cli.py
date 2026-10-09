"""Tests for ``hermes mordred encryption {enable,disable,purge} memory``.

The target owns the Mordred-side lifecycle of agent-memory at-rest encryption:
the ``HERMES_MEMORY_KEY`` in the vault ``.env`` (injected by the ``.env`` shim),
the opt-in marker that arms :mod:`mordred_hermes.keyvault._memory_hook`, and the
on-disk state of ``<home>/memories/*.md``.

State transitions (not symmetric):

- **enable**  — gate (runtime seam, macOS, env target, runtime probe), ensure the
  key, write the marker, then eagerly seal every plaintext memory file.
- **disable** — decrypt every sealed file back to plaintext, drop the marker and
  write the opt-out marker; the key stays in the vault (reversible). Refuses
  rather than proceed when the sealed files cannot be decrypted.
- **purge**   — ``disable`` first, then strip the key and remove both markers.

Built on the software fakes so the real hot-path open/enroll runs on any
platform; the cross-interpreter probes are monkeypatched (they shell out).
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, _runtime_probe, vault
from mordred_hermes.keyvault._memory_hook import memory_marker_path, memory_optout_marker_path
from mordred_hermes.keyvault._runtime_env import _env_optout_marker_path
from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.keyvault.memory_crypto import MAGIC, decode_key, is_sealed, seal, unseal
from mordred_hermes.wizard import encryption_cli, memory_cli
from mordred_hermes.wizard.vault_memory_key import _MEMORY_KEY_ENV, _effective_memory_key, _is_valid_memory_key

from ._helpers import _init_empty_vault
from ._keyvault_fakes import FakeAnchorStore, FakeBackend, FixedPassphrasePromptIO

_PASSPHRASE = "correct horse battery staple"
_FOREIGN_KEY = b"\x11" * 32


@pytest.fixture(autouse=True)
def _runtime_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default every test to a capable runtime and no running gateway.

    The three seams that answer "can this machine actually seal memory?" —
    the in-process seam check and the two cross-interpreter probes (which
    shell out to another interpreter) — are stubbed here so each test drives
    the gate it is about, and never the host's real process table.
    """
    monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, "seam A"))
    monkeypatch.setattr(_runtime_probe, "runtime_memory_encryption_available", lambda **_kw: (True, "seam A"))
    monkeypatch.setattr(_runtime_probe, "discover_running_gateway_runtimes", lambda **_kw: [])
    monkeypatch.setattr(_runtime_probe, "discover_runtime_python", lambda **_kw: None)


@pytest.fixture(autouse=True)
def _env_target_enrolled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default the env precondition to satisfied (memory rides on the .env shim)."""
    monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})


def _vault_env_text(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> str:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        return opened.read_file(".env").decode("utf-8") if ".env" in opened.list_files() else ""


def _vault_memory_key(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> bytes:
    value = _effective_memory_key(_vault_env_text(root, backend, store))
    assert value is not None
    return decode_key(value)


def _enroll_env_text(root: Path, backend: FakeBackend, store: FakeAnchorStore, text: str) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        opened.enroll_file(".env", text.encode("utf-8"))


def _raw_flag(home: Path) -> object:
    """The actual ``memory.encryption.enabled`` value (True / False / None)."""
    from ruamel.yaml import YAML

    if not (home / "config.yaml").exists():
        return None
    data = YAML(typ="safe").load((home / "config.yaml").read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    memory = data.get("memory")
    encryption = memory.get("encryption") if isinstance(memory, dict) else None
    return encryption.get("enabled") if isinstance(encryption, dict) else None


def _memories(home: Path) -> Path:
    path = home / "memories"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _setup_home_and_vault(tmp_path: Path) -> tuple[Path, Path, FakeBackend, FakeAnchorStore]:
    root, home = tmp_path / "v", tmp_path / "home"
    home.mkdir()
    backend, store = FakeBackend(), FakeAnchorStore()
    _init_empty_vault(root, backend, store)
    return root, home, backend, store


def _enable(home: Path, root: Path, backend: FakeBackend, store: FakeAnchorStore, **kwargs: object) -> int:
    return memory_cli.enable(home=home, root=root, backend=backend, store=store, platform="darwin", **kwargs)  # type: ignore[arg-type]


# -----------------------------------------------------------------------------
# enable — the gates, in order. None of them may write anything.
# -----------------------------------------------------------------------------
class TestEnableGates:
    def test_refuses_without_a_wrappable_seam(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (False, "tools.memory_tool is missing"))
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()

        rc = memory_cli.enable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore(), platform="darwin")

        assert rc == 1
        assert not memory_marker_path(home).exists()
        assert not root.exists()  # no vault created
        err = capsys.readouterr().err
        assert "tools.memory_tool is missing" in err
        assert "set-memory-key" in err

    def test_refuses_unsupported_platform(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()

        rc = memory_cli.enable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore(), platform="win32")

        assert rc == 1
        assert not memory_marker_path(home).exists()
        assert "unsupported" in capsys.readouterr().err.lower()

    def test_refuses_when_env_target_is_not_enrolled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: set())
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()

        rc = memory_cli.enable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore(), platform="darwin")

        assert rc == 1
        assert not memory_marker_path(home).exists()
        assert "encryption enable env" in capsys.readouterr().err

    def test_refuses_when_env_target_is_opted_out(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """The key rides on the .env shim: enrolled but injection off is no good."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        marker = _env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")

        rc = memory_cli.enable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore(), platform="darwin")

        assert rc == 1
        assert not memory_marker_path(home).exists()
        assert "encryption enable env" in capsys.readouterr().err

    def test_refuses_when_the_expected_runtime_cannot_seal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            _runtime_probe,
            "runtime_memory_encryption_available",
            lambda **_kw: (False, "mordred is not installed there"),
        )
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()

        rc = memory_cli.enable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore(), platform="darwin")

        assert rc == 1
        assert not memory_marker_path(home).exists()
        assert not root.exists()
        assert "mordred is not installed there" in capsys.readouterr().err

    def test_refuses_when_a_running_gateway_cannot_seal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The gateway's interpreter is the one that must open sealed files."""
        gateway_python = tmp_path / "other" / ".venv" / "bin" / "python"
        monkeypatch.setattr(
            _runtime_probe,
            "discover_running_gateway_runtimes",
            lambda **_kw: [GatewayRuntime(pid=4242, python=gateway_python)],
        )
        monkeypatch.setattr(
            _runtime_probe,
            "runtime_memory_encryption_available",
            lambda **kw: (kw.get("runtime_python") is None, "no memory hook there"),
        )
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()

        rc = memory_cli.enable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore(), platform="darwin")

        assert rc == 1
        assert not memory_marker_path(home).exists()
        err = capsys.readouterr().err
        assert "pid 4242" in err
        assert "no memory hook there" in err

    def test_force_runtime_unverified_skips_both_probes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _never(**_kw: object) -> tuple[bool, str]:
            raise AssertionError("--force-runtime-unverified must not probe")

        monkeypatch.setattr(_runtime_probe, "runtime_memory_encryption_available", _never)
        root, home, backend, store = _setup_home_and_vault(tmp_path)

        rc = _enable(home, root, backend, store, force_runtime_unverified=True)

        assert rc == 0
        assert memory_marker_path(home).exists()


# -----------------------------------------------------------------------------
# enable — key, marker, eager migration
# -----------------------------------------------------------------------------
class TestEnable:
    def test_writes_a_private_marker_and_seals_existing_files(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        memories = _memories(home)
        (memories / "MEMORY.md").write_text("the cat is on the mat\n", encoding="utf-8")
        (memories / "USER.md.bak.20260819").write_text("a stale snapshot\n", encoding="utf-8")

        rc = _enable(home, root, backend, store)

        assert rc == 0
        marker = memory_marker_path(home)
        assert marker.exists()
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600
        assert stat.S_IMODE(marker.parent.stat().st_mode) == 0o700

        key = _vault_memory_key(root, backend, store)
        expected_files = (("MEMORY.md", "the cat is on the mat\n"), ("USER.md.bak.20260819", "a stale snapshot\n"))
        for name, expected in expected_files:
            data = (memories / name).read_bytes()
            assert data.startswith(MAGIC)
            assert expected.encode("utf-8") not in data
            assert unseal(data, key=key, name=name).decode("utf-8") == expected

        out = capsys.readouterr().out
        assert "Agent-memory encryption enabled (2 file(s) sealed; hook armed at next Hermes start)." in out

    def test_skips_already_sealed_files(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        memories = _memories(home)
        sealed = seal(b"already sealed\n", key=_FOREIGN_KEY, name="MEMORY.md")
        (memories / "MEMORY.md").write_bytes(sealed)

        assert _enable(home, root, backend, store) == 0

        # Byte-identical: a sealed file is never re-sealed under the new key.
        assert (memories / "MEMORY.md").read_bytes() == sealed
        assert "(0 file(s) sealed" in capsys.readouterr().out

    def test_clears_the_optout_marker(self, tmp_path: Path) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        optout = memory_optout_marker_path(home)
        optout.parent.mkdir(parents=True, exist_ok=True)
        optout.write_text("opt-out\n", encoding="utf-8")

        assert _enable(home, root, backend, store) == 0
        assert not optout.exists()

    def test_never_prints_the_key(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)

        assert _enable(home, root, backend, store) == 0

        captured = capsys.readouterr()
        value = _effective_memory_key(_vault_env_text(root, backend, store))
        assert value is not None
        assert value not in captured.out
        assert value not in captured.err

    def test_does_not_write_the_legacy_config_flag(self, tmp_path: Path) -> None:
        """The marker is the source of truth; config.yaml is left alone."""
        root, home, backend, store = _setup_home_and_vault(tmp_path)

        assert _enable(home, root, backend, store) == 0
        assert not (home / "config.yaml").exists()

    def test_leaves_an_existing_legacy_flag_alone(self, tmp_path: Path) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (home / "config.yaml").write_text("memory:\n  encryption:\n    enabled: true\n", encoding="utf-8")

        assert _enable(home, root, backend, store) == 0
        assert _raw_flag(home) is True

    def test_warns_about_plaintext_pending_approvals(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (home / "config.yaml").write_text("memory:\n  write_approval: true\n", encoding="utf-8")

        assert _enable(home, root, backend, store) == 0
        assert "write_approval" in capsys.readouterr().err

    def test_warns_that_a_running_gateway_must_restart(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            _runtime_probe,
            "discover_running_gateway_runtimes",
            lambda **_kw: [GatewayRuntime(pid=777, python=tmp_path / "bin" / "python")],
        )
        root, home, backend, store = _setup_home_and_vault(tmp_path)

        assert _enable(home, root, backend, store) == 0
        err = capsys.readouterr().err
        assert "restart it (pid 777)" in err
        # The old wording claimed the still-running gateway "writes plaintext
        # memories" -- wrong: it fails closed (write refusal / an apparently
        # empty memory), never plaintext. See `_memory_hook`'s module docstring
        # ("Fail-closed on the write side, loud on the read side").
        assert "fail closed" in err
        assert "do NOT write plaintext" in err
        assert "plaintext memories" not in err

    def test_migration_failure_keeps_the_marker_and_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def _boom(_path: Path, _data: bytes) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(memory_cli, "_write_private", _boom)
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (_memories(home) / "MEMORY.md").write_text("still plaintext\n", encoding="utf-8")

        rc = _enable(home, root, backend, store)

        assert rc == 1
        assert memory_marker_path(home).exists()  # armed anyway: the hook seals on the next write
        err = capsys.readouterr().err
        assert "disk full" in err
        assert "next write" in err
        assert (home / "memories" / "MEMORY.md").read_text(encoding="utf-8") == "still plaintext\n"

    def test_missing_vault_is_auto_created(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()

        rc = memory_cli.enable(
            home=home,
            root=root,
            backend=backend,
            store=store,
            platform="darwin",
            prompt_io=FixedPassphrasePromptIO(_PASSPHRASE),
        )

        assert rc == 0
        assert _is_valid_memory_key(_effective_memory_key(_vault_env_text(root, backend, store)))
        assert memory_marker_path(home).exists()

    def test_vault_create_refused_writes_no_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()

        rc = memory_cli.enable(
            home=home,
            root=root,
            backend=FakeBackend(),
            store=FakeAnchorStore(),
            platform="darwin",
            prompt_io=FixedPassphrasePromptIO(""),
        )

        assert rc == 1
        assert not memory_marker_path(home).exists()

    def test_symlinked_memory_file_is_not_followed(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """W2: `_memory_file_paths` excludes symlinks, so `enable` never even
        sees one -- the target is untouched, the link stays a link, and the
        sealed-file count reports only the real file."""
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        memories = _memories(home)
        outside = tmp_path / "outside.md"
        outside.write_text("plaintext outside the memories dir\n", encoding="utf-8")
        link = memories / "linked.md"
        link.symlink_to(outside)
        (memories / "MEMORY.md").write_text("real plaintext\n", encoding="utf-8")

        rc = _enable(home, root, backend, store)

        assert rc == 0
        assert link.is_symlink()  # link intact, not replaced by a sealed regular file
        assert outside.read_text(encoding="utf-8") == "plaintext outside the memories dir\n"  # target untouched
        assert "(1 file(s) sealed" in capsys.readouterr().out  # only the real file was ever seen


# -----------------------------------------------------------------------------
# _seal_plaintext_files — direct coverage of the sealer's symlink guard (W2,
# defence in depth) and its scan-to-write TOCTOU narrowing (W3).
# -----------------------------------------------------------------------------
class TestSealPlaintextFiles:
    _KEY = b"\x01" * 32

    def test_symlink_counts_as_a_failure_not_a_silent_skip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defence in depth: even if a symlink reached this function despite
        `encryption_cli._memory_file_paths`'s primary filter (a caller that
        does not go through it, or a race), it must never be followed."""
        home = tmp_path / "home"
        memories = _memories(home)
        outside = tmp_path / "outside.md"
        outside.write_text("plaintext outside\n", encoding="utf-8")
        link = memories / "linked.md"
        link.symlink_to(outside)
        monkeypatch.setattr(encryption_cli, "_memory_file_paths", lambda _home: [link])

        sealed, failures = memory_cli._seal_plaintext_files(home, key=self._KEY)

        assert sealed == 0
        assert failures == ["linked.md: is a symlink — refusing to follow it"]
        assert outside.read_text(encoding="utf-8") == "plaintext outside\n"  # target untouched
        assert link.is_symlink()  # link intact

    def test_skips_a_file_sealed_between_the_read_and_the_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """W3: a concurrently-armed hook (a still-running gateway) can seal a
        plaintext file between our read and our write. Re-checking right
        before `_write_private` must skip -- not clobber -- the concurrent
        seal with our now-stale plaintext."""
        from mordred_hermes.keyvault import memory_crypto

        home = tmp_path / "home"
        memories = _memories(home)
        path = memories / "MEMORY.md"
        path.write_text("original plaintext\n", encoding="utf-8")
        concurrent_seal = seal(b"sealed by someone else in the meantime\n", key=_FOREIGN_KEY, name="MEMORY.md")

        real_seal = memory_crypto.seal

        def _seal_and_race(data: bytes, *, key: bytes, name: str) -> bytes:
            # Simulate the race: something else seals the file between our
            # first read (already done by the caller) and our write below.
            path.write_bytes(concurrent_seal)
            return real_seal(data, key=key, name=name)

        monkeypatch.setattr(memory_crypto, "seal", _seal_and_race)

        sealed, failures = memory_cli._seal_plaintext_files(home, key=self._KEY)

        assert sealed == 0  # not counted a success -- the concurrent seal is what's on disk
        assert failures == []  # and not a failure either: nothing was lost
        assert path.read_bytes() == concurrent_seal  # the concurrent seal wins, never clobbered

    def test_still_seals_files_untouched_by_a_concurrent_writer(self, tmp_path: Path) -> None:
        """The TOCTOU guard must not make sealing spuriously skip everything —
        only a file that actually changed underneath it."""
        home = tmp_path / "home"
        memories = _memories(home)
        (memories / "MEMORY.md").write_text("quiet the whole time\n", encoding="utf-8")

        sealed, failures = memory_cli._seal_plaintext_files(home, key=self._KEY)

        assert sealed == 1
        assert failures == []
        assert is_sealed((memories / "MEMORY.md").read_bytes())


# -----------------------------------------------------------------------------
# disable — decrypt back (reversible), or refuse
# -----------------------------------------------------------------------------
class TestDisable:
    def test_nothing_sealed_just_writes_the_optout_marker(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 0
        assert memory_optout_marker_path(home).exists()
        assert not memory_marker_path(home).exists()
        assert "0 file(s) decrypted" in capsys.readouterr().out

    def test_does_not_create_the_legacy_flag(self, tmp_path: Path) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)

        assert memory_cli.disable(home=home, root=root, backend=backend, store=store) == 0
        assert not (home / "config.yaml").exists()

    def test_clears_an_existing_legacy_flag(self, tmp_path: Path) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (home / "config.yaml").write_text("memory:\n  encryption:\n    enabled: true\n", encoding="utf-8")

        assert memory_cli.disable(home=home, root=root, backend=backend, store=store) == 0
        assert _raw_flag(home) is False

    def test_decrypts_sealed_files_back_and_keeps_the_key(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        memories = _memories(home)
        (memories / "MEMORY.md").write_text("the cat is on the mat\n", encoding="utf-8")
        (memories / "USER.md.bak.1").write_text("a stale snapshot\n", encoding="utf-8")
        assert _enable(home, root, backend, store) == 0
        capsys.readouterr()

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 0
        assert (memories / "MEMORY.md").read_text(encoding="utf-8") == "the cat is on the mat\n"
        assert (memories / "USER.md.bak.1").read_text(encoding="utf-8") == "a stale snapshot\n"
        assert not memory_marker_path(home).exists()
        assert memory_optout_marker_path(home).exists()
        assert _is_valid_memory_key(_effective_memory_key(_vault_env_text(root, backend, store)))
        out = capsys.readouterr().out
        assert "Agent-memory encryption disabled (2 file(s) decrypted back to plaintext; key kept" in out

    def test_refuses_when_the_key_is_gone(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (_memories(home) / "MEMORY.md").write_bytes(seal(b"secret\n", key=_FOREIGN_KEY, name="MEMORY.md"))
        marker = memory_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("armed\n", encoding="utf-8")
        _enroll_env_text(root, backend, store, "OTHER=1\n")

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 1
        assert marker.exists()  # still armed — the operator can restore the key
        assert not memory_optout_marker_path(home).exists()
        assert is_sealed((home / "memories" / "MEMORY.md").read_bytes())
        err = capsys.readouterr().err
        assert "set-memory-key is NOT it" in err

    def test_refuses_when_a_file_cannot_be_decrypted(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        assert _enable(home, root, backend, store) == 0
        # Sealed under a key that is not the vault's — e.g. restored from a
        # backup taken before a rotation.
        (_memories(home) / "MEMORY.md").write_bytes(seal(b"secret\n", key=_FOREIGN_KEY, name="MEMORY.md"))
        capsys.readouterr()

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 1
        assert memory_marker_path(home).exists()
        assert not memory_optout_marker_path(home).exists()
        assert is_sealed((home / "memories" / "MEMORY.md").read_bytes())
        assert "MEMORY.md" in capsys.readouterr().err

    def test_warns_that_a_running_gateway_keeps_the_hook_armed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        assert _enable(home, root, backend, store) == 0
        monkeypatch.setattr(
            _runtime_probe,
            "discover_running_gateway_runtimes",
            lambda **_kw: [GatewayRuntime(pid=99, python=tmp_path / "bin" / "python")],
        )
        capsys.readouterr()

        assert memory_cli.disable(home=home, root=root, backend=backend, store=store) == 0
        err = capsys.readouterr().err
        assert "pid 99" in err
        assert "armed" in err

    def test_refuses_when_a_symlink_reaches_the_unseal_step(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Defence in depth (W2): if a symlink somehow reached the sealed-files
        list (a race after the scan, or a future caller bug), `disable` must
        refuse loudly rather than follow it."""
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        memories = _memories(home)
        outside = tmp_path / "outside.md"
        outside.write_text("plaintext outside\n", encoding="utf-8")
        link = memories / "linked.md"
        link.symlink_to(outside)
        monkeypatch.setattr(memory_cli, "_sealed_memory_files", lambda _home: [link])
        monkeypatch.setattr(memory_cli, "_memory_key_from_vault", lambda **_kw: b"\x02" * 32)

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 1
        assert link.is_symlink()
        assert outside.read_text(encoding="utf-8") == "plaintext outside\n"
        assert "linked.md" in capsys.readouterr().err

    def test_refuses_when_a_file_is_resealed_during_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """W3: the initial scan and the decrypt loop are not one atomic step —
        a still-armed gateway can seal (or re-seal) a file after it was
        scanned. `disable` must re-scan after the loop and refuse the marker
        removal rather than report success while anything is sealed again."""
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (_memories(home) / "MEMORY.md").write_text("plain\n", encoding="utf-8")
        assert _enable(home, root, backend, store) == 0
        capsys.readouterr()

        real_sealed_memory_files = memory_cli._sealed_memory_files
        calls = {"n": 0}

        def _flaky(home_arg: Path) -> list[Path]:
            calls["n"] += 1
            if calls["n"] == 1:
                return real_sealed_memory_files(home_arg)
            # Simulate: a concurrent gateway re-sealed MEMORY.md while this
            # run was decrypting it.
            return [home_arg / "memories" / "MEMORY.md"]

        monkeypatch.setattr(memory_cli, "_sealed_memory_files", _flaky)

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 1
        assert calls["n"] == 2  # scanned before the loop and re-scanned after
        assert memory_marker_path(home).exists()  # marker stays armed -- the hook keeps working
        assert not memory_optout_marker_path(home).exists()
        err = capsys.readouterr().err
        assert "MEMORY.md" in err
        assert "re-run" in err
        assert "gateway" in err.lower()

    def test_succeeds_when_the_rescan_finds_nothing_sealed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The new post-loop re-scan must not turn an ordinary, uncontended
        `disable` into a false refusal."""
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (_memories(home) / "MEMORY.md").write_text("plain\n", encoding="utf-8")
        assert _enable(home, root, backend, store) == 0
        capsys.readouterr()

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 0
        assert not memory_marker_path(home).exists()
        assert memory_optout_marker_path(home).exists()


# -----------------------------------------------------------------------------
# _unseal_files — direct coverage of the unsealer's symlink guard (W2) and its
# scan-to-write TOCTOU narrowing (W3): it must decrypt the RE-READ bytes, and
# refuse (not silently skip) a file that is no longer sealed when it gets there.
# -----------------------------------------------------------------------------
class TestUnsealFiles:
    def test_symlink_counts_as_a_failure(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        memories = _memories(home)
        outside = tmp_path / "outside.md"
        outside.write_bytes(seal(b"secret\n", key=_FOREIGN_KEY, name="linked.md"))
        link = memories / "linked.md"
        link.symlink_to(outside)

        decrypted, failure = memory_cli._unseal_files([link], key=_FOREIGN_KEY)

        assert decrypted == 0
        assert failure == "linked.md: is a symlink — refusing to follow it"
        assert link.is_symlink()

    def test_reports_a_file_no_longer_sealed_at_write_time(self, tmp_path: Path) -> None:
        """A file the earlier scan classified as sealed but which is plaintext
        by the time this function gets to it (a concurrent writer beat it to
        the punch) must be reported as a failure, not silently skipped —
        skipping it would let `disable` claim success while this file was
        simply never touched, sealed or not."""
        home = tmp_path / "home"
        memories = _memories(home)
        path = memories / "MEMORY.md"
        path.write_text("plaintext by the time we get here\n", encoding="utf-8")

        decrypted, failure = memory_cli._unseal_files([path], key=_FOREIGN_KEY)

        assert decrypted == 0
        assert failure is not None
        assert "no longer sealed" in failure
        assert path.read_text(encoding="utf-8") == "plaintext by the time we get here\n"  # untouched

    def test_decrypts_the_re_read_bytes_not_a_stale_copy(self, tmp_path: Path) -> None:
        """However `_unseal_files` came to believe a path is sealed, it must
        decrypt whatever is actually on disk right now."""
        home = tmp_path / "home"
        memories = _memories(home)
        path = memories / "MEMORY.md"
        path.write_bytes(seal(b"the latest content\n", key=_FOREIGN_KEY, name="MEMORY.md"))

        decrypted, failure = memory_cli._unseal_files([path], key=_FOREIGN_KEY)

        assert failure is None
        assert decrypted == 1
        assert path.read_text(encoding="utf-8") == "the latest content\n"


# -----------------------------------------------------------------------------
# _sealed_memory_files — a file whose text STARTS with the magic line but
# fails the full `is_sealed` check (truncated, appended to, or otherwise
# corrupted) must be treated as sealed (W4), not silently classified as
# plaintext -- which would let `disable` skip it and `purge` strip the key out
# from under it.
# -----------------------------------------------------------------------------
class TestSealedMemoryFilesBrokenSeal:
    @staticmethod
    def _break(blob: bytes) -> bytes:
        """Corrupt one byte of the base64 body: still starts with the magic
        line, but structurally invalid -- ``is_sealed`` must now say False."""
        prefix_len = len(MAGIC) + 1  # b"<MAGIC>\n"
        return blob[:prefix_len] + b"!" + blob[prefix_len + 1 :]

    def test_broken_seal_is_treated_as_sealed(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        memories = _memories(home)
        blob = seal(b"a real secret\n", key=_FOREIGN_KEY, name="MEMORY.md")
        broken = self._break(blob)
        assert not is_sealed(broken)  # sanity: the corruption actually broke it
        (memories / "MEMORY.md").write_bytes(broken)

        assert (memories / "MEMORY.md") in memory_cli._sealed_memory_files(home)

    def test_disable_refuses_on_a_broken_seal_instead_of_skipping_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        memories = _memories(home)
        (memories / "MEMORY.md").write_text("original notes\n", encoding="utf-8")
        assert _enable(home, root, backend, store) == 0
        capsys.readouterr()
        broken = self._break((memories / "MEMORY.md").read_bytes())
        (memories / "MEMORY.md").write_bytes(broken)

        rc = memory_cli.disable(home=home, root=root, backend=backend, store=store)

        assert rc == 1
        assert memory_marker_path(home).exists()
        assert not memory_optout_marker_path(home).exists()
        assert "MEMORY.md" in capsys.readouterr().err

    def test_purge_refuses_on_a_broken_seal_too(self, tmp_path: Path) -> None:
        """The scenario the finding warns about: without this fix, `disable`
        would silently skip the broken file, report success, and `purge`
        would then strip the key -- permanently orphaning it."""
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        memories = _memories(home)
        (memories / "MEMORY.md").write_text("original notes\n", encoding="utf-8")
        assert _enable(home, root, backend, store) == 0
        broken = self._break((memories / "MEMORY.md").read_bytes())
        (memories / "MEMORY.md").write_bytes(broken)

        rc = memory_cli.purge(home=home, root=root, backend=backend, store=store)

        assert rc == 1
        assert _MEMORY_KEY_ENV in _vault_env_text(root, backend, store)  # key kept
        assert memory_marker_path(home).exists()


# -----------------------------------------------------------------------------
# purge — disable first, then strip the key
# -----------------------------------------------------------------------------
class TestPurge:
    def test_removes_the_key_and_both_markers(self, tmp_path: Path) -> None:
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        (_memories(home) / "MEMORY.md").write_text("plain\n", encoding="utf-8")
        assert _enable(home, root, backend, store) == 0

        rc = memory_cli.purge(home=home, root=root, backend=backend, store=store)

        assert rc == 0
        assert _MEMORY_KEY_ENV not in _vault_env_text(root, backend, store)
        assert not memory_marker_path(home).exists()
        assert not memory_optout_marker_path(home).exists()
        assert (home / "memories" / "MEMORY.md").read_text(encoding="utf-8") == "plain\n"

    def test_refuses_while_undecryptable_files_remain(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Stripping the key under a sealed file destroys it — never do that."""
        root, home, backend, store = _setup_home_and_vault(tmp_path)
        assert _enable(home, root, backend, store) == 0
        (_memories(home) / "MEMORY.md").write_bytes(seal(b"secret\n", key=_FOREIGN_KEY, name="MEMORY.md"))
        capsys.readouterr()

        rc = memory_cli.purge(home=home, root=root, backend=backend, store=store)

        assert rc == 1
        assert _MEMORY_KEY_ENV in _vault_env_text(root, backend, store)  # key kept
        assert memory_marker_path(home).exists()
        assert "refusing to strip the key" in capsys.readouterr().err


# -----------------------------------------------------------------------------
# _set_encryption_flag must round-trip config.yaml through PolicyWriter's
# shared ruamel instance, not a bare YAML(). A bare YAML() uses ruamel's
# default indent settings, which reformat every sequence already in the file
# (e.g. a `plugins.enabled` list PolicyWriter wrote at dash-indent offset 2
# collapses to offset 0) -- so alternating `configure` / `network init` /
# `upgrade` with `encryption {disable,purge} memory` caused gratuitous
# config.yaml diff churn on lists that were never touched by this command.
# -----------------------------------------------------------------------------
class TestSetEncryptionFlagPreservesFormatting:
    def test_plugins_enabled_list_formatting_survives_round_trip(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.policy_writer import PolicySnapshot, PolicyWriter

        home = tmp_path / "home"
        home.mkdir()
        # Seed config.yaml exactly the way PolicyWriter writes it (indent
        # mapping=2, sequence=4, offset=2) so the test reproduces the real
        # on-disk shape rather than a hand-authored approximation of it.
        writer = PolicyWriter(
            config_path=home / "config.yaml",
            policy_json_path=home / "mordred" / "policy.json",
            mordred_dir=home / "mordred",
        )
        writer.write(PolicySnapshot(policy="lenient"))
        before = (home / "config.yaml").read_text(encoding="utf-8")
        enabled_block = "  enabled:\n    - mordred\n"
        assert enabled_block in before, "test setup must reproduce PolicyWriter's offset-2 dash indent"

        rc = memory_cli._set_encryption_flag(home, enabled=True)
        assert rc == 0

        after = (home / "config.yaml").read_text(encoding="utf-8")
        # The plugins.enabled block's indentation must be byte-identical --
        # only the new memory.encryption.enabled key was added. A bare YAML()
        # would instead collapse the dash indent to offset 0.
        assert enabled_block in after
        assert after.startswith(before.rstrip("\n"))


@pytest.fixture(autouse=True)
def _macos_key_custody_contract(monkeypatch):
    """These regressions exercise macOS env/vault custody on every CI OS."""
    import mordred_hermes.wizard.memory_cli as module
    from tests._helpers import PlatformSys

    monkeypatch.setattr(module, "sys", PlatformSys("darwin"))
