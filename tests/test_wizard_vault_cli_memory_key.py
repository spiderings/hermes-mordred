"""Vault CLI memory-key enrollment and shared hot-path tests."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

import pytest

from mordred_hermes.keyvault import vault
from mordred_hermes.wizard import vault_cli, vault_memory_key

from ._keyvault_fakes import FakeAnchorStore, FakeBackend
from ._wizard_vault_cli_helpers import _PASSPHRASE, _PromptIO, _ReadOSErrorVault, _ReadRaisesStore


class TestSetMemoryKey:
    """``vault set-memory-key`` — enroll/rotate ``HERMES_MEMORY_KEY`` in the vault ``.env``.

    The agent-memory encryption key: storing it in the vault ``.env`` means the
    device key protects it at rest and the runtime shim injects it into the
    environment at startup, where Mordred's memory hook reads it.
    ``encryption enable memory`` is the switch that actually arms the hook.
    """

    @pytest.fixture(autouse=True)
    def _isolate_ambient_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """No ambient HERMES_MEMORY_KEY by default, so tests exercise the fresh-key path.

        Clears the env var and points the Hermes home at an empty dir (no plaintext
        .env to adopt). The adoption tests override these.
        """
        monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
        empty_home = tmp_path / "ambient_home"
        empty_home.mkdir()
        monkeypatch.setattr(vault_memory_key, "_hermes_home", lambda: empty_home)

    def _init(self, root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )

    def _env_text(self, root: Path) -> str:
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            return opened.read_file(".env").decode("utf-8")
        finally:
            opened.close()

    def _generation(self, root: Path) -> int:
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            return opened.generation
        finally:
            opened.close()

    def _key_value(self, root: Path) -> str:
        for line in self._env_text(root).splitlines():
            if line.startswith("HERMES_MEMORY_KEY="):
                return line.split("=", 1)[1]
        raise AssertionError("HERMES_MEMORY_KEY not enrolled")

    @staticmethod
    def _decodes_to_32_bytes(value: str) -> bool:
        padding = "=" * (-len(value) % 4)
        return len(base64.urlsafe_b64decode(value + padding)) == 32

    def test_adds_key_to_empty_vault(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._decodes_to_32_bytes(self._key_value(root))  # a valid AES-256 key

    def test_preserves_existing_env_lines(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"ANTHROPIC_API_KEY=sk-secret\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert "ANTHROPIC_API_KEY=sk-secret" in text
        assert "FOO=bar" in text
        assert "HERMES_MEMORY_KEY=" in text

    def test_idempotent_when_already_set(self, tmp_path: Path) -> None:
        """A second call without ``--rotate`` is a no-op: same key, no new generation."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        first_value = self._key_value(root)
        gen = self._generation(root)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) == first_value  # unchanged
        assert self._generation(root) == gen  # no needless re-enroll

    def test_rotate_replaces_key(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        first_value = self._key_value(root)
        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert self._key_value(root) != first_value  # rotated
        assert text.count("HERMES_MEMORY_KEY=") == 1  # replaced in place, not duplicated

    def test_does_not_print_secret(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        captured = capsys.readouterr()
        value = self._key_value(root)
        assert value not in captured.out
        assert value not in captured.err

    def test_prints_config_hint(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        out = capsys.readouterr().out.lower()
        # Storing the key does not turn sealing on: name the switch that does.
        assert "encryption enable memory" in out

    def test_ensure_memory_key_returns_the_value_without_printing_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``enable memory`` needs the key *value* to migrate files — through the
        same single vault open (one Touch ID), and never on stdout."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)

        rc, value = vault_memory_key.ensure_memory_key(root=root, rotate=False, backend=backend, store=store)

        assert rc == 0
        assert value == self._key_value(root)
        captured = capsys.readouterr()
        assert value is not None
        assert value not in captured.out
        assert value not in captured.err

    def test_ensure_memory_key_returns_the_existing_value_on_a_no_op(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0

        rc, value = vault_memory_key.ensure_memory_key(root=root, rotate=False, backend=backend, store=store)

        assert rc == 0
        assert value == self._key_value(root)  # unchanged, and reported back

    def test_ensure_memory_key_reports_failure_without_a_value(self, tmp_path: Path) -> None:
        rc, value = vault_memory_key.ensure_memory_key(
            root=tmp_path / "v", rotate=False, backend=FakeBackend(), store=FakeAnchorStore()
        )
        assert rc == 1
        assert value is None

    def test_uninitialised_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_memory_key.set_memory_key(root=tmp_path / "v", backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_keychain_error_opening_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=_ReadRaisesStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_non_utf8_existing_env_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A non-UTF-8 enrolled ``.env`` cannot be merged as text — fail closed, enroll nothing."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"\xff\xfe not utf-8")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)
        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""
        assert self._generation(root) == gen  # nothing enrolled

    def test_rotate_collapses_duplicate_keys(self, tmp_path: Path) -> None:
        """Review P2: ``--rotate`` must leave exactly one key — dotenv keeps the *last*,
        so a stale later duplicate would silently win over the rotated value."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=aaa\nHERMES_MEMORY_KEY=bbb\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert text.count("HERMES_MEMORY_KEY=") == 1  # both duplicates collapsed to one
        assert "FOO=bar" in text  # unrelated entry preserved
        assert self._key_value(root) not in {"aaa", "bbb"}  # a fresh value, not a stale duplicate
        assert self._decodes_to_32_bytes(self._key_value(root))

    def test_rotate_warns_about_orphaned_memories(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Review P1: rotating orphans memories encrypted under the old key — warn loudly."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        capsys.readouterr()  # drop the initial store output (no warning expected there)

        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        err = capsys.readouterr().err.lower()
        assert "warning" in err
        assert "memor" in err  # names the agent-memory files at risk

    def test_first_store_does_not_warn(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """The orphaned-memory warning is rotation-only; a first store must not emit it."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert "warning" not in capsys.readouterr().err.lower()

    def test_read_oserror_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Review P2: a read I/O error (KeyvaultPermissionError) fails closed, not a traceback."""

        def _fake_open(*args: object, **kwargs: object) -> _ReadOSErrorVault:
            return _ReadOSErrorVault()

        monkeypatch.setattr(vault, "open_vault", _fake_open)
        rc = vault_memory_key.set_memory_key(root=tmp_path / "v", backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_invalid_existing_key_is_replaced_without_rotate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Re-review P2: a present-but-unusable key is not treated as 'already set'.

        An empty / wrong-length `HERMES_MEMORY_KEY` would make `memory.encryption`
        fail at startup, so it must be replaced even without `--rotate` — and
        without the rotation warning, since it never encrypted anything.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=\nFOO=bar\n")  # empty value → not 32 bytes
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._decodes_to_32_bytes(self._key_value(root))  # now a usable key
        assert "FOO=bar" in self._env_text(root)
        assert "warning" not in capsys.readouterr().err.lower()  # nothing was orphaned

    def test_short_existing_key_is_replaced(self, tmp_path: Path) -> None:
        """A too-short value decodes to ≠32 bytes → invalid → replaced, not kept."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=abc\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) != "abc"
        assert self._decodes_to_32_bytes(self._key_value(root))

    def test_refuses_when_effective_key_invalid_but_valid_exists(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Re-review P1/P2: a valid key shadowed by a later invalid duplicate is ambiguous.

        dotenv last-wins makes the *effective* key the invalid one, yet an earlier
        valid key may have encrypted memories. Refuse (rc 1) rather than guess or
        regenerate — and leave the .env untouched so nothing is lost.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        valid = base64.urlsafe_b64encode(b"\x22" * 32).decode("ascii")
        src = tmp_path / "s"
        src.write_bytes(f"HERMES_MEMORY_KEY={valid}\nHERMES_MEMORY_KEY=oops\nFOO=bar\n".encode())
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)

        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 1
        assert "rotate" in capsys.readouterr().err.lower()  # guidance points at --rotate
        assert self._env_text(root).count("HERMES_MEMORY_KEY=") == 2  # .env untouched
        assert self._generation(root) == gen  # nothing enrolled — no data loss

    def test_quoted_valid_key_is_recognized(self, tmp_path: Path) -> None:
        """Re-review P2: a dotenv-quoted valid key (``"base64:..."``) is recognized, not replaced."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        raw = base64.urlsafe_b64encode(b"\x33" * 32).decode("ascii")
        src = tmp_path / "s"
        src.write_bytes(f'HERMES_MEMORY_KEY="base64:{raw}"\n'.encode())
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)

        # Recognized as already set (the runtime's dotenv parse strips quotes) → no-op.
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._generation(root) == gen  # untouched, not regenerated

    def test_bare_key_line_does_not_shadow_written_key(self, tmp_path: Path) -> None:
        """Re-review P2: a bare ``HERMES_MEMORY_KEY`` (dotenv → None) must be removed on write.

        Otherwise it stays as the last entry and shadows the written key, so the
        runtime shim's dotenv parse sees None and injects nothing.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        # invalid assignment then a bare line → dotenv effective value is None.
        src.write_bytes(b"HERMES_MEMORY_KEY=bad\nHERMES_MEMORY_KEY\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert "FOO=bar" in text  # unrelated entry preserved
        # The effective value the runtime would inject is now a usable 32-byte key,
        # not None — i.e. the bare shadow was removed, not left behind.
        assert vault_memory_key._is_valid_memory_key(vault_memory_key._effective_memory_key(text))

    def test_bare_key_with_trailing_comment_does_not_shadow(self, tmp_path: Path) -> None:
        """Re-review P2: ``HERMES_MEMORY_KEY # comment`` is a dotenv bare entry (None) too.

        Delegating removal to dotenv's parser drops it like any other binding, so
        it can't be left behind to shadow the written key.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=bad\nHERMES_MEMORY_KEY # disabled\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert "FOO=bar" in text
        # the effective value the runtime would inject is now a usable 32-byte key
        assert vault_memory_key._is_valid_memory_key(vault_memory_key._effective_memory_key(text))

    def test_refuses_valid_key_with_trailing_comment_shadowed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A valid key with a trailing comment, shadowed by a later invalid one, is detected.

        dotenv strips the comment, so the earlier line *is* a valid key — the
        ambiguity must be surfaced (refuse), not lost by regenerating.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        valid = base64.urlsafe_b64encode(b"\x44" * 32).decode("ascii")
        src = tmp_path / "s"
        src.write_bytes(f"HERMES_MEMORY_KEY={valid} # my key\nHERMES_MEMORY_KEY=bad\n".encode())
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)

        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 1
        assert "rotate" in capsys.readouterr().err.lower()
        assert self._generation(root) == gen  # .env untouched — no data loss

    def test_adopts_env_var_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Re-review P1: a valid HERMES_MEMORY_KEY in the live env is ADOPTED, not replaced.

        A fresh key would override the user's existing one at startup and orphan
        memories already encrypted under it.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        existing = base64.urlsafe_b64encode(b"\x55" * 32).decode("ascii")
        monkeypatch.setenv("HERMES_MEMORY_KEY", existing)

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) == existing  # adopted the env key, not regenerated

    def test_adopts_plaintext_home_env_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A valid key in the plaintext home .env (not yet migrated) is adopted."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        home = tmp_path / "real_home"
        home.mkdir()
        existing = base64.urlsafe_b64encode(b"\x66" * 32).decode("ascii")
        (home / ".env").write_text(f"HERMES_MEMORY_KEY={existing}\n", encoding="utf-8")
        monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
        monkeypatch.setattr(vault_memory_key, "_hermes_home", lambda: home)

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) == existing  # adopted from the plaintext .env

    def test_rotate_mints_fresh_even_with_ambient_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--rotate ignores the ambient key, mints fresh, and warns about orphaning."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        ambient = base64.urlsafe_b64encode(b"\x77" * 32).decode("ascii")
        monkeypatch.setenv("HERMES_MEMORY_KEY", ambient)

        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        assert self._key_value(root) != ambient  # a fresh key, not the ambient one
        assert "warning" in capsys.readouterr().err.lower()  # rotating away a usable key warns

    def test_cli_set_memory_key_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, rotate: bool = False, backend: object = None, store: object = None) -> int:
            seen["root"] = root
            seen["rotate"] = rotate
            return 0

        monkeypatch.setattr(vault_memory_key, "set_memory_key", _spy)
        rc = vault_memory_key.cli_set_memory_key(argparse.Namespace(root=str(tmp_path), rotate=True))
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["rotate"] is True


class TestOpenHotPath:
    """``_open_hot_path_or_report`` — the shared hot-path open used by add /
    migrate / set_memory_key. Returns the opened vault (caller closes it), or
    prints a fail-closed reason to stderr and returns ``None``.
    """

    def test_returns_opened_vault_when_initialised(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        assert opened is not None
        try:
            assert opened.generation == 0  # freshly initialised, nothing enrolled
        finally:
            opened.close()

    def test_uninitialised_returns_none_and_points_at_init(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        opened = vault_cli._open_hot_path_or_report(tmp_path / "v", backend=FakeBackend(), store=FakeAnchorStore())
        assert opened is None
        assert "init" in capsys.readouterr().err.lower()  # guidance: run `vault init` first

    def test_keychain_error_returns_none(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        opened = vault_cli._open_hot_path_or_report(tmp_path / "v", backend=FakeBackend(), store=_ReadRaisesStore())
        assert opened is None
        assert capsys.readouterr().err.strip() != ""
