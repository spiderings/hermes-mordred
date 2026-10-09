"""Tests for ``hermes-mordred keyvault {list,verify-digest}``.

These are the **backend-free**
keyvault CLI commands — they only read the on-disk keyvault layout
(``meta.json`` + ``digests/<hash>.commit``) and need no Secure Enclave
``NativeBackend``:

- ``keyvault list`` — list key ids (no key material).
- ``keyvault verify-digest`` — re-display the full verification digest
  of each key for offline cross-checking.

``keyvault init`` / ``keyvault recover`` (and ``audit decrypt``) need the
production ``NativeBackend`` and are deferred to a later PR.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _bip39, _native_key_id, _storage, api
from mordred_hermes.keyvault import digest as kvdigest
from mordred_hermes.keyvault import pow as kvpow
from mordred_hermes.keyvault.network_fallback import BlackoutNotAsserted
from mordred_hermes.wizard import keyvault_cli
from tests._keyvault_fakes import FakeBackend


def _key_id_hash(key_id: str) -> str:
    """On-disk key-id hash — ``SHA-256(key_id)[:16].hex()`` (api._hash_id)."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


def _build_keyvault(home: Path, keys: dict[str, bytes]) -> Path:
    """Materialize a keyvault under ``home`` with the given ``{key_id: digest}``.

    Returns the keyvault root. Each digest is a 32-byte verification
    digest written to ``digests/<hash>.commit`` exactly as confirm_generate
    would; the ``meta.json`` row carries the cleartext ``key_id``.
    """
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id, digest in keys.items():
        h = _key_id_hash(key_id)
        meta["keys"][h] = {"key_id": key_id, "created_at": "2026-05-16T00:00:00Z"}
        _storage.atomic_write(root / "digests" / f"{h}.commit", digest)
    _storage.save_meta(root, meta)
    return root


# ---------------------------------------------------------------------------
# keyvault list
# ---------------------------------------------------------------------------


class TestList:
    def test_empty_keyvault_reports_no_keys(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        assert "no keys" in capsys.readouterr().out.lower()

    def test_absent_keyvault_dir_reports_no_keys(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        # No ensure_layout — the keyvault has never been initialised.
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        assert "no keys" in capsys.readouterr().out.lower()

    def test_lists_each_key_id_and_hash(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_keyvault(tmp_path, {"default": b"\x11" * 32, "payments": b"\x22" * 32})
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "default" in out
        assert "payments" in out
        assert _key_id_hash("default") in out
        assert "2026-05-16T00:00:00Z" in out

    def test_plain_list_escapes_metadata_terminal_controls(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        key_id = "payments\n\x1b[31mowned"
        created_at = "2026-05-16T00:00:00Z\n\x1b]52;c;Y2xpcGJvYXJk\x07"
        root = _build_keyvault(tmp_path, {key_id: b"\x11" * 32})
        meta = _storage.load_meta(root)
        meta["keys"][_key_id_hash(key_id)]["created_at"] = created_at
        _storage.save_meta(root, meta)

        assert keyvault_cli.list_keys(home=tmp_path) == 0

        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert key_id not in out
        assert created_at not in out
        assert "payments\\n\\x1b[31mowned" in out
        assert "2026-05-16T00:00:00Z\\n\\x1b]52;c;Y2xpcGJvYXJk\\x07" in out

    def test_list_does_not_leak_key_material(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``list`` must not print the verification digest (key material)."""
        _build_keyvault(tmp_path, {"default": b"\xab" * 32})
        keyvault_cli.list_keys(home=tmp_path)
        assert (b"\xab" * 32).hex() not in capsys.readouterr().out

    def test_cli_list_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """cli_list(args) delegates to list_keys against the resolved home."""
        _build_keyvault(tmp_path, {"default": b"\x11" * 32})
        monkeypatch.setattr(keyvault_cli, "_hermes_home", lambda: tmp_path)
        assert keyvault_cli.cli_list(argparse.Namespace()) == 0

    def test_corrupt_meta_returns_1_with_friendly_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A corrupt meta.json must surface a clean error, not a traceback."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ not valid json", encoding="utf-8")
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 1
        err = capsys.readouterr().err.lower()
        assert "corrupt" in err
        assert "meta.json" in err
        # A remediation hint — recover from backup or reset the keyvault.
        assert "recover" in err or "reset" in err

    def test_non_utf8_meta_returns_1_without_traceback(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_bytes(b"\xffnot-utf8")

        assert keyvault_cli.list_keys(home=tmp_path) == 1

        err = capsys.readouterr().err.lower()
        assert "corrupt" in err
        assert "utf-8" in err

    def test_non_object_row_returns_1_without_traceback(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        meta["keys"][_key_id_hash("default")] = ["not", "an", "object"]
        _storage.save_meta(root, meta)

        rc = keyvault_cli.list_keys(home=tmp_path)

        assert rc == 1
        assert "invalid key row" in capsys.readouterr().err.lower()

    def test_unreadable_meta_returns_1_with_friendly_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A meta.json with the wrong mode (KeyvaultPermissionError, an
        OSError subclass) must also surface cleanly, not raise."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = root / "meta.json"
        meta.write_text("{}", encoding="utf-8")
        meta.chmod(0o644)  # KeyvaultPermissionError: keyvault files must be 0o600
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 1
        assert "meta.json" in capsys.readouterr().err.lower()

    def test_pending_reset_journal_is_not_listed_as_initialized(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x11" * 32})
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b"pending reset")

        assert keyvault_cli.list_keys(home=tmp_path) == 1
        assert "reset" in capsys.readouterr().err.lower()

    def test_list_waits_for_lifecycle_then_observes_reset_journal(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x11" * 32})
        started = threading.Event()
        finished = threading.Event()
        results: list[int] = []

        def list_from_thread() -> None:
            started.set()
            results.append(keyvault_cli.list_keys(home=tmp_path))
            finished.set()

        with _storage.keyvault_lifecycle_lock(root):
            thread = threading.Thread(target=list_from_thread)
            thread.start()
            assert started.wait(timeout=5)
            assert not finished.wait(timeout=0.1)
            _storage.write_reset_journal(root, b"pending reset")

        thread.join(timeout=5)
        assert not thread.is_alive()
        assert results == [1]
        assert "reset" in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# keyvault verify-digest
# ---------------------------------------------------------------------------


class TestVerifyDigest:
    def test_no_keys_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 1
        assert "no keys" in capsys.readouterr().err.lower()

    def test_displays_full_digest_hex(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        digest = bytes(range(32))
        _build_keyvault(tmp_path, {"default": digest})
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert digest.hex() in out  # full 64-hex digest, not a prefix
        assert "default" in out

    def test_verify_escapes_metadata_key_id_terminal_controls(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        key_id = "payments\n\x1b[2Jowned"
        digest = b"\x23" * 32
        _build_keyvault(tmp_path, {key_id: digest})

        assert keyvault_cli.verify_digest(home=tmp_path) == 0

        captured = capsys.readouterr()
        assert "\x1b" not in captured.out + captured.err
        assert key_id not in captured.out + captured.err
        assert "payments\\n\\x1b[2Jowned" in captured.out
        assert digest.hex() in captured.out

    def test_displays_every_key(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32, "payments": b"\x02" * 32})
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert (b"\x01" * 32).hex() in out
        assert (b"\x02" * 32).hex() in out

    def test_holds_lifecycle_through_commit_snapshot(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        reading_commit = threading.Event()
        release_commit = threading.Event()
        reset_acquired = threading.Event()
        results: list[int] = []
        real_safe_read = _storage.safe_read

        def pausing_safe_read(path: Path) -> bytes:
            data = real_safe_read(path)
            if path.suffix == ".commit":
                reading_commit.set()
                assert release_commit.wait(timeout=5)
            return data

        def verify() -> None:
            results.append(keyvault_cli.verify_digest(home=tmp_path))

        def resetter() -> None:
            with _storage.keyvault_lifecycle_lock(root):
                reset_acquired.set()

        monkeypatch.setattr(_storage, "safe_read", pausing_safe_read)
        verify_thread = threading.Thread(target=verify)
        reset_thread = threading.Thread(target=resetter)
        verify_thread.start()
        assert reading_commit.wait(timeout=5)
        reset_thread.start()
        try:
            assert not reset_acquired.wait(timeout=0.1)
        finally:
            release_commit.set()

        verify_thread.join(timeout=5)
        reset_thread.join(timeout=5)
        assert not verify_thread.is_alive()
        assert not reset_thread.is_alive()
        assert results == [0]
        assert reset_acquired.is_set()

    def test_missing_commit_file_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A meta row whose digests/<hash>.commit is gone is surfaced, not crashed."""
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        (root / "digests" / f"{_key_id_hash('default')}.commit").unlink()
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 1
        combined = capsys.readouterr()
        assert "default" in (combined.out + combined.err)

    @pytest.mark.parametrize("digest", [b"", b"\x01" * 31, b"\x01" * 33])
    def test_wrong_length_commit_returns_1(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        digest: bytes,
    ) -> None:
        _build_keyvault(tmp_path, {"default": digest})

        rc = keyvault_cli.verify_digest(home=tmp_path)

        captured = capsys.readouterr()
        assert rc == 1
        assert "exactly 32 bytes" in captured.err.lower()
        if digest:
            assert digest.hex() not in captured.out

    @pytest.mark.parametrize("row", [None, ["not", "an", "object"], {}, {"key_id": 7}])
    def test_invalid_metadata_row_returns_1_without_traceback(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        row: object,
    ) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        meta["keys"][_key_id_hash("default")] = row
        _storage.save_meta(root, meta)

        rc = keyvault_cli.verify_digest(home=tmp_path)

        assert rc == 1
        assert "invalid key row or hash" in capsys.readouterr().err.lower()

    def test_traversal_hash_is_rejected_before_external_digest_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        [(_key_hash, row)] = meta["keys"].items()
        hostile_hash = "../../../victim"
        meta["keys"] = {hostile_hash: row}
        _storage.save_meta(root, meta)
        victim = (root / "digests" / f"{hostile_hash}.commit").resolve()
        victim.write_bytes(b"V" * 32)
        os.chmod(victim, 0o600)
        victim_before = victim.read_bytes()
        read_paths: list[Path] = []
        real_safe_read = _storage.safe_read

        def tracking_safe_read(path: Path) -> bytes:
            read_paths.append(path.resolve(strict=False))
            return real_safe_read(path)

        monkeypatch.setattr(_storage, "safe_read", tracking_safe_read)

        rc = keyvault_cli.verify_digest(home=tmp_path)

        assert rc == 1
        assert "invalid key row or hash" in capsys.readouterr().err.lower()
        assert victim.resolve() not in read_paths
        assert victim.read_bytes() == victim_before

    def test_symlinked_digests_is_rejected_before_external_digest_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        digests = root / "digests"
        digests.rename(root / "original-digests")
        external = tmp_path / "external-digests"
        external.mkdir(mode=0o700)
        os.chmod(external, 0o700)
        victim = external / f"{_key_id_hash('default')}.commit"
        victim.write_bytes(b"V" * 32)
        os.chmod(victim, 0o600)
        digests.symlink_to(external, target_is_directory=True)
        victim_before = victim.read_bytes()
        read_paths: list[Path] = []
        real_safe_read = _storage.safe_read

        def tracking_safe_read(path: Path) -> bytes:
            read_paths.append(path.resolve(strict=False))
            return real_safe_read(path)

        monkeypatch.setattr(_storage, "safe_read", tracking_safe_read)

        rc = keyvault_cli.verify_digest(home=tmp_path)

        assert rc == 1
        assert "digest directory" in capsys.readouterr().err.lower()
        assert victim.resolve() not in read_paths
        assert victim.read_bytes() == victim_before

    def test_cli_verify_digest_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _build_keyvault(tmp_path, {"default": b"\x09" * 32})
        monkeypatch.setattr(keyvault_cli, "_hermes_home", lambda: tmp_path)
        assert keyvault_cli.cli_verify_digest(argparse.Namespace()) == 0

    def test_corrupt_meta_returns_1_with_friendly_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A corrupt meta.json must surface a clean error, not a traceback."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ not valid json", encoding="utf-8")
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 1
        err = capsys.readouterr().err.lower()
        assert "corrupt" in err
        assert "meta.json" in err


# ---------------------------------------------------------------------------
# keyvault recover (Phase 4 PR10 step-C)
# ---------------------------------------------------------------------------


class ScriptedPromptIO:
    """Test :class:`~mordred_hermes.wizard.configure.PromptIO` — no TTY.

    ``text`` / ``password`` give a single fixed answer to every
    ``ask_text`` / ``ask_password`` call. ``texts`` / ``passwords`` give
    a queue popped in order (needed for the init flow, which asks for the
    Passphrase twice and then the digest).
    """

    def __init__(
        self,
        *,
        text: str = "",
        password: str = "",
        texts: list[str] | None = None,
        passwords: list[str] | None = None,
    ) -> None:
        self._text = text
        self._password = password
        self._texts = list(texts) if texts is not None else None
        self._passwords = list(passwords) if passwords is not None else None

    def ask_choice(self, label: str, choices: Any, default: str) -> str:
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        if self._texts is not None:
            return self._texts.pop(0)
        return self._text

    def ask_bool(self, label: str, default: bool) -> bool:
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        if self._passwords is not None:
            return self._passwords.pop(0)
        return self._password


class _RecordingPromptIO:
    """:class:`PromptIO` double that records every prompt as ``(kind, label)``.

    Used to assert *which channel* a given field is collected through
    (security review H5): the Seed Phrase must go through ``ask_password``
    (masked), never ``ask_text`` (visible echo). Seed vs passphrase is
    disambiguated by label substring so call order is not relied upon.
    """

    def __init__(self, *, seed: str = "", passphrase: str = "") -> None:
        self._seed = seed
        self._passphrase = passphrase
        self.calls: list[tuple[str, str]] = []

    def ask_choice(self, label: str, choices: Any, default: str) -> str:
        self.calls.append(("choice", label))
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        self.calls.append(("text", label))
        return default

    def ask_bool(self, label: str, default: bool) -> bool:
        self.calls.append(("bool", label))
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        self.calls.append(("password", label))
        if "Seed" in label:
            return self._seed
        return self._passphrase


class FakeSurface:
    """No-op :class:`~mordred_hermes.keyvault.seed_display.SeedDisplaySurface`."""

    def __init__(self) -> None:
        self.shown: list[str] = []

    def banner(self, message: str) -> None:
        return None

    def show(self, seed: str) -> None:
        self.shown.append(seed)

    def clear(self) -> None:
        return None


def _sink() -> Any:
    """A throwaway audit sink (the CLI tests do not assert on audit entries)."""

    def append(entry: dict[str, Any]) -> None:
        return None

    return append


# A valid 24-word BIP39 phrase + passphrase used across recover tests.
RECOVER_SEED = _bip39.entropy_to_mnemonic(bytes(range(32)))
RECOVER_PASS = "correct horse battery staple"


@pytest.fixture
def _fast_pow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lower PoW difficulty so recover tests stay sub-second.

    PoW is deterministic in the seed at any difficulty, so a blob built
    and recovered under the same lowered difficulty round-trips cleanly.
    """
    monkeypatch.setattr(kvpow, "POW_DIFFICULTY_BITS", 4)


def _make_backup_blob(home: Path, backend: FakeBackend) -> bytes:
    """Build a real export blob on a 'device A' rooted at ``home``."""
    pow_bytes = kvpow.compute_pow(api._normalize_seed_phrase(RECOVER_SEED), difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    _handle, digest = api.prepare_generate(RECOVER_SEED, RECOVER_PASS, pow_bytes)
    result = api.generate(RECOVER_SEED, RECOVER_PASS, pow_bytes, digest, backend=backend, audit_sink=_sink(), home=home)
    api.encrypt(result.key_id, b"the-secret", "vault", backend=backend, audit_sink=_sink(), home=home)
    return api.export_backup(
        result.key_id,
        RECOVER_PASS,
        backend=backend,
        audit_sink=_sink(),
        home=home,
        seed_phrase=RECOVER_SEED,
        pow_bytes=pow_bytes,
    )


class TestRecover:
    def test_missing_blob_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.recover(
            blob_path=tmp_path / "nope.mrkv",
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS]),
        )
        assert rc == 1
        assert "nope.mrkv" in capsys.readouterr().err

    def test_unreadable_blob_wins_over_a_seed_that_would_also_fail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Multi-fault: the blob path does not exist AND the seed the operator
        would type is also bogus (fails the BIP39 checksum). ``_read_backup_blob``
        must run and report FIRST — the same "cannot read backup blob" message
        as a lone missing blob — before either prompt is ever issued.

        Mutation-sensitive: swapping ``_read_backup_blob`` and the
        prompt/``_validated_seed_and_pow`` sequence inside ``recover`` makes
        this fail — the seed prompt would run (recorded below) and the error
        would become the BIP39 rejection instead.
        """
        prompt_io = _RecordingPromptIO(seed=" ".join(["abandon"] * 24), passphrase=RECOVER_PASS)

        rc = keyvault_cli.recover(
            blob_path=tmp_path / "nope.mrkv",
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=prompt_io,
        )

        assert rc == 1
        assert prompt_io.calls == []  # neither prompt was ever reached
        err = capsys.readouterr().err.lower()
        assert "cannot read backup blob" in err
        assert "seed phrase rejected" not in err

    def test_bad_seed_checksum_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        blob_file = tmp_path / "b.mrkv"
        blob_file.write_bytes(b"unused")
        bad_seed = " ".join(["abandon"] * 24)  # 24 words but an invalid BIP39 checksum
        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[bad_seed, RECOVER_PASS]),
        )
        assert rc == 1
        assert "seed" in capsys.readouterr().err.lower()

    def test_corrupt_blob_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None) -> None:
        blob_file = tmp_path / "b.mrkv"
        blob_file.write_bytes(b"not-a-real-MRKV-blob" * 8)
        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS]),
        )
        assert rc == 1
        assert "corrupt" in capsys.readouterr().err.lower()

    def test_recover_roundtrip(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None) -> None:
        blob = _make_backup_blob(tmp_path / "a", FakeBackend())
        blob_file = tmp_path / "backup.mrkv"
        blob_file.write_bytes(blob)

        home_b = tmp_path / "b"
        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=home_b,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS]),
        )
        assert rc == 0
        assert "recovered" in capsys.readouterr().out.lower()
        meta = _storage.load_meta(_storage.resolve_keyvault_dir(home_b))
        assert meta["keys"]  # the imported key landed on device B

    def test_recover_escapes_imported_key_id_terminal_controls(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        _fast_pow: None,
    ) -> None:
        hostile_key_id = "restored\n\x1b[31mowned"
        blob_file = tmp_path / "backup.mrkv"
        blob_file.write_bytes(b"authenticated-by-test-double")
        monkeypatch.setattr(api, "import_backup", lambda *args, **kwargs: hostile_key_id)
        monkeypatch.setattr(keyvault_cli, "_provision_audit_log_key", lambda *args, **kwargs: None)

        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS]),
        )

        assert rc == 0
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert hostile_key_id not in out
        assert "restored\\n\\x1b[31mowned" in out

    def test_wrong_passphrase_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None
    ) -> None:
        blob = _make_backup_blob(tmp_path / "a", FakeBackend())
        blob_file = tmp_path / "backup.mrkv"
        blob_file.write_bytes(blob)

        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path / "b",
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, "wrong passphrase"]),
        )
        assert rc == 1
        assert "mis-transcribed" in capsys.readouterr().err.lower()

    def test_recovers_legacy_blob_with_separate_backup_passphrase(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None
    ) -> None:
        from mordred_hermes.keyvault import backup

        current_blob = _make_backup_blob(tmp_path / "a", FakeBackend())
        parsed = backup.parse_header(current_blob)
        manifest_json = backup.decrypt_body(parsed, RECOVER_PASS)
        legacy_backup_passphrase = "legacy-export-typo"
        legacy_blob = backup.export(
            manifest_json,
            legacy_backup_passphrase,
            verification_digest=parsed.verification_digest,
        )
        blob_file = tmp_path / "legacy.mrkv"
        blob_file.write_bytes(legacy_blob)

        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path / "b",
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS, legacy_backup_passphrase]),
        )

        assert rc == 0
        assert "recovered" in capsys.readouterr().out.lower()

    def test_authenticated_ciphertext_tamper_returns_1_without_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None
    ) -> None:
        blob = bytearray(_make_backup_blob(tmp_path / "a", FakeBackend()))
        blob[-1] ^= 1
        blob_file = tmp_path / "tampered.mrkv"
        blob_file.write_bytes(blob)

        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path / "b",
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS, ""]),
        )

        assert rc == 1
        assert "authentication failed" in capsys.readouterr().err.lower()

    def test_existing_destination_is_rejected_without_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None
    ) -> None:
        blob_file = tmp_path / "backup.mrkv"
        blob_file.write_bytes(_make_backup_blob(tmp_path / "source", FakeBackend()))
        destination = tmp_path / "destination"
        existing_backend = FakeBackend()
        _make_backup_blob(destination, existing_backend)

        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=destination,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS]),
        )

        assert rc == 1
        err = capsys.readouterr().err.lower()
        assert "not fresh" in err
        assert "reset" in err

    def test_cli_recover_adapter_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, Path] = {}

        def fake(*, blob_path: Path) -> int:
            seen["blob_path"] = blob_path
            return 0

        monkeypatch.setattr(keyvault_cli, "recover", fake)
        assert keyvault_cli.cli_recover(argparse.Namespace(blob="/tmp/x.mrkv")) == 0
        assert str(seen["blob_path"]) == "/tmp/x.mrkv"

    def test_seed_phrase_is_entered_without_echo(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None
    ) -> None:
        """Security review H5: the 24-word Seed Phrase is the root secret for
        the whole keyvault. It must be collected through ``ask_password``
        (masked, no terminal echo / scrollback), never ``ask_text``.
        """
        blob = _make_backup_blob(tmp_path / "a", FakeBackend())
        blob_file = tmp_path / "backup.mrkv"
        blob_file.write_bytes(blob)

        recording = _RecordingPromptIO(seed=RECOVER_SEED, passphrase=RECOVER_PASS)
        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path / "b",
            backend=FakeBackend(),
            prompt_io=recording,
        )

        assert rc == 0, "roundtrip must succeed with the seed entered via ask_password"
        seed_labels_via_password = [lbl for kind, lbl in recording.calls if kind == "password" and "Seed" in lbl]
        seed_labels_via_text = [lbl for kind, lbl in recording.calls if kind == "text" and "Seed" in lbl]
        assert seed_labels_via_password, "Seed Phrase must be requested through ask_password (masked)"
        assert not seed_labels_via_text, "Seed Phrase must never be requested through ask_text (visible echo)"


# ---------------------------------------------------------------------------
# keyvault init (Phase 4 PR10 step-D)
# ---------------------------------------------------------------------------


class TestInit:
    """``hermes mordred keyvault init`` orchestration.

    ``display_fn`` is injected so the tests never run the full 60s
    Seed-display flow (that flow is covered by test_keyvault_seed_display).
    The PoW difficulty is lowered and the mnemonic pinned so the test can
    precompute the verification digest the operator "transcribes" back.
    """

    FIXED_SEED = _bip39.entropy_to_mnemonic(bytes(range(1, 33)))
    PASSPHRASE = "my secret passphrase"

    @pytest.fixture(autouse=True)
    def _patches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(kvpow, "POW_DIFFICULTY_BITS", 4)
        monkeypatch.setattr(_bip39, "generate_mnemonic", lambda: self.FIXED_SEED)
        # init now pre-checks the air-gap before the passphrase prompt. Default
        # the resolved probe to "offline" so the flow tests below exercise their
        # own concern, not the host's live network. The online-refusal path is
        # covered explicitly by test_online_refuses_before_passphrase_prompt,
        # which injects its own raising blackout_assert.
        monkeypatch.setattr(
            "mordred_hermes.keyvault.network_fallback.resolve_blackout_assert",
            lambda: lambda **_kw: None,
        )

    def _expected_digest(self) -> bytes:
        norm_seed = api._normalize_seed_phrase(self.FIXED_SEED)
        pow_bytes = kvpow.compute_pow(norm_seed, difficulty_bits=4)
        return kvdigest.compute_digest(norm_seed, api._normalize_passphrase(self.PASSPHRASE), pow_bytes)

    def _noop_display(self, handle: object, surface: object) -> None:
        return None

    def test_init_refuses_seed_display_when_stdout_not_a_tty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # capsys replaces stdout with a non-tty buffer — exactly the redirected
        # case (`keyvault init > log.txt`) the guard must refuse: the production
        # surface prints the 24 words to stdout, so a redirect would persist
        # them to disk. Must refuse BEFORE the passphrase prompt (fail fast,
        # like the blackout pre-check), hence surface=None + a recording
        # prompt_io that must stay untouched.
        prompt_io = _RecordingPromptIO(seed=self.FIXED_SEED, passphrase=self.PASSPHRASE)
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=prompt_io,
            surface=None,
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert prompt_io.calls == []  # refused before any prompt
        captured = capsys.readouterr()
        assert "stdout is not a terminal" in captured.err
        assert "SEED" not in captured.out

    def test_already_initialised_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "already" in capsys.readouterr().err.lower()

    @pytest.mark.parametrize(
        "field",
        [
            _native_key_id.AUDIT_KEY_FIELD,
            _native_key_id.PENDING_AUDIT_KEY_FIELD,
        ],
    )
    def test_residual_audit_ownership_refuses_before_ceremony(
        self,
        field: str,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        meta[field] = {"residual": True}
        _storage.save_meta(root, meta)
        before_meta = _storage.safe_read(root / "meta.json")
        prompt_io = _RecordingPromptIO(seed=self.FIXED_SEED, passphrase=self.PASSPHRASE)
        backend = FakeBackend()
        audit_entries: list[dict[str, Any]] = []

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=prompt_io,
            surface=FakeSurface(),
            display_fn=self._noop_display,
            audit_sink=audit_entries.append,
        )

        assert rc == 1
        assert prompt_io.calls == []
        assert backend.calls == []
        assert audit_entries == []
        assert _storage.safe_read(root / "meta.json") == before_meta
        assert "residual native-key ownership" in capsys.readouterr().err.lower()

    def test_pending_reset_refuses_before_ceremony_prompts(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        root.parent.mkdir(mode=0o700, parents=True)
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b"pending reset")
        prompt_io = _RecordingPromptIO(seed=self.FIXED_SEED, passphrase=self.PASSPHRASE)

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=prompt_io,
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )

        assert rc == 1
        assert prompt_io.calls == []
        assert "reset is incomplete" in capsys.readouterr().err.lower()

    def test_passphrase_mismatch_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=["pass-a", "pass-b"]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "match" in capsys.readouterr().err.lower()

    def test_empty_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=["", ""]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "empty" in capsys.readouterr().err.lower()

    def test_blackout_failure_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        def refuse(handle: object, surface: object) -> None:
            raise BlackoutNotAsserted("host is still reachable")

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=refuse,
        )
        assert rc == 1
        err = capsys.readouterr().err.lower()
        assert "disconnect" in err or "network" in err
        assert not _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))["keys"]

    def test_online_refuses_before_passphrase_prompt(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """UX review 2026-06-15: an online host must be told to go offline
        *before* the passphrase is requested, so no entry is wasted. The late
        blackout gate in display_seed stays the real security precondition."""

        def online(**_kw: Any) -> None:
            raise BlackoutNotAsserted("host is still reachable")

        recording = _RecordingPromptIO(passphrase=self.PASSPHRASE)
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=recording,
            surface=FakeSurface(),
            display_fn=self._noop_display,
            blackout_assert=online,
        )
        assert rc == 1
        # The air-gap check fired before any prompt — no wasted passphrase entry.
        assert recording.calls == []
        err = capsys.readouterr().err.lower()
        assert "go offline" in err
        assert not _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))["keys"]

    def test_bad_digest_hex_exhausts_attempts_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """UX review 2026-06-11 Phase 4: a typo must re-prompt, not torch the
        whole ceremony — but persistent garbage still aborts (bounded)."""
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(texts=["not-hex-zz"] * 5, passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "hex" in capsys.readouterr().err.lower()
        assert not _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))["keys"]

    def test_bad_digest_hex_then_valid_succeeds(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """One mistyped digest must not force a fresh 60-second seed ceremony."""
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=["not-hex-zz", self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        assert _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))["keys"]

    def test_init_explains_before_passphrase_prompt(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """UX review 2026-06-15: init must orient the operator — what the
        command does and what the Passphrase is for — before the prompt."""

        class _ErrSnapshotPromptIO(ScriptedPromptIO):
            """Records the stderr already emitted at the first ask_password."""

            def __init__(self, capfix: pytest.CaptureFixture[str], **kw: Any) -> None:
                super().__init__(**kw)
                self._capfix = capfix
                self.err_at_first_password: str | None = None

            def ask_password(self, label: str, default: str = "") -> str:
                if self.err_at_first_password is None:
                    # readouterr() drains the buffer, so re-emit what we read to
                    # keep the rest of the run's capture intact for later asserts.
                    captured = self._capfix.readouterr()
                    self.err_at_first_password = captured.err
                    print(captured.out, end="")
                    print(captured.err, end="", file=sys.stderr)
                return super().ask_password(label, default)

        prompt_io = _ErrSnapshotPromptIO(
            capsys,
            texts=[self._expected_digest().hex()],
            passwords=[self.PASSPHRASE, self.PASSPHRASE],
        )
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=prompt_io,
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        intro = prompt_io.err_at_first_password or ""
        # The explanation precedes the very first passphrase prompt.
        assert "keyvault init" in intro
        assert "Passphrase" in intro
        # Names the consequence so the operator does not pick a throwaway.
        assert "never stored" in intro
        assert "recover" in intro.lower()

    def test_init_success_prints_next_step_hint(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Success must orient the user toward what the keyvault unlocks next."""
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "Next:" in out
        assert "hermes-mordred" in out

    def test_digest_mismatch_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(texts=["00" * 32], passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "mismatch" in capsys.readouterr().err.lower()
        assert not _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))["keys"]

    def test_init_success(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        assert "initialised" in capsys.readouterr().out.lower()
        meta = _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))
        assert meta["keys"]

    def test_unattended_kwarg_reaches_confirm_generate(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The ``hermes-mordred setup`` orchestrator threads its resolved
        unattended-key policy through ``init_keyvault`` -> ``_confirm_or_refuse``
        -> ``api.confirm_generate`` (which already accepts it). Spy on the real
        ``api.confirm_generate`` -- rather than replacing it outright -- so the
        ceremony still runs for real and this stays a behavioural, not just a
        wiring, test."""
        captured: dict[str, Any] = {}
        original_confirm_generate = api.confirm_generate

        def spy(*args: Any, **kwargs: Any) -> Any:
            captured["unattended"] = kwargs.get("unattended")
            return original_confirm_generate(*args, **kwargs)

        monkeypatch.setattr(api, "confirm_generate", spy)

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
            unattended=True,
        )

        assert rc == 0
        assert captured["unattended"] is True

    def test_unattended_defaults_to_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Omitting ``unattended`` must preserve today's exact behaviour: ``None``
        reaches ``api.confirm_generate`` unchanged, which falls back to the
        ``MORDRED_SEKEY_UNATTENDED`` env var deep in ``_seckey_backend``."""
        captured: dict[str, Any] = {}
        original_confirm_generate = api.confirm_generate

        def spy(*args: Any, **kwargs: Any) -> Any:
            captured["unattended"] = kwargs.get("unattended")
            return original_confirm_generate(*args, **kwargs)

        monkeypatch.setattr(api, "confirm_generate", spy)

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )

        assert rc == 0
        assert captured["unattended"] is None

    def test_cli_init_adapter_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "init_keyvault", fake)
        assert keyvault_cli.cli_init(argparse.Namespace()) == 0
        assert captured["store_seed_for_hd"] is True

    def test_cli_init_forwards_store_seed_for_hd_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "init_keyvault", fake)
        keyvault_cli.cli_init(argparse.Namespace(store_seed_for_hd=True))
        assert captured.get("store_seed_for_hd") is True

    def test_cli_init_forwards_paper_only_opt_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "init_keyvault", fake)
        keyvault_cli.cli_init(argparse.Namespace(store_seed_for_hd=False))
        assert captured.get("store_seed_for_hd") is False

    def test_init_provisions_audit_log_wrapping_key(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """init must also generate the audit-log wrapping key so the L465
        encrypted-audit factory can engage afterward."""
        from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID

        backend = FakeBackend()
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        root = _storage.resolve_keyvault_dir(tmp_path)
        audit_native_key_id = _native_key_id.scoped_native_key_id(root, AUDIT_LOG_KEY_ID)
        assert ("generate", audit_native_key_id) in backend.calls
        meta = _storage.load_meta(root)
        assert _native_key_id.PENDING_AUDIT_KEY_FIELD not in meta
        assert _native_key_id.committed_audit_key_from_meta(root, meta, AUDIT_LOG_KEY_ID) == audit_native_key_id

    def test_init_store_seed_for_hd_persists_seed_and_derives(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """init with store_seed_for_hd=True SE-encrypts the seed and lets the
        HD wallet derive deterministic Ethereum accounts from it afterward."""
        # eth_keys (optional `ethereum` extra) is required only by this HD test;
        # skip just this case when it is absent rather than the whole module.
        pytest.importorskip("eth_keys")
        import hashlib

        from eth_keys import keys

        from mordred_hermes.keyvault import _bip32, _bip39
        from mordred_hermes.keyvault.ethereum import _SEED_PURPOSE, derive_ethereum_key

        backend = FakeBackend()
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
            store_seed_for_hd=True,
        )
        assert rc == 0

        # The seed is now stored SE-encrypted under bip39.seed.v1.
        root = _storage.resolve_keyvault_dir(tmp_path)
        purpose_hash_hex = hashlib.sha256(_SEED_PURPOSE.encode()).digest()[:16].hex()
        seed_envs = list((root / "ciphertexts").rglob(f"{purpose_hash_hex}/*.gcm"))
        assert len(seed_envs) == 1
        seed_env_id = seed_envs[0].stem

        # Deriving via the stored seed must match an independent derivation
        # from the same (fixed) mnemonic — proving the round-trip is correct.
        addr, path = derive_ethereum_key("default", seed_env_id, 0, backend=backend, audit_sink=_sink(), home=tmp_path)
        expected_priv = _bip32.derive_path(_bip39.mnemonic_to_seed(self.FIXED_SEED), "m/44'/60'/0'/0/0")
        expected_addr = keys.PrivateKey(expected_priv).public_key.to_checksum_address()
        assert addr == expected_addr
        assert path == "m/44'/60'/0'/0/0"

    def test_init_default_stores_seed(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Default init stores the seed SE-encrypted for later HD use."""
        import hashlib

        from mordred_hermes.keyvault.ethereum import _SEED_PURPOSE

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        root = _storage.resolve_keyvault_dir(tmp_path)
        purpose_hash_hex = hashlib.sha256(_SEED_PURPOSE.encode()).digest()[:16].hex()
        assert len(list((root / "ciphertexts").rglob(f"{purpose_hash_hex}/*.gcm"))) == 1

    def test_init_paper_only_does_not_store_seed(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Explicit paper-only init must NOT persist the seed at rest."""
        import hashlib

        from mordred_hermes.keyvault.ethereum import _SEED_PURPOSE

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
            store_seed_for_hd=False,
        )
        assert rc == 0
        root = _storage.resolve_keyvault_dir(tmp_path)
        purpose_hash_hex = hashlib.sha256(_SEED_PURPOSE.encode()).digest()[:16].hex()
        assert not list((root / "ciphertexts").rglob(f"{purpose_hash_hex}/*.gcm"))

    def test_init_store_seed_does_not_unwrap(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Storing the seed at init time is offline (wrap uses the public key).

        init must NOT perform an Enclave ECDH/unwrap, which on a real device
        would force a Touch ID / passcode prompt at the end of init.
        """
        backend = FakeBackend()
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
            store_seed_for_hd=True,
        )
        assert rc == 0
        assert not any(call[0] == "ecdh" for call in backend.calls)

    def test_corrupt_keyvault_meta_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A corrupt meta.json must surface a clean error, not a traceback."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ not valid json", encoding="utf-8")
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "corrupt" in capsys.readouterr().err.lower()

    def test_init_audit_lines_distinguish_started_from_completed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The two ``keyvault.init`` / ``decision=allow`` audit lines must be
        distinguishable. They share event + decision and only differ by
        ``reason``; the default stderr sink now appends it so an operator can
        tell the durability-barrier emit from the completion emit.
        """
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        err = capsys.readouterr().err
        assert "[audit] keyvault.init decision=allow (keyvault.init_started)" in err
        assert "[audit] keyvault.init decision=allow (keyvault.init_completed)" in err


class TestStderrAuditSink:
    """The default ``init`` / ``recover`` audit sink (``_stderr_audit_sink``)."""

    def test_appends_reason_when_present(self, capsys: pytest.CaptureFixture[str]) -> None:
        keyvault_cli._stderr_audit_sink(
            {"event": "keyvault.init", "decision": "allow", "reason": "keyvault.init_started"}
        )
        assert capsys.readouterr().err.strip() == "[audit] keyvault.init decision=allow (keyvault.init_started)"

    def test_omits_suffix_when_reason_absent(self, capsys: pytest.CaptureFixture[str]) -> None:
        keyvault_cli._stderr_audit_sink({"event": "keyvault.import_backup", "decision": "allow"})
        assert capsys.readouterr().err.strip() == "[audit] keyvault.import_backup decision=allow"


class TestGuidanceSpelling:
    """UX review 2026-06-11: failure guidance must name the working CLI form.

    Hermes 0.11 does not wire `hermes mordred ...`; pointing a user there
    after a failed ceremony strands them (the broad guard lives in
    test_ux_guidance_guard.py — these pin the two keyvault messages).
    """

    def test_reinit_guard_points_at_working_recover_command(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=["pp", "pp"]),
            surface=FakeSurface(),
            display_fn=lambda handle, surface: None,
        )
        assert rc == 1
        assert "hermes-mordred keyvault recover" in capsys.readouterr().err


class TestBlackoutGuidance:
    """Phase 4: the go-offline instructions were macOS-only (menu bar,
    `route get`) — wrong guidance on a Linux/TPM host."""

    def test_darwin_guidance_uses_macos_steps(self) -> None:
        text = keyvault_cli._blackout_guidance("darwin")
        assert "Wi-Fi" in text
        assert "route get 1.1.1.1" in text
        assert "nmcli" not in text

    def test_linux_guidance_uses_linux_steps(self) -> None:
        text = keyvault_cli._blackout_guidance("linux")
        assert "nmcli" in text
        assert "ip route" in text
        assert "menu bar" not in text

    def test_both_explain_the_safety_check_and_rerun(self) -> None:
        for platform in ("darwin", "linux"):
            text = keyvault_cli._blackout_guidance(platform)
            assert "hermes-mordred keyvault init" in text
            assert "Nothing has been written" in text


class TestListJson:
    """Phase 5 (UX review 2026-06-11): read commands need --json for scripting."""

    def test_list_json_carries_ids_and_timestamps(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        import json

        _build_keyvault(tmp_path, {"default": b"\x11" * 32})
        rc = keyvault_cli.list_keys(home=tmp_path, as_json=True)
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body == [
            {
                "key_id": "default",
                "key_id_hash": _key_id_hash("default"),
                "created_at": "2026-05-16T00:00:00Z",
            }
        ]

    def test_list_json_preserves_control_characters_as_data(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import json

        key_id = "payments\n\x1b[31mowned"
        created_at = "2026-05-16\n\x1b[2J"
        root = _build_keyvault(tmp_path, {key_id: b"\x11" * 32})
        meta = _storage.load_meta(root)
        meta["keys"][_key_id_hash(key_id)]["created_at"] = created_at
        _storage.save_meta(root, meta)

        assert keyvault_cli.list_keys(home=tmp_path, as_json=True) == 0

        [row] = json.loads(capsys.readouterr().out)
        assert row["key_id"] == key_id
        assert row["created_at"] == created_at

    def test_empty_keyvault_json_is_empty_array(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        import json

        rc = keyvault_cli.list_keys(home=tmp_path, as_json=True)
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == []

    def test_list_json_flag_is_wired(self) -> None:
        from mordred_hermes.wizard import cli

        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["keyvault", "list", "--json"])
        assert ns.json is True


class TestTerminalSeedSurface:
    """``keyvault init`` seed rendering: the numbered paper list PLUS a single
    copyable line, so transcribing into the offline digest script is not a
    24-line hand-retype (the common drop-off point)."""

    _SEED = "swing wasp snack lottery surface rhythm family head aware theme border traffic royal torch truck"

    def test_show_renders_numbered_list_and_one_line(self, capsys: pytest.CaptureFixture[str]) -> None:
        keyvault_cli.TerminalSeedSurface().show(self._SEED)
        out = capsys.readouterr().out

        # The paper backup: every word numbered, one per line.
        words = self._SEED.split()
        for index, word in enumerate(words, start=1):
            assert f"{index:2}. {word}" in out

        # The one-line form: all words on a single space-separated line, in
        # order — the BIP39 mnemonic the offline digest script accepts verbatim.
        assert "one line (for the offline verification digest):" in out
        assert " ".join(words) in out
        # The joined line is on a single physical line (no stray newline split).
        assert any(" ".join(words) in line for line in out.splitlines())

    def test_show_prints_enter_to_continue_hint_on_tty(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On an interactive TTY the operator is told they can press ENTER to
        clear the seed early and move on (the early-dismiss UX)."""
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        keyvault_cli.TerminalSeedSurface().show(self._SEED)
        out = capsys.readouterr().out
        assert "press ENTER" in out
        assert "verification-digest prompt" in out

    def test_show_omits_enter_hint_off_tty(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Off a TTY the ENTER hint is suppressed — early-dismiss is TTY-only,
        so advertising it on a piped/scripted run would mislead."""
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        keyvault_cli.TerminalSeedSurface().show(self._SEED)
        out = capsys.readouterr().out
        assert "press ENTER" not in out


class TestErrorColour:
    """Keyvault errors route through ``_term.emit_error``: red ``error:`` on a tty, plain off it.

    Mirrors the network / vault reproducers (PR #159 / #164). Uses the no-prompt
    unreadable-backup-blob path — the read fails before any prompt is consulted,
    so no scripted seed/passphrase interaction is needed for the assertion.
    """

    def test_recover_error_is_red_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        rc = keyvault_cli.recover(
            blob_path=tmp_path / "nope.mrkv",
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS]),
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "\033[31m" in err  # red `error:` label
        assert "nope.mrkv" in err

    def test_recover_error_plain_and_prefixed_off_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Off a tty the output is plain, now carrying the shared `error:` prefix.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        rc = keyvault_cli.recover(
            blob_path=tmp_path / "nope.mrkv",
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[RECOVER_SEED, RECOVER_PASS]),
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert err.startswith("error: cannot read backup blob")
        assert "\033" not in err


class TestOfflineDigestScriptLocator:
    """The init banner must point at a real copy of the offline digest tool —
    a repo ``scripts/`` checkout here, the wheel's ``_offline/`` copy after a
    plain ``pip install`` (UX review 2026-07-07: the old banner hardcoded
    ``scripts/keyvault_offline_digest.py``, a dead path for PyPI users).
    """

    def test_locates_an_existing_copy(self) -> None:
        from mordred_hermes.wizard import _keyvault_init

        path = _keyvault_init._locate_offline_digest_script()
        assert path is not None
        assert path.is_file()
        assert path.name == "keyvault_offline_digest.py"


class TestOfflineCopyHint:
    """The seed banner's copy hint must show a concrete, paste-safe copy
    command when the digest tool was located (UX review 2026-08-20: naming
    the path alone still left operators to invent the copy step), and must
    state what the offline device needs in both branches.
    """

    def test_hint_with_located_script_shows_quoted_cp_command(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard import _keyvault_init

        script = tmp_path / "keyvault_offline_digest.py"
        script.write_text("#!/usr/bin/env python3\n")
        hint = _keyvault_init._offline_copy_hint(script)
        # Both paths quoted: pasting the line verbatim must never let the
        # <your-usb> placeholder act as shell redirection.
        assert f'cp "{script}" "/Volumes/<your-usb>/"' in hint
        assert "python3 with the blake3 package" in hint

    def test_hint_without_script_still_names_requirements(self) -> None:
        from mordred_hermes.wizard import _keyvault_init

        hint = _keyvault_init._offline_copy_hint(None)
        assert "ships with hermes-mordred" in hint
        assert "python3 with the blake3 package" in hint
