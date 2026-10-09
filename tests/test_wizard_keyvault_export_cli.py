"""Portable Keyvault export CLI and end-to-end recovery tests.

Every test uses a temporary Hermes home and the software P-256 fake backend;
the real home, macOS Keychain, Secure Enclave, and TPM helper are never opened.
"""

from __future__ import annotations

import argparse
import errno
import os
import signal
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _bip39, _native_key_id, _storage, api, backup, ethereum
from mordred_hermes.keyvault import pow as keyvault_pow
from mordred_hermes.wizard import configure, keyvault_cli, keyvault_export_cli
from mordred_hermes.wizard._prompt_io import NonInteractiveAbort, _RefusingPromptIO
from mordred_hermes.wizard.cli import _setup_subparser, dispatch, main
from tests._keyvault_fakes import FakeBackend

SEED = _bip39.entropy_to_mnemonic(bytes(range(32)))
OTHER_VALID_SEED = _bip39.entropy_to_mnemonic(bytes(reversed(range(32))))
PASSPHRASE = "correct horse battery staple"
RANDOM_ETHEREUM_KEY = bytes(range(1, 33))


class RecordingPromptIO:
    """Queue-backed PromptIO test double that records masked vs visible input."""

    def __init__(self, passwords: list[str]) -> None:
        self._passwords = list(passwords)
        self.calls: list[tuple[str, str]] = []

    def ask_choice(self, label: str, choices: object, default: str) -> str:
        self.calls.append(("choice", label))
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        self.calls.append(("text", label))
        return default

    def ask_bool(self, label: str, default: bool) -> bool:
        self.calls.append(("bool", label))
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        del default
        self.calls.append(("password", label))
        return self._passwords.pop(0)


@pytest.fixture(autouse=True)
def _fast_pow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep real deterministic PoW coverage while making CLI tests fast."""

    monkeypatch.setattr(keyvault_pow, "POW_DIFFICULTY_BITS", 4)


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make accidental default-home resolution harmless as well as explicit calls."""

    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _sink(entries: list[dict[str, Any]]) -> Any:
    def append(entry: dict[str, Any]) -> None:
        entries.append(dict(entry))

    return append


def _initialize_source(
    home: Path,
    backend: FakeBackend,
    *,
    store_seed: bool,
    add_ethereum_key: bool = False,
) -> tuple[str, str | None, list[dict[str, Any]]]:
    """Create the API-equivalent of a completed normal or paper-only init."""

    entries: list[dict[str, Any]] = []
    sink = _sink(entries)
    normalized_seed = api._normalize_seed_phrase(SEED)
    pow_bytes = keyvault_pow.compute_pow(
        normalized_seed,
        difficulty_bits=keyvault_pow.POW_DIFFICULTY_BITS,
    )
    _handle, digest = api.prepare_generate(SEED, PASSPHRASE, pow_bytes)
    generated = api.generate(
        SEED,
        PASSPHRASE,
        pow_bytes,
        digest,
        backend=backend,
        audit_sink=sink,
        home=home,
    )
    if store_seed:
        ethereum.store_seed_phrase(
            generated.key_id,
            SEED,
            backend=backend,
            audit_sink=sink,
            home=home,
        )
    ethereum_envelope: str | None = None
    if add_ethereum_key:
        ethereum_envelope = api.encrypt(
            generated.key_id,
            RANDOM_ETHEREUM_KEY,
            "ethereum.key.v1",
            backend=backend,
            audit_sink=sink,
            home=home,
        )
    entries.clear()
    return generated.key_id, ethereum_envelope, entries


def _export(
    *,
    home: Path,
    backend: FakeBackend,
    output: Path,
    prompts: RecordingPromptIO,
    entries: list[dict[str, Any]] | None = None,
) -> int:
    audit_entries = entries if entries is not None else []
    return keyvault_export_cli.export_keyvault_backup(
        output_path=output,
        home=home,
        backend=backend,
        prompt_io=prompts,
        audit_sink=_sink(audit_entries),
    )


def _assert_fresh_destination(home: Path, backend: FakeBackend) -> None:
    root = _storage.resolve_keyvault_dir(home)
    if root.exists():
        assert _storage.load_meta(root)["keys"] == {}
    assert backend._keys == {}


def _file_snapshot(root: Path) -> dict[Path, bytes]:
    """Return managed file contents so export's read-only source contract is testable."""

    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


class _MissingPromptToolkitIO(RecordingPromptIO):
    """Reproduce ``PromptToolkitIO.ask_password`` without ``prompt_toolkit`` installed."""

    def ask_password(self, label: str, default: str = "") -> str:
        del label, default
        raise RuntimeError(configure._PROMPT_TOOLKIT_REQUIRED)


def _patch_meta(monkeypatch: pytest.MonkeyPatch, meta: dict[str, Any]) -> None:
    """Make the export command observe a crafted ``meta.json`` layout."""

    def load_meta(root: Path) -> dict[str, Any]:
        del root
        return dict(meta)

    monkeypatch.setattr(keyvault_export_cli._storage, "load_meta", load_meta)


def _staging_leftovers(output: Path) -> list[Path]:
    """Return the private staging hard links publication may have left behind."""

    return sorted(output.parent.glob(f".{output.name}.mordred-materialize-*"))


class TestPortableExport:
    def test_initialized_keyvault_exports_parseable_mode_0600_blob(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _key_id, _ethereum_envelope, entries = _initialize_source(
            isolated_home,
            backend,
            store_seed=True,
        )
        output = tmp_path / "keyvault-backup.mrkv"
        prompts = RecordingPromptIO([PASSPHRASE])
        source_before = _file_snapshot(isolated_home)
        native_keys_before = dict(backend._keys)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=prompts,
                entries=entries,
            )
            == 0
        )

        blob = output.read_bytes()
        assert backup.parse_header(blob).version == backup.VERSION
        assert blob.startswith(b"MRKV")
        assert os.stat(output, follow_symlinks=False).st_mode & 0o777 == 0o600
        assert prompts.calls == [("password", "Keyvault init passphrase")]
        assert any(entry.get("reason") == "keyvault.backup_exported" for entry in entries)
        assert _file_snapshot(isolated_home) == source_before
        assert backend._keys == native_keys_before
        out = capsys.readouterr().out
        assert "snapshot" in out.lower()
        assert "keyvault eth new" in out

    def test_stored_seed_rejects_wrong_init_passphrase_without_output(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "wrong-passphrase.mrkv"
        wrong_passphrase = "a secret but incorrect passphrase"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([wrong_passphrase]),
            )
            == 1
        )

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "does not match" in rendered
        assert wrong_passphrase not in rendered
        assert PASSPHRASE not in rendered
        assert not (output.exists() or output.is_symlink())

    def test_existing_file_is_never_overwritten_or_prompted_for(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "existing.mrkv"
        output.write_bytes(b"keep-me")
        prompts = RecordingPromptIO([])

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert output.read_bytes() == b"keep-me"
        assert prompts.calls == []
        assert "overwrite" in capsys.readouterr().err.lower()

    def test_existing_directory_is_never_replaced(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "backup.mrkv"
        output.mkdir()

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([]),
            )
            == 1
        )

        assert output.is_dir()
        assert "directory" in capsys.readouterr().err.lower()

    def test_existing_special_file_is_never_replaced(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "fifo.mrkv"
        os.mkfifo(output)
        prompts = RecordingPromptIO([])

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert prompts.calls == []
        err = capsys.readouterr().err
        assert "filesystem object" in err
        assert "refusing to overwrite" in err

    def test_missing_output_parent_fails_before_prompt(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        prompts = RecordingPromptIO([])
        output = tmp_path / "missing-parent" / "backup.mrkv"

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert prompts.calls == []
        assert "does not exist" in capsys.readouterr().err.lower()
        assert not output.exists()

    def test_symlink_output_parent_is_rejected_before_prompt(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        real_parent = tmp_path / "real-parent"
        real_parent.mkdir()
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        prompts = RecordingPromptIO([])
        output = linked_parent / "backup.mrkv"

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert prompts.calls == []
        err = capsys.readouterr().err
        assert "real directory" in err.lower()
        # The refusal is only actionable with the remedy attached.
        assert "resolved directory path" in err
        assert "/private/tmp" in err
        assert not (real_parent / "backup.mrkv").exists()

    def test_symlink_is_rejected_without_touching_its_target(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        target = tmp_path / "target"
        target.write_bytes(b"target-stays")
        output = tmp_path / "backup.mrkv"
        output.symlink_to(target)
        prompts = RecordingPromptIO([])

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert output.is_symlink()
        assert target.read_bytes() == b"target-stays"
        assert prompts.calls == []
        assert "symbolic link" in capsys.readouterr().err.lower()

    def test_paper_only_export_masks_seed_and_recomputes_pow(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=False)
        output = tmp_path / "paper-only.mrkv"
        prompts = RecordingPromptIO([PASSPHRASE, SEED])

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 0

        assert output.read_bytes().startswith(b"MRKV")
        assert prompts.calls == [
            ("password", "Keyvault init passphrase"),
            ("password", "24-word Seed Phrase (paper-only Keyvault)"),
        ]
        assert not any(kind == "text" for kind, _label in prompts.calls)

    def test_paper_only_invalid_seed_is_rejected_without_output(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=False)
        output = tmp_path / "invalid-paper.mrkv"
        invalid_seed = "not a valid seed phrase"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE, invalid_seed]),
            )
            == 1
        )

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "valid 24-word BIP39" in rendered
        assert invalid_seed not in rendered
        assert PASSPHRASE not in rendered
        assert not output.exists()

    def test_empty_passphrase_is_rejected_without_output(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "empty-passphrase.mrkv"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([""]),
            )
            == 1
        )

        assert "must not be empty" in capsys.readouterr().err.lower()
        assert not output.exists()

    def test_uninitialized_keyvault_is_actionable_and_does_not_prompt(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        prompts = RecordingPromptIO([])
        output = tmp_path / "uninitialized.mrkv"

        assert _export(home=isolated_home, backend=FakeBackend(), output=output, prompts=prompts) == 1

        assert prompts.calls == []
        assert "keyvault init" in capsys.readouterr().err.lower()
        assert not output.exists()

    def test_output_write_failure_leaves_no_final_file(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "unwritten.mrkv"

        def fail_write(path: Path, data: bytes) -> bool:
            del path, data
            raise OSError("simulated full disk")

        monkeypatch.setattr(keyvault_export_cli._plaintext_capture, "publish_plaintext_no_replace", fail_write)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert not (output.exists() or output.is_symlink())
        assert "written safely" in capsys.readouterr().err.lower()

    def test_output_that_appears_during_export_wins_without_replacement(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "raced.mrkv"

        def lose_publication_race(path: Path, data: bytes) -> bool:
            del path, data
            output.write_bytes(b"other-writer")
            return False

        monkeypatch.setattr(
            keyvault_export_cli._plaintext_capture,
            "publish_plaintext_no_replace",
            lose_publication_race,
        )

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert output.read_bytes() == b"other-writer"
        assert "appeared during export" in capsys.readouterr().err.lower()


class TestExportRecovery:
    def test_export_then_recover_restores_hd_seed_and_random_ethereum_key(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        source_backend = FakeBackend()
        key_id, ethereum_envelope, _entries = _initialize_source(
            isolated_home,
            source_backend,
            store_seed=True,
            add_ethereum_key=True,
        )
        assert ethereum_envelope is not None
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )

        destination = tmp_path / "fresh-hermes-home"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, PASSPHRASE]),
                audit_sink=_sink([]),
            )
            == 0
        )

        assert ethereum.list_seed_envelope_ids(key_id, home=destination)
        restored = api.decrypt(
            key_id,
            ethereum_envelope,
            "ethereum.key.v1",
            backend=destination_backend,
            audit_sink=_sink([]),
            home=destination,
        )
        assert restored == RANDOM_ETHEREUM_KEY
        assert "recovered" in capsys.readouterr().out.lower()

    def test_paper_only_export_recovers_into_fresh_keyvault(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        key_id, ethereum_envelope, _entries = _initialize_source(
            isolated_home,
            source_backend,
            store_seed=False,
            add_ethereum_key=True,
        )
        assert ethereum_envelope is not None
        output = tmp_path / "paper.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE, SEED]),
            )
            == 0
        )

        destination = tmp_path / "paper-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, PASSPHRASE]),
                audit_sink=_sink([]),
            )
            == 0
        )
        assert (
            api.decrypt(
                key_id,
                ethereum_envelope,
                "ethereum.key.v1",
                backend=destination_backend,
                audit_sink=_sink([]),
                home=destination,
            )
            == RANDOM_ETHEREUM_KEY
        )

    def test_wrong_passphrase_is_fail_closed_without_partial_destination(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        _initialize_source(isolated_home, source_backend, store_seed=True, add_ethereum_key=True)
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )

        destination = tmp_path / "wrong-passphrase-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, "wrong passphrase"]),
                audit_sink=_sink([]),
            )
            == 1
        )
        _assert_fresh_destination(destination, destination_backend)

    def test_wrong_valid_seed_is_fail_closed_without_partial_destination(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        _initialize_source(isolated_home, source_backend, store_seed=True, add_ethereum_key=True)
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )

        destination = tmp_path / "wrong-seed-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([OTHER_VALID_SEED, PASSPHRASE]),
                audit_sink=_sink([]),
            )
            == 1
        )
        _assert_fresh_destination(destination, destination_backend)

    def test_tampered_blob_is_fail_closed_without_partial_destination(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        _initialize_source(isolated_home, source_backend, store_seed=True, add_ethereum_key=True)
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )
        tampered = bytearray(output.read_bytes())
        tampered[-1] ^= 1
        output.write_bytes(tampered)
        output.chmod(0o600)

        destination = tmp_path / "tampered-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, PASSPHRASE, ""]),
                audit_sink=_sink([]),
            )
            == 1
        )
        _assert_fresh_destination(destination, destination_backend)


class TestExportParserAndSecrecy:
    def test_help_lists_export(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["keyvault", "--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "export" in out
        assert "--output" not in out  # option is shown by `keyvault export --help`

        with pytest.raises(SystemExit) as export_exc:
            main(["keyvault", "export", "--help"])
        assert export_exc.value.code == 0
        export_help = capsys.readouterr().out
        assert "--output" in export_help
        assert "0600" in export_help

    def test_standalone_and_host_use_the_same_export_parser_surface(self, tmp_path: Path) -> None:
        standalone = argparse.ArgumentParser(prog="hermes-mordred")
        _setup_subparser(standalone, required=False)
        standalone_ns = standalone.parse_args(["keyvault", "export", "--output", str(tmp_path / "a.mrkv")])

        host = argparse.ArgumentParser(prog="hermes")
        host_sub = host.add_subparsers(dest="command", required=True)
        mordred = host_sub.add_parser("mordred")
        _setup_subparser(mordred)
        host_ns = host.parse_args(["mordred", "keyvault", "export", "--output", str(tmp_path / "a.mrkv")])

        assert standalone_ns.keyvault_command == host_ns.keyvault_command == "export"
        assert standalone_ns.output == host_ns.output
        assert standalone_ns.func is host_ns.func

    def test_cli_adapter_passes_output_path_without_subprocess(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen: list[Path] = []

        def fake_export(*, output_path: Path) -> int:
            seen.append(output_path)
            return 0

        monkeypatch.setattr(keyvault_export_cli, "export_keyvault_backup", fake_export)
        output = tmp_path / "adapter.mrkv"

        assert keyvault_export_cli.cli_export(argparse.Namespace(output=str(output))) == 0
        assert seen == [output]

    def test_secrets_and_blob_never_reach_output_or_audit(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True, add_ethereum_key=True)
        entries: list[dict[str, Any]] = []
        output = tmp_path / "redacted.mrkv"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
                entries=entries,
            )
            == 0
        )

        blob = output.read_bytes()
        captured = capsys.readouterr()
        rendered = captured.out + captured.err + repr(entries)
        assert PASSPHRASE not in rendered
        assert SEED not in rendered
        assert blob.hex() not in rendered
        assert repr(blob) not in rendered
        assert all("passphrase" not in repr(entry).lower() for entry in entries)
        assert all("seed" not in repr(entry).lower() for entry in entries)

    def test_unexpected_secret_bearing_exception_is_redacted(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "never-created.mrkv"
        blob_marker = "MRKV-secret-body-marker"

        def explode(*args: object, **kwargs: object) -> bytes:
            del args, kwargs
            raise RuntimeError(f"{PASSPHRASE} {SEED} {blob_marker}")

        monkeypatch.setattr(api, "export_backup", explode)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert PASSPHRASE not in rendered
        assert SEED not in rendered
        assert blob_marker not in rendered
        assert "failed safely" in rendered.lower()
        assert not (output.exists() or output.is_symlink())


class TestPublicationFailureModes:
    """Publication errnos must be reported for what they actually did to disk."""

    def test_directory_sync_failure_reports_the_complete_published_file(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "sync-fail.mrkv"

        def unsyncable(directory: Path) -> None:
            del directory
            raise OSError(errno.EIO, "simulated directory-sync failure")

        # publish_plaintext_no_replace syncs the parent AFTER os.link commits,
        # so this raises with a complete final file already on disk.
        monkeypatch.setattr(keyvault_export_cli._plaintext_capture, "_sync_directory", unsyncable)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        blob = output.read_bytes()
        assert blob.startswith(b"MRKV")
        assert backup.parse_header(blob).version == backup.VERSION
        assert os.stat(output, follow_symlinks=False).st_mode & 0o777 == 0o600
        assert _staging_leftovers(output)
        err = capsys.readouterr().err
        assert str(output) in err
        assert "durability or cleanup step after publication failed" in err
        assert "mordred-materialize" in err
        assert "written safely" not in err

    def test_staging_cleanup_failure_after_successful_sync_is_still_reported_as_published(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The other post-link sub-case: the directory sync succeeded, only the staging cleanup's sync failed."""

        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "cleanup-fail.mrkv"
        real_sync = keyvault_export_cli._plaintext_capture._sync_directory
        calls = {"n": 0}

        def second_sync_fails(directory: Path) -> None:
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(errno.EIO, "simulated staging-cleanup sync failure")
            real_sync(directory)

        monkeypatch.setattr(keyvault_export_cli._plaintext_capture, "_sync_directory", second_sync_fails)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert calls["n"] == 2
        blob = output.read_bytes()
        assert blob.startswith(b"MRKV")
        assert os.stat(output, follow_symlinks=False).st_mode & 0o777 == 0o600
        # The staging name was unlinked before its directory sync raised.
        assert _staging_leftovers(output) == []
        err = capsys.readouterr().err
        assert "durability or cleanup step after publication failed" in err
        assert "written safely" not in err

    def test_hard_link_unsupported_destination_names_the_filesystem_limit(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "no-hardlinks.mrkv"
        real_link = os.link

        def refuse_link(src: Any, dst: Any, **kwargs: Any) -> None:
            if Path(dst) != output:
                real_link(src, dst, **kwargs)
                return
            # Mirror CPython: two-path syscalls populate both filename attributes.
            raise OSError(errno.EPERM, "hard links are not supported on this filesystem", str(src), None, str(dst))

        monkeypatch.setattr(os, "link", refuse_link)
        assert os.link is not real_link

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert not (output.exists() or output.is_symlink())
        assert _staging_leftovers(output) == []
        err = capsys.readouterr().err
        assert "does not support" in err
        assert "hard links" in err
        assert "written safely" not in err

    def test_eperm_from_staging_creation_keeps_the_generic_guidance(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """EPERM raised before ``os.link`` (immutable/TCC-protected dir) is not a hard-link limit."""

        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "locked-dir.mrkv"

        def refuse_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
            del args, kwargs
            raise OSError(errno.EPERM, "Operation not permitted", str(output.parent))

        monkeypatch.setattr(keyvault_export_cli._plaintext_capture.tempfile, "mkstemp", refuse_mkstemp)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert not (output.exists() or output.is_symlink())
        assert _staging_leftovers(output) == []
        err = capsys.readouterr().err
        assert "check directory permissions and free space" in err
        assert "hard links" not in err

    def test_vanished_output_directory_keeps_its_own_guidance(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "vanished.mrkv"

        def vanished(path: Path, data: bytes) -> bool:
            del path, data
            raise OSError(errno.ENOENT, "no such file or directory")

        monkeypatch.setattr(keyvault_export_cli._plaintext_capture, "publish_plaintext_no_replace", vanished)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert not output.exists()
        assert "directory disappeared" in capsys.readouterr().err


class TestPromptDependencyAndNonInteractive:
    def test_missing_prompt_toolkit_keeps_its_install_hint(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "no-prompt-toolkit.mrkv"

        rc = _export(
            home=isolated_home,
            backend=backend,
            output=output,
            prompts=_MissingPromptToolkitIO([]),
        )

        assert rc != 0
        err = capsys.readouterr().err
        assert "pip install prompt_toolkit" in err
        assert configure._PROMPT_TOOLKIT_REQUIRED in err
        assert "failed safely" not in err
        assert not output.exists()

    def test_non_interactive_abort_is_not_redacted_and_dispatches_as_usage_error(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "non-interactive.mrkv"

        with pytest.raises(NonInteractiveAbort):
            keyvault_export_cli.export_keyvault_backup(
                output_path=output,
                home=isolated_home,
                backend=backend,
                prompt_io=_RefusingPromptIO(),
                audit_sink=_sink([]),
            )
        assert not output.exists()

        def refuse(*, output_path: Path) -> int:
            del output_path
            raise NonInteractiveAbort("--non-interactive set but prompt required: 'Keyvault init passphrase'")

        monkeypatch.setattr(keyvault_export_cli, "export_keyvault_backup", refuse)
        namespace = argparse.Namespace(func=keyvault_export_cli.cli_export, output=str(output))
        assert dispatch(namespace) == 2


class TestKeyvaultStateGuards:
    """Every `_single_key_id` refusal must be actionable and output-free."""

    def _refuse(
        self,
        home: Path,
        tmp_path: Path,
        name: str,
    ) -> tuple[int, Path, RecordingPromptIO]:
        output = tmp_path / f"{name}.mrkv"
        prompts = RecordingPromptIO([])
        rc = _export(home=home, backend=FakeBackend(), output=output, prompts=prompts)
        return rc, output, prompts

    def test_reset_in_progress_points_at_finishing_reset(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _initialize_source(isolated_home, FakeBackend(), store_seed=True)

        def in_reset(root: Path) -> None:
            del root
            raise _storage.KeyvaultResetInProgressError("reset journal present")

        monkeypatch.setattr(keyvault_export_cli._storage, "assert_keyvault_active", in_reset)

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "reset-in-progress")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        assert "reset is incomplete" in capsys.readouterr().err

    def test_corrupt_meta_points_at_a_verified_backup(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _initialize_source(isolated_home, FakeBackend(), store_seed=True)

        def corrupt(root: Path) -> dict[str, Any]:
            del root
            raise _storage.KeyvaultCorruptError("meta.json is not valid JSON")

        monkeypatch.setattr(keyvault_export_cli._storage, "load_meta", corrupt)

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "corrupt-meta")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        assert "metadata is corrupt" in capsys.readouterr().err

    def test_unreadable_metadata_points_at_permissions(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _initialize_source(isolated_home, FakeBackend(), store_seed=True)

        def unreadable(root: Path) -> dict[str, Any]:
            del root
            raise PermissionError(errno.EACCES, "permission denied")

        monkeypatch.setattr(keyvault_export_cli._storage, "load_meta", unreadable)

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "unreadable-meta")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        assert "owner-only permissions" in capsys.readouterr().err

    def test_pending_native_key_points_at_reset(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        key_id, _envelope, _entries = _initialize_source(isolated_home, FakeBackend(), store_seed=True)
        _patch_meta(
            monkeypatch,
            {
                "version": 1,
                "keys": {},
                _native_key_id.PENDING_NATIVE_KEY_FIELD: {"key_id": key_id, "native_key_id": "x"},
            },
        )

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "pending-native-key")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        assert "provisioning is incomplete" in capsys.readouterr().err

    def test_zero_keys_gives_the_uninitialized_guidance(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _initialize_source(isolated_home, FakeBackend(), store_seed=True)
        _patch_meta(monkeypatch, {"version": 1, "keys": {}})

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "zero-keys")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        err = capsys.readouterr().err
        assert "keyvault init" in err
        assert "reset" not in err.lower()

    def test_multiple_keys_names_the_api_instead_of_recommending_reset(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _initialize_source(isolated_home, FakeBackend(), store_seed=True)
        _patch_meta(
            monkeypatch,
            {"version": 1, "keys": {"aa" * 8: {"key_id": "one"}, "bb" * 8: {"key_id": "two"}}},
        )

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "multi-key")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        err = capsys.readouterr().err
        assert "exactly one initialized Keyvault key" in err
        assert "this Keyvault has 2" in err
        assert "export_backup(" in err
        assert "reset" not in err.lower()

    def test_invalid_key_row_shapes_are_rejected(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _initialize_source(isolated_home, FakeBackend(), store_seed=True)

        for index, keys in enumerate(({"aa" * 8: "not-a-mapping"}, {7: {"key_id": "one"}})):
            _patch_meta(monkeypatch, {"version": 1, "keys": keys})

            rc, output, prompts = self._refuse(isolated_home, tmp_path, f"invalid-row-{index}")

            assert (rc, prompts.calls, output.exists()) == (1, [], False)
            assert "invalid key row" in capsys.readouterr().err

    def test_invalid_key_id_is_rejected(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _initialize_source(isolated_home, FakeBackend(), store_seed=True)
        _patch_meta(monkeypatch, {"version": 1, "keys": {"aa" * 8: {"key_id": ""}}})

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "invalid-key-id")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        assert "invalid key id" in capsys.readouterr().err

    def test_key_hash_mismatch_is_rejected(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        key_id, _envelope, _entries = _initialize_source(isolated_home, FakeBackend(), store_seed=True)
        _patch_meta(monkeypatch, {"version": 1, "keys": {"00" * 16: {"key_id": key_id}}})

        rc, output, prompts = self._refuse(isolated_home, tmp_path, "hash-mismatch")

        assert (rc, prompts.calls, output.exists()) == (1, [], False)
        assert "does not match its key id" in capsys.readouterr().err


class TestBackupBlobErrorMap:
    """Known `api.export_backup` failures keep their specific, redacted guidance."""

    def _export_raising(
        self,
        home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        exc: Exception,
        name: str,
    ) -> tuple[int, Path]:
        backend = FakeBackend()
        _initialize_source(home, backend, store_seed=True)
        output = tmp_path / f"{name}.mrkv"

        def explode(*args: object, **kwargs: object) -> bytes:
            del args, kwargs
            raise exc

        monkeypatch.setattr(api, "export_backup", explode)
        rc = _export(home=home, backend=backend, output=output, prompts=RecordingPromptIO([PASSPHRASE]))
        return rc, output

    def test_invalid_tag_reports_failed_authentication(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cryptography.exceptions import InvalidTag

        rc, output = self._export_raising(isolated_home, tmp_path, monkeypatch, InvalidTag(), "invalid-tag")

        assert (rc, output.exists()) == (1, False)
        assert "failed authentication" in capsys.readouterr().err

    def test_backup_corrupt_points_at_verify_digest(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        rc, output = self._export_raising(
            isolated_home,
            tmp_path,
            monkeypatch,
            backup.BackupCorrupt("truncated envelope"),
            "backup-corrupt",
        )

        assert (rc, output.exists()) == (1, False)
        err = capsys.readouterr().err
        assert "verify-digest" in err
        assert "truncated envelope" not in err

    def test_wrap_error_points_at_the_device_key(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapError

        rc, output = self._export_raising(
            isolated_home,
            tmp_path,
            monkeypatch,
            WrapError("enclave declined"),
            "wrap-error",
        )

        assert (rc, output.exists()) == (1, False)
        err = capsys.readouterr().err
        assert "authorize the device key" in err
        assert "enclave declined" not in err

    def test_value_error_points_at_the_recovery_material(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        rc, output = self._export_raising(
            isolated_home,
            tmp_path,
            monkeypatch,
            ValueError(PASSPHRASE),
            "value-error",
        )

        assert (rc, output.exists()) == (1, False)
        err = capsys.readouterr().err
        assert "could not verify the Keyvault recovery material" in err
        assert PASSPHRASE not in err


class TestPublishedOutputProbe:
    """The post-failure probe must recognise only this export's own complete file."""

    def test_exact_private_file_matches_and_different_bytes_do_not(self, tmp_path: Path) -> None:
        path = tmp_path / "probe.mrkv"
        path.write_bytes(b"MRKV-body")
        path.chmod(0o600)

        assert keyvault_export_cli._is_complete_published_output(path, b"MRKV-body")
        assert not keyvault_export_cli._is_complete_published_output(path, b"MRKV-bodX")
        assert not keyvault_export_cli._is_complete_published_output(path, b"MRKV-body-longer")
        assert not keyvault_export_cli._is_complete_published_output(path, b"MRKV-bod")

    def test_absent_loose_moded_and_unreadable_objects_are_not_ours(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assert not keyvault_export_cli._is_complete_published_output(tmp_path / "absent.mrkv", b"x")

        loose = tmp_path / "loose.mrkv"
        loose.write_bytes(b"x")
        loose.chmod(0o644)
        assert not keyvault_export_cli._is_complete_published_output(loose, b"x")

        # A symlink to a byte-identical private file is still not our output:
        # the probe opens O_NOFOLLOW so the link itself is what gets rejected.
        target = tmp_path / "target.mrkv"
        target.write_bytes(b"x")
        target.chmod(0o600)
        link = tmp_path / "link.mrkv"
        link.symlink_to(target)
        assert keyvault_export_cli._is_complete_published_output(target, b"x")
        assert not keyvault_export_cli._is_complete_published_output(link, b"x")

        # A FIFO raced into the output pathname must be rejected, not waited on:
        # the probe opens O_NONBLOCK so this returns instead of hanging forever.
        # The alarm turns a regression of that flag into a failure, not a hang.
        fifo = tmp_path / "fifo.mrkv"
        os.mkfifo(fifo, 0o600)

        def _wedged(signum: int, frame: object) -> None:
            del signum, frame
            raise TimeoutError("probe blocked on a FIFO: O_NONBLOCK regressed")

        previous = signal.signal(signal.SIGALRM, _wedged)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            assert not keyvault_export_cli._is_complete_published_output(fifo, b"x")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous)

        private = tmp_path / "private.mrkv"
        private.write_bytes(b"x")
        private.chmod(0o600)

        def unreadable(fd: int, size: int) -> bytes:
            del fd, size
            raise OSError(errno.EIO, "simulated read failure")

        with monkeypatch.context() as scoped:
            scoped.setattr(os, "read", unreadable)
            assert not keyvault_export_cli._is_complete_published_output(private, b"x")

        # A byte-identical private file owned by someone else is not ours either;
        # the euid seam is what makes the ownership check testable without root.
        with monkeypatch.context() as scoped:
            scoped.setattr(keyvault_export_cli, "_geteuid", lambda: os.geteuid() + 1)
            assert not keyvault_export_cli._is_complete_published_output(private, b"x")
        assert keyvault_export_cli._is_complete_published_output(private, b"x")
