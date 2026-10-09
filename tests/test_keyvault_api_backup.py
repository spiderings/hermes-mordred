"""Phase 4 PR4 step-E RED — ``api.export_backup`` / ``api.import_backup``.

Implementation lands in step-E GREEN. The ciphertext-rewrap manifest
contract is defined in SPEC.md §"export_backup / import_backup
(ciphertext-rewrap manifest, codex BLOCKER #1)":

- ``export_backup`` walks every ``.gcm`` envelope, unwraps each DEK,
  re-encrypts the plaintext under a *portable* manifest AAD (no per-device
  MRKW prefix), packs a JSON manifest, and wraps it in a PR2 ``MRKV`` blob
  whose passphrase-derived KEK protects the manifest (and the DEKs it
  carries) at rest.
- ``import_backup`` verifies the embedded verification digest BEFORE any
  KDF / decryption (PR2 verify-before-decrypt), then on the destination
  device generates a fresh Enclave key, re-wraps each DEK against it, and
  reconstructs every MREN envelope.

Enclave authorization is abstracted by the ``FakeBackend`` reused from
``test_keyvault_wrap`` — a software P-256 keypair store. Two distinct
``FakeBackend`` instances + two ``home`` roots model two physical
devices, which is the only honest way to exercise cross-machine
recovery: the source Enclave key is non-exportable, so the destination
must reconstruct everything from the passphrase-protected manifest.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import threading
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _native_key_id, _secret_ops, _storage, api, backup
from mordred_hermes.keyvault.backup import BackupCorrupt, BackupImportConflict
from mordred_hermes.keyvault.digest import VerificationDigestMismatch
from mordred_hermes.keyvault.recovery import RecoveryDigestMismatch

# Software Enclave stand-in — see module docstring of test_keyvault_wrap.
from tests._keyvault_fakes import FakeBackend

# Canonical inputs. ASCII so the split-normalization layer is a no-op and
# the digest is stable regardless of NFKD behavior.
SEED = "test seed phrase one two three four"
PASSPHRASE = "correct horse battery staple"
POW = bytes(range(32))


# ----------------------------- fixtures -----------------------------


@pytest.fixture
def audit() -> tuple[list[dict[str, Any]], Any]:
    log: list[dict[str, Any]] = []

    def sink(entry: dict[str, Any]) -> None:
        log.append(dict(entry))

    return log, sink


def _init_device(home: Path, backend: FakeBackend, sink: Any) -> str:
    """Generate a keyvault key on a device rooted at ``home``."""
    _handle, digest = api.prepare_generate(SEED, PASSPHRASE, POW)
    result = api.generate(SEED, PASSPHRASE, POW, digest, backend=backend, audit_sink=sink, home=home)
    return result.key_id


def _key_id_hash_hex(key_id: str) -> str:
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


# ----------------------------- export blob shape -----------------------------


class TestExportBlob:
    def test_export_returns_parseable_mrkv_blob(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)

        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend,
            audit_sink=sink,
            home=home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        assert blob[:4] == b"MRKV"
        # The PR2 backup parser must accept it without complaint.
        parsed = backup.parse_header(blob)
        assert parsed.version == backup.VERSION

    def test_export_embeds_commit_verification_digest(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        """The blob's embedded digest is the one written to
        ``digests/<kid>.commit`` at generate time — that is what
        ``import_backup`` recomputes and checks against."""
        _log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)

        commit_path = home / "mordred" / "keyvault" / "digests" / f"{_key_id_hash_hex(key_id)}.commit"
        commit_digest = _storage.safe_read(commit_path)

        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend,
            audit_sink=sink,
            home=home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )
        assert backup.parse_header(blob).verification_digest == commit_digest

    def test_export_emits_backup_exported(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        log.clear()

        api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend,
            audit_sink=sink,
            home=home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        exported = [e for e in log if e.get("reason") == "keyvault.backup_exported"]
        assert len(exported) == 1

    def test_export_audit_fields_match_policy(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        """POLICY.md #24: event=keyvault.backup_export, decision=allow,
        key_id_hash, blob_version=1, kdf_id=1, envelope_count."""
        log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        api.encrypt(key_id, b"one", "alpha", backend=backend, audit_sink=sink, home=home)
        api.encrypt(key_id, b"two", "beta", backend=backend, audit_sink=sink, home=home)
        log.clear()

        api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend,
            audit_sink=sink,
            home=home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        entry = next(e for e in log if e.get("reason") == "keyvault.backup_exported")
        assert entry["event"] == "keyvault.backup_export"
        assert entry["decision"] == "allow"
        assert entry["blob_version"] == 1
        assert entry["kdf_id"] == 1
        assert entry["envelope_count"] == 2
        # key_id_hash is the 16-char audit hex prefix, never the cleartext id.
        assert entry["key_id_hash"] and key_id not in str(entry["key_id_hash"])

    def test_export_empty_keyvault_envelope_count_zero(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        log.clear()

        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend,
            audit_sink=sink,
            home=home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        assert blob[:4] == b"MRKV"
        entry = next(e for e in log if e.get("reason") == "keyvault.backup_exported")
        assert entry["envelope_count"] == 0

    def test_export_sink_failure_on_backup_exported_is_suppressed(self, tmp_path: Path) -> None:
        """POLICY.md #24: success-path emit suppressed via
        contextlib.suppress — the blob is already in hand."""
        backend = FakeBackend()
        home = tmp_path / "deviceA"

        def init_sink(_entry: dict[str, Any]) -> None:
            return None

        _handle, digest = api.prepare_generate(SEED, PASSPHRASE, POW)
        result = api.generate(SEED, PASSPHRASE, POW, digest, backend=backend, audit_sink=init_sink, home=home)

        def failing_sink(entry: dict[str, Any]) -> None:
            if entry.get("reason") == "keyvault.backup_exported":
                raise RuntimeError("audit log disk full")

        blob = api.export_backup(
            result.key_id,
            PASSPHRASE,
            backend=backend,
            audit_sink=failing_sink,
            home=home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )
        assert blob[:4] == b"MRKV"

    def test_export_rejects_passphrase_not_bound_to_commit_before_unwrap(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        api.encrypt(key_id, b"secret", "vault", backend=backend, audit_sink=sink, home=home)
        backend.calls.clear()
        log.clear()

        with pytest.raises(VerificationDigestMismatch, match="export refused"):
            api.export_backup(
                key_id,
                "one-character-typo",
                backend=backend,
                audit_sink=sink,
                home=home,
                seed_phrase=SEED,
                pow_bytes=POW,
            )

        assert backend.calls == [], "a bad export passphrase must reject before any Enclave unwrap"
        assert not any(entry.get("reason") == "keyvault.backup_exported" for entry in log)

    def test_paper_only_export_requires_recovery_material(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        api.encrypt(key_id, b"must-not-be-opened", "secret", backend=backend, audit_sink=sink, home=home)
        backend.calls.clear()

        with pytest.raises(ValueError, match="paper-only vault"):
            api.export_backup(
                key_id,
                PASSPHRASE,
                backend=backend,
                audit_sink=sink,
                home=home,
            )
        assert backend.calls == [], "paper-only detection must happen before an unrelated envelope unwrap"

    def test_stored_seed_is_verified_before_the_general_manifest_walk(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        _log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        api.encrypt(
            key_id,
            SEED.encode(),
            "bip39.seed.v1",
            backend=backend,
            audit_sink=sink,
            home=home,
        )
        unrelated_id = api.encrypt(
            key_id,
            b"unrelated",
            "secret",  # its hash sorts before bip39.seed.v1
            backend=backend,
            audit_sink=sink,
            home=home,
        )
        root = _storage.resolve_keyvault_dir(home)
        unrelated_path = _secret_ops._envelope_path_for(root, key_id, "secret", unrelated_id)
        unrelated_path.write_bytes(b"corrupt envelope that must not be read")

        from mordred_hermes.keyvault import pow as keyvault_pow

        monkeypatch.setattr(keyvault_pow, "compute_pow", lambda *a, **k: POW)
        backend.calls.clear()
        with pytest.raises(VerificationDigestMismatch, match="passphrase does not match"):
            api.export_backup(
                key_id,
                "wrong-passphrase",
                backend=backend,
                audit_sink=sink,
                home=home,
            )

        native_key_id = _native_key_id.scoped_native_key_id(root, key_id)
        assert backend.calls == [("ecdh", native_key_id)], "only the known recovery-seed envelope should be unwrapped"


# ----------------------------- cross-machine roundtrip -----------------------------


class TestCrossMachineRoundtrip:
    def test_single_envelope_roundtrip(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        # Device A: generate, encrypt, export.
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        eid = api.encrypt(key_id, b"the-secret-payload", "vault", backend=backend_a, audit_sink=sink, home=home_a)
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        # Device B: a fresh Enclave + a fresh home — the source key is gone.
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )
        assert imported == key_id

        recovered = api.decrypt(imported, eid, "vault", backend=backend_b, audit_sink=sink, home=home_b)
        assert recovered == b"the-secret-payload"

    def test_multiple_purposes_roundtrip(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        items = {
            "alpha": b"payload-alpha",
            "beta": b"payload-beta-longer-value",
            "gamma": b"",
        }
        eids = {
            purpose: api.encrypt(key_id, pt, purpose, backend=backend_a, audit_sink=sink, home=home_a)
            for purpose, pt in items.items()
        }
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )

        for purpose, expected in items.items():
            got = api.decrypt(imported, eids[purpose], purpose, backend=backend_b, audit_sink=sink, home=home_b)
            assert got == expected

    def test_empty_keyvault_roundtrip_key_usable_after_import(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        """Exporting a keyvault with zero envelopes still transports the
        key; the destination can encrypt + decrypt afterwards."""
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )

        eid = api.encrypt(imported, b"post-import", "fresh", backend=backend_b, audit_sink=sink, home=home_b)
        assert api.decrypt(imported, eid, "fresh", backend=backend_b, audit_sink=sink, home=home_b) == b"post-import"

    def test_import_refuses_stale_ciphertext_residue_without_mutation(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        """An importer cannot prove stale-looking residue is disposable."""
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        api.encrypt(key_id, b"live-secret", "vault", backend=backend_a, audit_sink=sink, home=home_a)
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        # Device B: pre-seed the residue — an envelope under this key id's
        # tree, wrapped by a key that no longer exists anywhere.
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        root_b = home_b / "mordred" / "keyvault"
        _storage.ensure_layout(root_b)
        stale_dir = root_b / "ciphertexts" / _key_id_hash_hex(key_id) / ("0" * 32)
        stale_dir.mkdir(parents=True, mode=0o700)
        stale_path = stale_dir / "deadbeef.gcm"
        stale_path.write_bytes(b"MREN-garbage-wrapped-by-a-destroyed-key")

        with pytest.raises(BackupImportConflict, match="fresh keyvault"):
            api.import_backup(
                blob,
                PASSPHRASE,
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )

        assert stale_path.read_bytes() == b"MREN-garbage-wrapped-by-a-destroyed-key"
        assert backend_b.calls == []

    def test_same_key_id_in_different_backend_namespace_cannot_erase_live_vault(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit

        source_home = tmp_path / "source"
        source_backend = FakeBackend()
        source_key_id = _init_device(source_home, source_backend, sink)
        api.encrypt(
            source_key_id,
            b"backup-secret",
            "vault",
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
        )
        blob = api.export_backup(
            source_key_id,
            PASSPHRASE,
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        live_home = tmp_path / "live"
        live_backend = FakeBackend()
        live_key_id = _init_device(live_home, live_backend, sink)
        live_envelope = api.encrypt(
            live_key_id,
            b"must-survive",
            "live",
            backend=live_backend,
            audit_sink=sink,
            home=live_home,
        )
        live_path = _secret_ops._envelope_path_for(
            _storage.resolve_keyvault_dir(live_home),
            live_key_id,
            "live",
            live_envelope,
        )
        before = live_path.read_bytes()

        empty_import_backend = FakeBackend()
        with pytest.raises(BackupImportConflict, match="existing key metadata"):
            api.import_backup(
                blob,
                PASSPHRASE,
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=empty_import_backend,
                audit_sink=sink,
                home=live_home,
            )

        assert empty_import_backend.calls == []
        assert live_path.read_bytes() == before
        assert (
            api.decrypt(
                live_key_id,
                live_envelope,
                "live",
                backend=live_backend,
                audit_sink=sink,
                home=live_home,
            )
            == b"must-survive"
        )

    def test_import_of_different_key_id_still_respects_v1_single_key_invariant(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        source_home = tmp_path / "source"
        source_backend = FakeBackend()
        handle, digest = api.prepare_generate(SEED, PASSPHRASE, POW)
        source = api.confirm_generate(
            handle,
            digest,
            key_id="other-key",
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
        )
        blob = api.export_backup(
            source.key_id,
            PASSPHRASE,
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        live_home = tmp_path / "live"
        live_backend = FakeBackend()
        _init_device(live_home, live_backend, sink)
        import_backend = FakeBackend()
        with pytest.raises(BackupImportConflict, match="existing key metadata"):
            api.import_backup(
                blob,
                PASSPHRASE,
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=import_backend,
                audit_sink=sink,
                home=live_home,
            )
        assert import_backend.calls == []

    def test_concurrent_imports_generate_exactly_one_destination_key(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        _log, sink = audit
        source_home = tmp_path / "source"
        source_backend = FakeBackend()
        key_id = _init_device(source_home, source_backend, sink)
        envelope_id = api.encrypt(
            key_id,
            b"one-winner",
            "vault",
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
        )
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )
        parsed = backup.parse_header(blob)
        manifest_json = backup.decrypt_body(parsed, PASSPHRASE)
        barrier = threading.Barrier(2)

        def synchronized_recovery(*_args: object, **_kwargs: object) -> bytes:
            barrier.wait()
            return manifest_json

        monkeypatch.setattr(_secret_ops.recovery, "import_backup", synchronized_recovery)
        destination = tmp_path / "destination"
        backends = [FakeBackend(), FakeBackend()]
        outcomes: list[tuple[str, FakeBackend | BaseException]] = []

        def run_import(backend: FakeBackend) -> None:
            try:
                api.import_backup(
                    blob,
                    PASSPHRASE,
                    seed_phrase=SEED,
                    pow_bytes=POW,
                    backend=backend,
                    audit_sink=sink,
                    home=destination,
                )
                outcomes.append(("ok", backend))
            except BaseException as exc:
                outcomes.append(("error", exc))

        threads = [threading.Thread(target=run_import, args=(backend,)) for backend in backends]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert [kind for kind, _value in outcomes].count("ok") == 1
        errors = [value for kind, value in outcomes if kind == "error"]
        assert len(errors) == 1
        assert isinstance(errors[0], BackupImportConflict)
        loser = next(backend for backend in backends if not backend.calls)
        winner = next(backend for backend in backends if backend.calls)
        assert loser.calls == []
        assert (
            api.decrypt(
                key_id,
                envelope_id,
                "vault",
                backend=winner,
                audit_sink=sink,
                home=destination,
            )
            == b"one-winner"
        )

    def test_encrypt_cannot_publish_with_import_key_that_is_rolled_back(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        """The native key is provisional until import's meta/commit point.

        Hold import immediately after native-key generation, start encrypt
        against that same backend/home, then force the import commit to fail.
        Encrypt must wait on the lifecycle/keyvault transaction locks and,
        after rollback, reject the missing authoritative row without ever
        wrapping or writing an orphan.
        """
        _log, sink = audit
        source_home = tmp_path / "source"
        source_backend = FakeBackend()
        key_id = _init_device(source_home, source_backend, sink)
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        generated = threading.Barrier(2)
        release_generation = threading.Barrier(2)

        class PausingBackend(FakeBackend):
            def generate_enclave_key(self, generated_key_id: str, *, unattended: bool | None = None) -> bytes:
                public = super().generate_enclave_key(generated_key_id, unattended=unattended)
                generated.wait(timeout=5)
                release_generation.wait(timeout=5)
                return public

        destination_backend = PausingBackend()
        destination = tmp_path / "destination"
        real_atomic_write = _storage.atomic_write

        def fail_import_commit(path: Path, data: bytes) -> None:
            if threading.current_thread().name == "failing-import" and path.suffix == ".commit":
                raise OSError("forced import commit failure")
            real_atomic_write(path, data)

        monkeypatch.setattr(_storage, "atomic_write", fail_import_commit)

        encrypt_started = threading.Event()
        encrypt_finished = threading.Event()
        import_errors: list[BaseException] = []
        encrypt_errors: list[BaseException] = []

        def run_import() -> None:
            try:
                api.import_backup(
                    blob,
                    PASSPHRASE,
                    seed_phrase=SEED,
                    pow_bytes=POW,
                    backend=destination_backend,
                    audit_sink=sink,
                    home=destination,
                )
            except BaseException as exc:
                import_errors.append(exc)

        def run_encrypt() -> None:
            encrypt_started.set()
            try:
                api.encrypt(
                    key_id,
                    b"must-not-be-orphaned",
                    "vault",
                    backend=destination_backend,
                    audit_sink=sink,
                    home=destination,
                )
            except BaseException as exc:
                encrypt_errors.append(exc)
            finally:
                encrypt_finished.set()

        import_thread = threading.Thread(target=run_import, name="failing-import")
        import_thread.start()
        generated.wait(timeout=5)

        encrypt_thread = threading.Thread(target=run_encrypt, name="racing-encrypt")
        encrypt_thread.start()
        assert encrypt_started.wait(timeout=5)
        # ensure_layout now joins the same stable lifecycle critical section,
        # so encrypt can block before it reaches the inner keyvault lock.
        assert not encrypt_finished.wait(timeout=0.1)
        assert not any(operation == "get_pub" for operation, _key in destination_backend.calls)

        release_generation.wait(timeout=5)
        import_thread.join(timeout=5)
        encrypt_thread.join(timeout=5)

        assert not import_thread.is_alive()
        assert not encrypt_thread.is_alive()
        assert len(import_errors) == 1
        assert isinstance(import_errors[0], OSError)
        assert len(encrypt_errors) == 1
        assert isinstance(encrypt_errors[0], _storage.KeyvaultCorruptError)
        assert not any(operation == "get_pub" for operation, _key in destination_backend.calls)
        destination_root = _storage.resolve_keyvault_dir(destination)
        assert (
            "delete",
            _native_key_id.scoped_native_key_id(destination_root, key_id),
        ) in destination_backend.calls
        cipher_root = _storage.resolve_keyvault_dir(destination) / "ciphertexts"
        assert not list(cipher_root.rglob("*.gcm"))

    def test_export_cannot_observe_import_digest_that_is_rolled_back(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        """Digest, metadata, and native key must be one export snapshot.

        Import writes its digest before the authoritative meta row.  Pause
        immediately after that provisional digest reaches disk, start an
        export, then make import fail and roll back.  Export must wait for the
        provisioning lock and reject the rolled-back key without returning a
        blob or emitting a success audit event.
        """
        log, sink = audit
        source_home = tmp_path / "source"
        source_backend = FakeBackend()
        key_id = _init_device(source_home, source_backend, sink)
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )
        log.clear()

        destination = tmp_path / "destination"
        destination_backend = FakeBackend()
        commit_written = threading.Event()
        release_commit = threading.Event()
        real_atomic_write = _storage.atomic_write

        def fail_after_provisional_commit(path: Path, data: bytes) -> None:
            real_atomic_write(path, data)
            if threading.current_thread().name == "failing-import" and path.suffix == ".commit":
                commit_written.set()
                if not release_commit.wait(timeout=5):
                    raise AssertionError("test did not release the provisional import commit")
                raise OSError("forced import failure after digest publication")

        monkeypatch.setattr(_storage, "atomic_write", fail_after_provisional_commit)

        export_waiting = threading.Event()
        real_keyvault_lock = _storage.keyvault_lock

        @contextlib.contextmanager
        def observed_keyvault_lock(root: Path):  # type: ignore[no-untyped-def]
            if threading.current_thread().name == "racing-export":
                export_waiting.set()
            with real_keyvault_lock(root):
                yield

        monkeypatch.setattr(_storage, "keyvault_lock", observed_keyvault_lock)
        import_errors: list[BaseException] = []
        export_errors: list[BaseException] = []
        exported_blobs: list[bytes] = []

        def run_import() -> None:
            try:
                api.import_backup(
                    blob,
                    PASSPHRASE,
                    seed_phrase=SEED,
                    pow_bytes=POW,
                    backend=destination_backend,
                    audit_sink=sink,
                    home=destination,
                )
            except BaseException as exc:
                import_errors.append(exc)

        def run_export() -> None:
            try:
                exported_blobs.append(
                    api.export_backup(
                        key_id,
                        PASSPHRASE,
                        backend=destination_backend,
                        audit_sink=sink,
                        home=destination,
                        seed_phrase=SEED,
                        pow_bytes=POW,
                    )
                )
            except BaseException as exc:
                export_errors.append(exc)

        import_thread = threading.Thread(target=run_import, name="failing-import")
        import_thread.start()
        assert commit_written.wait(timeout=5)

        export_thread = threading.Thread(target=run_export, name="racing-export")
        export_thread.start()
        assert export_waiting.wait(timeout=5)
        assert export_thread.is_alive(), "export must wait while the import transaction owns the lock"

        release_commit.set()
        import_thread.join(timeout=5)
        export_thread.join(timeout=5)

        assert not import_thread.is_alive()
        assert not export_thread.is_alive()
        assert len(import_errors) == 1
        assert isinstance(import_errors[0], OSError)
        assert len(export_errors) == 1
        assert isinstance(export_errors[0], _storage.KeyvaultCorruptError)
        assert exported_blobs == []
        assert not any(entry.get("reason") == "keyvault.backup_exported" for entry in log)
        commit = _storage.resolve_keyvault_dir(destination) / "digests" / f"{_key_id_hash_hex(key_id)}.commit"
        assert not commit.exists()

    def test_import_post_replace_failure_and_delete_failure_keeps_pending_fail_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        _log, sink = audit
        source_home = tmp_path / "source"
        source_backend = FakeBackend()
        key_id = _init_device(source_home, source_backend, sink)
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=source_backend,
            audit_sink=sink,
            home=source_home,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        class DeleteFailBackend(FakeBackend):
            def delete_enclave_key(self, deleted_key_id: str) -> None:
                self.calls.append(("delete", deleted_key_id))
                raise OSError("native delete transport failed")

        destination = tmp_path / "destination"
        destination_root = _storage.resolve_keyvault_dir(destination)
        destination_backend = DeleteFailBackend()
        real_save_meta = _storage.save_meta
        destination_save_count = 0

        def ownership_commit_then_boom(root: Path, meta: dict[str, Any]) -> None:
            nonlocal destination_save_count
            real_save_meta(root, meta)
            if root == destination_root:
                destination_save_count += 1
                if destination_save_count == 2:
                    raise OSError("parent-dir fsync failed after import ownership rename")

        monkeypatch.setattr(_storage, "save_meta", ownership_commit_then_boom)
        with pytest.raises(OSError, match="ownership rename"):
            api.import_backup(
                blob,
                PASSPHRASE,
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=destination_backend,
                audit_sink=sink,
                home=destination,
            )

        meta = _storage.load_meta(destination_root)
        physical = _native_key_id.scoped_native_key_id(destination_root, key_id)
        assert _native_key_id.pending_native_key_from_meta(destination_root, meta) == (key_id, physical)
        assert meta["keys"][_key_id_hash_hex(key_id)][_native_key_id.NATIVE_KEY_ID_FIELD] == physical

        destination_backend.calls.clear()
        with pytest.raises(_storage.KeyvaultCorruptError, match="provisioning is incomplete"):
            api.encrypt(
                key_id,
                b"must-not-use-uncertain-import",
                "vault",
                backend=destination_backend,
                audit_sink=sink,
                home=destination,
            )
        assert destination_backend.calls == []

    def test_import_creates_meta_row_and_commit_digest(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        api.encrypt(key_id, b"x", "p", backend=backend_a, audit_sink=sink, home=home_a)
        blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )

        root_b = home_b / "mordred" / "keyvault"
        meta = _storage.load_meta(root_b)
        assert _key_id_hash_hex(imported) in meta["keys"]
        commit = root_b / "digests" / f"{_key_id_hash_hex(imported)}.commit"
        assert _storage.safe_read(commit) == backup.parse_header(blob).verification_digest

    def test_nfkd_equivalent_passphrases_use_the_same_backup_kdf(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        composed = "vault-caf\u00e9"
        decomposed = unicodedata.normalize("NFKD", composed)
        assert composed != decomposed

        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        _handle, digest = api.prepare_generate(SEED, composed, POW)
        result = api.generate(SEED, composed, POW, digest, backend=backend_a, audit_sink=sink, home=home_a)
        envelope_id = api.encrypt(
            result.key_id,
            b"nfkd-secret",
            "vault",
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
        )
        blob = api.export_backup(
            result.key_id,
            decomposed,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob,
            composed,
            seed_phrase=SEED,
            pow_bytes=POW,
            backend=backend_b,
            audit_sink=sink,
            home=home_b,
        )
        assert (
            api.decrypt(imported, envelope_id, "vault", backend=backend_b, audit_sink=sink, home=home_b)
            == b"nfkd-secret"
        )

    def test_import_retries_raw_passphrase_for_pre_normalization_backup(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        legacy_passphrase = "vault-caf\u00e9"
        assert api._normalize_passphrase(legacy_passphrase) != legacy_passphrase

        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        _handle, digest = api.prepare_generate(SEED, legacy_passphrase, POW)
        result = api.generate(
            SEED,
            legacy_passphrase,
            POW,
            digest,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
        )
        envelope_id = api.encrypt(
            result.key_id,
            b"legacy-nfkd-secret",
            "vault",
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
        )
        current_blob = api.export_backup(
            result.key_id,
            legacy_passphrase,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )
        parsed = backup.parse_header(current_blob)
        manifest_json = backup.decrypt_body(parsed, api._normalize_passphrase(legacy_passphrase))
        legacy_blob = backup.export(
            manifest_json,
            legacy_passphrase,
            verification_digest=parsed.verification_digest,
        )

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            legacy_blob,
            legacy_passphrase,
            seed_phrase=SEED,
            pow_bytes=POW,
            backend=backend_b,
            audit_sink=sink,
            home=home_b,
        )
        assert (
            api.decrypt(imported, envelope_id, "vault", backend=backend_b, audit_sink=sink, home=home_b)
            == b"legacy-nfkd-secret"
        )

    def test_import_can_recover_legacy_blob_encrypted_with_a_different_passphrase(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        envelope_id = api.encrypt(
            key_id,
            b"legacy-split-secret",
            "vault",
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
        )
        current_blob = api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )
        parsed = backup.parse_header(current_blob)
        manifest_json = backup.decrypt_body(parsed, PASSPHRASE)
        legacy_backup_passphrase = "the-typo-used-at-export"
        legacy_blob = backup.export(
            manifest_json,
            legacy_backup_passphrase,
            verification_digest=parsed.verification_digest,
        )

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            legacy_blob,
            PASSPHRASE,
            backup_passphrase=legacy_backup_passphrase,
            seed_phrase=SEED,
            pow_bytes=POW,
            backend=backend_b,
            audit_sink=sink,
            home=home_b,
        )
        assert (
            api.decrypt(imported, envelope_id, "vault", backend=backend_b, audit_sink=sink, home=home_b)
            == b"legacy-split-secret"
        )


# ----------------------------- import rejection paths -----------------------------


class TestImportRejection:
    def _exported_blob(self, tmp_path: Path, sink: Any) -> bytes:
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        api.encrypt(key_id, b"secret", "p", backend=backend_a, audit_sink=sink, home=home_a)
        return api.export_backup(
            key_id,
            PASSPHRASE,
            backend=backend_a,
            audit_sink=sink,
            home=home_a,
            seed_phrase=SEED,
            pow_bytes=POW,
        )

    def test_wrong_passphrase_raises_recovery_mismatch(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                "wrong-passphrase-entirely",
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )

    def test_wrong_seed_phrase_raises_recovery_mismatch(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                PASSPHRASE,
                seed_phrase="totally different seed phrase here now",
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )

    def test_corrupt_blob_raises_backup_corrupt(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(BackupCorrupt):
            api.import_backup(
                b"this is not a valid MRKV backup blob at all",
                PASSPHRASE,
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )

    def test_digest_mismatch_creates_no_enclave_key(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        """Verify-before-decrypt: a mismatch must reject BEFORE the
        destination Enclave key is generated (SPEC import step 2 — steps
        1-5 are pre-mutation)."""
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                "wrong-passphrase",
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )
        assert backend_b.calls == [], "no Enclave operation may run on a rejected import"

    def test_digest_mismatch_writes_no_ciphertexts(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                "wrong-passphrase",
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )
        cipher_dir = home_b / "mordred" / "keyvault" / "ciphertexts" / _key_id_hash_hex("default")
        assert not cipher_dir.exists()


# ----------------------------- audit reason freeze -----------------------------


def test_backup_exported_is_now_in_freeze() -> None:
    """Step-E lands the ``api.export_backup`` emit site, so #24
    ``keyvault.backup_exported`` graduates into the ``ReasonCode`` Literal
    (POLICY.md freeze discipline: freeze a code only once it has an emit
    site). This replaces the prior
    ``test_backup_exported_deliberately_not_frozen_yet``."""
    from typing import get_args

    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.backup_exported" in get_args(ReasonCode)


class TestImportBackupManifestValidation:
    """``import_backup`` must reject a structurally-malformed (but AES-GCM-
    authenticated) manifest with ``BackupCorrupt`` BEFORE generating the
    destination Enclave key — not propagate a raw ``KeyError`` / ``TypeError``
    and generate-then-roll-back a phantom key.
    """

    def _import_crafted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        manifest_json: bytes,
        backend: FakeBackend,
    ) -> str:
        # Bypass the real recovery (digest verify + AES-GCM decrypt) so the
        # crafted manifest reaches api's post-decrypt validation directly.
        monkeypatch.setattr(_secret_ops.recovery, "import_backup", lambda *a, **k: manifest_json)
        return api.import_backup(
            b"dummy-blob",
            "passphrase",
            seed_phrase="abandon " * 24,
            pow_bytes=b"\x00" * 32,
            backend=backend,
            audit_sink=lambda e: None,
            home=tmp_path,
        )

    @pytest.mark.parametrize(
        "field",
        [
            _native_key_id.AUDIT_KEY_FIELD,
            _native_key_id.PENDING_AUDIT_KEY_FIELD,
        ],
    )
    def test_residual_audit_ownership_rejects_fresh_import_without_mutation(
        self,
        field: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        meta[field] = {"residual": True}
        _storage.save_meta(root, meta)
        before_files = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
        backend = FakeBackend()
        audit_entries: list[dict[str, Any]] = []
        manifest = json.dumps({"version": 1, "key_id": "default", "envelopes": []}).encode()
        monkeypatch.setattr(_secret_ops.recovery, "import_backup", lambda *args, **kwargs: manifest)

        with pytest.raises(BackupImportConflict, match="fresh keyvault"):
            api.import_backup(
                b"dummy-blob",
                PASSPHRASE,
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend,
                audit_sink=audit_entries.append,
                home=tmp_path,
            )

        after_files = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
        assert after_files == before_files
        assert backend.calls == []
        assert audit_entries == []

    def test_missing_key_id_is_backup_corrupt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "envelopes": []}).encode("utf-8")
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == [], "no Enclave key may be generated for a malformed manifest"

    def test_envelopes_not_a_list_is_backup_corrupt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "key_id": "default", "envelopes": "nope"}).encode("utf-8")
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []

    def test_key_id_not_str_is_backup_corrupt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "key_id": 123, "envelopes": []}).encode("utf-8")
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []

    @pytest.mark.parametrize("key_id", ["", "mordred.audit-log", "\ud800"])
    def test_empty_or_reserved_key_id_rejects_before_destination_mutation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        key_id: str,
    ) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "key_id": key_id, "envelopes": []}).encode("utf-8")

        with pytest.raises(BackupCorrupt, match="key_id"):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)

        assert backend.calls == []
        assert not (tmp_path / "mordred" / "keyvault").exists()

    def test_invalid_json_is_backup_corrupt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        backend = FakeBackend()
        with pytest.raises(BackupCorrupt, match="UTF-8 JSON"):
            self._import_crafted(monkeypatch, tmp_path, b"{not-json", backend)
        assert backend.calls == []

    @pytest.mark.parametrize(
        "bad",
        [
            b'{"version":1,"version":1,"key_id":"default","envelopes":[]}',
            b'{"version":1,"key_id":"default","envelopes":[],"future":true}',
        ],
    )
    def test_duplicate_or_unknown_root_field_rejects_before_key_generation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        bad: bytes,
    ) -> None:
        backend = FakeBackend()
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []

    @pytest.mark.parametrize(
        "entry",
        [
            None,
            {},
            {
                "purpose_hash_hex": "0" * 31,
                "envelope_id": "A" * 22,
                "dek_hex": "0" * 64,
                "manifest_aes_blob_b64": base64.b64encode(b"\x00" * 28).decode(),
            },
            {
                "purpose_hash_hex": "z" * 32,
                "envelope_id": "A" * 22,
                "dek_hex": "0" * 64,
                "manifest_aes_blob_b64": base64.b64encode(b"\x00" * 28).decode(),
            },
            {
                "purpose_hash_hex": "0" * 32,
                "envelope_id": "../not-an-envelope-id",
                "dek_hex": "0" * 64,
                "manifest_aes_blob_b64": base64.b64encode(b"\x00" * 28).decode(),
            },
            {
                "purpose_hash_hex": "0" * 32,
                "envelope_id": "A" * 22,
                "dek_hex": "0" * 63,
                "manifest_aes_blob_b64": base64.b64encode(b"\x00" * 28).decode(),
            },
            {
                "purpose_hash_hex": "0" * 32,
                "envelope_id": "A" * 22,
                "dek_hex": "0" * 64,
                "manifest_aes_blob_b64": "not-base64!",
            },
            {
                "purpose_hash_hex": "0" * 32,
                "envelope_id": "A" * 22,
                "dek_hex": "0" * 64,
                "manifest_aes_blob_b64": base64.b64encode(b"\x00" * 27).decode(),
            },
        ],
    )
    def test_malformed_envelope_entry_rejects_before_key_generation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        entry: object,
    ) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "key_id": "default", "envelopes": [entry]}).encode()
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []

    def test_duplicate_destination_rejects_before_key_generation(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        backend = FakeBackend()
        entry = {
            "purpose_hash_hex": "0" * 32,
            "envelope_id": "A" * 22,
            "dek_hex": "0" * 64,
            "manifest_aes_blob_b64": base64.b64encode(b"\x00" * 28).decode(),
        }
        bad = json.dumps({"version": 1, "key_id": "default", "envelopes": [entry, entry]}).encode()
        with pytest.raises(BackupCorrupt, match="duplicates"):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []

    @pytest.mark.parametrize(
        "entry_json",
        [
            (
                '{"purpose_hash_hex":"00000000000000000000000000000000",'
                '"envelope_id":"AAAAAAAAAAAAAAAAAAAAAA",'
                '"dek_hex":"0000000000000000000000000000000000000000000000000000000000000000",'
                '"manifest_aes_blob_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",'
                '"future":"no"}'
            ),
            (
                '{"purpose_hash_hex":"00000000000000000000000000000000",'
                '"envelope_id":"AAAAAAAAAAAAAAAAAAAAAA",'
                '"envelope_id":"BBBBBBBBBBBBBBBBBBBBBB",'
                '"dek_hex":"0000000000000000000000000000000000000000000000000000000000000000",'
                '"manifest_aes_blob_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}'
            ),
        ],
    )
    def test_duplicate_or_unknown_entry_field_rejects_before_key_generation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        entry_json: str,
    ) -> None:
        backend = FakeBackend()
        bad = ('{"version":1,"key_id":"default","envelopes":[' + entry_json + "]}").encode()
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []
