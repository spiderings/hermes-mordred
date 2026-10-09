"""Tests for the privacy_check audit-writer factory.

Once the keyvault is initialized, privacy_check must construct an
:class:`EncryptedWriter` instead of an :class:`NDJSONWriter` so the audit
log is AES-GCM-encrypted at rest.

``make_audit_writer`` is **fail-open**: an uninitialized keyvault, a
corrupt keyvault, a missing audit-log wrapping key, or an unavailable
native backend all fall back to :class:`NDJSONWriter` so privacy_check
never stops auditing.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _native_key_id, _storage
from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID, EncryptedWriter, decrypt_log_file
from mordred_hermes.privacy_check.audit import NDJSONWriter, make_audit_writer
from tests._keyvault_fakes import FakeBackend

#: The degraded-marker reason an encrypted→plaintext audit downgrade emits.
_DOWNGRADE_REASON = "mordred.degraded.audit_encryption_unavailable"


def _audit_reasons(log_path: Path) -> list[str]:
    """Return the ``reason`` of every NDJSON entry in ``log_path`` (or [])."""
    if not log_path.exists():
        return []
    reasons: list[str] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            reasons.append(str(json.loads(line).get("reason", "")))
    return reasons


def _init_meta(home: Path) -> None:
    """Mark the keyvault initialized — a ``meta.json`` carrying one key row."""
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    meta["keys"]["00112233445566778899aabbccddeeff"] = {
        "key_id": "default",
        "created_at": "2026-05-16T00:00:00Z",
    }
    _storage.save_meta(root, meta)


class TestMakeAuditWriter:
    def test_uninitialized_keyvault_returns_ndjson(self, tmp_path: Path) -> None:
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path)
        assert isinstance(writer, NDJSONWriter)

    def test_initialized_with_audit_key_returns_encrypted(self, tmp_path: Path) -> None:
        _init_meta(tmp_path)
        backend = FakeBackend()
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=backend)
        assert isinstance(writer, EncryptedWriter)

    @pytest.mark.parametrize(
        "field",
        [
            _native_key_id.AUDIT_KEY_FIELD,
            _native_key_id.PENDING_AUDIT_KEY_FIELD,
        ],
    )
    def test_legacy_main_with_scoped_audit_ownership_falls_back_before_backend_io(
        self,
        field: str,
        tmp_path: Path,
    ) -> None:
        _init_meta(tmp_path)
        root = _storage.resolve_keyvault_dir(tmp_path)
        meta = _storage.load_meta(root)
        meta[field] = {"residual": True}
        _storage.save_meta(root, meta)
        backend = FakeBackend()
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        backend.calls.clear()

        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=backend)

        assert isinstance(writer, NDJSONWriter)
        assert backend.calls == []

    def test_initialized_without_audit_key_falls_back_to_ndjson(self, tmp_path: Path) -> None:
        _init_meta(tmp_path)
        backend = FakeBackend()  # AUDIT_LOG_KEY_ID intentionally not generated
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=backend)
        assert isinstance(writer, NDJSONWriter)

    def test_corrupt_keyvault_falls_back_to_ndjson(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ this is not valid json", encoding="utf-8")
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=FakeBackend())
        assert isinstance(writer, NDJSONWriter)

    def test_initialized_without_audit_key_emits_downgrade_marker(self, tmp_path: Path) -> None:
        """An encrypted→plaintext downgrade must leave a trace in the audit log.

        The keyvault is initialized, so encryption was *expected*; the
        missing audit-log wrapping key forces a plaintext fallback. That
        downgrade is security-relevant and must be visible in the trail,
        not only in Python logging.
        """
        _init_meta(tmp_path)
        log_path = tmp_path / "audit.log"
        backend = FakeBackend()  # AUDIT_LOG_KEY_ID intentionally not generated

        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=backend)

        assert isinstance(writer, NDJSONWriter)
        assert _DOWNGRADE_REASON in _audit_reasons(log_path)

    def test_corrupt_keyvault_emits_downgrade_marker(self, tmp_path: Path) -> None:
        """A corrupt keyvault also emits the downgrade marker."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ this is not valid json", encoding="utf-8")
        log_path = tmp_path / "audit.log"

        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=FakeBackend())

        assert isinstance(writer, NDJSONWriter)
        assert _DOWNGRADE_REASON in _audit_reasons(log_path)

    def test_uninitialized_keyvault_emits_no_downgrade_marker(self, tmp_path: Path) -> None:
        """A never-initialized keyvault is the baseline, not a downgrade.

        The pre-keyvault plaintext NDJSON path must stay silent — emitting
        a degraded marker on every session of an install that never had a
        keyvault would be noise, not signal.
        """
        log_path = tmp_path / "audit.log"

        writer = make_audit_writer(log_path, keyvault_home=tmp_path)

        assert isinstance(writer, NDJSONWriter)
        assert _DOWNGRADE_REASON not in _audit_reasons(log_path)

    def test_downgrade_preserves_existing_encrypted_log(self, tmp_path: Path) -> None:
        """A degraded fallback must not corrupt an existing MRAL log.

        Codex PR #40 review (P1): if ``audit.log`` is already a Phase 4
        ``MRAL``-encrypted file and the keyvault later breaks, the fallback
        ``NDJSONWriter`` must not ``O_APPEND`` plaintext onto the ciphertext
        stream — that would make ``audit decrypt`` fail for the whole file.
        The encrypted log is rotated aside (still decryptable) and a fresh
        plaintext ``audit.log`` is started.
        """
        _init_meta(tmp_path)
        log_path = tmp_path / "audit.log"

        # A prior session wrote an encrypted MRAL log.
        enc_backend = FakeBackend()
        enc_backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        enc = make_audit_writer(log_path, keyvault_home=tmp_path, backend=enc_backend)
        assert isinstance(enc, EncryptedWriter)
        enc.append({"event": "policy.strict.clearnet"})
        enc.close()

        # The keyvault breaks (audit-log wrapping key gone) — degraded path.
        broken = FakeBackend()  # AUDIT_LOG_KEY_ID intentionally not generated
        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=broken)
        assert isinstance(writer, NDJSONWriter)

        # The MRAL log was rotated aside, not appended onto — and the
        # original encrypted entry is still decryptable.
        rotated = sorted(p for p in tmp_path.iterdir() if p.name.startswith("audit.log."))
        assert rotated, "the encrypted log must be rotated aside, not corrupted"
        entries = decrypt_log_file(
            rotated[-1],
            backend=enc_backend,
            audit_sink=lambda e: None,
            keyvault_home=tmp_path,
        )
        assert entries[0]["event"] == "policy.strict.clearnet"

        # The fresh active log is plaintext NDJSON carrying the downgrade marker.
        assert _DOWNGRADE_REASON in _audit_reasons(log_path)

    def test_uninitialized_with_stale_encrypted_log_rotates_it_aside(self, tmp_path: Path) -> None:
        """A de-initialized keyvault must also not corrupt a stale MRAL log.

        If the keyvault made encrypted logs and was later de-initialized,
        ``make_audit_writer`` returns an ``NDJSONWriter`` via the
        keyvault-uninitialized path — which must also rotate the stale
        ``MRAL`` log aside rather than append plaintext onto it. This path
        stays silent (no downgrade marker — an uninitialized keyvault is
        the baseline).
        """
        _init_meta(tmp_path)
        log_path = tmp_path / "audit.log"
        enc_backend = FakeBackend()
        enc_backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        enc = make_audit_writer(log_path, keyvault_home=tmp_path, backend=enc_backend)
        enc.append({"event": "policy.strict.tor"})
        enc.close()

        # De-initialize the keyvault: drop every key row.
        root = _storage.resolve_keyvault_dir(tmp_path)
        meta = _storage.load_meta(root)
        meta["keys"].clear()
        _storage.save_meta(root, meta)

        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=enc_backend)
        assert isinstance(writer, NDJSONWriter)

        rotated = sorted(p for p in tmp_path.iterdir() if p.name.startswith("audit.log."))
        assert rotated, "the stale encrypted log must be rotated aside"
        entries = decrypt_log_file(
            rotated[-1],
            backend=enc_backend,
            audit_sink=lambda e: None,
            keyvault_home=tmp_path,
        )
        assert entries[0]["event"] == "policy.strict.tor"
        assert _DOWNGRADE_REASON not in _audit_reasons(log_path)

    def test_factory_encrypted_writer_roundtrips(self, tmp_path: Path) -> None:
        """A factory-produced EncryptedWriter writes a decryptable MRAL log."""
        _init_meta(tmp_path)
        backend = FakeBackend()
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        log_path = tmp_path / "audit.log"
        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=backend)
        writer.append({"event": "policy.strict.clearnet"})
        writer.close()
        entries = decrypt_log_file(
            log_path,
            backend=backend,
            audit_sink=lambda entry: None,
            keyvault_home=tmp_path,
        )
        assert entries[0]["event"] == "policy.strict.clearnet"

    def test_factory_writer_rejects_recreated_keyvault_generation(self, tmp_path: Path) -> None:
        """A cached DEK must not outlive reset + same-path reinitialization."""
        _init_meta(tmp_path)
        root = _storage.resolve_keyvault_dir(tmp_path)
        backend = FakeBackend()
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        log_path = tmp_path / "audit.log"
        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=backend)
        assert isinstance(writer, EncryptedWriter)
        writer.append({"event": "old-generation"})
        size_before = log_path.stat().st_size

        # Keep the old inode alive under a sibling name so the recreated root
        # is guaranteed to have a different identity (no inode-reuse flake).
        old_root = root.with_name("keyvault.old-generation")
        with _storage.keyvault_lifecycle_lock(root):
            root.rename(old_root)
            _storage.ensure_layout(root)

        with pytest.raises(OSError, match="keyvault root changed"):
            writer.append({"event": "must-not-cross-generation"})
        assert log_path.stat().st_size == size_before

    def test_factory_writer_rejects_rotated_epoch_even_with_same_root_inode(self, tmp_path: Path) -> None:
        """The random epoch closes the theoretical dev/inode-reuse gap."""
        _init_meta(tmp_path)
        root = _storage.resolve_keyvault_dir(tmp_path)
        backend = FakeBackend()
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        log_path = tmp_path / "audit.log"
        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=backend)
        assert isinstance(writer, EncryptedWriter)
        writer.append({"event": "old-epoch"})
        root_identity = (root.lstat().st_dev, root.lstat().st_ino)
        size_before = log_path.stat().st_size

        with _storage.keyvault_lifecycle_lock(root):
            _storage.ensure_generation_epoch(root, force_new=True)

        assert (root.lstat().st_dev, root.lstat().st_ino) == root_identity
        with pytest.raises(OSError, match="keyvault root changed"):
            writer.append({"event": "must-not-cross-epoch"})
        assert log_path.stat().st_size == size_before


class TestSharedBuildAuditWriter:
    """``_audit_support.build_audit_writer`` — the factory ``network`` /
    ``llm_guard`` use for the shared ``audit.log`` — must route through
    ``privacy_check.audit.make_audit_writer`` (audit HIGH #3). Otherwise those
    two plugins write plaintext NDJSON lines into an MRAL-encrypted log,
    leaking audit metadata at rest and breaking ``audit decrypt`` for the whole
    day's trail.
    """

    def test_delegates_to_make_audit_writer_with_log_bound_home(self, monkeypatch, tmp_path: Path) -> None:
        import mordred_hermes.privacy_check.audit as pc_audit
        from mordred_hermes import _audit_support

        seen: list[tuple[Path, Path]] = []
        sentinel = object()

        def fake_make(path: Path, *, keyvault_home: Path) -> object:
            seen.append((path, keyvault_home))
            return sentinel

        # build_audit_writer imports make_audit_writer lazily from this module,
        # so patching the attribute here is what the delegation resolves to.
        monkeypatch.setattr(pc_audit, "make_audit_writer", fake_make)
        audit_path = tmp_path / "mordred" / "audit.log"
        result = _audit_support.build_audit_writer(audit_path)
        assert result is sentinel
        # Encryption state is bound to THIS log's HERMES_BASE
        # (audit_path.parent.parent), matching privacy_check — not the ambient
        # default home.
        assert seen == [(audit_path, tmp_path)]


def _clear_shared_writer_references() -> None:
    """Drop plugin-local references before resetting the owning registry."""
    import mordred_hermes.llm_guard as llm_guard
    import mordred_hermes.network as network
    from mordred_hermes import _audit_support
    from mordred_hermes.keyvault import extension_sign
    from mordred_hermes.privacy_check import _runtime

    network._build_audit_writer.cache_clear()
    llm_guard._build_audit_writer.cache_clear()
    extension_sign._audit_writer.cache_clear()
    _runtime.reset_state_for_tests()
    _audit_support._reset_audit_writer_registry_for_tests()


@pytest.fixture
def clean_shared_writer_registry() -> Iterator[None]:
    """Keep this module's process-wide registry scenarios isolated."""
    _clear_shared_writer_references()
    yield
    _clear_shared_writer_references()


def test_shared_builder_normalizes_plaintext_writer_paths(
    tmp_path: Path,
    clean_shared_writer_registry: None,
) -> None:
    """An uninitialized keyvault also gets one writer per physical path."""
    from mordred_hermes import _audit_support

    home = tmp_path / "home"
    log_path = home / "mordred" / "audit.log"
    alias_path = home / "mordred" / "unused" / ".." / "audit.log"

    first = _audit_support.build_audit_writer(alias_path, keyvault_home=home)
    second = _audit_support.build_audit_writer(log_path, keyvault_home=home)

    assert isinstance(first, NDJSONWriter)
    assert first is second
    first.append({"event": "registry.plain.first"})
    second.append({"event": "registry.plain.second"})
    assert [json.loads(line)["event"] for line in log_path.read_text().splitlines()] == [
        "registry.plain.first",
        "registry.plain.second",
    ]


def test_shared_builder_preserves_final_symlink_for_writer_refusal(
    tmp_path: Path,
    clean_shared_writer_registry: None,
) -> None:
    """Registry normalization must not resolve ``audit.log`` to its victim."""
    from mordred_hermes import _audit_support

    home = tmp_path / "home"
    mordred_dir = home / "mordred"
    mordred_dir.mkdir(parents=True)
    victim = tmp_path / "victim.log"
    victim.write_text("do-not-touch\n", encoding="utf-8")
    victim.chmod(0o644)
    (mordred_dir / "audit.log").symlink_to(victim)

    with pytest.raises(OSError, match="regular file"):
        _audit_support.build_audit_writer(
            mordred_dir / "audit.log",
            keyvault_home=home,
        )

    assert victim.read_text(encoding="utf-8") == "do-not-touch\n"
    assert victim.stat().st_mode & 0o777 == 0o644


def test_shared_builder_rejects_conflicting_keyvault_homes(
    tmp_path: Path,
    clean_shared_writer_registry: None,
) -> None:
    """One log path cannot silently inherit whichever keyvault home won first."""
    from mordred_hermes import _audit_support

    log_path = tmp_path / "audit" / "audit.log"
    first_home = tmp_path / "home-a"
    second_home = tmp_path / "home-b"

    first = _audit_support.build_audit_writer(log_path, keyvault_home=first_home)
    with pytest.raises(ValueError, match="already bound to keyvault home"):
        _audit_support.build_audit_writer(log_path, keyvault_home=second_home)
    assert _audit_support.build_audit_writer(log_path, keyvault_home=first_home) is first


def test_plaintext_writer_warns_when_in_process_keyvault_init_requires_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    clean_shared_writer_registry: None,
) -> None:
    """Live references stay safe, but the plaintext lifetime is never silent."""
    from mordred_hermes import _audit_support
    from mordred_hermes.privacy_check import _keyvault_probe

    home = tmp_path / "home"
    log_path = home / "mordred" / "audit.log"
    writer = _audit_support.build_audit_writer(log_path, keyvault_home=home)
    assert isinstance(writer, NDJSONWriter)

    monkeypatch.setattr(_keyvault_probe, "keyvault_initialized", lambda _home: True)
    with caplog.at_level("WARNING", logger="mordred.audit"):
        assert _audit_support.build_audit_writer(log_path, keyvault_home=home) is writer
        assert _audit_support.build_audit_writer(log_path, keyvault_home=home) is writer

    warnings = [record.message for record in caplog.records if "restart Hermes" in record.message]
    assert len(warnings) == 1
    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    restart_entries = [entry for entry in entries if "restart Hermes" in str(entry.get("detail"))]
    assert len(restart_entries) == 1
    assert restart_entries[0]["reason"] == "mordred.degraded.audit_encryption_unavailable"


def test_all_plugin_factories_share_one_decryptable_mral_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    clean_shared_writer_registry: None,
) -> None:
    """Alternating plugin appends must never mix DEKs in one MRAL file.

    This exercises the actual network, llm_guard, privacy_check and
    extension-sign factory paths. The pre-registry implementation constructed
    four independent ``EncryptedWriter`` instances; the second constructor
    rotated the active file, after which the first appended ciphertext using
    the old DEK/AAD and made authentication fail.
    """
    import hermes_constants

    import mordred_hermes.llm_guard as llm_guard
    import mordred_hermes.network as network
    from mordred_hermes.keyvault import _identity, extension_sign
    from mordred_hermes.privacy_check import _runtime

    home = tmp_path / "home"
    log_path = home / "mordred" / "audit.log"
    alias_path = home / "mordred" / "unused" / ".." / "audit.log"
    _init_meta(home)
    backend = FakeBackend()
    backend.generate_enclave_key(AUDIT_LOG_KEY_ID)

    monkeypatch.setattr(_identity, "resolve_backend", lambda _candidate: backend)
    monkeypatch.setattr(hermes_constants, "get_hermes_home", lambda: home)

    network_writer = network._build_audit_writer(alias_path)
    llm_writer = llm_guard._build_audit_writer(log_path)
    privacy_writer = _runtime.ensure_state(
        config_path=home / "config.yaml",
        audit_path=log_path,
    ).audit
    extension_writer = extension_sign._audit_writer()

    assert isinstance(network_writer, EncryptedWriter)
    assert network_writer is llm_writer is privacy_writer is extension_writer
    assert network_writer.path == log_path.resolve()

    # A local memoizer reset must only drop that module's reference. The
    # process registry remains authoritative while other plugins are active.
    network._build_audit_writer.cache_clear()
    assert network._build_audit_writer(log_path) is network_writer

    # Likewise, policy reload must retain the same active DEK rather than
    # constructing a writer that rotates the file out from under sibling hooks.
    _runtime.reload_state()
    assert (
        _runtime.ensure_state(
            config_path=home / "config.yaml",
            audit_path=log_path,
        ).audit
        is network_writer
    )

    # Force several rotations without writing a 10 MiB fixture. Every active
    # and rotated MRAL file must authenticate independently.
    network_writer.rotate_bytes = 700
    writers = (network_writer, llm_writer, privacy_writer, extension_writer)
    expected_events: list[str] = []
    for seq in range(8):
        event = f"registry.plugin.{seq}"
        expected_events.append(event)
        writers[seq % len(writers)].append(
            {
                "event": event,
                "decision": "allow",
                "detail": "x" * 220,
            }
        )

    files = sorted(log_path.parent.glob("audit.log*"))
    assert log_path in files
    assert any(path.name.endswith(".gz") for path in files)

    actual_events: list[str] = []
    for path in files:
        entries = decrypt_log_file(
            path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )
        actual_events.extend(str(entry["event"]) for entry in entries)
    assert sorted(actual_events) == sorted(expected_events)
