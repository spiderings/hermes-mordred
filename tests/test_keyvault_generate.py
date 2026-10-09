"""Tests for the non-interactive ``generate`` lifecycle wrapper."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _native_key_id, _storage, api, wrap
from tests._keyvault_fakes import FakeBackend
from tests._keyvault_lifecycle_helpers import (
    _SPEC_DIGEST,
    _SPEC_PASSPHRASE,
    _SPEC_POW,
    _SPEC_SEED,
    _AuditCapture,
)


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def audit() -> _AuditCapture:
    return _AuditCapture()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def kv_root(home: Path) -> Path:
    return home / "mordred" / "keyvault"


# ============================ generate (non-interactive wrapper) ============================
#
# Contract frozen in SPEC.md §"PR4 API contract / Two-phase generate":
#
#     def generate(seed_phrase, passphrase, pow_bytes, expected_digest, *,
#                  key_id=None, backend, audit_sink, home=None) -> GenerateResult:
#         # prepare_generate → confirm_generate in one call.
#         # Tests / future automation use this; the wizard CLI MUST use the
#         # two-phase form so the user confirms the digest offline.
#
# Implementation note: generate delegates fully to confirm_generate (it does
# NOT pre-check the digest itself). confirm_generate reads the handle's
# prepared digest, compares expected_digest against it, and emits
# keyvault.init_denied on a mismatch. The SPEC sketch showed an early
# in-generate check that raised WITHOUT an audit emit; delegating is simpler
# and gives a non-interactive mismatch the same audit trail as the
# interactive path — a strict improvement, documented in the GREEN commit.


class TestGenerateSignature:
    """``generate`` is positional on (seed, passphrase, pow_bytes,
    expected_digest) then keyword-only (key_id, backend, audit_sink, home).
    """

    def test_signature_positional_then_keyword_only(self) -> None:
        sig = inspect.signature(api.generate)
        params = sig.parameters
        assert list(params) == [
            "seed_phrase",
            "passphrase",
            "pow_bytes",
            "expected_digest",
            "key_id",
            "backend",
            "audit_sink",
            "home",
            "unattended",
        ]
        assert params["expected_digest"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert params["backend"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["audit_sink"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["unattended"].kind is inspect.Parameter.KEYWORD_ONLY


class TestGenerateHappyPath:
    """Correct expected_digest → full prepare→confirm in one call."""

    def test_returns_generate_result(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert isinstance(result, api.GenerateResult)
        assert result.key_id == "default"

    def test_canonical_vector_succeeds(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        """The canonical SPEC vector drives a full generate end to end:
        the digest prepare_generate computes for those inputs equals
        _SPEC_DIGEST, so generate finalizes successfully.
        """
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        commit_path = kv_root / "digests" / f"{result.key_id_hash}.commit"
        assert _storage.safe_read(commit_path) == _SPEC_DIGEST

    def test_explicit_key_id_used(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            key_id="automation-key",
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert result.key_id == "automation-key"

    def test_enclave_key_generated_and_meta_written(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        meta = _storage.load_meta(kv_root)
        assert result.key_id_hash in meta["keys"]
        native_key_id = meta["keys"][result.key_id_hash][_native_key_id.NATIVE_KEY_ID_FIELD]
        assert (
            len(
                wrap.get_wrapping_key_public(
                    "default",
                    backend=backend,
                    native_key_id=native_key_id,
                )
            )
            == 65
        )

    def test_audit_emits_started_then_completed(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert [e["reason"] for e in audit.log] == [
            "keyvault.init_started",
            "keyvault.init_completed",
        ]


class TestGenerateMismatch:
    """A wrong expected_digest is rejected — the durable phase never runs."""

    def test_wrong_expected_digest_raises(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )

    def test_mismatch_emits_init_denied(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        """generate delegates to confirm_generate, so a non-interactive
        mismatch produces the same keyvault.init_denied audit trail as the
        interactive confirm_generate path.
        """
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        assert [e["reason"] for e in audit.log] == ["keyvault.init_denied"]

    def test_mismatch_generates_no_key(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        with pytest.raises(Exception):  # noqa: B017 — WrapKeyNotFound; key never created
            wrap.get_wrapping_key_public("default", backend=backend)

    def test_mismatch_touches_no_filesystem(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        assert not kv_root.exists()


class TestGenerateWipesHandle:
    """``generate`` is non-interactive — there is no display flow to call
    ``SeedDisplayHandle.consume()``, and ``confirm_generate`` only reads
    the handle (it never consumes). ``generate`` must therefore wipe the
    internal handle's seed payload itself, on both the success and the
    mismatch paths, so the seed does not linger in memory until GC (codex
    pre-merge P2).
    """

    @staticmethod
    def _capture_handle(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        """Patch api.prepare_generate so the test can grab the handle that
        ``generate`` mints internally and never returns.
        """
        captured: list[Any] = []
        real_prepare = api.prepare_generate

        def capturing_prepare(seed: str, passphrase: str, pow_bytes: bytes) -> tuple[Any, bytes]:
            handle, digest = real_prepare(seed, passphrase, pow_bytes)
            captured.append(handle)
            return handle, digest

        monkeypatch.setattr(api, "prepare_generate", capturing_prepare)
        return captured

    def test_generate_wipes_handle_seed_on_success(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_handle(monkeypatch)
        api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        handle = captured[0]
        assert all(b == 0 for b in handle._payload), (  # type: ignore[attr-defined]
            "generate() must wipe the internal handle's seed payload on success"
        )

    def test_generate_wipes_handle_seed_on_mismatch(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_handle(monkeypatch)
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        handle = captured[0]
        assert all(b == 0 for b in handle._payload), (  # type: ignore[attr-defined]
            "generate() must wipe the internal handle's seed payload even when confirm raises"
        )
