"""Integration: vault ``.env`` → env shim → usable ``HERMES_MEMORY_KEY``.

No Hermes release to date (verified through hermes-agent 0.20.0 and GitHub HEAD) implements agent-memory
encryption — nothing upstream consumes ``HERMES_MEMORY_KEY`` today. This is
**not** a test of Hermes's built-in agent-memory encryption; it proves the
*intended* contract for a future Mordred-owned memory-encryption runtime
(a Mordred-owned runtime tracked in docs/dev/TODO.md), which will be the actual consumer:

  vault-enrolled ``.env`` (``HERMES_MEMORY_KEY=...``)
    → ``_runtime_env.inject_vault_env`` lands it in ``os.environ`` at startup
    → the value decodes to a 32-byte AES-256 key a memory encryptor would accept.

The AES-256-GCM key format (URL-safe base64, exactly 32 bytes, with a
filename-bound AAD) mirrors upstream ``tools/memory_tool.py``'s documented
contract, reproduced here rather than imported (cross-package coupling; and
that module does not exist upstream today) — so the proof is self-contained
and runs on any platform via the software fakes (real P-256 ECDH + in-memory
anchor).
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mordred_hermes.keyvault import _identity, _runtime_env, vault
from mordred_hermes.wizard import vault_memory_key

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"
# Mirrors upstream tools/memory_tool.py _aad_for_path: "hermes-memory-v1:<name>".
_MEMORY_AAD = b"hermes-memory-v1:MEMORY.md"


@pytest.fixture(autouse=True)
def _isolate_ambient_memory_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No ambient HERMES_MEMORY_KEY: clear the env var and point the Hermes home at an
    empty dir, so ``set_memory_key`` mints a fresh key here instead of adopting one
    from the developer's real ``~/.hermes/.env`` (keeps these tests hermetic)."""
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    home = tmp_path / "ambient_home"
    home.mkdir()
    monkeypatch.setattr(vault_memory_key, "_hermes_home", lambda: home)


def _init_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """Materialize a real (empty) vault at ``root`` under the software fakes."""
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _enroll_env(root: Path, backend: FakeBackend, store: FakeAnchorStore, env_bytes: bytes) -> None:
    """Enroll ``.env`` into the vault at ``root`` (hot path)."""
    key_id = anchor_label = _identity.vault_identity(root)
    opened = vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
    try:
        opened.enroll_file(".env", env_bytes)
    finally:
        opened.close()


def _decode_memory_key(value: str) -> bytes:
    """Decode a URL-safe base64 ``HERMES_MEMORY_KEY`` value (upstream padding rule)."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _assert_usable_aes256_memory_key(value: str) -> None:
    """Assert ``value`` is a 32-byte key that drives an AES-256-GCM memory round-trip."""
    key = _decode_memory_key(value)
    assert len(key) == 32  # AES-256
    aes = AESGCM(key)
    nonce = bytes(12)
    ciphertext = aes.encrypt(nonce, b"a memory entry", _MEMORY_AAD)
    assert aes.decrypt(nonce, ciphertext, _MEMORY_AAD) == b"a memory entry"


class TestVaultEnvToMemoryKey:
    """A vault-enrolled ``HERMES_MEMORY_KEY`` is injected and usable for memory encryption."""

    def test_manually_enrolled_key_injects_and_is_usable(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault(root, backend, store)
        memory_key = base64.urlsafe_b64encode(b"\x11" * 32).decode("ascii")
        _enroll_env(root, backend, store, f"HERMES_MEMORY_KEY={memory_key}\nFOO=bar\n".encode())

        environ: dict[str, str] = {}
        _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)

        assert environ["HERMES_MEMORY_KEY"] == memory_key
        _assert_usable_aes256_memory_key(environ["HERMES_MEMORY_KEY"])

    def test_set_memory_key_then_inject_end_to_end(self, tmp_path: Path) -> None:
        """The on-ramp + the runtime shim compose: set the key, then inject it."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault(root, backend, store)

        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 0

        environ: dict[str, str] = {}
        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 1
        _assert_usable_aes256_memory_key(environ["HERMES_MEMORY_KEY"])

    def test_set_memory_key_preserves_other_env_vars(self, tmp_path: Path) -> None:
        """Adding the memory key must not drop existing vault ``.env`` entries."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault(root, backend, store)
        _enroll_env(root, backend, store, b"ANTHROPIC_API_KEY=sk-secret\nFOO=bar\n")

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0

        environ: dict[str, str] = {}
        _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ["ANTHROPIC_API_KEY"] == "sk-secret"
        assert environ["FOO"] == "bar"
        _assert_usable_aes256_memory_key(environ["HERMES_MEMORY_KEY"])
