"""Opt-in Linux TPM acceptance (hardware or gated swtpm); synthetic messages only."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "linux" or os.environ.get("MORDRED_LINUX_TELEGRAM_TEST") != "1",
        reason="requires explicit Linux TPM acceptance gate",
    ),
]


@pytest.fixture
def tpm_home(tmp_path, monkeypatch):
    # Requiring an explicit parent prevents accidentally using the operator profile.
    assert os.environ.get("HERMES_HOME"), "set a test-owned HERMES_HOME"
    home = tmp_path / "profile"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("MORDRED_HERMES_RUNTIME_PYTHON", sys.executable)
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    monkeypatch.delenv("MORDRED_TPMKEY_STORE", raising=False)
    # Preserve the operator's explicit emulator opt-in in CI. Without it the
    # native helper intentionally ignores socket TCTIs and requires a device.
    from mordred_hermes.wizard.memory_cli import enable

    assert enable(home=home, root=home / "mordred/keyvault/vault", platform="linux") == 0
    return home


def _python(source, *, env=None):
    with tempfile.TemporaryDirectory(prefix="mordred-acceptance-") as directory:
        script = Path(directory) / "hermes"
        script.write_text(source)
        return subprocess.run([sys.executable, str(script)], env=env, text=True, capture_output=True, timeout=30)


def test_fresh_runtime_lifecycle_and_fail_closed(tpm_home):
    from mordred_hermes.keyvault._memory_key import memory_key_path
    from mordred_hermes.keyvault.memory_crypto import is_sealed
    from mordred_hermes.wizard import memory_cli

    write = _python("""
from tools.memory_tool import MemoryStore
s = MemoryStore(); s.load_from_disk()
assert s.add("memory", "synthetic TPM memory canary")["success"]
""")
    assert write.returncode == 0, write.stderr
    path = tpm_home / "memories/MEMORY.md"
    blob = path.read_bytes()
    assert is_sealed(blob) and b"synthetic TPM memory canary" not in blob
    read_src = """
from tools.memory_tool import MemoryStore
s = MemoryStore(); s.load_from_disk()
assert "synthetic TPM memory canary" in s.memory_entries
"""
    assert _python(read_src).returncode == 0
    key_path = memory_key_path(tpm_home)
    wrapped = key_path.read_bytes()
    assert len(wrapped) == 127
    # Reset owns the surrounding native store, but not this independent key.
    from mordred_hermes.wizard.keyvault_cli import reset_keyvault

    assert reset_keyvault(home=tpm_home, assume_yes=True) == 1
    assert key_path.read_bytes() == wrapped
    assert _python(read_src).returncode == 0
    # An unreadable tree is not an empty tree: preserve both ciphertext and key.
    path.parent.chmod(0)
    try:
        assert memory_cli.purge(home=tpm_home, root=tpm_home / "mordred/keyvault/vault") == 1
        assert key_path.read_bytes() == wrapped
    finally:
        path.parent.chmod(0o700)
    assert path.read_bytes() == blob
    assert _python(read_src).returncode == 0
    key_path.write_bytes(b"corrupt")
    assert _python(read_src).returncode != 0
    assert path.read_bytes() == blob
    key_path.write_bytes(wrapped)
    bad_env = dict(os.environ, TCTI="device:/dev/mordred-missing-tpm", HERMES_MEMORY_KEY="hex:" + "ab" * 32)
    assert _python(read_src, env=bad_env).returncode != 0
    assert path.read_bytes() == blob
    assert _python(read_src).returncode == 0
    root = tpm_home / "mordred/keyvault/vault"
    assert memory_cli.disable(home=tpm_home, root=root) == 0
    assert b"synthetic TPM memory canary" in path.read_bytes()
    assert memory_cli.enable(home=tpm_home, root=root, platform="linux") == 0
    assert key_path.read_bytes() == wrapped
    assert _python(read_src).returncode == 0
    assert memory_cli.purge(home=tpm_home, root=root) == 0
    assert not key_path.exists()


def test_synthetic_telegram_service_with_real_tpm(tpm_home):
    from mordred_hermes.extension.telegram import service
    from mordred_hermes.extension.telegram.ask import AskRequest
    from mordred_hermes.extension.telegram.client import SyncOptions
    from mordred_hermes.extension.telegram.tee import TeeSecretStore, hardware_backend
    from tests.extension.test_telegram_import import _fake_messages, _FakeClient, _FakeDialog
    from tests.extension.test_telegram_tee import _LocalSession, _value

    class Client(_FakeClient):
        async def connect(self):
            pass

        async def disconnect(self):
            pass

        async def is_user_authorized(self):
            return True

    client = Client(
        dialogs=[(_FakeDialog(11, "Synthetic Bob", "bob", is_user=True), False)], history={"bob": _fake_messages(3)}
    )
    root = tpm_home / "mordred/telegram"
    secrets = TeeSecretStore(root, backend_factory=lambda: hardware_backend(tpm_home), audit_sink=lambda entry: None)
    secrets.ensure_key(require_presence=False)
    secrets.store(
        _value(backend="local", local_endpoint="http://127.0.0.1:11434/v1", local_model="qwen", venice_api_key=None)
    )
    http = _LocalSession()
    svc = service.TelegramService(
        secret_store=secrets,
        archive_root=root,
        client_factory=lambda *a, **kw: client,
        http_session_factory=lambda *a: http,
    )

    async def run():
        await svc.start_sync(SyncOptions(since_days=None))
        await svc.wait_for_sync()
        state = await svc.status()
        assert state["last_error"] is None, state
        dialogs = await svc.dialogs()
        assert len(dialogs) == 1
        chunks = [c async for c in svc.ask(AskRequest(question="message"), lambda meta: None)]
        assert "".join(chunks) == "ok"
        await svc.start_sync(SyncOptions(since_days=None))
        await svc.cancel_sync()
        assert not svc.syncing

    asyncio.run(run())
    assert http.calls[0][0] == "http://127.0.0.1:11434/v1/chat/completions"
    assert http.calls[0][1]["allow_redirects"] is False
    for path in root.rglob("*"):
        if path.is_file():
            assert b"message 1" not in path.read_bytes()
    # A separate interpreter must read the same hardware-bound credentials.
    proc = _python(
        "from mordred_hermes.extension.telegram.tee import TeeSecretStore; assert TeeSecretStore().load().session"
    )
    assert proc.returncode == 0, proc.stderr
