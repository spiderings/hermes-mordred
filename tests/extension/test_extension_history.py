"""Encrypted-at-rest conversation history: persists across loads, decrypts with
the shared key, and projects to viewer turns."""

from __future__ import annotations

import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_history, extension_pairing


@pytest.fixture(autouse=True)
def _paired_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    # Establish a pairing so a shared key exists for history encryption.
    code, _ = extension_pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    extension_pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))


def test_history_roundtrip_and_persistence():
    msgs = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi there"},
    ]
    extension_history.save_messages(msgs)
    assert extension_history.load_messages() == msgs
    # Reload (simulating a restart) — still there, not wiped.
    assert extension_history.load_messages() == msgs


def test_history_encrypted_at_rest(tmp_path):
    extension_history.save_messages([{"role": "user", "content": "secret-text"}])
    blob = (tmp_path / "extension" / "history.enc").read_text("utf-8")
    assert blob.startswith(xc.ENC_PREFIX)
    assert "secret-text" not in blob  # not stored in plaintext


def test_projection_extracts_text():
    extension_history.save_messages(
        [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [{"type": "text", "text": "answer"}]},
            {"role": "tool", "content": "ignored"},
        ]
    )
    turns = extension_history.projected_turns()
    assert turns == [{"role": "user", "content": "q"}, {"role": "assistant", "content": "answer"}]


def test_save_ignores_a_preplanted_tmp_symlink(tmp_path):
    """The old writer staged the blob at a *predictable* ``history.tmp`` opened
    without ``O_NOFOLLOW``, so a symlink pre-planted there redirected the (still
    secret-bearing) file and left history.enc a symlink. The canonical
    ``keyvault._storage.atomic_write`` uses a random tmp name + O_EXCL|O_NOFOLLOW
    and enforces 0600."""
    ext = tmp_path / "extension"
    ext.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (ext / "history.tmp").symlink_to(victim)

    extension_history.save_messages([{"role": "user", "content": "secret-text"}])

    assert victim.read_text() == "untouched"  # no write through the symlink
    history = ext / "history.enc"
    assert history.is_file() and not history.is_symlink()
    assert stat.S_IMODE(history.lstat().st_mode) == 0o600
    assert extension_history.load_messages() == [{"role": "user", "content": "secret-text"}]


def test_clear():
    extension_history.save_messages([{"role": "user", "content": "x"}])
    extension_history.clear()
    assert extension_history.load_messages() == []


def test_no_history_is_reported_as_empty_not_undecryptable(monkeypatch):
    monkeypatch.setattr(extension_history, "_undecryptable_warned", False)

    loaded = extension_history.load_history()

    assert loaded.messages == []
    assert loaded.status == "empty"
    assert loaded.undecryptable is False
    assert extension_history.load_messages() == []


def test_readable_history_is_reported_as_ok(monkeypatch):
    monkeypatch.setattr(extension_history, "_undecryptable_warned", False)
    extension_history.save_messages([{"role": "user", "content": "hello"}])

    loaded = extension_history.load_history()

    assert loaded.messages == [{"role": "user", "content": "hello"}]
    assert loaded.status == "ok"
    assert loaded.undecryptable is False


def test_undecryptable_history_is_distinguishable_and_warned_once(tmp_path, monkeypatch, caplog):
    """After re-pairing the stored blob no longer decrypts. That is a different
    outcome from "no history" and must not be silently rendered as an empty
    conversation."""
    monkeypatch.setattr(extension_history, "_undecryptable_warned", False)
    extension_history.save_messages([{"role": "user", "content": "secret-text"}])
    history_file = tmp_path / "extension" / "history.enc"
    history_file.write_text(history_file.read_text("utf-8")[:-8] + "AAAAAAAA", encoding="utf-8")

    with caplog.at_level("WARNING", logger="mordred_hermes.extension.history"):
        first = extension_history.load_history()
        second = extension_history.load_history()

    assert first.messages == [] and second.messages == []
    assert first.status == "undecryptable" and second.status == "undecryptable"
    assert first.undecryptable is True
    assert extension_history.load_messages() == []  # legacy callers unchanged
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1, [r.getMessage() for r in warnings]
    assert "undecryptable" in warnings[0].getMessage()


def test_projection_reports_the_load_status(monkeypatch, tmp_path):
    monkeypatch.setattr(extension_history, "_undecryptable_warned", False)
    extension_history.save_messages([{"role": "user", "content": "q"}])
    history_file = tmp_path / "extension" / "history.enc"
    history_file.write_text("🔒ENC:v1:not-a-real-envelope", encoding="utf-8")

    projection = extension_history.projected_history()

    assert projection.turns == []
    assert projection.status == "undecryptable"
