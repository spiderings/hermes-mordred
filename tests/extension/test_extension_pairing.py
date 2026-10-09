"""Pairing handshake tests — simulate the extension side and verify the
gateway derives the same key, signs a verifiable attestation, and issues a
valid token."""

from __future__ import annotations

import json
import stat
import threading

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


def _verify_attestation(challenge: bytes, se_pubkey_b64: str, signed_b64: str) -> bool:
    pub = load_der_public_key(xc.b64u_decode(se_pubkey_b64))
    raw = xc.b64u_decode(signed_b64)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, pairing.ATTEST_CONTEXT + challenge, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _webauthn_public_key_b64() -> str:
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return xc.b64u_encode(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def test_full_pairing_handshake():
    code, _exp = pairing.generate_code()
    assert code.startswith("MORT-")

    # Extension side
    ext_priv = X25519PrivateKey.generate()
    ext_pub_b64 = xc.b64u_encode(xc.x25519_public_raw(ext_priv))
    challenge = b"\x11" * 32

    result = pairing.handle_pair_init(code, ext_pub_b64, xc.b64u_encode(challenge))

    # Attestation verifies against the returned SE pubkey
    att = result["attestation"]
    assert _verify_attestation(challenge, att["se_pubkey"], att["signed_challenge"])

    # Both sides derive the same AES key
    ext_key = xc.derive_shared_key(ext_priv, result["hermes_pubkey"], code)
    stored = pairing.load_pairing()
    assert stored is not None
    assert stored.aes_key == ext_key

    # Token round-trips
    assert pairing.validate_token(result["ext_token"]) is True
    assert pairing.validate_token("wrong") is False


def test_attestation_key_creation_is_serialized_and_stable(monkeypatch):
    real_generate = pairing.ec.generate_private_key
    entered_generate = threading.Event()
    release_generate = threading.Event()
    generated = 0
    results: list[str] = []
    failures: list[BaseException] = []

    def delayed_generate(curve):
        nonlocal generated
        generated += 1
        entered_generate.set()
        assert release_generate.wait(timeout=5)
        return real_generate(curve)

    def load_public_key() -> None:
        try:
            results.append(pairing.attest_pubkey_spki_b64())
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    monkeypatch.setattr(pairing.ec, "generate_private_key", delayed_generate)
    first = threading.Thread(target=load_public_key)
    second = threading.Thread(target=load_public_key)
    first.start()
    assert entered_generate.wait(timeout=5)
    second.start()
    release_generate.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert generated == 1
    assert len(results) == 2 and results[0] == results[1]


def test_invalid_existing_attestation_key_is_never_replaced(tmp_path):
    pairing.attest_pubkey_spki_b64()
    path = tmp_path / "extension" / "attest_key.pem"
    corrupt = b"not a private key\n"
    path.write_bytes(corrupt)

    with pytest.raises(RuntimeError, match="invalid; refusing replacement"):
        pairing.attest_pubkey_spki_b64()

    assert path.read_bytes() == corrupt


def test_pairing_store_refuses_symlinked_extension_directory(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    extension = tmp_path / "extension"
    extension.symlink_to(target, target_is_directory=True)

    with pytest.raises(OSError, match="real directory"):
        pairing.generate_code()

    assert not (target / "pending.json").exists()
    assert not (target / ".lock").exists()


def test_missing_json_stores_keep_first_run_api_behaviour():
    """Genuine absence remains the compatible empty/unknown first-run state."""
    code = "MORT-AAAAAAAA-BBBBBBBB"

    assert pairing.load_pairing() is None
    assert pairing.load_channel_keys() == {}
    assert pairing.code_consumed(code) is False
    assert pairing.revoke_code(code) is False
    assert pairing.pair_outcome(code) == ("pending", None)


@pytest.mark.parametrize("payload", [b"{not-json", b"[]"])
def test_generate_code_does_not_replace_corrupt_pending_store(tmp_path, payload):
    extension = tmp_path / "extension"
    extension.mkdir(mode=0o700)
    pending = extension / "pending.json"
    pairing._write_private(pending, payload)

    with pytest.raises(RuntimeError, match=r"pending\.json.*unreadable or corrupt"):
        pairing.generate_code()

    assert pending.read_bytes() == payload


@pytest.mark.parametrize("payload", [b"{not-json", b"[]"])
def test_channel_key_rmw_does_not_replace_corrupt_state_store(tmp_path, payload):
    extension = tmp_path / "extension"
    extension.mkdir(mode=0o700)
    state_path = extension / "state.json"
    pairing._write_private(state_path, payload)

    with pytest.raises(RuntimeError, match=r"state\.json.*unreadable or corrupt"):
        pairing.save_channel_key("C-corrupt", b"\x44" * 32)

    assert state_path.read_bytes() == payload


def test_json_store_with_unsafe_permissions_fails_closed(tmp_path):
    extension = tmp_path / "extension"
    extension.mkdir(mode=0o700)
    pending = extension / "pending.json"
    pairing._write_private(pending, b"{}")
    pending.chmod(0o644)

    with pytest.raises(RuntimeError, match=r"pending\.json.*unreadable or corrupt"):
        pairing.generate_code()

    assert pending.read_bytes() == b"{}"
    assert stat.S_IMODE(pending.stat().st_mode) == 0o644


def test_json_store_symlink_is_not_followed_or_replaced(tmp_path):
    extension = tmp_path / "extension"
    extension.mkdir(mode=0o700)
    victim = tmp_path / "outside.json"
    victim.write_bytes(b'{"must":"survive"}')
    pending = extension / "pending.json"
    pending.symlink_to(victim)

    with pytest.raises(RuntimeError, match=r"pending\.json.*unreadable or corrupt"):
        pairing.generate_code()

    assert pending.is_symlink()
    assert victim.read_bytes() == b'{"must":"survive"}'


def test_code_single_use():
    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    ch = xc.b64u_encode(b"\x00" * 32)
    pairing.handle_pair_init(code, ext_pub, ch)
    with pytest.raises(pairing.PairError) as ei:
        pairing.handle_pair_init(code, ext_pub, ch)
    assert ei.value.reason == "already_used"


def test_revoke_code_burns_pending_code():
    code, _ = pairing.generate_code()

    assert pairing.revoke_code(code) is True
    assert pairing.revoke_code(code) is False
    assert pairing.pair_outcome(code) == ("failed", "cancelled")

    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError) as exc_info:
        pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))
    assert exc_info.value.reason == "already_used"


def test_revoke_code_cancels_a_claimed_handshake_before_commit(monkeypatch):
    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    entered_attestation = threading.Event()
    release_attestation = threading.Event()
    errors: list[BaseException] = []

    def blocked_attestation(_challenge: bytes) -> str:
        entered_attestation.set()
        assert release_attestation.wait(timeout=5)
        return "signed"

    monkeypatch.setattr(pairing, "_sign_attestation", blocked_attestation)
    monkeypatch.setattr(pairing, "attest_pubkey_spki_b64", lambda: "pub")
    monkeypatch.setattr(pairing, "se_available", lambda: False)

    def pair_in_background() -> None:
        try:
            pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x12" * 32))
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=pair_in_background)
    worker.start()
    assert entered_attestation.wait(timeout=5)
    assert pairing.code_consumed(code) is True

    assert pairing.revoke_code(code) is True
    release_attestation.set()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], pairing.PairError)
    assert errors[0].reason == "cancelled"
    assert pairing.load_pairing() is None
    assert pairing.pair_outcome(code) == ("failed", "cancelled")


def test_pair_outcome_uses_committed_state_when_pending_annotation_fails(monkeypatch):
    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    original_write = pairing._write_private

    def fail_paired_annotation(path, data):
        if path.name == "pending.json" and b'"result": "paired"' in data:
            raise OSError("simulated pending outcome write failure")
        original_write(path, data)

    monkeypatch.setattr(pairing, "_write_private", fail_paired_annotation)

    pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x14" * 32))

    assert pairing.load_pairing() is not None
    assert pairing.pair_outcome(code) == ("paired", None)
    assert pairing.revoke_code(code) is False


def test_successful_repair_revokes_previous_webauthn_credential():
    """A replacement extension must not be locked behind the old device's MFA."""
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    challenge = xc.b64u_encode(b"\x12" * 32)

    first_code, _ = pairing.generate_code()
    first = pairing.handle_pair_init(first_code, ext_pub, challenge)
    pairing.save_webauthn_credential(
        "old-credential",
        _webauthn_public_key_b64(),
        origin="chrome-extension://abcdefghijklmnopabcdefghijklmnop",
    )
    assert pairing.has_webauthn_credential() is True

    second_code, _ = pairing.generate_code()
    second = pairing.handle_pair_init(second_code, ext_pub, challenge)

    assert pairing.validate_token(first["ext_token"]) is False
    assert pairing.validate_token(second["ext_token"]) is True
    assert pairing.has_webauthn_credential() is False
    assert not pairing._webauthn_path().exists()


def test_clear_pairing_clears_webauthn_credential():
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    code, _ = pairing.generate_code()
    pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x13" * 32))
    pairing.save_webauthn_credential(
        "credential",
        _webauthn_public_key_b64(),
        origin="chrome-extension://abcdefghijklmnopabcdefghijklmnop",
    )

    pairing.clear_pairing()

    assert pairing.load_pairing() is None
    assert pairing.has_webauthn_credential() is False
    assert not pairing._webauthn_path().exists()


def test_invalid_code():
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError) as ei:
        pairing.handle_pair_init("MORT-AAAAAAAA-BBBBBBBB", ext_pub, xc.b64u_encode(b"\x00" * 32))
    assert ei.value.reason == "invalid_code"


def test_pair_outcome_lifecycle():
    """pending → paired, recorded on the pending entry for the polling CLI."""
    code, _ = pairing.generate_code()
    assert pairing.pair_outcome(code) == ("pending", None)

    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))

    assert pairing.pair_outcome(code) == ("paired", None)


def test_handshake_failure_after_consume_records_failed_outcome():
    """A pair_init that dies *after* claiming the code must not look paired:
    the CLI-visible outcome is ("failed", reason), no pairing is saved, and
    the code stays burned (single-use)."""
    code, _ = pairing.generate_code()
    with pytest.raises(pairing.PairError) as ei:
        pairing.handle_pair_init(code, "!!!not-a-key!!!", xc.b64u_encode(b"\x00" * 32))
    assert ei.value.reason == "invalid_pubkey"

    assert pairing.pair_outcome(code) == ("failed", "invalid_pubkey")
    assert pairing.load_pairing() is None
    with pytest.raises(pairing.PairError) as ei2:
        pairing.handle_pair_init(code, "!!!not-a-key!!!", xc.b64u_encode(b"\x00" * 32))
    assert ei2.value.reason == "already_used"


def test_invalid_challenge_records_failed_outcome():
    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError):
        pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x01"))  # < 16 bytes
    assert pairing.pair_outcome(code) == ("failed", "invalid_challenge")


def test_late_failure_preserves_existing_pairing(monkeypatch):
    """A handshake that fails AFTER key derivation (e.g. attestation signing
    I/O error) must not clobber a previously-working pairing: nothing is
    persisted until every fallible step has succeeded, and the outcome is
    recorded as failed."""
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    ch = xc.b64u_encode(b"\x22" * 32)

    code1, _ = pairing.generate_code()
    pairing.handle_pair_init(code1, ext_pub, ch)
    before = pairing.load_pairing()
    assert before is not None

    def _boom(_challenge: bytes) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(pairing, "_sign_attestation", _boom)
    code2, _ = pairing.generate_code()
    with pytest.raises(OSError):
        pairing.handle_pair_init(code2, ext_pub, ch)

    assert pairing.load_pairing() == before  # working pairing untouched
    assert pairing.pair_outcome(code2) == ("failed", "internal_error")


def test_legacy_consumed_entry_reports_consumed():
    """An entry claimed by a server build that predates outcome recording
    (used=True, no result field) reads as 'consumed' — the CLI applies its
    grace fallback, not an immediate paired/failed verdict."""
    code, _ = pairing.generate_code()
    pairing._consume_code(code)
    assert pairing.pair_outcome(code) == ("consumed", None)


def test_normalize_code():
    assert pairing.normalize_code("mort-abcdefgh-jklmnpqr") == "MORT-ABCDEFGH-JKLMNPQR"
    # Strips ambiguous/garbage chars and re-groups.
    assert pairing.normalize_code("ABCDEFGHJKLMNPQR") == "MORT-ABCDEFGH-JKLMNPQR"


def test_state_write_ignores_a_preplanted_tmp_symlink(tmp_path):
    """The pairing state holds the shared AES key and the ext_token. The old
    hand-rolled writer staged them at a *predictable* ``state.json.tmp`` opened
    without ``O_NOFOLLOW``, so a symlink pre-planted there redirected the secret
    (and left state.json a symlink). ``keyvault._storage.atomic_write`` uses a
    random tmp name + ``O_EXCL | O_NOFOLLOW``."""
    ext = tmp_path / "extension"
    ext.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (ext / "state.json.tmp").symlink_to(victim)

    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    result = pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))

    assert victim.read_text() == "untouched"  # no write through the symlink
    assert result["ext_token"] not in victim.read_text()
    state = ext / "state.json"
    assert state.is_file() and not state.is_symlink()
    assert stat.S_IMODE(state.lstat().st_mode) == 0o600


def test_extchat_key_is_never_persisted():
    """K_extchat is always derived from the master key (api._extchat_key); the
    dead load/save_extchat_key pair (and its state field) is gone."""
    assert not hasattr(pairing, "load_extchat_key")
    assert not hasattr(pairing, "save_extchat_key")


def test_consume_code_single_use_under_concurrency():
    """Racing pair_init frames must not consume the same one-time code twice
    (read-modify-write on pending.json is guarded by the state lock)."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    code, _ = pairing.generate_code()
    n = 8
    barrier = threading.Barrier(n)

    def attempt(_i: int) -> str:
        barrier.wait()
        try:
            pairing._consume_code(code)
            return "ok"
        except pairing.PairError as e:
            return e.reason

    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(attempt, range(n)))

    assert results.count("ok") == 1
    assert set(results) <= {"ok", "already_used"}


def _count_state_json_parses(monkeypatch) -> list[int]:
    """Patch ``pairing._read_json`` to count parses of state.json specifically
    (pending.json/webauthn.json reads are unaffected and uncounted)."""
    counter = [0]
    real_read_json = pairing._read_json

    def counting_read_json(path):
        if path == pairing._state_path():
            counter[0] += 1
        return real_read_json(path)

    monkeypatch.setattr(pairing, "_read_json", counting_read_json)
    return counter


def test_load_pairing_parses_state_once_per_generation(monkeypatch):
    """state.json carries the E2E replay cache and can reach several MB at
    capacity; repeated load_pairing() calls between writes must not re-parse
    it every time (PR #88 follow-up)."""
    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))

    counter = _count_state_json_parses(monkeypatch)

    first = pairing.load_pairing()
    for _ in range(4):
        assert pairing.load_pairing() == first

    assert counter[0] == 1


def test_load_channel_keys_parses_state_once_per_generation(monkeypatch):
    pairing.save_channel_key("C1", b"\x09" * 32)

    counter = _count_state_json_parses(monkeypatch)

    for _ in range(4):
        assert pairing.load_channel_keys()["C1"] == b"\x09" * 32

    assert counter[0] == 1


def test_pairing_state_cache_invalidates_on_each_owned_write_path():
    """Every write path this module owns (re-pair, channel-key push, replay
    claim, clear) must be visible on the very next read — never a stale
    generation, and this must not depend on the filesystem's mtime
    resolution advancing between two writes in the same test tick."""
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))

    code1, _ = pairing.generate_code()
    pairing.handle_pair_init(code1, ext_pub, xc.b64u_encode(b"\x01" * 32))
    first_pairing = pairing.load_pairing()
    assert first_pairing is not None

    code2, _ = pairing.generate_code()
    pairing.handle_pair_init(code2, ext_pub, xc.b64u_encode(b"\x02" * 32))
    second_pairing = pairing.load_pairing()
    assert second_pairing is not None
    assert second_pairing.ext_token != first_pairing.ext_token

    pairing.save_channel_key("C-live", b"\x03" * 32)
    assert pairing.load_channel_keys()["C-live"] == b"\x03" * 32

    identity_a = "a" * 64
    assert pairing.claim_e2e_replay_identities((identity_a,)) is True
    # A second claim of the same identity must see the just-committed entry,
    # not a cached pre-claim snapshot.
    assert pairing.claim_e2e_replay_identities((identity_a,)) is False

    pairing.clear_pairing()
    assert pairing.load_pairing() is None
    assert pairing.load_channel_keys() == {}


def test_state_cache_reloads_after_a_write_outside_this_modules_helpers():
    """The cache must not serve content older than what is currently on disk
    even when this module's own write paths never ran — e.g. state.json
    restored from a backup by another process. This exercises the per-access
    (mtime, size) guard directly, bypassing every explicit invalidation call
    this module makes on its own write paths."""
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="first",
            ext_pubkey_b64="e",
            hermes_pubkey_b64="h",
            paired_at=1.0,
        )
    )
    loaded = pairing.load_pairing()
    assert loaded is not None
    assert loaded.ext_token == "first"

    # Bypass every helper that calls _invalidate_state_cache() and write
    # directly, as an external process replacing the file out from under this
    # one would. A longer token value also changes the file's size, so the
    # cache key differs regardless of the filesystem's mtime resolution.
    raw = pairing._read_json(pairing._state_path())
    raw["ext_token"] = "rewritten-externally-with-a-longer-token-value"
    pairing._write_private(pairing._state_path(), json.dumps(raw).encode("utf-8"))

    reloaded = pairing.load_pairing()
    assert reloaded is not None
    assert reloaded.ext_token == "rewritten-externally-with-a-longer-token-value"


def test_state_cache_does_not_republish_a_snapshot_a_write_invalidated(monkeypatch):
    """A reader descheduled past a concurrent write must not install its
    pre-write snapshot after that write's invalidation.

    Readers deliberately skip ``_state_lock()`` — that is the point of the fast
    path — so ``stat -> parse -> store`` is not atomic against a writer. The
    (mtime, size) key normally catches the resulting stale store on the *next*
    read, but that is exactly the filesystem-resolution dependency the explicit
    ``_invalidate_state_cache()`` calls exist to remove. Pinning the stat key
    here reproduces the pathological case (a write that leaves mtime_ns and
    size unchanged) so the generation guard, not the clock, is what is tested.
    """
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="before-the-racing-write",
            ext_pubkey_b64="e",
            hermes_pubkey_b64="h",
            paired_at=1.0,
        )
    )
    pinned_key = (pairing._state_path(), 1, 1)
    monkeypatch.setattr(pairing, "_state_stat_key", lambda: pinned_key)
    pairing._invalidate_state_cache()

    real_read_json = pairing._read_json
    raced = [False]

    def read_json_then_let_a_write_land(path):
        data = real_read_json(path)
        if path == pairing._state_path() and not raced[0]:
            # The writer commits between our parse and our cache store. It runs
            # under _state_lock(), which this reader never took.
            raced[0] = True
            monkeypatch.setattr(pairing, "_read_json", real_read_json)
            pairing._save_pairing(
                pairing.Pairing(
                    aes_key=b"\x02" * 32,
                    ext_token="after-the-racing-write",
                    ext_pubkey_b64="e",
                    hermes_pubkey_b64="h",
                    paired_at=2.0,
                )
            )
        return data

    monkeypatch.setattr(pairing, "_read_json", read_json_then_let_a_write_land)
    stale = pairing.load_pairing()
    assert stale is not None
    assert raced[0] is True
    # The racing reader may legitimately return its own pre-write snapshot.
    # What it must not do is leave that snapshot in the cache for everyone else.
    assert stale.ext_token == "before-the-racing-write"

    fresh = pairing.load_pairing()
    assert fresh is not None
    assert fresh.ext_token == "after-the-racing-write"
