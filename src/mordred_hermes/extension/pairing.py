"""Mordred Extension pairing — codes, ECDH key agreement, and attestation.

The pairing handshake is split across two processes:

- ``hermes mordred extension pair`` (CLI) generates a code, writes it to the
  shared pending-code store, and waits for the gateway to consume it.
- The gateway's extension WebSocket server (``extension_api.py``) receives the
  ``pair_init`` frame, validates the code, performs ECDH + HKDF to derive the
  shared AES key, signs the attestation challenge, issues an ``ext_token``,
  persists the pairing, and returns ``pair_complete``.

State lives under ``~/.hermes/extension/`` with ``0600`` permissions:

- ``pending.json``  — unconsumed pairing codes (CLI ⇄ gateway handoff).
- ``state.json``    — the active pairing (shared AES key, ext_token, pubkeys).
- ``attest_key.pem`` — the P-256 attestation key (TOFU-pinned by the extension).
- ``webauthn.json`` — the optional credential managed by :mod:`.webauthn`.

WebAuthn operations remain available from this module for compatibility, while
their credential binding and assertion verification live in :mod:`.webauthn`.

See ``Mordred-Extension/SPEC.ja.md`` §3.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import math
import os
import secrets
import stat
import sys
import threading
import time
import types
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, NoReturn, TypeGuard, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .._file_lock import private_flock
from ..keyvault._storage import atomic_write, safe_read
from . import webauthn as _webauthn
from .crypto import b64u_decode, b64u_encode, derive_shared_key, x25519_public_raw
from .webauthn import (
    _active_webauthn_data as _active_webauthn_data,
)
from .webauthn import (
    _authenticator_data_matches as _authenticator_data_matches,
)
from .webauthn import (
    _client_data_matches as _client_data_matches,
)
from .webauthn import (
    _decode_webauthn_fields as _decode_webauthn_fields,
)
from .webauthn import (
    _legacy_client_origins as _legacy_client_origins,
)
from .webauthn import (
    _legacy_signed_rp_hash as _legacy_signed_rp_hash,
)
from .webauthn import (
    _migrate_legacy_webauthn_binding as _migrate_legacy_webauthn_binding,
)
from .webauthn import (
    _pairing_token_hash as _pairing_token_hash,
)
from .webauthn import (
    _parse_client_data as _parse_client_data,
)
from .webauthn import (
    _persist_legacy_webauthn_binding as _persist_legacy_webauthn_binding,
)
from .webauthn import (
    _rp_id_for_origin as _rp_id_for_origin,
)
from .webauthn import (
    _serialized_extension_origin as _serialized_extension_origin,
)
from .webauthn import (
    _signature_valid as _signature_valid,
)
from .webauthn import (
    _stored_webauthn_binding as _stored_webauthn_binding,
)
from .webauthn import (
    _webauthn_path as _webauthn_path,
)
from .webauthn import (
    authentication_generation_fingerprint as authentication_generation_fingerprint,
)
from .webauthn import (
    clear_webauthn_credential as clear_webauthn_credential,
)
from .webauthn import (
    has_webauthn_credential as has_webauthn_credential,
)
from .webauthn import (
    save_webauthn_credential as save_webauthn_credential,
)
from .webauthn import (
    verify_webauthn_assertion as verify_webauthn_assertion,
)

_WEBAUTHN_COMPAT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "_active_webauthn_data",
        "_authenticator_data_matches",
        "_client_data_matches",
        "_decode_webauthn_fields",
        "_legacy_client_origins",
        "_legacy_signed_rp_hash",
        "_migrate_legacy_webauthn_binding",
        "_pairing_token_hash",
        "_parse_client_data",
        "_persist_legacy_webauthn_binding",
        "_rp_id_for_origin",
        "_serialized_extension_origin",
        "_signature_valid",
        "_stored_webauthn_binding",
        "_webauthn_path",
        "authentication_generation_fingerprint",
        "clear_webauthn_credential",
        "has_webauthn_credential",
        "save_webauthn_credential",
        "verify_webauthn_assertion",
    }
)


class _WebauthnCompatModule(types.ModuleType):
    """Mirror writes to the pre-split WebAuthn seams onto :mod:`.webauthn`.

    The names in ``_WEBAUTHN_COMPAT_NAMES`` are static re-exports whose
    implementations resolve each other through *webauthn's* module globals.
    Before the split they lived in this module, so harnesses patched e.g.
    ``pairing._webauthn_path`` and save/clear/verify honored the patch. A
    static alias alone turns such a patch into a silent no-op — the real
    ``~/.hermes/extension/webauthn.json`` would still be written while the
    harness reads its sandbox (review 2026-07-29). Forwarding assignment
    and deletion keeps the two modules in lockstep, in both patch and
    restore directions.
    """

    def __setattr__(self, name: str, value: Any) -> None:
        if name in _WEBAUTHN_COMPAT_NAMES:
            setattr(_webauthn, name, value)
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if name in _WEBAUTHN_COMPAT_NAMES and hasattr(_webauthn, name):
            delattr(_webauthn, name)
        super().__delattr__(name)


cast(Any, sys.modules[__name__]).__class__ = _WebauthnCompatModule

# Unambiguous alphabet (no 0/O/1/I) — matches the extension and Hermes' own
# DM pairing (gateway/pairing.py).
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_TTL_SECONDS = 10 * 60
ATTEST_CONTEXT = b"mordred-ext-attest-v1"
_E2E_REPLAY_FIELD = "e2e_replay_v3"
# Raw K_chan length. AES-256-GCM throughout (crypto.derive_shared_key /
# derive_subkey both emit 32 bytes), so any other length is a malformed push.
_CHANNEL_KEY_LEN = 32
_E2E_REPLAY_TTL_SECONDS = 30 * 24 * 3600
_E2E_REPLAY_MAX_IDENTITIES = 32_768
# Warn while there is still room to act. Exhaustion refuses every authenticated
# command, so it must not be the first thing the operator learns about.
_E2E_REPLAY_WARN_THRESHOLD = (_E2E_REPLAY_MAX_IDENTITIES * 9) // 10
_LOG = logging.getLogger("mordred.extension.pairing")
_PAIRING_CODE_DIGEST_FIELD = "paired_code_sha256"
_STATE_THREAD_LOCK = threading.RLock()


class PairError(Exception):
    """Pairing rejected. ``reason`` is one of the SPEC pair_fail reasons."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def _ext_dir() -> Path:
    from .._home import hermes_home

    d = hermes_home() / "extension"
    try:
        metadata = d.lstat()
    except FileNotFoundError:
        with contextlib.suppress(FileExistsError):
            d.mkdir(mode=0o700, parents=True)
        metadata = d.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError("extension state directory must be a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        os.chmod(d, 0o700, follow_symlinks=False)
    return d


def _write_private(path: Path, data: bytes) -> None:
    """0600 atomic write, delegated to the keyvault's canonical helper.

    These files hold the pairing AES key, the ext_token and the attestation
    private key — the same class of secret the keyvault protects — so they get
    the same guarantees instead of a hand-rolled, weaker copy: unpredictable tmp
    name, ``O_EXCL | O_NOFOLLOW`` (no symlink follow / tmp pre-planting), fsync
    of the tmp fd *and* the parent dir, and tmp cleanup on failure. The parent
    directory always exists here — every caller resolves its path through
    :func:`_ext_dir`, which mkdirs it."""
    atomic_write(path, data)


def _read_json(path: Path) -> dict[str, Any]:
    """Read a private JSON-object store, tolerating only genuine absence.

    An absent store is the normal first-run state and remains represented by
    ``{}`` for compatibility with the existing callers.  Once a directory
    entry exists, however, treating an unreadable, unsafe, malformed, or
    non-object file as empty would let the next read-modify-write silently
    replace pairing credentials, pending-code evidence, or channel keys.
    Existing bad state therefore fails closed and is left byte-for-byte intact.
    """
    try:
        raw = safe_read(path)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RuntimeError(f"extension JSON store {path.name} is unreadable or corrupt") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"extension JSON store {path.name} is unreadable or corrupt") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"extension JSON store {path.name} is unreadable or corrupt")
    return data


def _read_json_strict(path: Path, purpose: str) -> dict[str, Any]:
    """Read a private JSON object, distinguishing missing/corrupt from empty."""
    try:
        raw = safe_read(path)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"{purpose} is missing, unreadable, or corrupt") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{purpose} is missing, unreadable, or corrupt")
    return data


def _reject_unsafe_state_lock(_lock_path: Path) -> NoReturn:
    """Fail closed when ``.lock`` is not a private regular file.

    Kept in this module (rather than inside ``private_flock``) so the raised
    exception stays byte-identical: a single-argument :exc:`OSError` with no
    ``errno``, unlike the ``EPERM``-tagged three-argument form the wizard
    writers raise.
    """
    raise OSError("extension state lock must be a mode-0600 regular file")


@contextlib.contextmanager
def _state_lock() -> Iterator[None]:
    """Cross-process mutex for read-modify-write cycles on the JSON stores.

    The CLI (``extension pair``) and the gateway server mutate ``pending.json``
    / ``state.json`` from different processes; without this, interleaved
    read→write cycles lose updates — e.g. two racing ``pair_init`` frames could
    both consume the same one-time code. Locked sections must stay synchronous
    (no awaits): callers run on the gateway's event loop and rely on the lock
    being held only for a quick file round-trip.

    The descriptor lifecycle (private ``O_NOFOLLOW`` open, mode-0600 assertion
    on the opened inode, ``flock`` / unlock / close ordering) is
    :func:`mordred_hermes._file_lock.private_flock`; ``_ext_dir()`` still owns
    creating and validating the parent directory, and the raise in
    :func:`_reject_unsafe_state_lock` still happens in this module so its
    exact one-argument :exc:`OSError` is unchanged.
    """
    with _STATE_THREAD_LOCK, private_flock(_ext_dir() / ".lock", on_unsafe=_reject_unsafe_state_lock):
        yield


# --------------------------------------------------------------------------- #
# Pairing code helpers
# --------------------------------------------------------------------------- #


def _format_code(raw16: str) -> str:
    return f"MORT-{raw16[:8]}-{raw16[8:16]}"


def normalize_code(code: str) -> str:
    """Canonicalize input to ``MORT-XXXXXXXX-XXXXXXXX`` (strip, upper).

    Strips a single leading ``MORT`` literal first (matching the extension's
    ``normalizeCode``) so its letters don't leak into the payload — otherwise
    ``M``/``R``/``T`` are valid alphabet chars and would shift the grouping."""
    upper = code.upper()
    if upper.startswith("MORT"):
        upper = upper[4:]
    cleaned = "".join(c for c in upper if c in _CODE_ALPHABET)
    return _format_code(cleaned[:16])


def generate_code() -> tuple[str, float]:
    """Create a pairing code, persist it as pending, return ``(code, expires_at)``."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(16))
    code = _format_code(raw)
    expires_at = time.time() + _CODE_TTL_SECONDS
    path = _ext_dir() / "pending.json"
    with _state_lock():
        pending = _read_json(path)
        # Drop expired entries to keep the file bounded.
        now = time.time()
        pending = {k: v for k, v in pending.items() if v.get("expires_at", 0) > now}
        pending[code] = {"expires_at": expires_at, "used": False, "paired_at": None}
        _write_private(path, json.dumps(pending).encode("utf-8"))
    return code, expires_at


def revoke_code(code: str) -> bool:
    """Atomically burn a pairing code that has not committed a pairing.

    A gateway may already have claimed the code and be deriving keys when the
    CLI is cancelled. Such an in-flight code is still revocable: the final
    pairing commit checks the cancellation marker under this same state lock.
    ``False`` therefore means the code was absent or its pairing had already
    reached a terminal result.
    """
    code = normalize_code(code)
    path = _ext_dir() / "pending.json"
    with _state_lock():
        pending = _read_json(path)
        entry = pending.get(code)
        if not isinstance(entry, dict) or entry.get("result") is not None:
            return False
        state = _read_state_cached()
        if state.get(_PAIRING_CODE_DIGEST_FIELD) == _pairing_code_digest(code):
            return False
        entry["used"] = True
        entry["cancelled_at"] = time.time()
        entry["result"] = "failed"
        entry["fail_reason"] = "cancelled"
        pending[code] = entry
        _write_private(path, json.dumps(pending).encode("utf-8"))
        return True


def _consume_code(code: str) -> None:
    """Validate a code against the pending store and mark it used. Raises PairError."""
    path = _ext_dir() / "pending.json"
    # The lock spans check + mark-used: without it two racing pair_init frames
    # could both see used=False and pair against the same one-time code.
    with _state_lock():
        pending = _read_json(path)
        entry = pending.get(code)
        if entry is None:
            raise PairError("invalid_code")
        if entry.get("used"):
            raise PairError("already_used")
        if entry.get("expires_at", 0) < time.time():
            raise PairError("expired")
        entry["used"] = True
        entry["paired_at"] = time.time()
        pending[code] = entry
        _write_private(path, json.dumps(pending).encode("utf-8"))


def code_consumed(code: str) -> bool:
    """Has this code been claimed by a pair_init attempt? (legacy CLI polling).

    Claimed ≠ paired: the handshake can still fail after the code is consumed.
    Prefer :func:`pair_outcome`, which distinguishes the two; this stays for
    older CLI builds and the Hermes-fork gateway's identical pending.json."""
    entry = _read_json(_ext_dir() / "pending.json").get(code)
    return bool(entry and entry.get("used"))


def _mark_pair_result(code: str, result: str, fail_reason: str | None = None) -> None:
    """Record the pair_init outcome on the consumed pending entry.

    The polling CLI reads this back via :func:`pair_outcome`; without it a
    handshake that dies *after* claiming the code is indistinguishable from a
    successful pairing. Additive fields only — servers that predate them (the
    Hermes-fork gateway) simply never write a result."""
    path = _ext_dir() / "pending.json"
    with _state_lock():
        pending = _read_json(path)
        entry = pending.get(code)
        if entry is None:  # pruned meanwhile — nothing to annotate
            return
        entry["result"] = result
        if fail_reason is not None:
            entry["fail_reason"] = fail_reason
        pending[code] = entry
        _write_private(path, json.dumps(pending).encode("utf-8"))


def pair_outcome(code: str) -> tuple[str, str | None]:
    """CLI polling: ``(state, fail_reason)``.

    ``state`` is one of:

    - ``"pending"``  — not claimed yet.
    - ``"paired"``   — handshake completed and the pairing was persisted.
    - ``"failed"``   — claimed, then rejected; ``fail_reason`` is the SPEC
      pair_fail reason. The code stays burned (single-use).
    - ``"consumed"`` — claimed with no outcome recorded: mid-handshake, or a
      server implementation that predates result recording.
    """
    code = normalize_code(code)
    with _state_lock():
        entry = _read_json(_ext_dir() / "pending.json").get(code)
        committed = _read_state_cached().get(_PAIRING_CODE_DIGEST_FIELD) == _pairing_code_digest(code)
    if committed:
        return ("paired", None)
    if not entry or not entry.get("used"):
        return ("pending", None)
    result = entry.get("result")
    if result == "paired":
        return ("paired", None)
    if result == "failed":
        return ("failed", entry.get("fail_reason") or "unknown")
    return ("consumed", None)


# --------------------------------------------------------------------------- #
# Attestation key (P-256) — persistent, TOFU-pinned by the extension
# --------------------------------------------------------------------------- #


def _load_or_create_attest_key() -> ec.EllipticCurvePrivateKey:
    path = _ext_dir() / "attest_key.pem"
    with _state_lock():
        try:
            pem = safe_read(path)
        except FileNotFoundError:
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            _write_private(path, pem)
            return key
        except OSError as exc:
            raise RuntimeError("attestation identity is unreadable; refusing replacement") from exc
        try:
            loaded_key = serialization.load_pem_private_key(pem, password=None)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("attestation identity is invalid; refusing replacement") from exc
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey) or not isinstance(loaded_key.curve, ec.SECP256R1):
            raise RuntimeError("attestation identity is invalid; refusing replacement")
        return loaded_key


def attest_pubkey_spki_b64() -> str:
    key = _load_or_create_attest_key()
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return b64u_encode(spki)


def _sign_attestation(challenge: bytes) -> str:
    """ECDSA-P256-SHA256 over ``ATTEST_CONTEXT || challenge``, returned as raw
    IEEE-P1363 (r‖s, 64 bytes) base64url — the format the extension verifies."""
    key = _load_or_create_attest_key()
    der = key.sign(ATTEST_CONTEXT + challenge, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


# --------------------------------------------------------------------------- #
# Secure-Enclave capability probe
# --------------------------------------------------------------------------- #


def se_available() -> bool:
    try:
        from mordred_hermes.keyvault import native

        return bool(native.is_secure_enclave_available())
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Active pairing state
# --------------------------------------------------------------------------- #


@dataclass
class Pairing:
    aes_key: bytes
    ext_token: str
    ext_pubkey_b64: str
    hermes_pubkey_b64: str
    paired_at: float


def _state_path() -> Path:
    return _ext_dir() / "state.json"


def _pairing_code_digest(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- #
# state.json parse cache
# --------------------------------------------------------------------------- #
#
# state.json carries the E2E replay cache (up to _E2E_REPLAY_MAX_IDENTITIES
# entries, several MB at capacity) alongside the pairing key and channel keys.
# Every authenticated WS frame reads it at least once — _authentication_is_current
# fingerprints the active pairing on every authed dispatch (extension_api.py) —
# so a bare _read_json(_state_path()) per frame put a multi-millisecond
# json.loads on the gateway's single-threaded event loop for every message
# (review 2026-08-02, PR #88 follow-up).
#
# The cache is keyed on (path, mtime_ns, size) rather than a manual dirty flag:
# the path is included because HERMES_HOME — hence state.json's location — can
# change within a process (the test suite's per-test isolated homes); mtime/size
# because that is cheap to check on every access (a stat, not a parse) and also
# catches a state.json rewritten by another process or restored from backup,
# not just this module's own writes. Every write path this module owns
# additionally calls _invalidate_state_cache() explicitly right after the write
# commits, so a fresh read is never gated on the filesystem's mtime resolution
# actually advancing between two writes issued back-to-back.
#
# That explicit invalidation only holds against a concurrent reader because of
# the generation counter below. Readers deliberately do NOT take _state_lock()
# (skipping it is the point of the fast path), so a reader can stat and parse a
# pre-write state.json, get descheduled, and only reach its cache store after a
# writer has already invalidated — re-publishing the snapshot the invalidation
# was meant to retire. Storing only when the generation is unchanged since the
# read began makes a raced read fall back to leaving the cache cold, so the
# next reader re-parses instead of trusting mtime to have advanced.
#
# Only READ-ONLY consumers of the parsed dict may use _read_state_cached(): it
# can hand back the very same dict object to multiple callers, so a read-modify
# -write cycle (_write_pairing_locked / save_channel_key /
# claim_e2e_replay_identities) must keep reading via the uncached _read_json /
# _read_json_strict — mutating the cached dict in place would let a concurrent
# reader observe an uncommitted write before it reaches disk.
_STATE_CACHE_LOCK = threading.Lock()
_state_cache: tuple[Path, int, int, dict[str, Any]] | None = None
_state_cache_generation = 0


def _state_stat_key() -> tuple[Path, int, int] | None:
    """(path, mtime_ns, size) identifying the on-disk state.json, or ``None``
    if it does not currently exist."""
    path = _state_path()
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (path, st.st_mtime_ns, st.st_size)


def _invalidate_state_cache() -> None:
    global _state_cache, _state_cache_generation
    with _STATE_CACHE_LOCK:
        _state_cache = None
        _state_cache_generation += 1


def _read_state_cached() -> dict[str, Any]:
    """Read-only, cached equivalent of ``_read_json(_state_path())``."""
    global _state_cache
    key = _state_stat_key()
    with _STATE_CACHE_LOCK:
        cached = _state_cache
        generation = _state_cache_generation
    if key is not None and cached is not None and (cached[0], cached[1], cached[2]) == key:
        return cached[3]
    data = _read_json(_state_path())
    with _STATE_CACHE_LOCK:
        if _state_cache_generation != generation:
            # A write committed while we were parsing: `data` may predate it,
            # and `key` certainly does. Leave the cache cold rather than
            # publish a snapshot the writer already invalidated.
            _state_cache = None
        else:
            _state_cache = (key[0], key[1], key[2], data) if key is not None else None
    return data


def load_pairing() -> Pairing | None:
    data = _read_state_cached()
    if not data or "aes_key" not in data:
        return None
    return Pairing(
        aes_key=b64u_decode(data["aes_key"]),
        ext_token=data["ext_token"],
        ext_pubkey_b64=data.get("ext_pubkey", ""),
        hermes_pubkey_b64=data.get("hermes_pubkey", ""),
        paired_at=data.get("paired_at", 0.0),
    )


def _write_pairing_locked(p: Pairing, *, paired_code_digest: str | None) -> None:
    """Persist *p* while the caller holds :func:`_state_lock`."""
    # Preserve any v2 keyring fields (channel_keys) already in state.
    data = _read_json(_state_path()) or {}
    data.update(
        {
            "aes_key": b64u_encode(p.aes_key),
            "ext_token": p.ext_token,
            "ext_pubkey": p.ext_pubkey_b64,
            "hermes_pubkey": p.hermes_pubkey_b64,
            "paired_at": p.paired_at,
            # Any WebAuthn file not explicitly bound to this new token is
            # from an older pairing generation and must be ignored.
            "reject_unbound_webauthn": True,
        }
    )
    if paired_code_digest is None:
        data.pop(_PAIRING_CODE_DIGEST_FIELD, None)
    else:
        data[_PAIRING_CODE_DIGEST_FIELD] = paired_code_digest
    _write_private(_state_path(), json.dumps(data).encode("utf-8"))
    _invalidate_state_cache()
    # Normal lifecycle cleanup. The state marker above remains the
    # authoritative revocation if unlink fails (permissions/race).
    # Resolved through the webauthn module (the canonical seam), not this
    # module's static alias: a harness that sandboxes the store by
    # patching webauthn._webauthn_path must also redirect this unlink,
    # or a pairing flow would delete the real production credential
    # while every other patched operation uses the sandbox
    # (review 2026-07-29).
    with _suppress_oserror():
        _webauthn._webauthn_path().unlink()


def _save_pairing(p: Pairing) -> None:
    with _state_lock():
        _write_pairing_locked(p, paired_code_digest=None)


def _commit_pairing(code: str, p: Pairing) -> None:
    """Commit a claimed code unless the polling CLI cancelled it.

    Cancellation and the state write are ordered by the same cross-process
    lock. The code digest in ``state.json`` is the authoritative commit marker
    if the best-effort outcome annotation in ``pending.json`` cannot be saved.
    """
    path = _ext_dir() / "pending.json"
    with _state_lock():
        pending = _read_json(path)
        entry = pending.get(code)
        if not isinstance(entry, dict) or not entry.get("used"):
            raise PairError("invalid_code")
        result = entry.get("result")
        if result is not None:
            reason = entry.get("fail_reason") if result == "failed" else "already_used"
            raise PairError(str(reason or "already_used"))

        _write_pairing_locked(p, paired_code_digest=_pairing_code_digest(code))

        entry["result"] = "paired"
        pending[code] = entry
        # Outcome metadata improves the polling UX, but state.json already
        # proves the commit and must not be rolled back if this annotation
        # fails after the pairing was durably saved.
        with contextlib.suppress(OSError):
            _write_private(path, json.dumps(pending).encode("utf-8"))


# --- v2 key ring (SPEC-v2 §1.3): per-channel Slack keys + extension-chat key ---


def load_channel_keys() -> dict[str, bytes]:
    """channelId → raw K_chan for every stored Slack channel key."""
    data = _read_state_cached() or {}
    out: dict[str, bytes] = {}
    for cid, kb in (data.get("channel_keys") or {}).items():
        try:
            out[cid] = b64u_decode(kb)
        except Exception:
            continue
    return out


def save_channel_key(channel_id: str, raw_key: bytes) -> None:
    """Persist a raw 32-byte channel key, rejecting anything else.

    Validating the length here rather than at the caller makes a truncated or
    mis-encoded push fail loudly *at push time*. Stored unchecked, it would
    instead surface later as ``authentication_failed`` on every command in the
    channel — indistinguishable from a genuinely wrong key, and diagnosable
    only by hand-minting a token (the #83 experience).
    """
    if len(raw_key) != _CHANNEL_KEY_LEN:
        raise ValueError(f"channel key must be exactly {_CHANNEL_KEY_LEN} bytes, got {len(raw_key)}")
    with _state_lock():
        data = _read_json(_state_path()) or {}
        ck = dict(data.get("channel_keys") or {})
        ck[channel_id] = b64u_encode(raw_key)
        data["channel_keys"] = ck
        _write_private(_state_path(), json.dumps(data).encode("utf-8"))
        _invalidate_state_cache()


def _is_replay_identity(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _replay_timestamp(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _require_active_replay_state(data: dict[str, Any]) -> None:
    aes_key_encoded = data.get("aes_key")
    try:
        active_key_valid = (
            isinstance(aes_key_encoded, str)
            and len(b64u_decode(aes_key_encoded)) == 32
            and b64u_encode(b64u_decode(aes_key_encoded)) == aes_key_encoded
        )
    except Exception:
        active_key_valid = False
    if not isinstance(data.get("ext_token"), str) or not data.get("ext_token") or not active_key_valid:
        raise RuntimeError("active pairing required for E2E replay protection")


def _replay_relief_description(kept: list[dict[str, Any]], now: float) -> str:
    """Describe when TTL pruning will next free replay-cache capacity."""
    timestamps = [entry["accepted_at"] for entry in kept if isinstance(entry.get("accepted_at"), (int, float))]
    if not timestamps:
        return "the next TTL sweep"
    expires_at = min(timestamps) + _E2E_REPLAY_TTL_SECONDS
    stamp = datetime.fromtimestamp(expires_at, tz=UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    hours_left = max(0.0, (expires_at - now) / 3600.0)
    return f"{stamp} (~{hours_left:.0f}h)"


def _warn_if_replay_cache_filling(used: int) -> None:
    """Log before the cache wedges, so exhaustion is not the first signal."""
    if used >= _E2E_REPLAY_WARN_THRESHOLD:
        _LOG.warning(
            "E2E replay cache is %d/%d full; once full, authenticated commands are "
            "refused until 30-day-old entries expire.",
            used,
            _E2E_REPLAY_MAX_IDENTITIES,
        )


def _retained_replay_entries(
    raw_entries: Any,
    *,
    accepted_at: float,
) -> tuple[list[dict[str, Any]], set[str]]:
    if raw_entries is None:
        return [], set()
    if not isinstance(raw_entries, list):
        raise RuntimeError("invalid E2E replay state")

    cutoff = accepted_at - _E2E_REPLAY_TTL_SECONDS
    kept: list[dict[str, Any]] = []
    known: set[str] = set()
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise RuntimeError("invalid E2E replay entry")
        identity = raw.get("id")
        timestamp = _replay_timestamp(raw.get("accepted_at"))
        if not _is_replay_identity(identity) or timestamp is None:
            raise RuntimeError("invalid E2E replay entry")
        # Future timestamps are retained: a backwards clock jump must not
        # erase replay evidence.
        if timestamp >= cutoff or timestamp > accepted_at:
            kept.append({"id": identity, "accepted_at": timestamp})
            known.add(identity)
    return kept, known


def claim_e2e_replay_identities(
    identities: tuple[str, ...],
    *,
    now: float | None = None,
) -> bool:
    """Atomically persist authenticated E2E-v3 replay identities.

    Returns ``False`` if any identity was already accepted, otherwise records
    all of them and returns ``True``. The 30-day TTL-bounded cache lives in the
    private pairing state so a gateway restart cannot make captured commands
    fresh again. Unexpired evidence is never evicted merely to meet its size
    cap: capacity exhaustion raises and therefore fails the command closed
    until TTL pruning frees space. Callers provide only domain-separated
    SHA-256 hex digests; raw message IDs and nonces are never persisted.
    """
    if not identities or any(not _is_replay_identity(identity) for identity in identities):
        raise ValueError("invalid E2E replay identity")
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate E2E replay identity")

    accepted_at = time.time() if now is None else now
    with _state_lock():
        data = _read_json_strict(_state_path(), "E2E replay state store")
        _require_active_replay_state(data)
        kept, known = _retained_replay_entries(
            data.get(_E2E_REPLAY_FIELD),
            accepted_at=accepted_at,
        )

        if any(identity in known for identity in identities):
            return False
        if len(kept) + len(identities) > _E2E_REPLAY_MAX_IDENTITIES:
            # Never make room by evicting unexpired evidence: that would
            # reopen replay of an older authenticated command. Refuse new
            # commands until normal TTL pruning frees bounded state instead.
            #
            # Say *when* capacity returns: the operator's only lever is waiting
            # for the oldest entry's TTL, so an opaque "exhausted" leaves them
            # with a dead channel and no idea whether it is permanent.
            raise RuntimeError(
                "E2E replay cache capacity exhausted "
                f"({len(kept)}/{_E2E_REPLAY_MAX_IDENTITIES} unexpired identities). "
                "Commands are refused rather than evicting replay evidence. "
                f"Capacity frees up from {_replay_relief_description(kept, accepted_at)}."
            )
        _warn_if_replay_cache_filling(len(kept) + len(identities))
        kept.extend({"id": identity, "accepted_at": accepted_at} for identity in identities)
        data[_E2E_REPLAY_FIELD] = kept
        _write_private(_state_path(), json.dumps(data, separators=(",", ":")).encode("utf-8"))
        _invalidate_state_cache()
        return True


# NOTE: there is deliberately no load/save_extchat_key here. K_extchat is always
# DERIVED fresh from the pairing master key (``api._extchat_key`` →
# ``hkdf_subkey``); a persisted copy was written and read by nobody and would
# only invite a derive-vs-stored mismatch after a re-pair.


def clear_pairing() -> None:
    with _state_lock():
        for name in ("state.json", "webauthn.json"):
            with _suppress_oserror():
                (_ext_dir() / name).unlink()
        _invalidate_state_cache()


class _suppress_oserror:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, *_: Any) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


def validate_token(ext_token: str) -> bool:
    p = load_pairing()
    if p is None or not ext_token:
        return False
    return secrets.compare_digest(p.ext_token, ext_token)


# --------------------------------------------------------------------------- #
# pair_init handler (gateway side)
# --------------------------------------------------------------------------- #


def handle_pair_init(code: str, ext_pubkey_b64: str, challenge_b64: str) -> dict[str, Any]:
    """Validate the code, derive the shared key, persist the pairing, and return
    the ``pair_complete`` payload. Raises :class:`PairError` on rejection.

    The outcome is recorded back onto the consumed pending entry (see
    :func:`_mark_pair_result`) so the polling CLI reports rejection instead of
    a false "Paired" when the handshake dies after the code is claimed."""
    code = normalize_code(code)
    _consume_code(code)  # raises on invalid/expired/used — nothing to record

    try:
        try:
            challenge = b64u_decode(challenge_b64)
        except Exception as exc:
            raise PairError("invalid_challenge") from exc
        if len(challenge) < 16:
            raise PairError("invalid_challenge")

        hermes_priv = X25519PrivateKey.generate()
        try:
            aes_key = derive_shared_key(hermes_priv, ext_pubkey_b64, code)
        except Exception as exc:
            raise PairError("invalid_pubkey") from exc

        hermes_pub_b64 = b64u_encode(x25519_public_raw(hermes_priv))
        ext_token = b64u_encode(secrets.token_bytes(32))

        # Everything that can fail (attestation signing included) runs BEFORE
        # _save_pairing: a failure after the save would have replaced a
        # previously-working pairing's key/token with a half-completed one.
        payload = {
            "hermes_pubkey": hermes_pub_b64,
            "ext_token": ext_token,
            "attestation": {
                "signed_challenge": _sign_attestation(challenge),
                "se_pubkey": attest_pubkey_spki_b64(),
                "se_available": se_available(),
            },
        }

        _commit_pairing(
            code,
            Pairing(
                aes_key=aes_key,
                ext_token=ext_token,
                ext_pubkey_b64=ext_pubkey_b64,
                hermes_pubkey_b64=hermes_pub_b64,
                paired_at=time.time(),
            ),
        )
    except PairError as exc:
        # Outcome marking is best-effort UX metadata — never let its I/O
        # failure mask the PairError the extension's pair_fail frame needs.
        with contextlib.suppress(OSError):
            _mark_pair_result(code, "failed", exc.reason)
        raise
    except Exception:
        with contextlib.suppress(OSError):
            _mark_pair_result(code, "failed", "internal_error")
        raise

    return payload
