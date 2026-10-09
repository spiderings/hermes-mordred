"""``hermes-mordred keyvault {list,verify-digest,recover,init}`` — keyvault CLI.

Phase 4 PR8 (``list`` / ``verify-digest``) + PR10 (``recover`` / ``init``).
SPEC.md §4.2 / TODO.md §4.2.

``list`` / ``verify-digest`` only *read* the on-disk keyvault layout
(``meta.json`` + ``digests/<key_id_hash>.commit``); they need neither a
Secure-Enclave ``NativeBackend`` nor the ``cryptography`` stack, so the
read helpers import on any platform.

- ``list`` — print each key's cleartext id, on-disk hash and creation
  timestamp. The verification digest (key material) is never printed.
- ``verify-digest`` — print the full 32-byte verification digest of
  every key, hex-encoded, so the operator can cross-check it against the
  value recorded on a second device at generation time.
- ``recover`` — restore a keyvault from an :func:`export_backup` blob.
  Backend-coupled: it builds a production ``_SecKeyBackend`` and calls
  :func:`mordred_hermes.keyvault.api.import_backup` (PR9 landed the
  backend). The heavy imports stay function-local so this module still
  imports on any platform.
- ``init`` — the air-gap-gated generation ceremony, which lives in
  :mod:`mordred_hermes.wizard._keyvault_init` and is re-exported here as
  :func:`init_keyvault` / :class:`TerminalSeedSurface`.

The wizard owns reads over ``~/.hermes/mordred/keyvault/``; ``keyvault``
itself remains the sole writer (PATHS.md).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._home import hermes_home as _hermes_home
from ..keyvault import _native_key_id, _storage
from . import _term
from ._defaults import resolve_backend, resolve_prompt_io
from ._keyvault_init import (
    TerminalSeedSurface,
    _provision_audit_log_key,
    _stderr_audit_sink,
    init_keyvault,
)
from ._keyvault_init import (
    _blackout_guidance as _blackout_guidance,  # re-exported for tests
)

if TYPE_CHECKING:
    from ..keyvault.wrap import AuditSink, NativeBackend
    from .configure import PromptIO

__all__ = [
    "TerminalSeedSurface",
    "cli_init",
    "cli_list",
    "cli_recover",
    "cli_reset",
    "cli_verify_digest",
    "init_keyvault",
    "list_keys",
    "recover",
    "reset_keyvault",
    "verify_digest",
]


def _resolve_root(home: Path | None) -> Path:
    """Resolve the keyvault root, defaulting the Hermes home via :func:`_hermes_home`.

    The home is resolved here (not deferred to ``resolve_keyvault_dir``'s
    own default) so tests can monkeypatch this module's :func:`_hermes_home`
    to point at a ``tmp_path``.
    """
    return _storage.resolve_keyvault_dir(home if home is not None else _hermes_home())


def _terminal_safe(value: object) -> str:
    """Render persisted values without emitting terminal control characters."""

    text = value if isinstance(value, str) else str(value)
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _load_meta_or_report(root: Path) -> dict[str, Any] | None:
    """``load_meta`` with the read commands' shared corrupt/unreadable reporting.

    Returns ``None`` after printing the error (callers return 1) so the two
    read-only commands can't drift apart on wording or remediation hints.
    """
    try:
        with _storage.keyvault_read_lock(root) as profile_present:
            if not profile_present:
                return {"version": 1, "keys": {}}
            _storage.assert_keyvault_active(root)
            return _storage.load_meta(root)
    except _storage.KeyvaultCorruptError as exc:
        _term.emit_error(
            f"keyvault metadata is corrupt ({root / 'meta.json'}): {exc}. "
            "Run `hermes-mordred keyvault recover` from a backup blob, or "
            "`hermes-mordred keyvault reset` to discard this keyvault and start over."
        )
        return None
    except OSError as exc:
        _term.emit_error(f"cannot read keyvault metadata ({root / 'meta.json'}): {exc}")
        return None


def _validated_metadata_key_row(key_id_hash: str, row: object) -> tuple[str, dict[str, Any]] | None:
    """Validate a CLI-visible metadata row and its canonical object key."""

    if not isinstance(row, dict):
        return None
    try:
        key_id = _native_key_id.validate_main_key_id(row.get("key_id"))
        expected_key_id_hash = hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()
    except (_native_key_id.InvalidMainKeyId, UnicodeEncodeError):
        return None
    if key_id_hash != expected_key_id_hash:
        return None
    return key_id, row


def _validated_digest_dir_or_report(root: Path) -> Path | None:
    """Return the safe digest directory, reporting an unsafe parent cleanly."""

    digests_dir = root / "digests"
    try:
        # ``safe_read`` validates only the final file component. The parent
        # must be a real mode-0700 directory before any metadata-derived
        # commit path is constructed.
        _storage._check_dir_mode(digests_dir)
    except OSError as exc:
        _term.emit_error(f"cannot inspect keyvault digest directory: {exc}")
        return None
    return digests_dir


def _display_verification_digest(digests_dir: Path, key_id_hash: str, row: object) -> bool:
    """Validate and print one digest; return whether the row was usable."""

    validated = _validated_metadata_key_row(key_id_hash, row)
    if validated is None:
        # The object key is metadata-controlled. Reject it before constructing
        # a path so traversal-shaped hashes can never escape ``digests/``.
        _term.emit_error("  keyvault metadata contains an invalid key row or hash")
        return False
    display_key_id = _terminal_safe(validated[0])
    commit = digests_dir / f"{key_id_hash}.commit"
    try:
        digest = _storage.safe_read(commit)
    except OSError as exc:
        _term.emit_error(f"  {display_key_id}  (hash {key_id_hash}): digest unavailable — {exc}")
        return False
    if len(digest) != 32:
        _term.emit_error(f"  {display_key_id}  (hash {key_id_hash}): digest must be exactly 32 bytes")
        return False
    print(f"  {display_key_id}  (hash {key_id_hash}): {digest.hex()}")
    return True


def list_keys(*, home: Path | None = None, as_json: bool = False) -> int:
    """Print the keyvault's key ids. Returns 0 always (an empty vault is not an error).

    Returns 1 when the on-disk keyvault state cannot be read at all (corrupt
    ``meta.json`` / unreadable file) — the read fails before there is
    anything to list, so this is a genuine error, not an empty vault.
    """
    import json

    root = _resolve_root(home)
    meta = _load_meta_or_report(root)
    if meta is None:
        return 1
    if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
        _term.emit_error("Keyvault native-key provisioning is incomplete; run `hermes-mordred keyvault reset`.")
        return 1
    keys = meta["keys"]
    validated_rows: list[tuple[str, str, dict[str, Any]]] = []
    for key_id_hash in sorted(keys):
        validated = _validated_metadata_key_row(key_id_hash, keys[key_id_hash])
        if validated is None:
            _term.emit_error("keyvault metadata contains an invalid key row")
            return 1
        validated_rows.append((key_id_hash, validated[0], validated[1]))
    if as_json:
        rows = [
            {
                "key_id": key_id,
                "key_id_hash": key_id_hash,
                "created_at": row.get("created_at", "<unknown>"),
            }
            for key_id_hash, key_id, row in validated_rows
        ]
        print(json.dumps(rows, indent=2))
        return 0
    if not keys:
        print("No keys in keyvault.")
        return 0
    print(f"{len(keys)} key(s) in keyvault:")
    for key_id_hash, key_id, row in validated_rows:
        created = row.get("created_at", "<unknown>")
        print(f"  {_terminal_safe(key_id)}  (hash {key_id_hash}, created {_terminal_safe(created)})")
    return 0


def verify_digest(*, home: Path | None = None) -> int:
    """Print every key's full verification digest for offline cross-checking.

    Returns 0 when every digest was read, 1 when the vault is empty, any
    ``digests/<hash>.commit`` file could not be read, or ``meta.json`` itself
    is corrupt/unreadable.
    """
    root = _resolve_root(home)
    try:
        # Keep the metadata row set and every corresponding commit read in one
        # lifecycle snapshot. Otherwise reset can publish its journal/remove
        # the tree after meta.json is read but before the digest files are read.
        with _storage.keyvault_read_lock(root) as profile_present:
            if not profile_present:
                _term.emit_error("No keys to verify in keyvault.")
                return 1
            meta = _load_meta_or_report(root)
            if meta is None:
                return 1
            if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
                _term.emit_error("Keyvault native-key provisioning is incomplete; run `hermes-mordred keyvault reset`.")
                return 1
            keys = meta["keys"]
            if not keys:
                _term.emit_error("No keys to verify in keyvault.")
                return 1
            digests_dir = _validated_digest_dir_or_report(root)
            if digests_dir is None:
                return 1

            rc = 0
            print("Verification digests (compare against the value recorded at generation time):")
            for key_id_hash in sorted(keys):
                if not _display_verification_digest(digests_dir, key_id_hash, keys[key_id_hash]):
                    rc = 1
            return rc
    except OSError as exc:
        _term.emit_error(f"cannot read keyvault metadata ({root / 'meta.json'}): {exc}")
        return 1


def _preflight_recovery_imports() -> None:
    """Resolve the recovery stack before any secret is prompted for.

    Before the split into helpers, ``recover`` imported the crypto-backed modules
    right after reading the blob — so a broken install failed *before* the
    operator typed the Seed Phrase. The helpers below import lazily; this keeps
    that ordering by importing the same modules up front.
    """
    for name in (
        "cryptography.exceptions",
        "mordred_hermes.keyvault._bip39",
        "mordred_hermes.keyvault.api",
        "mordred_hermes.keyvault.pow",
        "mordred_hermes.keyvault.backup",
        "mordred_hermes.keyvault.recovery",
    ):
        importlib.import_module(name)


def _read_backup_blob(blob_path: Path) -> bytes | None:
    """Read the backup blob, reporting (and returning ``None`` on) an OSError.

    Split out of :func:`recover` for cyclomatic headroom only — same message,
    same exit behaviour (the caller returns 1 on ``None``).
    """
    try:
        return blob_path.read_bytes()
    except OSError as exc:
        _term.emit_error(f"cannot read backup blob {blob_path}: {exc}")
        return None


def _validated_seed_and_pow(seed_phrase: str) -> tuple[str, bytes] | None:
    """Normalize the Seed Phrase, validate its BIP39 checksum, and compute the PoW.

    Returns ``(normalized_seed, pow_bytes)`` on success or ``None`` (already
    reported) when the checksum fails. Split out of :func:`recover` for
    cyclomatic headroom only — the checksum validation and its error message,
    and the PoW computation, are unchanged and in the same order.
    """
    from ..keyvault import _bip39, api
    from ..keyvault import pow as kvpow

    # Validate the BIP39 checksum up front for a legible error. import_backup
    # would also reject a mistyped seed, but later and via a digest mismatch.
    normalized_seed = api._normalize_seed_phrase(seed_phrase)
    try:
        _bip39.mnemonic_to_entropy(normalized_seed)
    except ValueError as exc:
        _term.emit_error(f"Seed Phrase rejected: {exc}")
        return None

    # PoW is a deterministic function of the normalized seed (SPEC
    # §"Proof-of-Work (PoW) algorithm"), so recovery recomputes it rather
    # than asking the operator to transcribe 32 more bytes.
    pow_bytes = kvpow.compute_pow(normalized_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    return normalized_seed, pow_bytes


def _import_backup_or_report(
    *,
    blob: bytes,
    passphrase: str,
    seed_phrase: str,
    pow_bytes: bytes,
    backend: NativeBackend,
    sink: AuditSink,
    home: Path | None,
    prompt_io: PromptIO,
) -> str | None:
    """Import the backup, retrying once with a legacy backup passphrase on ``InvalidTag``.

    Returns the imported ``key_id`` on success, or ``None`` after reporting the
    failure. Split out of :func:`recover` for cyclomatic headroom only: every
    exception type, message, and the InvalidTag -> legacy-prompt -> retry
    sequence are unchanged, in the same order. The legacy backup passphrase
    (prompted for only on that retry) never leaves this frame — its reference
    is dropped when the function returns.
    """
    from cryptography.exceptions import InvalidTag

    from ..keyvault import api
    from ..keyvault._exceptions import WrapError
    from ..keyvault.backup import BackupCorrupt, BackupImportConflict
    from ..keyvault.recovery import RecoveryDigestMismatch

    legacy_backup_passphrase: str | None = None

    try:
        try:
            key_id = api.import_backup(
                blob,
                passphrase,
                seed_phrase=seed_phrase,
                pow_bytes=pow_bytes,
                backend=backend,
                audit_sink=sink,
                home=home,
            )
        except InvalidTag:
            # Older export_backup accepted an arbitrary KDF passphrase while
            # embedding a digest committed under the recovery passphrase. Such
            # a blob needs both values. Ask only after the normal, consistent
            # path fails authentication; current backups still use two prompts.
            legacy_backup_passphrase = prompt_io.ask_password(
                "Legacy backup encryption passphrase (leave blank to cancel)"
            )
            if not legacy_backup_passphrase:
                _term.emit_error(
                    "Recovery rejected: backup ciphertext authentication failed "
                    "(wrong legacy encryption passphrase or a tampered blob)."
                )
                return None
            key_id = api.import_backup(
                blob,
                passphrase,
                seed_phrase=seed_phrase,
                pow_bytes=pow_bytes,
                backend=backend,
                audit_sink=sink,
                home=home,
                backup_passphrase=legacy_backup_passphrase,
            )
    except RecoveryDigestMismatch:
        _term.emit_error(
            "Recovery rejected: the verification digest does not match — the Seed "
            "Phrase or Passphrase was mis-transcribed."
        )
        return None
    except BackupCorrupt as exc:
        _term.emit_error(f"Recovery rejected: backup blob is corrupt — {exc}")
        return None
    except BackupImportConflict as exc:
        _term.emit_error(
            f"Recovery rejected: destination keyvault is not fresh — {exc}. "
            "Use a new Hermes home, or verify a backup and reset the existing keyvault first."
        )
        return None
    except InvalidTag:
        _term.emit_error(
            "Recovery rejected: backup ciphertext authentication failed "
            "(wrong legacy encryption passphrase or a tampered blob)."
        )
        return None
    except WrapError as exc:
        _term.emit_error(f"Recovery failed: Secure Enclave error — {exc}")
        return None
    return key_id


def recover(
    *,
    blob_path: Path,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    audit_sink: AuditSink | None = None,
) -> int:
    """Restore a keyvault from an ``export_backup`` blob on this device.

    Reads the blob at ``blob_path``, prompts for the 24-word Seed Phrase
    and the Passphrase, recomputes the seed-bound PoW, and restores the
    keyvault via :func:`mordred_hermes.keyvault.api.import_backup`.

    ``backend=None`` builds the production Secure-Enclave backend;
    ``prompt_io=None`` uses the prompt_toolkit-backed prompts. Both are
    injected by tests.

    Returns 0 on success; 1 on an unreadable/corrupt blob, a Seed Phrase
    that fails the BIP39 checksum, a verification-digest mismatch
    (mis-transcribed seed/passphrase), or a Secure Enclave failure.
    """
    blob = _read_backup_blob(blob_path)
    if blob is None:
        return 1
    _preflight_recovery_imports()

    prompt_io = resolve_prompt_io(prompt_io)
    # Security review H5: the Seed Phrase is the keyvault's root secret —
    # collect it masked (ask_password), never with terminal echo
    # (ask_text), so it does not land in scrollback or a shared TTY.
    seed_phrase = prompt_io.ask_password("24-word Seed Phrase")
    passphrase = prompt_io.ask_password("Passphrase")

    validated = _validated_seed_and_pow(seed_phrase)
    if validated is None:
        return 1
    normalized_seed, pow_bytes = validated
    del validated  # the tuple would otherwise keep the normalized seed alive past the final del

    backend = resolve_backend(backend)
    sink = audit_sink if audit_sink is not None else _stderr_audit_sink

    key_id = _import_backup_or_report(
        blob=blob,
        passphrase=passphrase,
        seed_phrase=seed_phrase,
        pow_bytes=pow_bytes,
        backend=backend,
        sink=sink,
        home=home,
        prompt_io=prompt_io,
    )
    if key_id is None:
        return 1

    _provision_audit_log_key(backend, home=home)
    # L2 (PR #39 review): import_backup has consumed the seed/passphrase;
    # drop the str references (CPython cannot zero an immutable str in
    # place — this shortens the exposure window rather than scrubbing it).
    # The legacy backup passphrase, if prompted for, was local to
    # _import_backup_or_report and is already gone with that frame.
    del seed_phrase, passphrase, normalized_seed
    print(f"Keyvault recovered. Imported key: {_terminal_safe(key_id)}")
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_list(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault list [--json]``."""
    return list_keys(as_json=bool(getattr(args, "json", False)))


def cli_verify_digest(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault verify-digest`` (takes no options)."""
    del args
    return verify_digest()


def cli_recover(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault recover --blob <path>``."""
    return recover(blob_path=Path(args.blob))


def cli_init(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault init`` (encrypted seed storage by default)."""
    return init_keyvault(store_seed_for_hd=getattr(args, "store_seed_for_hd", True))


def cli_reset(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault reset [--yes]``."""
    return reset_keyvault(assume_yes=bool(getattr(args, "assume_yes", False)))


# -----------------------------------------------------------------------------
# keyvault reset — destroy all key material (irreversible).
# -----------------------------------------------------------------------------

#: Phrase the operator must type to confirm an interactive reset.
_RESET_CONFIRM_PHRASE = "reset"
_RESET_JOURNAL_VERSION = 1


@dataclass(frozen=True)
class _ResetJournal:
    """Validated state needed to finish an interrupted reset."""

    key_ids: dict[str, str]
    retained_legacy: list[str]
    metadata_incomplete: bool
    root_identity: tuple[int, int]


def _classify_reset_row(
    root: Path,
    metadata_key_hash: object,
    row: object,
) -> tuple[str, str | None, bool] | None:
    """Return ``(logical, physical-or-legacy-None, metadata_incomplete)``.

    A malformed persisted physical selector is never returned. When the row
    still has a valid logical main-key id, its deterministic current-profile
    selector is safe to clean up and the row is marked incomplete.
    """

    if not isinstance(row, dict):
        return None
    key_id = row.get("key_id")
    try:
        key_id = _native_key_id.validate_main_key_id(key_id)
    except _native_key_id.InvalidMainKeyId:
        return None
    try:
        expected_key_hash = hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()
    except UnicodeEncodeError:
        return None
    row_incomplete = metadata_key_hash != expected_key_hash
    if _native_key_id.NATIVE_KEY_ID_FIELD not in row:
        return key_id, None, row_incomplete
    try:
        return key_id, _native_key_id.native_key_id_from_row(root, key_id, row), row_incomplete
    except _native_key_id.NativeKeyIdMismatch:
        return key_id, _native_key_id.scoped_native_key_id(root, key_id), True


def _pending_reset_target(root: Path, meta: dict[str, Any]) -> tuple[tuple[str, str] | None, bool]:
    """Return a safe pending-main target and whether its metadata is corrupt."""

    if _native_key_id.PENDING_NATIVE_KEY_FIELD not in meta:
        return None, False
    try:
        pending = _native_key_id.pending_native_key_from_meta(root, meta)
        if pending is None:  # pragma: no cover - field presence guarantees a result
            raise _native_key_id.NativeKeyIdMismatch("pending native-key ownership journal is malformed")
        pending_logical = _native_key_id.validate_main_key_id(pending[0])
    except (_native_key_id.InvalidMainKeyId, _native_key_id.NativeKeyIdMismatch):
        # Recover only the logical id from a malformed journal. Its physical
        # selector is untrusted; derive the profile-owned target.
        raw_pending = meta[_native_key_id.PENDING_NATIVE_KEY_FIELD]
        raw_logical = raw_pending.get("key_id") if isinstance(raw_pending, Mapping) else None
        try:
            pending_logical = _native_key_id.validate_main_key_id(raw_logical)
        except _native_key_id.InvalidMainKeyId:
            return None, True
        return (pending_logical, _native_key_id.scoped_native_key_id(root, pending_logical)), True
    return (pending_logical, pending[1]), False


def _audit_reset_target(root: Path, meta: dict[str, Any], logical_key_id: str) -> tuple[str | None, bool]:
    """Validate audit ownership records without trusting malformed selectors."""

    valid_targets: set[str] = set()
    incomplete = False
    for field, reader in (
        (_native_key_id.AUDIT_KEY_FIELD, _native_key_id.committed_audit_key_from_meta),
        (_native_key_id.PENDING_AUDIT_KEY_FIELD, _native_key_id.pending_audit_key_from_meta),
    ):
        if field not in meta:
            continue
        try:
            physical = reader(root, meta, logical_key_id)
        except _native_key_id.NativeKeyIdMismatch:
            incomplete = True
            continue
        if physical is not None:
            valid_targets.add(physical)
    if len(valid_targets) == 1:
        return valid_targets.pop(), incomplete
    # Disagreeing records are corrupt. The caller retains its canonical known
    # target and warns that manual cleanup may be necessary.
    return None, incomplete or len(valid_targets) > 1


def _collect_reset_key_ids(root: Path) -> tuple[dict[str, str], list[str], bool]:
    """Return ``(owned_targets, retained_legacy, metadata_incomplete)``.

    ``owned_targets`` maps operator-facing logical ids to deterministic
    profile-scoped physical ids.  A legacy metadata row has no
    ``native_key_id`` and cannot prove exclusive ownership of its machine-global
    Keychain tag, so reset retains that tag rather than risking deletion of a
    different ``HERMES_HOME`` profile's key.

    Corrupt/missing metadata cannot safely name custom keys.  The two
    well-known *scoped* ids are still safe to attempt because their physical ids
    are derived from this root, but no legacy logical id is ever inferred.
    """
    from ..keyvault.api import _DEFAULT_KEY_ID
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID

    targets: dict[str, str] = {
        _DEFAULT_KEY_ID: _native_key_id.scoped_native_key_id(root, _DEFAULT_KEY_ID),
        AUDIT_LOG_KEY_ID: _native_key_id.scoped_native_key_id(root, AUDIT_LOG_KEY_ID),
    }
    retained_legacy: list[str] = []
    metadata_incomplete = False
    try:
        meta = _storage.load_meta(root)
    except _storage.KeyvaultCorruptError:
        metadata_incomplete = True
        meta = {"keys": {}}
    if not (root / "meta.json").exists():
        metadata_incomplete = True

    for metadata_key_hash, row in meta.get("keys", {}).items():
        classified = _classify_reset_row(root, metadata_key_hash, row)
        if classified is None:
            metadata_incomplete = True
            continue
        key_id, physical, row_incomplete = classified
        metadata_incomplete = metadata_incomplete or row_incomplete
        if physical is None:
            retained_legacy.append(key_id)
            continue
        targets[key_id] = physical

    pending_target, pending_incomplete = _pending_reset_target(root, meta)
    metadata_incomplete = metadata_incomplete or pending_incomplete
    if pending_target is not None:
        targets[pending_target[0]] = pending_target[1]

    # Audit ownership records are auxiliary but still part of the reset
    # schema. Validate them so malformed selectors produce the incomplete
    # cleanup warning. Never use an invalid persisted selector; the canonical
    # scoped audit target seeded above remains safe and sufficient.
    audit_target, audit_incomplete = _audit_reset_target(root, meta, AUDIT_LOG_KEY_ID)
    metadata_incomplete = metadata_incomplete or audit_incomplete
    if audit_target is not None:
        targets[AUDIT_LOG_KEY_ID] = audit_target

    # The global legacy audit tag is retained whenever any legacy main row
    # exists. The scoped known ids above are always safe/idempotent cleanup
    # targets, including after a failed first generation with no committed row.
    if retained_legacy:
        retained_legacy.append(AUDIT_LOG_KEY_ID)

    return dict(sorted(targets.items())), sorted(set(retained_legacy)), metadata_incomplete


def _encode_reset_journal(
    root: Path,
    key_ids: dict[str, str],
    retained_legacy: list[str],
    metadata_incomplete: bool,
) -> tuple[_ResetJournal, bytes]:
    """Build the durable recovery record committed before native deletion."""
    root_meta = root.lstat()
    journal = _ResetJournal(
        key_ids=dict(sorted(key_ids.items())),
        retained_legacy=sorted(set(retained_legacy)),
        metadata_incomplete=metadata_incomplete,
        root_identity=(root_meta.st_dev, root_meta.st_ino),
    )
    payload = {
        "version": _RESET_JOURNAL_VERSION,
        "root_identity": {
            "device": journal.root_identity[0],
            "inode": journal.root_identity[1],
        },
        "targets": [
            {
                "key_id": key_id,
                _native_key_id.NATIVE_KEY_ID_FIELD: native_key_id,
            }
            for key_id, native_key_id in journal.key_ids.items()
        ],
        "retained_legacy": journal.retained_legacy,
        "metadata_incomplete": journal.metadata_incomplete,
    }
    return journal, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_reset_journal(  # noqa: C901, PLR0912 - strict schema validation is intentionally explicit
    root: Path,
) -> _ResetJournal:
    """Read and strictly validate a pending stable-parent reset journal."""
    try:
        payload = json.loads(_storage.safe_read(_storage.reset_journal_path(root)))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _storage.KeyvaultCorruptError("reset journal is not valid JSON") from exc
    required_fields = {
        "version",
        "root_identity",
        "targets",
        "retained_legacy",
        "metadata_incomplete",
    }
    if not isinstance(payload, dict) or set(payload) != required_fields:
        raise _storage.KeyvaultCorruptError("reset journal has an invalid schema")
    if type(payload["version"]) is not int or payload["version"] != _RESET_JOURNAL_VERSION:
        raise _storage.KeyvaultCorruptError("reset journal has an unsupported version")

    identity = payload["root_identity"]
    if not isinstance(identity, dict) or set(identity) != {"device", "inode"}:
        raise _storage.KeyvaultCorruptError("reset journal has an invalid root identity")
    device = identity["device"]
    inode = identity["inode"]
    if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
        raise _storage.KeyvaultCorruptError("reset journal has an invalid root identity")

    rows = payload["targets"]
    if not isinstance(rows, list):
        raise _storage.KeyvaultCorruptError("reset journal targets must be a list")
    key_ids: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"key_id", _native_key_id.NATIVE_KEY_ID_FIELD}:
            raise _storage.KeyvaultCorruptError("reset journal has an invalid target")
        key_id = row["key_id"]
        native_key_id = row[_native_key_id.NATIVE_KEY_ID_FIELD]
        if not isinstance(key_id, str) or not key_id or not isinstance(native_key_id, str):
            raise _storage.KeyvaultCorruptError("reset journal has an invalid target")
        if key_id in key_ids:
            raise _storage.KeyvaultCorruptError("reset journal contains a duplicate logical key id")
        try:
            validated_native_key_id = _native_key_id.persisted_native_key_id(root, key_id, native_key_id)
        except _native_key_id.NativeKeyIdMismatch as exc:
            raise _storage.KeyvaultCorruptError("reset journal target does not belong to this profile") from exc
        key_ids[key_id] = validated_native_key_id

    from ..keyvault.api import _DEFAULT_KEY_ID
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID

    if not {_DEFAULT_KEY_ID, AUDIT_LOG_KEY_ID} <= key_ids.keys():
        raise _storage.KeyvaultCorruptError("reset journal is missing a required profile-owned target")

    retained = payload["retained_legacy"]
    if (
        not isinstance(retained, list)
        or any(not isinstance(key_id, str) or not key_id for key_id in retained)
        or len(set(retained)) != len(retained)
    ):
        raise _storage.KeyvaultCorruptError("reset journal has an invalid retained-legacy list")
    metadata_incomplete = payload["metadata_incomplete"]
    if not isinstance(metadata_incomplete, bool):
        raise _storage.KeyvaultCorruptError("reset journal has an invalid metadata-incomplete flag")

    return _ResetJournal(
        key_ids=dict(sorted(key_ids.items())),
        retained_legacy=sorted(retained),
        metadata_incomplete=metadata_incomplete,
        root_identity=(device, inode),
    )


def _confirm_reset(
    prompt_io: PromptIO,
    key_ids: list[str],
    retained_legacy: list[str] | None = None,
) -> bool:
    """Show the irreversible-destruction warning and require the operator to type
    the confirmation phrase. Returns True only on an exact (stripped) match.
    """
    retained_note = ""
    if retained_legacy:
        displayed_retained = ", ".join(_terminal_safe(key_id) for key_id in retained_legacy)
        retained_note = f"  Legacy global keys retained (exclusive ownership is unproven): {displayed_retained}\n"
    displayed_key_ids = ", ".join(_terminal_safe(key_id) for key_id in key_ids)
    print(
        "\n"
        "WARNING: keyvault reset DESTROYS the listed profile-owned key material — "
        "this cannot be undone.\n"
        "  The only way back is `keyvault recover` with your 24-word Seed Phrase,\n"
        "  Passphrase and backup blob. Without them, any wallet or secret derived\n"
        "  from this keyvault is lost permanently.\n"
        f"  Keys to destroy: {displayed_key_ids}\n"
        f"{retained_note}",
        file=sys.stderr,
    )
    answer = prompt_io.ask_text(f"Type {_RESET_CONFIRM_PHRASE!r} to confirm")
    return answer.strip() == _RESET_CONFIRM_PHRASE


def _delete_wrapping_keys(
    key_ids: dict[str, str],
    *,
    root: Path,
    backend: NativeBackend | None,
) -> list[str]:
    """Delete native wrapping keys and return the ids that could not be removed.

    Every id is attempted so one backend failure does not strand later keys.
    The caller keeps the on-disk metadata when this returns failures, allowing
    a later reset retry to discover custom key ids rather than orphaning them.
    """
    from ..keyvault import _native_key_id, wrap

    try:
        backend = resolve_backend(backend)
    except Exception as exc:
        _term.emit_error(
            f"could not initialize the native wrapping-key backend ({exc}); "
            "the on-disk keyvault was retained so cleanup can be retried."
        )
        return list(key_ids)
    backend = _native_key_id.bind_backend_to_root(backend, root)

    failures: list[str] = []
    for key_id, native_key_id in key_ids.items():
        try:
            wrap.delete_wrapping_key(key_id, backend=backend, native_key_id=native_key_id)
        except Exception as exc:
            failures.append(key_id)
            _term.emit_error(
                f"could not delete native wrapping key {key_id!r} ({exc}); "
                "the on-disk keyvault was retained so cleanup can be retried."
            )
    return failures


def reset_keyvault(
    *,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    assume_yes: bool = False,
) -> int:
    """Reset keyvault only after independent TPM memory custody is removed."""
    from ..keyvault._memory_key import MemoryKeyError, memory_key_lock, memory_key_path

    root = _resolve_root(home)
    resolved_home = root.parent.parent
    wrapped = memory_key_path(resolved_home)
    if (sys.platform == "linux" and root.exists()) or wrapped.exists() or wrapped.is_symlink():
        try:
            # Same lock as provision/purge: no new memory key can appear between
            # this guard and recursive removal of its native keyvault/tpm store.
            with memory_key_lock(resolved_home):
                if wrapped.exists() or wrapped.is_symlink() or (root.parent / "memory-vault.marker").exists():
                    _term.emit_error(
                        "TPM memory depends on this keyvault directory. Run `hermes-mordred encryption purge memory` "
                        "to restore plaintext and remove its key before keyvault reset. Nothing was deleted."
                    )
                    return 1
                return _reset_keyvault(home=resolved_home, backend=backend, prompt_io=prompt_io, assume_yes=assume_yes)
        except MemoryKeyError:
            _term.emit_error("cannot lock TPM memory before keyvault reset; nothing was deleted")
            return 1
    return _reset_keyvault(home=resolved_home, backend=backend, prompt_io=prompt_io, assume_yes=assume_yes)


def _reset_keyvault(  # noqa: C901, PLR0912, PLR0915 - destructive state machine is intentionally explicit
    *,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    assume_yes: bool = False,
) -> int:
    """Destroy the keyvault: delete every provably profile-owned native
    wrapping key and remove the on-disk keyvault directory. Irreversible.

    Legacy machine-global keys are retained when exclusive ownership cannot be
    proven; the completion message reports those ids explicitly.

    Returns 0 once the keyvault is gone (or was already absent), 1 if the operator
    declines the confirmation. ``assume_yes`` skips the interactive prompt for
    scripted use; tests inject ``prompt_io`` / ``backend``.
    """
    root = _resolve_root(home)
    journal_path = _storage.reset_journal_path(root)
    try:
        root.lstat()
    except FileNotFoundError:
        root_seen = False
    except OSError as exc:
        _term.emit_error(f"cannot inspect keyvault root before reset: {exc}")
        return 1
    else:
        # ``lstat`` is intentional: a dangling root symlink is an unsafe
        # existing object, not an absent keyvault.
        root_seen = True
    try:
        journal_path.lstat()
    except FileNotFoundError:
        journal_seen = False
    except OSError as exc:
        _term.emit_error(f"cannot inspect keyvault reset journal: {exc}")
        return 1
    else:
        journal_seen = True
    if not root_seen and not journal_seen:
        # Do not create ~/.hermes/mordred merely to report a no-op.
        print("No keyvault found — nothing to reset.")
        return 0

    try:
        with _storage.keyvault_lifecycle_lock(root):
            try:
                journal = _load_reset_journal(root)
            except FileNotFoundError:
                journal = None
            except (OSError, _storage.KeyvaultCorruptError) as exc:
                _term.emit_error(f"cannot inspect pending keyvault reset journal: {exc}")
                return 1

            if journal is not None:
                # Resume from the durable exact target set even when a prior
                # rmtree removed meta.json or the whole root. The journal is
                # recovery state, not proof of operator consent: every
                # interactive invocation confirms again before native deletion.
                try:
                    root_meta = root.lstat()
                except FileNotFoundError:
                    root_meta = None
                if root_meta is not None:
                    try:
                        _storage._check_dir_mode(root)
                    except OSError as exc:
                        _term.emit_error(f"refusing to resume reset against unsafe keyvault root {root}: {exc}")
                        return 1
                    if (root_meta.st_dev, root_meta.st_ino) != journal.root_identity:
                        _term.emit_error(
                            "cannot resume keyvault reset: the keyvault root was replaced "
                            "after the reset journal was committed"
                        )
                        return 1
                if not assume_yes:
                    prompt_io = resolve_prompt_io(prompt_io)
                    if not _confirm_reset(prompt_io, list(journal.key_ids), journal.retained_legacy):
                        print("Reset aborted — nothing was deleted.")
                        return 1
            else:
                try:
                    _storage._check_dir_mode(root)
                except FileNotFoundError:
                    # A concurrent reset completed between the unlocked
                    # preflight and this lifecycle acquisition.
                    print("No keyvault found — nothing to reset.")
                    return 0
                except OSError as exc:
                    _term.emit_error(f"refusing to reset unsafe keyvault root {root}: {exc}")
                    return 1

                try:
                    key_ids, retained_legacy, metadata_incomplete = _collect_reset_key_ids(root)
                except (OSError, _storage.KeyvaultCorruptError) as exc:
                    _term.emit_error(f"cannot inspect keyvault metadata before reset: {exc}")
                    return 1

                # Keep the stable lifecycle lock across confirmation. This
                # makes the displayed key list authoritative: no concurrent
                # generation can add a key after the operator approves
                # destruction.
                if not assume_yes:
                    prompt_io = resolve_prompt_io(prompt_io)
                    if not _confirm_reset(prompt_io, list(key_ids), retained_legacy):
                        print("Reset aborted — nothing was deleted.")
                        return 1

                journal, encoded_journal = _encode_reset_journal(
                    root,
                    key_ids,
                    retained_legacy,
                    metadata_incomplete,
                )
                try:
                    _storage.write_reset_journal(root, encoded_journal)
                except Exception as exc:
                    _term.emit_error(f"could not durably journal keyvault reset ({exc}); no native keys were deleted.")
                    return 1

            # Rotate the independent generation lease after the stable journal
            # is durable and before native deletion. This invalidates cached
            # writers even if a later re-init happens to reuse root dev/inode.
            try:
                _storage.ensure_generation_epoch(root, force_new=True)
            except Exception as exc:
                _term.emit_error(
                    f"could not rotate the keyvault generation lease ({exc}); "
                    "the reset journal was retained and no native keys were deleted."
                )
                return 1

            failures = _delete_wrapping_keys(journal.key_ids, root=root, backend=backend)
            if failures:
                _term.emit_error(
                    "Keyvault reset is incomplete; the on-disk key list and reset "
                    "journal were retained. Retry after resolving native backend access."
                )
                return 1

            try:
                current_root = root.lstat()
            except FileNotFoundError:
                current_root = None
            if current_root is not None:
                if (current_root.st_dev, current_root.st_ino) != journal.root_identity:
                    _term.emit_error(
                        "Native wrapping keys were deleted, but the keyvault root "
                        "was replaced before directory removal; reset journal retained."
                    )
                    return 1
                try:
                    shutil.rmtree(root)
                except OSError as exc:
                    # The stable parent journal survives even if rmtree removed
                    # in-root metadata before failing, keeping cached writers
                    # fail-closed and preserving exact retry targets.
                    _term.emit_error(
                        f"Native wrapping keys deleted, but the keyvault directory could "
                        f"not be removed ({exc}); retry reset to finish cleanup."
                    )
                    return 1
            try:
                root.lstat()
            except FileNotFoundError:
                pass
            else:
                _term.emit_error(
                    "Native wrapping keys were deleted, but the keyvault directory "
                    "still exists; reset journal retained."
                )
                return 1

            try:
                # Commit the root-directory removal before clearing the
                # recovery journal. A crash between these two flushes can only
                # leave an absent root with a retained journal, never resurrect
                # an old root whose native keys have already been destroyed.
                _storage.fsync_keyvault_parent(root)
            except OSError as exc:
                _term.emit_error(
                    f"Native wrapping keys and keyvault files were removed, but "
                    f"directory removal could not be made durable ({exc}); retry reset."
                )
                return 1

            try:
                _storage.clear_reset_journal(root)
            except _storage.KeyvaultResetJournalRestoreError as exc:
                _term.emit_error(
                    "CRITICAL: keyvault reset removed all profile-owned material, but "
                    f"its fail-closed reset journal could not be restored after a storage "
                    f"flush failure ({exc}). Do not recreate or use this profile until "
                    "the filesystem is healthy and reset has been retried."
                )
                return 1
            except OSError as exc:
                _term.emit_error(
                    f"Keyvault files and native keys were removed, but the completed "
                    f"reset journal could not be durably cleared ({exc}); retry reset."
                )
                return 1
    except OSError as exc:
        _term.emit_error(f"cannot lock keyvault lifecycle for reset: {exc}")
        return 1

    if journal.retained_legacy or journal.metadata_incomplete:
        print("Keyvault files reset — all provably profile-owned key material was destroyed.")
        if journal.retained_legacy:
            displayed_retained = ", ".join(_terminal_safe(key_id) for key_id in journal.retained_legacy)
            print(
                "Legacy global native key(s) were retained because exclusive profile ownership "
                f"cannot be proven: {displayed_retained}."
            )
        if journal.metadata_incomplete:
            print("Metadata was incomplete; unknown legacy/custom native keys may require manual cleanup.")
    else:
        print("Keyvault reset — all profile-owned key material destroyed.")
    print("Run `hermes-mordred keyvault init` to create a new key.")
    return 0
