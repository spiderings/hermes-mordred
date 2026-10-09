"""Portable Keyvault backup export CLI.

This module is the non-``argparse`` implementation behind
``hermes-mordred keyvault export --output <path>``.  It deliberately delegates
all cryptography and MRKV wire-format work to
:func:`mordred_hermes.keyvault.api.export_backup`; the wizard layer only owns
interactive recovery-material collection and safe publication of the returned
blob.

The output is published from a fully-written, mode-0600 same-directory staging
file through an atomic no-replace hard link.  Existing files, directories, and
symlinks therefore win races without being modified, and an interrupted write
can never expose a partial final file.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._home import hermes_home as _hermes_home
from ..keyvault import _native_key_id, _plaintext_capture, _storage
from . import _term
from ._defaults import resolve_backend, resolve_prompt_io
from ._keyvault_init import _stderr_audit_sink
from ._prompt_io import _PROMPT_TOOLKIT_REQUIRED, NonInteractiveAbort

if TYPE_CHECKING:
    from ..keyvault.wrap import AuditSink, NativeBackend
    from .configure import PromptIO

__all__ = ["cli_export", "export_keyvault_backup"]

#: Shared with the publication primitive so the probe cannot drift from what
#: ``publish_plaintext_no_replace`` actually wrote. ``O_NONBLOCK`` mirrors
#: ``_plaintext_capture._open_regular_no_follow``: without it, opening a FIFO
#: another writer raced into the output pathname would block the CLI forever
#: instead of being rejected as a non-regular file.
_O_NOFOLLOW = _plaintext_capture._O_NOFOLLOW
_O_CLOEXEC = _plaintext_capture._O_CLOEXEC
_O_NONBLOCK = _plaintext_capture._O_NONBLOCK
_PRIVATE_MODE = _plaintext_capture._PRIVATE_MODE
_geteuid = getattr(os, "geteuid", None)

#: ``os.link`` errnos that mean "this destination filesystem has no hard links"
#: rather than "the write failed": Linux returns ``EPERM`` for a filesystem
#: without link support (also macOS FAT/exFAT), and some FUSE/SMB mounts return
#: ``ENOTSUP``/``EOPNOTSUPP``. Publication is atomic-no-replace via ``os.link``,
#: so those destinations can never be served — the operator needs a different
#: instruction from "check permissions and free space, then retry".
_HARD_LINK_UNSUPPORTED_ERRNOS = frozenset({errno.EPERM, errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)})


def _terminal_safe(value: object) -> str:
    """Render an operator-controlled path without terminal control bytes."""

    text = value if isinstance(value, str) else str(value)
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _path_kind(mode: int) -> str:
    """Return a short user-facing description for an existing output object."""

    if stat.S_ISLNK(mode):
        return "symbolic link"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    return "filesystem object"


def _preflight_output(path: Path) -> bool:
    """Reject an existing output and require a real immediate parent directory.

    This is an early, friendly check only.  The final publication still uses
    atomic no-replace semantics, which closes the check-to-write race.
    """

    display_path = _terminal_safe(path)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        _term.emit_error(f"cannot inspect backup output path {display_path}; check its permissions and retry.")
        return False
    else:
        _term.emit_error(
            f"refusing to overwrite existing {_path_kind(existing.st_mode)} at {display_path}; "
            "choose a new output path."
        )
        return False

    try:
        parent = path.parent.lstat()
    except FileNotFoundError:
        _term.emit_error(
            f"backup output directory does not exist for {display_path}; create a private directory first."
        )
        return False
    except OSError:
        _term.emit_error(f"cannot inspect the backup output directory for {display_path}; check its permissions.")
        return False
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        _term.emit_error(
            f"backup output parent must be a real directory, not a symlink or special file: "
            f"{_terminal_safe(path.parent)}. Pass the resolved directory path instead "
            "(on macOS `/tmp` is a symlink to `/private/tmp`)."
        )
        return False
    return True


def _select_single_key_row(keys: Mapping[str, object]) -> tuple[str, dict[str, Any]] | None:
    """Return the one ``meta['keys']`` row, reporting count/shape-specific guidance.

    An empty mapping is an *uninitialized* layout, not a damaged one: a
    ``keyvault init`` that failed after its ``init_started`` journal (or a
    manually deleted ``meta.json`` — :func:`_storage.load_meta` rebuilds it as
    ``{"version": 1, "keys": {}}``) leaves exactly this state, and the operator
    fix is to run init, not to repair or reset. More than one key is a layout
    this CLI never creates, so it is reported as unsupported-here rather than
    answered with a destructive ``reset`` suggestion.
    """

    if len(keys) == 0:
        _term.emit_error("Keyvault is not initialized; run `hermes-mordred keyvault init` first.")
        return None
    if len(keys) > 1:
        _term.emit_error(
            f"Backup export supports exactly one initialized Keyvault key; this Keyvault has {len(keys)}. "
            "Multi-key profiles are not an operator-supported layout for `keyvault export`; use the Keyvault "
            "API `mordred_hermes.keyvault.api.export_backup(key_id, passphrase, ...)` to export one specific key."
        )
        return None
    [(key_id_hash, row)] = keys.items()
    if not isinstance(key_id_hash, str) or not isinstance(row, dict):
        _term.emit_error("Keyvault metadata contains an invalid key row; restore a verified backup or reset it.")
        return None
    return key_id_hash, row


def _single_key_id(home: Path) -> str | None:
    """Return the one initialized logical Keyvault key, reporting safe errors."""

    root = _storage.resolve_keyvault_dir(home)
    try:
        with _storage.keyvault_read_lock(root) as profile_present:
            if not profile_present:
                _term.emit_error("Keyvault is not initialized; run `hermes-mordred keyvault init` first.")
                return None
            _storage.assert_keyvault_active(root)
            meta = _storage.load_meta(root)
    except _storage.KeyvaultResetInProgressError:
        _term.emit_error(
            "Keyvault reset is incomplete; finish `hermes-mordred keyvault reset` before exporting a backup."
        )
        return None
    except _storage.KeyvaultCorruptError:
        _term.emit_error(
            "Keyvault metadata is corrupt; restore a verified backup or reset the Keyvault before exporting."
        )
        return None
    except OSError:
        _term.emit_error("Keyvault metadata cannot be read safely; check owner-only permissions and retry.")
        return None

    if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
        _term.emit_error(
            "Keyvault native-key provisioning is incomplete; run `hermes-mordred keyvault reset` before exporting."
        )
        return None

    entry = _select_single_key_row(meta["keys"])
    if entry is None:
        return None
    key_id_hash, row = entry
    try:
        key_id = _native_key_id.validate_main_key_id(row.get("key_id"))
        expected_hash = hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()
    except (_native_key_id.InvalidMainKeyId, UnicodeEncodeError):
        _term.emit_error("Keyvault metadata contains an invalid key id; restore a verified backup or reset it.")
        return None
    if key_id_hash != expected_hash:
        _term.emit_error("Keyvault metadata key hash does not match its key id; restore a verified backup or reset it.")
        return None
    return key_id


def _paper_recovery_material(
    key_id: str,
    *,
    home: Path,
    prompt_io: PromptIO,
) -> tuple[str | None, bytes | None] | None:
    """Collect and validate paper recovery material only when no HD seed exists."""

    from ..keyvault import _bip39, api, ethereum
    from ..keyvault import pow as keyvault_pow

    if ethereum.list_seed_envelope_ids(key_id, home=home):
        # Omitting both values asks api.export_backup to decrypt the stored HD
        # seed and verify the entered init passphrase against the committed
        # digest before it walks the rest of the Keyvault.
        return None, None

    seed_phrase = prompt_io.ask_password("24-word Seed Phrase (paper-only Keyvault)")
    normalized_seed = api._normalize_seed_phrase(seed_phrase)
    try:
        _bip39.mnemonic_to_entropy(normalized_seed)
    except ValueError:
        _term.emit_error("Seed Phrase rejected; enter the valid 24-word BIP39 phrase recorded at Keyvault init.")
        return None
    pow_bytes = keyvault_pow.compute_pow(
        normalized_seed,
        difficulty_bits=keyvault_pow.POW_DIFFICULTY_BITS,
    )
    return seed_phrase, pow_bytes


class _ExportRefused(Exception):
    """Known export failure carrying only a fixed, secret-free CLI message."""


def _build_backup_blob(
    key_id: str,
    passphrase: str,
    *,
    seed_phrase: str | None,
    pow_bytes: bytes | None,
    home: Path,
    backend: NativeBackend,
    audit_sink: AuditSink,
) -> bytes:
    """Call the existing API and translate known failures into redacted guidance."""

    from cryptography.exceptions import InvalidTag

    from ..keyvault import api
    from ..keyvault._exceptions import WrapError
    from ..keyvault.backup import BackupCorrupt
    from ..keyvault.digest import VerificationDigestMismatch

    try:
        if seed_phrase is None or pow_bytes is None:
            return api.export_backup(
                key_id,
                passphrase,
                backend=backend,
                audit_sink=audit_sink,
                home=home,
            )
        return api.export_backup(
            key_id,
            passphrase,
            backend=backend,
            audit_sink=audit_sink,
            home=home,
            seed_phrase=seed_phrase,
            pow_bytes=pow_bytes,
        )
    except VerificationDigestMismatch:
        raise _ExportRefused(
            "Backup export refused: the Keyvault init passphrase or paper Seed Phrase does not match "
            "the committed recovery digest."
        ) from None
    except InvalidTag:
        raise _ExportRefused(
            "Backup export refused: stored Keyvault ciphertext failed authentication; restore from a verified backup."
        ) from None
    except BackupCorrupt:
        raise _ExportRefused(
            "Backup export refused: Keyvault backup metadata or an encrypted envelope is corrupt; "
            "run `hermes-mordred keyvault verify-digest` and restore a verified backup."
        ) from None
    except WrapError:
        raise _ExportRefused(
            "Backup export could not authorize the device key; unlock or approve the platform key and retry."
        ) from None
    except (ValueError, _storage.KeyvaultCorruptError):
        raise _ExportRefused(
            "Backup export could not verify the Keyvault recovery material. Check the init passphrase and, "
            "for a paper-only Keyvault, the recorded 24-word Seed Phrase."
        ) from None


def _is_complete_published_output(path: Path, blob: bytes) -> bool:
    """Whether ``path`` is exactly the private regular file this export published.

    ``publish_plaintext_no_replace`` syncs the destination directory *after*
    ``os.link`` has already committed the final name, so an ``OSError`` from it
    can arrive with a complete mode-0600 output on disk. Reading the published
    bytes back is the only way to tell that apart from a genuine write failure.
    The comparison is not secret-sensitive (``blob`` is the ciphertext this
    process just built and is about to hand the operator), but
    :func:`hmac.compare_digest` keeps the habit and costs nothing here.
    """

    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK)
    except OSError:
        return False
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != _PRIVATE_MODE:
            return False
        if _geteuid is not None and opened.st_uid != _geteuid():
            return False
        # Bounded read: anything longer than the blob is not our output, and a
        # foreign large regular file at this pathname must not stall the CLI.
        limit = len(blob) + 1
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return False
    finally:
        # A deferred write-back error surfacing at close must not escape the
        # failure handler and turn into the generic "failed safely" report.
        with suppress(OSError):
            os.close(fd)
    return total == len(blob) and hmac.compare_digest(b"".join(chunks), blob)


def _report_publish_failure(path: Path, blob: bytes, exc: OSError) -> None:
    """Emit the guidance that matches what publication actually left on disk."""

    if _is_complete_published_output(path, blob):
        # Post-link failure (directory sync or staging cleanup): the file is real
        # and complete, only its durability is unconfirmed. Reporting "not
        # written" here would send the operator to a retry that
        # `_preflight_output` then refuses.
        _term.emit_error(
            f"Backup was published at {_terminal_safe(path)} (complete, mode 0600) but a durability or cleanup "
            "step after publication failed, so its directory entry may not be durably synced; a private staging "
            f"copy named `.{_terminal_safe(path.name)}.mordred-materialize-*` may remain in the same directory. "
            "Verify the file and remove any staging copy before relying on it."
        )
        return
    if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
        _term.emit_error("Backup output directory disappeared; recreate it and retry with a new path.")
        return
    # ``filename2`` is set only by two-path syscalls, and ``os.link`` is the only
    # one publication performs, so its presence is what ties EPERM to "no hard
    # links" rather than to ``mkstemp``/``write``/``fsync`` on an immutable or
    # TCC-protected directory (which keeps the generic guidance below).
    if exc.errno in _HARD_LINK_UNSUPPORTED_ERRNOS and exc.filename2 is not None:
        _term.emit_error(
            "The destination filesystem does not support the atomic no-replace publication (hard links); "
            "export to a local disk and copy the file afterwards."
        )
        return
    _term.emit_error(
        "Backup output could not be written safely; check directory permissions and free space, then retry "
        "with a new output path."
    )


def _publish_backup(path: Path, blob: bytes) -> bool:
    """Publish ``blob`` atomically without replacement, reporting safe errors.

    Returns ``False`` on every failure, including the post-link directory-sync
    failure that leaves a complete output behind: the command must still exit
    non-zero there because durability is unconfirmed, so the message — not the
    exit code — is what tells the operator the file exists.
    """

    try:
        published = _plaintext_capture.publish_plaintext_no_replace(path, blob)
    except OSError as exc:
        _report_publish_failure(path, blob, exc)
        return False
    if not published:
        _term.emit_error(
            f"refusing to overwrite an output that appeared during export at {_terminal_safe(path)}; choose a new path."
        )
        return False
    return True


def export_keyvault_backup(
    *,
    output_path: Path,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    audit_sink: AuditSink | None = None,
) -> int:
    """Create one portable MRKV snapshot at ``output_path``.

    This typed function is shared by the argparse adapter and tests.  It
    auto-selects the initialized v1 key, masks every recovery-material prompt,
    verifies the Keyvault-init passphrase through the stored HD seed when
    available, and asks for the paper seed (then recomputes its PoW) otherwise.

    Returns ``0`` on success and ``1`` after a user-actionable, redacted error.
    ``KeyboardInterrupt``/``EOFError`` and the standard non-interactive prompt
    refusal propagate to the shared top-level dispatcher.
    """

    if not _preflight_output(output_path):
        return 1

    resolved_home = home if home is not None else _hermes_home()
    key_id = _single_key_id(resolved_home)
    if key_id is None:
        return 1

    passphrase: str | None = None
    seed_phrase: str | None = None
    pow_bytes: bytes | None = None
    blob: bytes | None = None
    try:
        prompts = resolve_prompt_io(prompt_io)
        passphrase = prompts.ask_password("Keyvault init passphrase")
        if not passphrase:
            _term.emit_error("Keyvault init passphrase must not be empty.")
            return 1

        recovery_material = _paper_recovery_material(key_id, home=resolved_home, prompt_io=prompts)
        if recovery_material is None:
            return 1
        seed_phrase, pow_bytes = recovery_material

        operation_backend = resolve_backend(backend)
        sink = audit_sink if audit_sink is not None else _stderr_audit_sink
        try:
            blob = _build_backup_blob(
                key_id,
                passphrase,
                seed_phrase=seed_phrase,
                pow_bytes=pow_bytes,
                home=resolved_home,
                backend=operation_backend,
                audit_sink=sink,
            )
        except _ExportRefused as exc:
            _term.emit_error(str(exc))
            return 1
        if not _publish_backup(output_path, blob):
            return 1
    except (EOFError, ModuleNotFoundError, NonInteractiveAbort):
        raise
    except Exception as exc:
        if type(exc) is RuntimeError and exc.args == (_PROMPT_TOOLKIT_REQUIRED,):
            # The prompt layer's missing-dependency signal is a fixed library
            # literal with no operator or secret data in it, so the install hint
            # is surfaced verbatim (from the constant, never from `exc`) instead
            # of being redacted into the unactionable generic text below.
            _term.emit_error(_PROMPT_TOOLKIT_REQUIRED)
            return 1
        # Never interpolate an unexpected exception: a lower layer or injected
        # backend could have included a passphrase, seed, plaintext, or blob in
        # its message. The actionable recovery surface is intentionally fixed.
        _term.emit_error(
            "Backup export failed safely; no incomplete output file was published. "
            "Check `hermes-mordred keyvault list` and `verify-digest`, then retry with a new output path."
        )
        return 1
    finally:
        # Immutable Python str/bytes objects cannot be zeroed in place. Drop
        # references promptly so secrets and the backup blob are not retained
        # for the rest of the CLI process.
        passphrase = None
        seed_phrase = None
        pow_bytes = None
        blob = None

    print(f"Portable Keyvault backup written to {_terminal_safe(output_path)} (mode 0600).")
    print(
        "This backup is a snapshot. Re-run `hermes-mordred keyvault export` whenever Keyvault contents change, "
        "including after `keyvault eth new` or direct Keyvault API writes."
    )
    return 0


def cli_export(args: argparse.Namespace) -> int:
    """argparse adapter for ``keyvault export --output <path>``."""

    return export_keyvault_backup(output_path=Path(args.output))
