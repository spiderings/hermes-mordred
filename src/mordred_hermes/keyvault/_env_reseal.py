"""Non-interactive core: reseal a stray plaintext ``.env`` back into the vault.

Owned by ``keyvault`` — not ``wizard`` — because two callers need it and one of
them, :mod:`mordred_hermes.keyvault._env_write_guard` (wired onto the
``on_session_start`` / ``on_session_end`` plugin hooks by
:func:`mordred_hermes.keyvault.register`), lives in this foundational package.

Before this module existed, ``_env_write_guard.reseal_stray_env_if_present``
reached UP into ``mordred_hermes.wizard.env_decrypt_cli.reseal`` at runtime — a
layering inversion: ~150 other call sites across the codebase go
``wizard -> keyvault``, never the reverse, so ``keyvault``'s session-end hook
transitively depended on ``mordred_wizard`` being importable just to heal a
stray plaintext. :func:`reseal_env` is the same merge-and-reseal logic, moved
down; ``mordred_hermes.wizard.env_decrypt_cli.reseal`` now calls it
(``wizard -> keyvault``, the correct direction) and keeps only the public
name / signature its own callers (``enable``'s drift branch, existing tests)
already depend on.

Non-interactive by construction — no ``prompt_io`` seam, because there is
nothing to prompt for: every message is emitted via
:mod:`mordred_hermes._term` (already used elsewhere in ``keyvault``, e.g.
:mod:`._env_write_guard` / :mod:`.api`, specifically so non-wizard packages can
reuse it — see that module's docstring). So this module carries no dependency
on the wizard-owned ``PromptIO`` machinery either.

:func:`_open_hot_or_report` and :func:`_env_enrolled` are keyvault-local
counterparts of ``wizard._vault_open._open_hot_path_or_report`` and
``wizard.encryption_cli._enrolled_names`` (narrowed to ``.env``), so this
module never reaches up into ``wizard``. Only the ``vault.open_vault`` call
and its argument construction are duplicated; the fail-closed ``except``
chain both openers share lives in :mod:`._vault_open_report` (keyvault-side,
so ``wizard`` imports *down* into it). Both wizard originals stay in place
for wizard's own CLI commands (``vault add`` / ``migrate`` / ``status`` /
...); the little duplication left is the price of cutting the inverted edge.

Heavy imports (the cryptography-backed vault modules) stay function-local so
this module imports on any platform, matching ``_env_write_guard.py`` and the
original ``wizard/env_decrypt_cli.py`` this was extracted from.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .. import _term
from ._identity import resolve_backend, resolve_store, vault_identity
from ._plaintext_capture import (
    capture_plaintext,
    discard_capture,
    read_captured_plaintext,
    restore_capture_no_replace,
)
from ._runtime_env import _env_optout_marker_path

if TYPE_CHECKING:
    from .anchor import AnchorStore
    from .vault import OpenVault
    from .wrap import NativeBackend

__all__ = ["reseal_env"]

_ENV_NAME = ".env"

#: Optional keyvault crypto-stack extra ("[keyvault]"): argon2-cffi /
#: cryptography / blake3. Mirrors ``wizard._defaults.KEYVAULT_STACK_MODULES`` —
#: duplicated (not imported) so this module never depends on the wizard layer;
#: see the module docstring.
_KEYVAULT_STACK_MODULES = frozenset({"argon2", "cryptography", "blake3"})


def _env_enrolled(root: Path) -> bool:
    """Whether ``.env`` is enrolled per the manifest — cheap, no device unlock.

    Reads the newest manifest's *unverified* plaintext body (the ``files`` keys
    are operational metadata, not secret), so the drift / reseal decision needs
    neither the master key nor a passphrase. Mirrors
    ``wizard.encryption_cli._enrolled_names`` narrowed to ``.env`` — same
    manifest read, same graceful "nothing enrolled" degradation on a minimal
    install missing the ``[keyvault]`` extra (a genuinely unrelated missing
    module still propagates: a real bug keeps its traceback).
    """
    try:
        from . import manifest, vault
    except ModuleNotFoundError as exc:
        if (exc.name or "").partition(".")[0] in _KEYVAULT_STACK_MODULES:
            return False
        raise

    try:
        generation = vault._latest_manifest_generation(root)
        if generation is None:
            return False
        blob = vault._manifest_path(root, generation).read_bytes()
        parsed = manifest.parse_unverified(blob)
    except (OSError, manifest.ManifestError):
        return False
    return _ENV_NAME in parsed.files


def _open_hot_or_report(
    root: Path, *, backend: NativeBackend | None = None, store: AnchorStore | None = None
) -> OpenVault | None:
    """Open the vault at ``root`` on the hot path (device key, no passphrase), or
    report a reason via :mod:`mordred_hermes._term` and return ``None``.

    Still a keyvault-local counterpart to
    ``wizard._vault_open._open_hot_path_or_report`` — this module never reaches
    up into ``wizard`` (see module docstring) — but the ``except`` chain each of
    them used to carry its own copy of is now the single
    :func:`._vault_open_report.report_hot_open_failure`, so they cannot drift
    apart. Only the open *call* stays local, because tests pin it with
    ``monkeypatch.setattr(vault, "open_vault", ...)``. ``backend`` / ``store``
    default to the production implementations; tests inject fakes. The caller
    owns closing the returned vault.
    """
    from . import vault
    from ._vault_open_report import report_hot_open_failure

    key_id = anchor_label = vault_identity(root)
    backend = resolve_backend(backend)
    store = resolve_store(store)

    with report_hot_open_failure(root):
        return vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
    return None


def _render_env_value(value: str) -> str:
    """Render ``value`` for the right-hand side of a ``KEY=`` line so it round-trips
    back through ``dotenv`` to the same string.

    A bare ``KEY=value`` re-emission is lossy for anything ``dotenv`` parses
    specially: a space-then-``#`` is truncated at the inline comment, a newline ends
    the line, quotes are mis-read. Such values are double-quoted (with backslash,
    quote, and newline escaped), mirroring how the host writes them; plain tokens
    (the common case) and the empty string stay bare.
    """
    if value == "" or not any(c in value for c in " \t\n\r\"'#=$`\\"):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def _merge_env_text(base_text: str, overrides: dict[str, str]) -> str:
    """Apply ``overrides`` onto ``base_text``, set-or-append, preserving the rest.

    ``base_text`` is the vault's authoritative ``.env`` (the full set of enrolled
    secrets); ``overrides`` are the keys a host write just set on disk. Each
    override replaces its key in place (keeping the base file's comments, order,
    and untouched lines) or is appended if new. Keys present only in ``base_text``
    are **kept** — a host write after the seal produces a *partial* file, so a key
    missing from ``overrides`` means "untouched", never "delete". Mirrors the
    host's own set-or-append in ``hermes_cli.config.save_env_value``.
    """
    lines = base_text.splitlines(keepends=True)
    remaining = dict(overrides)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in remaining:
            lines[i] = f"{key}={_render_env_value(remaining.pop(key))}\n"
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    for key, value in remaining.items():
        lines.append(f"{key}={_render_env_value(value)}\n")
    return "".join(lines)


def _reseal_within_open(opened: OpenVault, overrides: dict[str, str]) -> tuple[bool, str | None]:
    """Merge ``overrides`` onto the enrolled ``.env`` inside an already-open vault.

    Re-enrolls only when the merge changes the bytes, and verifies the read-back
    through the *same* handle (one device-key unlock). Returns
    ``(remove_plaintext, success_message)``: ``remove_plaintext`` is ``False``
    (message ``None``) when the caller should keep the on-disk plaintext — a race
    (``.env`` no longer enrolled), a non-UTF-8 vault copy, or a read-back mismatch
    — and a warning has already been emitted.
    """
    if _ENV_NAME not in opened.list_files():
        return False, None  # raced: no longer enrolled — nothing to reconcile
    base = opened.read_file(_ENV_NAME)
    try:
        base_text = base.decode("utf-8")
    except UnicodeDecodeError as exc:
        _term.emit_warn(f"cannot reseal .env (vault copy is not UTF-8): {exc} — leaving the plaintext in place.")
        return False, None

    merged = _merge_env_text(base_text, overrides).encode("utf-8")
    if merged == base:
        # The stray plaintext changed nothing the vault does not already hold.
        return True, ".env: removed a redundant plaintext copy (the vault copy already held these values)."

    opened.enroll_file(_ENV_NAME, merged)
    if opened.read_file(_ENV_NAME) != merged:
        _term.emit_warn(
            ".env was merged + enrolled but the vault read-back does not match (changed during "
            "reseal?) — leaving the plaintext in place; re-run enable."
        )
        return False, None
    return True, ".env resealed: merged the new value(s) into the vault and removed the plaintext."


def _restore_or_preserve_capture(candidate: Path, env_path: Path) -> None:
    """Restore a failed capture without overwriting a concurrent live file."""
    try:
        restored = restore_capture_no_replace(candidate, env_path)
    except OSError as exc:
        _term.emit_warn(
            f".env reseal failed and the captured plaintext could not be restored: {exc}. "
            f"It remains at {candidate}; reconcile it manually."
        )
        return
    if not restored:
        _term.emit_warn(
            f".env changed while it was being resealed. The newer live file was "
            f"left untouched and the earlier captured values remain at {candidate}; "
            "merge/reseal both copies."
        )


def _discard_resealed_capture(candidate: Path, env_path: Path, success_msg: str | None) -> int:
    """Delete only the successfully-enrolled private capture, never ``env_path``."""
    try:
        discard_capture(candidate)
    except OSError as exc:
        _term.emit_warn(
            f".env was reconciled into the vault but its captured plaintext deletion at "
            f"{candidate} could not be made durable: {exc} — inspect and remove any residue."
        )
        return 0
    if env_path.exists() or env_path.is_symlink():
        _term.emit_warn(
            ".env changed while it was being resealed. The captured values were "
            "enrolled, and the newer live .env was left untouched for the next reseal."
        )
        return 0
    assert success_msg is not None
    print(success_msg)
    return 0


def reseal_env(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Reconcile a plaintext ``.env`` that reappeared while the vault still seals it.

    The sealed state (``.env`` enrolled, injection ON, macOS) must hold **no**
    plaintext ``.env``. When a host write puts one back (e.g.
    ``hermes_cli.config.save_env_value`` after ``enable`` removed the plaintext),
    that file is *partial*: the host starts from an empty file because the sealed
    plaintext was deleted, so it carries only the just-written keys. Adopting it
    wholesale would drop every other enrolled secret — so this **merges** the
    on-disk keys onto the vault copy (the authoritative base), re-enrolls the
    merged result, and removes the plaintext.

    Callers: :func:`mordred_hermes.wizard.env_decrypt_cli.reseal` (the
    ``hermes-mordred`` CLI surface and ``enable``'s drift-reconciliation branch)
    and :func:`mordred_hermes.keyvault._env_write_guard.reseal_stray_env_if_present`
    (the session-boundary sweep) — both callers gate on macOS before calling
    this. A no-op (returns 0) when there is no plaintext, ``.env`` is not
    enrolled, or the env target is in the reversible *disabled* state (opt-out
    marker present: the on-disk plaintext is then the intentional live copy, not
    drift). Returns 1 when the vault is present but cannot be opened or the
    re-enroll itself fails; on a read-back mismatch or an unremovable plaintext
    it returns 0 — in every non-clean case the plaintext is kept so no secret is
    stranded.
    """
    env_path = home / _ENV_NAME
    if (
        not (env_path.exists() or env_path.is_symlink())  # no stray plaintext
        or _env_optout_marker_path(home).exists()  # disabled: plaintext is intentional
        or not _env_enrolled(root)  # first-time enable owns unmanaged plaintext
    ):
        return 0

    try:
        captured_path = capture_plaintext(env_path)
    except OSError as exc:
        _term.emit_warn(f"cannot safely capture .env for reseal: {exc} — leaving it in place.")
        return 0
    if captured_path is None:
        return 0

    # Every return/exception before verified enrollment restores the captured
    # inode without replacing a concurrent new live file. This outer guard is
    # deliberately BaseException-safe via ``finally``: Ctrl-C/SystemExit from
    # dotenv parsing, vault open, context entry/exit, or an unexpected backend
    # error must not strand the sole plaintext under the private candidate name.
    restore_needed = True
    try:
        try:
            disk_bytes = read_captured_plaintext(captured_path)
            disk_text = disk_bytes.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _term.emit_warn(f"cannot reseal .env (unreadable / non-UTF-8 plaintext): {exc}.")
            return 0

        from io import StringIO

        from dotenv import dotenv_values

        overrides = {
            k: v for k, v in dotenv_values(stream=StringIO(disk_text), interpolate=False).items() if v is not None
        }

        # One device-key unlock (one Touch ID) covers read-base → enroll-merged →
        # verify-read-back through the *same* open (see :func:`_reseal_within_open`).
        # Enrolling the merged bytes directly means the full plaintext is never staged
        # in a temp file at rest, so an interrupted reseal leaves no plaintext behind.
        from . import anchor, vault
        from ._exceptions import WrapError

        opened = _open_hot_or_report(root, backend=backend, store=store)
        if opened is None:
            _term.emit_error(
                ".env is enrolled but the vault could not be opened to reseal a stray plaintext "
                "— leaving the plaintext in place (run `encryption status`)."
            )
            return 1

        try:
            with opened:
                remove_plaintext, success_msg = _reseal_within_open(opened, overrides)
        except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
            _term.emit_error(f"cannot reseal .env into the vault: {exc} — leaving the plaintext in place.")
            return 1

        if not remove_plaintext:
            return 0  # a warning was already emitted; the plaintext is kept

        # Read-back verification proved the vault now contains the captured
        # values. From here the candidate is safe to discard; a host write that
        # recreated the live pathname is never read/unlinked.
        restore_needed = False
        return _discard_resealed_capture(captured_path, env_path, success_msg)
    finally:
        if restore_needed:
            _restore_or_preserve_capture(captured_path, env_path)
