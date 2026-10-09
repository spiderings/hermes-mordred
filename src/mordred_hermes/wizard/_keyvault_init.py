"""The ``hermes-mordred keyvault init`` ceremony.

This module owns the multi-step, air-gap-gated keyvault generation flow:
passphrase prompt → BIP39 seed generation → offline-blackout seed display →
operator-transcribed verification digest → finalisation, plus the best-effort
audit-log-key / HD-seed on-ramps. It is the bulk of the keyvault CLI by line
count and is kept separate from the small read / recover / reset commands and
the argparse adapters in :mod:`mordred_hermes.wizard.keyvault_cli`, which
re-exports :func:`init_keyvault` / :class:`TerminalSeedSurface` /
:func:`_stderr_audit_sink` so existing callers and tests keep working.

The ceremony never touches the on-disk root via ``_resolve_root`` (it reads
through :mod:`..keyvault._storage` directly), so it carries no dependency back
on the facade module.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..keyvault import _native_key_id, _storage
from . import _term
from ._defaults import resolve_backend, resolve_prompt_io

if TYPE_CHECKING:
    from ..keyvault.api import GenerateResult, SeedDisplayHandle
    from ..keyvault.seed_display import SeedDisplaySurface
    from ..keyvault.wrap import AuditSink, NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO


def _stderr_audit_sink(entry: dict[str, Any]) -> None:
    """Surface a keyvault audit entry to stderr.

    ``recover`` runs before the keyvault is usable, so there is no
    encrypted audit log to append to yet. The recovery-digest-mismatch
    and DEK-unwrap decisions ``import_backup`` records are shown to the
    operator instead. Persisted recovery auditing is a v2 follow-up.

    The ``reason`` is appended when present so distinct lifecycle entries
    that share an ``event`` + ``decision`` are distinguishable: a normal
    ``keyvault init`` emits ``keyvault.init`` / ``decision=allow`` twice —
    once for ``keyvault.init_started`` (the durability barrier) and once
    for ``keyvault.init_completed`` — which otherwise print identically.
    """
    event = entry.get("event", "?")
    decision = entry.get("decision", "?")
    reason = entry.get("reason")
    suffix = f" ({reason})" if reason else ""
    print(f"[audit] {event} decision={decision}{suffix}", file=sys.stderr)


#: Bounded retries at the verification-digest prompt (init_keyvault).
_DIGEST_PROMPT_ATTEMPTS = 5

# OS-specific go-offline steps + the matching offline-verification command.
# Split per platform because the original macOS-only text (menu bar, BSD
# `route get`) was wrong guidance on a Linux/TPM host (UX review 2026-06-11).
_BLACKOUT_STEPS_DARWIN = (
    "    1. Turn Wi-Fi OFF                 (menu bar → Wi-Fi → Off)\n"
    "    2. Unplug Ethernet cables\n"
    "    3. Turn Bluetooth OFF             (blocks PAN / tethering)\n"
    "    4. Disable iPhone Personal Hotspot / USB tethering\n"
    "    5. Stop any VPN or virtual NIC    (Tailscale, ZeroTier, …)\n"
    "\n"
    "  Verify you are offline before retrying:\n"
    "\n"
    "      route get 1.1.1.1\n"
    "\n"
    "  You are offline when the command prints:\n"
    "      route: writing to routing socket: not in table\n"
    "  If instead it shows an `interface:` line with a real NIC\n"
    "  (e.g. `en0`, `en6`, `utun3`), that NIC is still routing —\n"
    "  disable it and re-check before retrying.\n"
)

_BLACKOUT_STEPS_LINUX = (
    "    1. Turn Wi-Fi and WWAN OFF        (nmcli radio all off)\n"
    "    2. Unplug Ethernet cables\n"
    "    3. Turn Bluetooth OFF             (blocks PAN / tethering)\n"
    "    4. Disable USB / phone tethering\n"
    "    5. Stop any VPN or virtual NIC    (Tailscale, ZeroTier, WireGuard, …)\n"
    "\n"
    "  Verify you are offline before retrying:\n"
    "\n"
    "      ip route get 1.1.1.1\n"
    "\n"
    "  You are offline when the command reports the network is\n"
    "  unreachable. If instead it prints a route via a real device\n"
    "  (e.g. `dev eth0`, `dev wlan0`), that interface is still\n"
    "  routing — disable it and re-check before retrying.\n"
)


def _blackout_guidance(platform: str, *, before_passphrase: bool = False) -> str:
    """The go-offline instructions shown when the network blackout check fails.

    ``platform`` is ``sys.platform`` (``"darwin"`` / ``"linux"`` …); unknown
    platforms get the Linux text, whose commands are the more portable set.

    ``before_passphrase`` tailors the header and the closing reassurance to
    where in the ceremony the check tripped. The early pre-check fires before
    anything is typed, so "your passphrase was not saved" would be misleading;
    the late gate (inside ``display_seed``) fires after the passphrase prompt.
    """
    steps = _BLACKOUT_STEPS_DARWIN if platform == "darwin" else _BLACKOUT_STEPS_LINUX
    if before_passphrase:
        header = "  Go offline before you start keyvault init\n"
        closing = "  Nothing has been entered or written yet. Re-run after\n  going offline to begin.\n"
    else:
        header = "  Next step: go offline before the Seed Phrase is shown\n"
        closing = (
            "  Nothing has been written yet — your passphrase was not\n"
            "  saved. Re-run after going offline to continue.\n"
        )
    return (
        "\n"
        "────────────────────────────────────────────────────────────\n"
        + header
        + "────────────────────────────────────────────────────────────\n"
        "\n"
        "  This is the expected safety check, not an error. Mordred\n"
        "  will only reveal your Seed Phrase when the host is fully\n"
        "  air-gapped, so the seed cannot leak over any active link.\n"
        "\n"
        "  Please disconnect every network interface, then re-run\n"
        "  `hermes-mordred keyvault init`:\n"
        "\n" + steps + "\n" + closing + "────────────────────────────────────────────────────────────\n"
    )


def _precheck_blackout_or_refuse(blackout_assert: Callable[..., None] | None) -> int | None:
    """Early air-gap pre-check, run before the passphrase prompt.

    The real security gate is the ``blackout_assert`` inside ``display_seed``
    (defense in depth); this earlier copy only fails *fast* so an online
    operator is told to go offline before typing a passphrase that the late
    gate would otherwise discard (UX review 2026-06-15: the host was probed
    only after the passphrase had been entered twice). On the rare race where
    the link returns between this check and the seed display, the late gate
    still refuses. Returns 1 (after printing) when the host is reachable, else
    None.
    """
    from ..keyvault.network_fallback import BlackoutNotAsserted, resolve_blackout_assert

    assert_fn = blackout_assert if blackout_assert is not None else resolve_blackout_assert()
    try:
        assert_fn()
    except BlackoutNotAsserted:
        print(_blackout_guidance(sys.platform, before_passphrase=True), file=sys.stderr)
        return 1
    return None


class TerminalSeedSurface:
    """A terminal :class:`SeedDisplaySurface` for ``keyvault init``.

    All three methods are safe to call repeatedly — ``display_seed``
    invokes :meth:`clear` on every exit path, possibly twice.
    """

    def banner(self, message: str) -> None:
        print(message, file=sys.stderr)

    def show(self, seed: str) -> None:
        words = seed.split()
        print("\n=== SEED PHRASE — transcribe onto paper now ===")
        for index, word in enumerate(words, start=1):
            print(f"  {index:2}. {word}")
        # One-line form of the SAME words. The numbered list is the paper
        # backup; this space-separated line is the BIP39-standard mnemonic the
        # offline digest script accepts verbatim. Re-typing 24 words one per
        # line into that script by hand is error-prone and a common drop-off
        # point, so we surface a single copyable line for the verification step.
        # It carries no new exposure (the words are already on screen) and is
        # wiped by the same 60s auto-clear / screen-clear as the list above.
        print("\n  one line (for the offline verification digest):")
        print(f"    {' '.join(words)}")
        print("=== END SEED PHRASE ===\n")
        # Actionable next step. Gated on an interactive TTY because the ENTER
        # early-dismiss it advertises is itself TTY-only (see
        # seed_display._default_dismiss_probe). Off a TTY the window just runs
        # out its 60s timer, so the prompt would be misleading.
        if sys.stdin.isatty():
            print(
                "  When you have written down all 24 words AND can re-type them on\n"
                "  your offline device, press ENTER to clear the seed now and move on\n"
                "  to the verification-digest prompt. (It clears on its own after 60s.)"
            )

    def clear(self) -> None:
        # ANSI clear-screen + cursor-home. Best-effort: harmless on a
        # terminal that does not interpret the escape sequence.
        print("\033[2J\033[H", end="", flush=True)


def _refuse_if_initialised(home: Path | None) -> int | None:
    """Reject corrupt, initialized, or residual native-ownership metadata."""
    root = _storage.resolve_keyvault_dir(home)
    try:
        _storage.assert_keyvault_active(root)
        existing_meta = _storage.load_meta(root)
    except _storage.KeyvaultResetInProgressError as exc:
        _term.emit_error(
            f"Keyvault reset is incomplete ({exc}). Run `hermes-mordred keyvault reset` before starting a new ceremony."
        )
        return 1
    except _storage.KeyvaultCorruptError as exc:
        _term.emit_error(f"Keyvault meta.json is corrupt — repair or remove it before init: {exc}")
        return 1
    if _native_key_id.PENDING_NATIVE_KEY_FIELD in existing_meta:
        _term.emit_error(
            "Keyvault has an incomplete native-key provisioning journal. "
            "Run `hermes-mordred keyvault reset` before starting a new ceremony."
        )
        return 1
    if _native_key_id.has_native_key_ownership_state(existing_meta):
        if not existing_meta.get("keys"):
            _term.emit_error(
                "Keyvault has residual native-key ownership metadata. "
                "Run `hermes-mordred keyvault reset` before starting a new ceremony."
            )
            return 1
        _term.emit_error(
            "Keyvault already initialised — v1 keyvault is single-key. To restore a "
            "different key, use `hermes-mordred keyvault recover`."
        )
        return 1
    return None


def _intro_banner() -> str:
    """The orientation shown before the first Passphrase prompt.

    UX review 2026-06-15: ``keyvault init`` opened straight onto a bare
    ``Choose a Passphrase:`` prompt — the operator had no idea what the
    command does or what that passphrase is for. This explains the
    ceremony, names the Passphrase's role, and warns it is never stored
    *before* anything is typed.
    """
    return (
        "\n"
        "────────────────────────────────────────────────────────────\n"
        "  keyvault init — set up your encrypted keyvault\n"
        "────────────────────────────────────────────────────────────\n"
        "\n"
        "  This creates a new keyvault on this device. In the next\n"
        "  steps you will:\n"
        "\n"
        "    1. Choose a Passphrase (below)\n"
        "    2. Write down a 24-word Seed Phrase shown on screen\n"
        "    3. Verify it on a second, OFFLINE device\n"
        "\n"
        "  The Passphrase below, combined with the Seed Phrase,\n"
        "  protects your keyvault. You will need BOTH (plus a backup\n"
        "  blob) to recover it on another device.\n"
        "\n"
        "  It is never stored anywhere — if you lose it, the keyvault\n"
        "  cannot be recovered. Choose something strong you can keep.\n"
        "  Nothing is written to disk until every step completes.\n"
        "────────────────────────────────────────────────────────────"
    )


def _read_passphrase(prompt_io: PromptIO, session: FlowSession | None = None) -> str | None:
    """Prompt for the passphrase twice. Returns it, or None (after printing) on a
    mismatch or an empty entry.

    With a ``session`` (``hermes-mordred setup``), a passphrase already chosen
    and confirmed earlier in the same run is reused without prompting, and a
    newly chosen one is remembered so a later step of the run (the at-rest
    vault's recovery passphrase) does not prompt again.
    """
    if session is not None and session.passphrase:
        print("Using the passphrase you already chose in this setup run.", file=sys.stderr)
        return session.passphrase
    passphrase = prompt_io.ask_password("Choose a Passphrase")
    if passphrase != prompt_io.ask_password("Re-enter the Passphrase"):
        _term.emit_error("Passphrases do not match — nothing was written.")
        return None
    if not passphrase:
        _term.emit_error("Passphrase must not be empty.")
        return None
    if session is not None:
        session.remember_passphrase(passphrase)
    return passphrase


#: Printed under the intro banner when the ceremony runs inside
#: ``hermes-mordred setup``: the one Passphrase is reused for the at-rest vault.
_SETUP_SHARED_PASSPHRASE_NOTE = (
    "  Setup asks for a passphrase only once: this Passphrase also\n"
    "  becomes the recovery passphrase of the encryption vault that\n"
    "  setup creates next (used only if this device is lost).\n"
)


def _generate_seed_material(passphrase: str, *, store_seed_for_hd: bool) -> tuple[SeedDisplayHandle, bytes, str | None]:
    """Generate the BIP39 seed + seed-bound PoW and compute the verification digest.

    Returns ``(handle, pow_bytes, mnemonic_for_hd)``. The handle holds the seed in
    a wipeable bytearray; ``mnemonic_for_hd`` is the seed string kept only when HD
    storage is requested (else None). The plain seed/normalized copies are local to
    this frame and released on return, shortening their in-memory exposure.
    """
    from ..keyvault import _bip39, api
    from ..keyvault import pow as kvpow

    seed_phrase = _bip39.generate_mnemonic()
    normalized_seed = api._normalize_seed_phrase(seed_phrase)
    pow_bytes = kvpow.compute_pow(normalized_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    # expected_digest is intentionally discarded — the operator must recompute it
    # independently on an offline device, which is the mis-transcription cross-check
    # confirm_generate enforces.
    handle, _expected_digest = api.prepare_generate(seed_phrase, passphrase, pow_bytes)
    # HD mode (store_seed_for_hd, Option A) is the deliberate exception: the seed
    # must survive to be SE-encrypted after the key is finalized, so we keep one
    # reference until storage. Otherwise it is dropped when this frame returns so it
    # is GC-eligible during the 60s display + digest prompt. CPython cannot zero an
    # immutable str in place — this shortens the exposure window, it does not scrub
    # the bytes; the handle's bytearray is the one wipeable copy.
    return handle, pow_bytes, (seed_phrase if store_seed_for_hd else None)


def _refuse_if_stdout_redirected(surface: SeedDisplaySurface | None) -> int | None:
    """Pre-init guard: the production surface prints the Seed to *stdout*, so a
    redirect (``keyvault init > log.txt``) would persist the 24 words to a file
    — and the ANSI clear that follows would scrub nothing. Returns 1 (after
    printing) when the production surface would write to a non-TTY stdout; an
    injected ``surface`` (tests / alternate UIs) owns its destination, so it
    passes. Runs before the passphrase prompt — same fail-fast rationale as
    the blackout pre-check.
    """
    if surface is not None:
        return None
    try:
        stdout_tty = sys.stdout.isatty()
    except (ValueError, OSError):
        stdout_tty = False  # closed/detached stream — treat as redirected
    if stdout_tty:
        return None
    _term.emit_error(
        "refusing to display the seed phrase: stdout is not a terminal, so "
        "the 24 words would be written into the redirect target instead of "
        "a screen that can be cleared. Re-run `hermes-mordred keyvault init` "
        "without redirecting or piping its output."
    )
    return 1


def _preflight_or_refuse(
    *,
    home: Path | None,
    blackout_assert: Callable[..., None] | None,
    surface: SeedDisplaySurface | None,
) -> int | None:
    """Run the pre-ceremony guards, all before the passphrase prompt so a
    doomed run never asks the operator to type one:

    1. re-init guard (v1 keyvault is single-key);
    2. air-gap pre-check — refuse fast while the host is online (UX review
       2026-06-15; ``display_seed`` re-asserts isolation as the real gate);
    3. stdout-TTY guard (:func:`_refuse_if_stdout_redirected`).

    Returns the refusal exit code (after printing), or None to proceed.
    """
    guard = _refuse_if_initialised(home)
    if guard is not None:
        return guard
    refusal = _precheck_blackout_or_refuse(blackout_assert)
    if refusal is not None:
        return refusal
    return _refuse_if_stdout_redirected(surface)


#: File name of the standalone offline verification-digest tool.
_OFFLINE_DIGEST_SCRIPT = "keyvault_offline_digest.py"


def _locate_offline_digest_script() -> Path | None:
    """Locate ``keyvault_offline_digest.py`` for the copy-to-offline-device step.

    Mirror of ``_seckey_helper._locate_helper_source()``: a ``scripts/`` repo
    checkout first (editable install / clone), then the ``_offline/`` copy the
    wheel force-includes (see pyproject). Unlike the helper sources this file is
    only *named* in the banner, never executed here, so no content validation is
    needed. Returns ``None`` when neither exists — the banner then names the
    file without a path instead of printing a dead one.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "scripts" / _OFFLINE_DIGEST_SCRIPT
        if candidate.is_file():
            return candidate
    try:
        from importlib.resources import files

        packaged = Path(str(files("mordred_hermes").joinpath("_offline", _OFFLINE_DIGEST_SCRIPT)))
        if packaged.is_file():
            return packaged
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    return None


def _offline_copy_hint(script: Path | None) -> str:
    """Render the copy-to-offline-device hint for the seed banner.

    With a located script, show a concrete, paste-safe copy command — both
    paths are quoted so the ``<your-usb>`` placeholder cannot act as shell
    redirection if an operator pastes the line verbatim. Without one, fall
    back to naming the file only (the 2026-07-07 locator fix already keeps
    this branch rare). Either way, state what the second device actually
    needs — python3 plus the blake3 package; the file itself is
    self-contained (UX review 2026-08-20: naming the path alone still left
    operators to invent the copy step themselves).
    """
    needs = "  (one self-contained file; the offline device only needs\n   python3 with the blake3 package installed)\n"
    if script is not None:
        return (
            "  Copy it to that device from this machine, e.g. via USB stick:\n"
            f'      cp "{script}" "/Volumes/<your-usb>/"\n' + needs
        )
    return "  (ships with hermes-mordred; copy it to that device first)\n" + needs


def _display_seed_or_refuse(
    handle: SeedDisplayHandle,
    pow_bytes: bytes,
    *,
    surface: SeedDisplaySurface | None,
    display_fn: Callable[[SeedDisplayHandle, SeedDisplaySurface], None] | None,
) -> int | None:
    """Show the offline-digest banner, then display the seed under a network
    blackout. Returns 1 (after printing) if the blackout / capture / expiry guard
    trips, or None on success.
    """
    from ..keyvault import seed_display
    from ..keyvault.api import SeedDisplayExpired
    from ..keyvault.network_fallback import BlackoutNotAsserted
    from ..keyvault.seed_display import SeedDisplayAborted

    if surface is None:
        surface = TerminalSeedSurface()
    show = display_fn if display_fn is not None else seed_display.display_seed
    # The operator needs top4(PoW) to recompute the digest offline; it is derived
    # from the (secret) seed but is itself only a 4-byte mask. The offline tool
    # ships inside the wheel (see pyproject force-include) so the path printed
    # here exists after a plain `pip install`, not only in a repo clone; the
    # second-device preparation steps live in the script's own header.
    script = _locate_offline_digest_script()
    copy_hint = _offline_copy_hint(script)
    surface.banner(
        "\n"
        "────────────────────────────────────────────────────────────\n"
        "  Next: compute the verification digest on your OFFLINE device\n"
        "────────────────────────────────────────────────────────────\n"
        "\n"
        "  On the second (air-gapped) device, run:\n"
        f"      python3 {_OFFLINE_DIGEST_SCRIPT}\n" + copy_hint + "\n"
        "  It will ask for THREE values — transcribe them in this order:\n"
        "\n"
        "    [1] Seed Phrase     →  the 24 words shown below (60s only)\n"
        "    [2] Passphrase      →  the passphrase you just chose\n"
        f"    [3] top4(PoW) hex   →  {pow_bytes[:4].hex()}    ← copy this 8-char string verbatim\n"
        "\n"
        "  The script prints a 64-char digest. Re-enter it on THIS\n"
        "  device at the `Verification digest ...` prompt below.\n"
        "  (Preparation steps are in the script's own header.)\n"
        "────────────────────────────────────────────────────────────"
    )

    try:
        show(handle, surface)
    except BlackoutNotAsserted:
        print(_blackout_guidance(sys.platform), file=sys.stderr)
        return 1
    except SeedDisplayAborted as exc:
        _term.emit_error(f"Seed display aborted: screen capture detected ({exc.detector}).")
        return 1
    except SeedDisplayExpired:
        _term.emit_error("Seed display window expired before the digest was confirmed.")
        return 1
    return None


def _prompt_for_digest(prompt_io: PromptIO) -> bytes | None:
    """Bounded re-prompt for the operator's offline verification digest.

    Re-prompts on non-hex input (a typo no longer torches the ceremony), capped at
    ``_DIGEST_PROMPT_ATTEMPTS`` so scripted / non-tty runs cannot loop forever.
    Returns the digest bytes, or None (after printing) once attempts are spent. A
    valid-hex-but-mismatching digest still aborts later in confirm_generate.
    """
    for _ in range(_DIGEST_PROMPT_ATTEMPTS):
        digest_hex = prompt_io.ask_text("Verification digest from your offline device (hex)")
        try:
            return bytes.fromhex(digest_hex.strip())
        except ValueError:
            _term.emit_error(
                "That is not a valid hex digest — paste the 64-character hex string "
                "printed by the offline tool and try again."
            )
    _term.emit_error(f"No valid hex digest after {_DIGEST_PROMPT_ATTEMPTS} attempts — nothing was written.")
    return None


def _confirm_or_refuse(
    handle: SeedDisplayHandle,
    user_digest: bytes,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None,
    unattended: bool | None = None,
) -> GenerateResult | None:
    """Finalize the keyvault iff the offline digest matches. Returns the
    GenerateResult, or None (after printing) on a digest mismatch, an Enclave wrap
    error, or the re-init race guard.

    ``unattended`` is forwarded verbatim to :func:`api.confirm_generate`, which
    already accepts it (``keyvault/api.py``); ``None`` preserves the existing
    behaviour exactly (the env-var fallback resolved deep in
    ``keyvault._seckey_backend``).
    """
    from ..keyvault import api
    from ..keyvault._exceptions import WrapError
    from ..keyvault.digest import VerificationDigestMismatch

    try:
        return api.confirm_generate(
            handle, user_digest, backend=backend, audit_sink=audit_sink, home=home, unattended=unattended
        )
    except VerificationDigestMismatch:
        _term.emit_error(
            "Verification digest mismatch — the Seed or Passphrase was mis-transcribed. "
            "Nothing was written; rerun `hermes-mordred keyvault init`."
        )
        return None
    except WrapError as exc:
        _term.emit_error(f"Keyvault init failed: Secure Enclave error — {exc}")
        return None
    except RuntimeError as exc:
        # confirm_generate's own re-init guard (a race with the pre-check).
        _term.emit_error(f"Keyvault init refused: {exc}")
        return None


def _audit_key_state(
    root: Path,
    meta: dict[str, Any],
    logical_key_id: str,
) -> tuple[str | None, str | None]:
    """Return validated ``(pending, committed)`` audit physical ids."""

    try:
        pending = _native_key_id.pending_audit_key_from_meta(root, meta, logical_key_id)
        committed = _native_key_id.committed_audit_key_from_meta(root, meta, logical_key_id)
    except _native_key_id.NativeKeyIdMismatch as exc:
        raise _storage.KeyvaultCorruptError(str(exc)) from None
    if pending is not None and committed is not None and pending != committed:
        raise _storage.KeyvaultCorruptError("audit-key pending and committed ownership records disagree")
    return pending, committed


def _require_scoped_main_key_for_audit(root: Path, meta: dict[str, Any]) -> None:
    """Require one fully committed profile-scoped main key."""

    from ..keyvault import _secret_ops

    rows = list(meta["keys"].items())
    if len(rows) != 1 or not isinstance(rows[0][1], dict):
        raise _storage.KeyvaultCorruptError("audit-key provisioning requires one committed main key")
    key_id_hash, row = rows[0]
    key_id = row.get("key_id")
    if not isinstance(key_id_hash, str) or not isinstance(key_id, str):
        raise _storage.KeyvaultCorruptError("main key metadata has no valid logical key id")
    if _native_key_id.NATIVE_KEY_ID_FIELD not in row:
        raise _storage.KeyvaultCorruptError(
            "legacy keyvault must be migrated by backup/reset/recover before scoped audit provisioning"
        )
    # `_assert_key_committed` validates either the current canonical scoped id
    # or the exact-abspath scoped id written before path canonicalization.
    # Both are profile-owned; only a row with no physical-id field is legacy.
    _secret_ops._assert_key_committed(root, key_id, key_id_hash)


def _rollback_new_audit_key(root: Path, backend: NativeBackend, native_key_id: str) -> None:
    """Best-effort rollback, retaining pending if native deletion fails."""

    try:
        backend.delete_enclave_key(native_key_id)
    except Exception:
        return
    try:
        repaired = _storage.load_meta(root)
        repaired.pop(_native_key_id.AUDIT_KEY_FIELD, None)
        repaired.pop(_native_key_id.PENDING_AUDIT_KEY_FIELD, None)
        _storage.save_meta(root, repaired)
    except Exception:
        # A remaining pending record keeps the factory fail-closed. If
        # cleanup published then reported an fsync error, the native key is
        # already gone and an empty visible record is safe as well.
        return


def _clear_pending_audit_key_after_commit(
    root: Path,
    *,
    logical_key_id: str,
    native_key_id: str,
) -> None:
    """Second-phase cleanup; never roll back a durably-owned audit key."""

    meta = _storage.load_meta(root)
    pending, committed = _audit_key_state(root, meta, logical_key_id)
    if pending != native_key_id or committed != native_key_id:
        raise _storage.KeyvaultCorruptError("audit-key ownership commit is incomplete")
    meta.pop(_native_key_id.PENDING_AUDIT_KEY_FIELD)
    try:
        _storage.save_meta(root, meta)
    except BaseException as exc:
        try:
            visible = _storage.load_meta(root)
            visible_pending, visible_committed = _audit_key_state(root, visible, logical_key_id)
        except Exception as visible_exc:
            exc.add_note(f"audit pending-key cleanup left unreadable metadata: {visible_exc}")
            raise exc from visible_exc
        if visible_pending is not None or visible_committed != native_key_id:
            exc.add_note("audit pending-key cleanup did not reach a committed visible state")
            raise exc
        if not isinstance(exc, Exception):
            raise exc
        _term.emit_warn(
            "audit-log key metadata reported a durability error after publishing "
            "a complete committed record; continuing with the verified visible state."
        )


def _commit_pending_audit_key(
    root: Path,
    *,
    backend: NativeBackend,
    logical_key_id: str,
    native_key_id: str,
    allow_duplicate_adoption: bool,
) -> None:
    """Generate/adopt the exact pending key and durably commit ownership."""

    from ..keyvault._exceptions import WrapKeyAlreadyExists
    from ..keyvault.wrap import generate_wrapping_key, get_wrapping_key_public

    generated = False
    try:
        try:
            generate_wrapping_key(
                logical_key_id,
                backend=backend,
                native_key_id=native_key_id,
            )
            generated = True
        except WrapKeyAlreadyExists:
            # The durable exact pending record proves this profile owns the
            # deterministic scoped selector. Adoption is still limited to a
            # key known to predate a freshly-published pending record, or a
            # row+pending retry proving generation previously succeeded. A
            # pending-only retry after a generation durability error remains
            # fail-closed: public visibility alone is not durability.
            if not allow_duplicate_adoption:
                # ...but refusing alone left the profile permanently plaintext:
                # every later retry re-derives the same scoped selector, hits the
                # same duplicate, and re-refuses. Discard the key of unproven
                # durability instead of adopting it — strictly stronger than
                # adoption, and safe because no ciphertext can depend on it
                # (``make_audit_writer`` requires COMMITTED ownership, which by
                # definition was never published on this path). The next attempt
                # then starts from a clean, fresh provisioning.
                _rollback_new_audit_key(root, backend, native_key_id)
                raise
            get_wrapping_key_public(
                logical_key_id,
                backend=backend,
                native_key_id=native_key_id,
            )

        ownership_meta = _storage.load_meta(root)
        ownership_pending, ownership_committed = _audit_key_state(root, ownership_meta, logical_key_id)
        if ownership_pending != native_key_id:
            raise _storage.KeyvaultCorruptError("audit-key pending ownership changed during provisioning")
        if ownership_committed is None:
            _native_key_id.add_committed_audit_key(
                root,
                ownership_meta,
                logical_key_id,
                native_key_id,
            )
        elif ownership_committed != native_key_id:
            raise _storage.KeyvaultCorruptError("audit-key committed ownership changed during provisioning")
        # First-phase ownership commit retains pending.
        _storage.save_meta(root, ownership_meta)
    except BaseException:
        if generated:
            _rollback_new_audit_key(root, backend, native_key_id)
        raise


def _provision_audit_log_key_locked(root: Path, backend: NativeBackend, logical_key_id: str) -> None:
    """Run resumable two-phase audit-key provisioning under keyvault_lock."""

    meta = _storage.load_meta(root)
    _require_scoped_main_key_for_audit(root, meta)
    native_key_id = _native_key_id.scoped_native_key_id(root, logical_key_id)
    pending, committed = _audit_key_state(root, meta, logical_key_id)
    if committed is not None and pending is None:
        return
    pending_was_present = pending is not None
    if pending is None:
        pending = _native_key_id.add_pending_audit_key(root, meta, logical_key_id)
        _storage.save_meta(root, meta)
    if pending != native_key_id:
        raise _storage.KeyvaultCorruptError("pending audit key does not belong to this profile")
    _commit_pending_audit_key(
        root,
        backend=backend,
        logical_key_id=logical_key_id,
        native_key_id=native_key_id,
        allow_duplicate_adoption=not pending_was_present or committed is not None,
    )
    _clear_pending_audit_key_after_commit(
        root,
        logical_key_id=logical_key_id,
        native_key_id=native_key_id,
    )


def _provision_audit_log_key(
    backend: NativeBackend,
    *,
    home: Path | None,
) -> None:
    """Best-effort provision a durably-recorded audit wrapping key."""

    from ..keyvault._exceptions import WrapError
    from ..keyvault.log_encryption import AUDIT_LOG_KEY_ID

    root = _storage.resolve_keyvault_dir(home)
    backend = _native_key_id.bind_backend_to_root(backend, root)
    try:
        # The lock joins reset's stable lifecycle lock and makes every pending
        # / ownership transition authoritative against concurrent reset.
        with _storage.keyvault_lock(root):
            _provision_audit_log_key_locked(root, backend, AUDIT_LOG_KEY_ID)
    except (WrapError, OSError, _storage.KeyvaultCorruptError, _native_key_id.NativeKeyIdMismatch) as exc:
        # Name the persistent consequence. This note is printed once, during
        # init/recover, but the degraded state outlives it: a stranded pending
        # record is deliberately not adopted on retry, so the audit log stays
        # plaintext indefinitely. Point at the surface that keeps reporting it
        # rather than implying a repair happens on its own.
        _term.emit_note(
            f"audit-log wrapping key not provisioned ({exc}); the audit log stays plaintext. "
            "This does not clear by itself — check `hermes-mordred status` (keyvault line) "
            "to confirm whether audit-log encryption is active."
        )


def _store_seed_for_hd_envelope(
    key_id: str,
    mnemonic: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None,
) -> None:
    """Best-effort HD on-ramp: SE-encrypt the just-generated seed so the HD wallet
    can derive Ethereum accounts later. A storage failure degrades to a note.
    """
    # Storing is OFFLINE — store_seed_phrase wraps the DEK with the Enclave *public*
    # key, so it never triggers an authorization prompt. We deliberately do NOT
    # derive an account here: derivation unwraps (ECDH), which on an interactive
    # wrapping key would force a Touch ID prompt at the very end of init. The catch
    # is broad (Exception) because the keyvault is already durable; any storage
    # failure must degrade to a note, not a traceback.
    try:
        from ..keyvault.ethereum import store_seed_phrase

        seed_env_id = store_seed_phrase(key_id, mnemonic, backend=backend, audit_sink=audit_sink, home=home)
        print(f"HD wallet enabled. Seed stored SE-encrypted (envelope {seed_env_id}).")
    except Exception as exc:
        _term.emit_note(
            f"HD seed not stored ({exc!r}); the keyvault is still initialised, "
            "but HD derivation is unavailable until the seed is stored."
        )


def init_keyvault(
    *,
    home: Path | None = None,
    backend: NativeBackend | None = None,
    prompt_io: PromptIO | None = None,
    surface: SeedDisplaySurface | None = None,
    audit_sink: AuditSink | None = None,
    display_fn: Callable[[SeedDisplayHandle, SeedDisplaySurface], None] | None = None,
    blackout_assert: Callable[..., None] | None = None,
    store_seed_for_hd: bool = True,
    unattended: bool | None = None,
    flow_session: FlowSession | None = None,
) -> int:
    """Initialise the keyvault: generate the key, display the Seed, finalize.

    Flow (SPEC.md §"``keyvault init`` flow"):

    1. Re-init guard — v1 keyvault is single-key.
    1a. Air-gap pre-check — refuse fast if the host is online, *before* the
        passphrase prompt, so an online operator is not asked to type a
        passphrase that the late blackout gate would discard. ``display_seed``
        re-asserts isolation as the real gate (defense in depth).
    1b. stdout-TTY guard — the production surface prints the Seed to stdout,
        so refuse under a redirect before the 24 words could land in a file
        (:func:`_refuse_if_stdout_redirected`).
    2. Prompt for the Passphrase twice (hidden, must match, non-empty).
    3. Generate a 24-word BIP39 Seed Phrase + the seed-bound PoW.
    4. ``prepare_generate`` — compute the verification digest in memory.
    5. ``display_seed`` — show the Seed under a network blackout for 60s.
    6. The operator computes the digest offline and transcribes it back.
    7. ``confirm_generate`` — finalize only if the digest matches.
    8. If ``store_seed_for_hd``: SE-encrypt the generated seed
       (offline wrap, no prompt) so the HD wallet can derive Ethereum
       accounts later without re-entering the words. Best-effort — the
       keyvault is already durable, so a storage failure degrades to a note.
       Default ``True`` makes encrypted seed storage the standard
       operation. ``False`` keeps the seed paper-only (never persisted).

    ``backend`` / ``prompt_io`` / ``surface`` / ``display_fn`` /
    ``blackout_assert`` default to the production implementations; tests
    inject fakes. Returns 0 on a finalized keyvault, 1 on any refusal
    (already initialised, online host at the pre-check, passphrase mismatch,
    blackout failure, capture abort, expiry, digest mismatch, Enclave error).

    ``unattended`` selects the authorization policy for the newly generated
    wrapping key: ``True`` makes it usable by background callers (e.g. the
    extension Gateway) without a per-use Touch ID / passcode prompt; ``False``
    keeps the interactive per-use prompt; ``None`` (the default) preserves the
    prior behaviour exactly, falling back to the ``MORDRED_SEKEY_UNATTENDED``
    env var deep in ``keyvault._seckey_backend``. Forwarded verbatim to
    :func:`..keyvault.api.confirm_generate`.

    ``flow_session`` is set only by ``hermes-mordred setup``: the
    Passphrase chosen here is remembered in memory so the vault created later in
    the same run reuses it instead of prompting again (see
    :mod:`._flow_session`). Standalone ``keyvault init`` passes ``None``.
    """
    refusal = _preflight_or_refuse(home=home, blackout_assert=blackout_assert, surface=surface)
    if refusal is not None:
        return refusal

    prompt_io = resolve_prompt_io(prompt_io)
    # Orient the operator before the bare passphrase prompt: what this
    # command does and what the Passphrase protects (UX review 2026-06-15).
    print(_intro_banner(), file=sys.stderr)
    if flow_session is not None:
        print(_SETUP_SHARED_PASSPHRASE_NOTE, file=sys.stderr)
    passphrase = _read_passphrase(prompt_io, flow_session)
    if passphrase is None:
        return 1

    handle, pow_bytes, mnemonic_for_hd = _generate_seed_material(passphrase, store_seed_for_hd=store_seed_for_hd)
    del passphrase

    refusal = _display_seed_or_refuse(handle, pow_bytes, surface=surface, display_fn=display_fn)
    if refusal is not None:
        return refusal

    user_digest = _prompt_for_digest(prompt_io)
    if user_digest is None:
        return 1

    backend = resolve_backend(backend)
    sink = audit_sink if audit_sink is not None else _stderr_audit_sink

    result = _confirm_or_refuse(handle, user_digest, backend=backend, audit_sink=sink, home=home, unattended=unattended)
    if result is None:
        return 1

    _provision_audit_log_key(backend, home=home)

    # HD mode (Option A): SE-encrypt the just-generated seed so the HD wallet can
    # derive Ethereum accounts later without re-entering the 24 words. Best-effort
    # — the keyvault is already durably initialised at this point.
    if mnemonic_for_hd is not None:
        _store_seed_for_hd_envelope(result.key_id, mnemonic_for_hd, backend=backend, audit_sink=sink, home=home)
        del mnemonic_for_hd

    print(f"Keyvault initialised. Key: {result.key_id}")
    print(
        "Next: create the portable Keyvault snapshot with "
        "`hermes-mordred keyvault export --output /secure/path/keyvault-backup.mrkv`. "
        "Store it separately from the init passphrase and 24-word Seed Phrase."
    )
    print(
        "The backup is a snapshot: export it again after `keyvault eth new`, direct Keyvault API writes, "
        "or any other Keyvault content change. Then use `hermes-mordred encryption enable env` for "
        "ordinary Hermes secrets, or `hermes-mordred status` for an overview."
    )
    return 0
