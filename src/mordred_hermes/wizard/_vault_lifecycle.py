"""At-rest vault lifecycle / key-management commands.

The commands that create or re-key a vault, as opposed to reading or enrolling
files (those live in :mod:`mordred_hermes.wizard._vault_entries`):

* :func:`init` -- create a fresh vault sealed under a new passphrase + device key.
* :func:`ensure_initialised` -- create the vault iff missing (the
  ``encryption enable`` on-ramp).
* :func:`change_passphrase` -- rotate the recovery passphrase, master unchanged.
* :func:`recover` -- re-key a copied vault onto this device, restoring the hot path.

They share the open / identity helpers in
:mod:`mordred_hermes.wizard._vault_open`; the argparse adapters that wrap them
live in :mod:`mordred_hermes.wizard.vault_cli`, which re-exports these so
existing callers and tests resolve them unchanged. Heavy cryptography-backed
imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

from . import _term
from ._defaults import resolve_backend, resolve_prompt_io, resolve_store
from ._vault_open import _build_device_auth, _vault_identity

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO


def init(
    *,
    root: Path,
    prompt_io: PromptIO | None = None,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
    _absence_checked: bool = False,
) -> int:
    """Create a fresh encrypted vault at ``root`` sealed under a new passphrase.

    Seals one master under both the device wrapping key (hot path) and an
    Argon2id passphrase recovery sidecar (cold path). The wrapping key prefers
    the Secure Enclave and transparently falls back to a software key when the
    Enclave is unavailable (e.g. a non-provisioned interpreter); the cold path
    is unaffected either way.

    Refuses to clobber an already-initialised vault (its anchor is present).
    ``backend`` / ``store`` / ``prompt_io`` default to the production
    implementations; tests inject fakes. Returns 0 on success, 1 on a re-init,
    a passphrase mismatch / empty passphrase, or a Secure-Enclave / Keychain
    error.

    ``flow_session`` (a guided flow: ``setup``, ``encryption enable all``, the
    Telegram / Desktop setup) shares state with the flow's other steps, in
    memory only:

    - a passphrase the operator already chose and confirmed earlier in the flow
      becomes the recovery passphrase without prompting again, and one chosen
      here is remembered for later steps;
    - ``flow_session.unattended`` selects the new device key's policy (``None``
      keeps the backend default: ``MORDRED_SEKEY_UNATTENDED``, else attended);
    - the freshly created vault stays open in the flow, so the flow's next
      steps enroll through it without unwrapping the master again (no Touch ID).
    """
    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError, WrapKeyNotFound

    key_id = anchor_label = _vault_identity(root)

    backend = resolve_backend(backend)
    store = resolve_store(store)

    # Re-init guard before prompting: an existing anchor means a live vault. A
    # Keychain read failure here is fail-closed (we cannot prove the vault is
    # absent, so we must not risk clobbering one). ``_absence_checked`` is set
    # only by :func:`ensure_initialised`, which has just read the same item and
    # found none: reading it again would be one more Keychain access for
    # nothing. ``init_vault`` re-checks under the vault lock either way.
    try:
        already_initialised = not _absence_checked and store.read(anchor_label) is not None
    except (anchor.AnchorError, OSError) as exc:
        _term.emit_error(f"Cannot determine vault state at {root}: {exc}")
        return 1
    if already_initialised:
        _term.emit_error(f"A vault is already initialised at {root} — refusing to clobber it.")
        return 1

    prompt_io = resolve_prompt_io(prompt_io)
    # Teach the two-key model at creation time — the single most confusing point
    # for newcomers (vault has ONE master key opened two ways): the device key is
    # the everyday opener; the passphrase is the cold-path backup, not something
    # typed day to day. Saying so up front pre-empts "do I type this every time?"
    # and "is the passphrase the only key?".
    print("This vault can be opened two ways:")
    print("  • this device          — automatically, no typing (Secure Enclave, or a software key if unavailable)")
    print("  • a recovery passphrase — your backup, used only if this device is lost or replaced")
    passphrase = _choose_recovery_passphrase(prompt_io, flow_session)
    if passphrase is None:
        return 1

    try:
        # Ensure the device wrapping key exists (init seals under it). A
        # pre-existing key from a crashed earlier init is reused — not an error.
        # (A pre-existing key keeps the policy it was created with.)
        unattended = flow_session.unattended if flow_session is not None else None
        with contextlib.suppress(WrapKeyNotFound):
            backend.generate_enclave_key(key_id, unattended=unattended)
        created = vault.init_vault(
            root, key_id=key_id, passphrase=passphrase, backend=backend, store=store, anchor_label=anchor_label
        )
        if flow_session is not None:
            # Keep it open for the flow's next steps (closed when the flow ends):
            # enrolling through it needs no second unwrap / Touch ID.
            flow_session.keep_vault(root, created)
        else:
            # Standalone: init enrolls nothing; close now so the in-RAM master is zeroed.
            created.close()
    except vault.VaultError as exc:
        # A concurrent init won the anchor race after our pre-check.
        _term.emit_error(f"Vault init refused: {exc}")
        return 1
    except (anchor.AnchorError, WrapError, OSError) as exc:
        _term.emit_error(f"Vault init failed: device key store / anchor error — {exc}")
        return 1
    finally:
        del passphrase

    print(f"Vault initialised at {root}.")
    print("  Day to day: this device opens the vault automatically — you won't be asked for the passphrase.")
    print(
        "  If this device is lost: the recovery passphrase is the ONLY way back in — "
        "store it safely (e.g. a password manager)."
    )
    return 0


def _choose_recovery_passphrase(prompt_io: PromptIO, flow_session: FlowSession | None) -> str | None:
    """The new vault's recovery passphrase: reused from the flow, or chosen now.

    A passphrase the operator already chose and confirmed earlier in the same
    flow is reused without prompting. Otherwise ask once plus one confirmation,
    and remember the result in the flow. Returns ``None`` (after printing) on an
    empty entry or a mismatch.
    """
    reused = flow_session.passphrase if flow_session is not None else None
    if reused:
        print("The recovery passphrase is the one you already chose in this setup run — no new prompt.")
        print()
        return reused
    print("Next you'll set the recovery passphrase. You will NOT need to type it day to day.")
    print()
    passphrase = prompt_io.ask_password("Choose a vault recovery passphrase")
    if not passphrase:
        _term.emit_error("Passphrase must not be empty — nothing was written.")
        return None
    if passphrase != prompt_io.ask_password("Re-enter the passphrase"):
        _term.emit_error("Passphrases do not match — nothing was written.")
        return None
    if flow_session is not None:
        flow_session.remember_passphrase(passphrase)
    return passphrase


def ensure_initialised(
    *,
    root: Path,
    prompt_io: PromptIO | None = None,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> int:
    """Create the vault if it is missing; no-op (return 0) if it already exists.

    The high-level ``encryption enable`` path *drives* the vault (USAGE §4, "the
    three storage layers"): a first enable on a fresh install creates the vault
    inline — prompting once for a recovery passphrase via :func:`init` — instead
    of failing with a "run ``vault init``" error. An already-initialised vault is
    left untouched, so repeat enables never re-prompt.

    Returns 0 when the vault exists (or was just created), 1 on a create failure
    (passphrase mismatch / empty, Secure-Enclave / Keychain error) or when the
    vault state cannot be determined (fail-closed, mirroring :func:`init`).

    ``flow_session`` is forwarded to :func:`init` (see there).
    """
    from ..keyvault import anchor

    if flow_session is not None and flow_session.lend_vault(root) is not None:
        # The flow already holds this vault open, so it exists: no Keychain read.
        return 0

    store = resolve_store(store)

    anchor_label = _vault_identity(root)
    try:
        if store.read(anchor_label) is not None:
            return 0  # vault already initialised — nothing to do
    except (anchor.AnchorError, OSError) as exc:
        # Fail-closed: we cannot prove the vault is absent, so do not risk
        # clobbering one with a fresh init (matches the guard in `init`).
        _term.emit_error(f"Cannot determine vault state at {root}: {exc}")
        return 1

    print(f"No vault yet at {root} — creating one (this is where `encryption` stores secrets at rest).")
    # `store` is already resolved above, so `init` reuses this instance rather than
    # opening a second Keychain connection — keep the resolution before delegating.
    return init(
        root=root,
        prompt_io=prompt_io,
        backend=backend,
        store=store,
        flow_session=flow_session,
        _absence_checked=True,
    )


def change_passphrase(
    *,
    root: Path,
    prompt_io: PromptIO | None = None,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Change the vault's recovery passphrase, keeping the master key unchanged.

    Tries the device key first — no old passphrase needed, the everyday "I forgot
    the passphrase but this machine still works" path. If the device key / anchor
    is unavailable (non-macOS, or a vault copied here), falls back to asking for
    the current passphrase. Only the recovery sidecar is rewritten; no enrolled
    file is re-encrypted and the device-key open is unaffected.

    Returns 0 on success, 1 on any failure (no vault, empty / mismatched new
    passphrase, wrong current passphrase, or an unrecoverable device error).
    """
    from cryptography.exceptions import InvalidTag

    from ..keyvault import anchor, recovery, vault
    from ..keyvault._exceptions import WrapError

    key_id = anchor_label = _vault_identity(root)

    # The recovery sidecar is the one file we rewrite; its absence means there is
    # no vault to rotate. Do NOT create one here (unlike `encryption enable`).
    if not (root / "recovery.mrkv").exists():
        _term.emit_error(f"No vault at {root} — nothing to rotate. Run `encryption enable env` first.")
        return 1

    # Off-macOS the SE backend / keychain don't import; _build_device_auth returns
    # (None, None) then, and we fall through to the passphrase path below.
    device_backend, device_store = _build_device_auth(backend, store)
    prompt_io = resolve_prompt_io(prompt_io)

    new_passphrase = prompt_io.ask_password("Choose a NEW recovery passphrase")
    if not new_passphrase:
        _term.emit_error("Passphrase must not be empty — nothing was changed.")
        return 1
    if new_passphrase != prompt_io.ask_password("Re-enter the new passphrase"):
        _term.emit_error("Passphrases do not match — nothing was changed.")
        return 1

    try:
        # Device-key path first — no need to know the old passphrase. With no
        # usable device backend/store (off-macOS), route straight to the cold path.
        if device_backend is None or device_store is None:
            raise WrapError("no usable device key on this host")
        vault.change_passphrase(
            root,
            new_passphrase=new_passphrase,
            old_passphrase=None,
            key_id=key_id,
            backend=device_backend,
            store=device_store,
            anchor_label=anchor_label,
        )
    except (anchor.AnchorError, WrapError):
        # Device key / anchor unusable here — fall back to the cold path, which is
        # authorized by the current passphrase instead.
        print("This device's key can't authorize the change here — enter your CURRENT passphrase to continue.")
        old_passphrase = prompt_io.ask_password("Current recovery passphrase")
        try:
            vault.change_passphrase(
                root,
                new_passphrase=new_passphrase,
                old_passphrase=old_passphrase,
                key_id=key_id,
                backend=device_backend,
                store=device_store,
                anchor_label=anchor_label,
            )
        except (vault.VaultError, recovery.RecoveryDigestMismatch, InvalidTag, ValueError, OSError) as exc:
            _term.emit_error(f"Could not change the passphrase: {exc}")
            return 1
        finally:
            del old_passphrase
    except (vault.VaultError, ValueError, OSError) as exc:
        # OSError covers a disk failure in the atomic sidecar write and a
        # wrong-mode .lock (KeyvaultPermissionError) — surface as a clean exit 1,
        # not a traceback. (AnchorError / WrapError are handled above as the
        # device-unavailable fallback, so they never reach here.)
        _term.emit_error(f"Could not change the passphrase: {exc}")
        return 1
    finally:
        del new_passphrase

    print("Recovery passphrase changed.")
    print("  Your device key is unchanged — day-to-day automatic opening still works exactly as before.")
    print("  Only the backup passphrase changed. Store the new one safely (e.g. a password manager).")
    return 0


def recover(
    *,
    root: Path,
    prompt_io: PromptIO | None = None,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Re-key a vault copied to THIS machine onto its device, restoring the hot path.

    The encryption-vault counterpart of ``keyvault recover``. A vault directory
    copied from another machine has lost the original Secure-Enclave wrapping key
    and the device-bound anchor, so ``vault cat`` opens it read-only (cold path)
    -- ``vault status`` needs neither the device key nor the passphrase, since it
    reads the on-disk manifest directly without opening the vault at all. This
    command cold-opens it via the recovery passphrase and
    re-wraps the SAME master under a fresh wrapping key on this device — writing a
    new manifest generation and flipping a new anchor — so the everyday writable
    device hot path works locally again. The master and every enrolled file are
    unchanged; only the device binding (``wmk`` + anchor) and the recovery sidecar
    are renewed.

    ``backend`` / ``store`` / ``prompt_io`` default to the production
    implementations (built tolerantly via :func:`_build_device_auth`); tests
    inject fakes. Returns 0 on success, 1 on any fail-closed error (no vault, a
    wrong passphrase, a tampered manifest / sidecar, or a Secure-Enclave /
    Keychain failure) with a reason printed to stderr.
    """
    from cryptography.exceptions import InvalidTag

    from ..keyvault import anchor, backup, manifest, recovery, vault
    from ..keyvault._exceptions import WrapError

    key_id = anchor_label = _vault_identity(root)

    # Re-keying needs a usable device backend + anchor store to bind onto. Off
    # macOS these don't import; _build_device_auth returns (None, None) then, and
    # we fail closed (there is no device to re-key onto).
    device_backend, device_store = _build_device_auth(backend, store)
    if device_backend is None or device_store is None:
        _term.emit_error(
            f"Cannot re-key the vault at {root}: no usable device key on this host (Secure Enclave / TPM unavailable)."
        )
        return 1

    prompt_io = resolve_prompt_io(prompt_io)
    passphrase = prompt_io.ask_password("Vault recovery passphrase")

    try:
        opened = vault.recover_to_device(
            root,
            passphrase,
            backend=device_backend,
            store=device_store,
            key_id=key_id,
            anchor_label=anchor_label,
        )
    except vault.VaultError as exc:
        _term.emit_error(f"Not a recoverable vault at {root}: {exc}")
        return 1
    except recovery.RecoveryDigestMismatch:
        _term.emit_error(
            "Vault rejected: the recovery sidecar does not match the manifest (substituted wmk / tampering)."
        )
        return 1
    except manifest.ManifestError:
        _term.emit_error("Vault rejected: the manifest failed authentication (tampering).")
        return 1
    except backup.BackupCorrupt as exc:
        _term.emit_error(f"Vault rejected: the recovery sidecar is corrupt — {exc}")
        return 1
    except InvalidTag:
        _term.emit_error("Wrong passphrase — vault not re-keyed.")
        return 1
    except (anchor.AnchorError, WrapError) as exc:
        _term.emit_error(f"Could not re-key the vault at {root}: device key / anchor error — {exc}")
        return 1
    except OSError as exc:
        _term.emit_error(f"Could not re-key the vault at {root}: {exc}")
        return 1
    finally:
        # CPython cannot zero an immutable str in place; dropping the reference
        # shortens the exposure window, it does not scrub the bytes.
        del passphrase
    opened.close()

    print(f"Vault re-keyed onto this device; hot path restored at {root}.")
    print("  Day to day: this device now opens the vault automatically — no passphrase needed.")
    print("  Your recovery passphrase is unchanged; keep it safe for the next machine.")
    return 0
