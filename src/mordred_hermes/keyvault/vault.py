"""mordred_hermes.keyvault.vault — the on-disk Mordred vault orchestration.

Composes the keyvault primitives into the artifact that actually encrypts
``.env`` / ``config.yaml`` / Hermes memory at rest:

- :mod:`mordred_hermes.keyvault.vault_master` seals ONE master (Secure-
  Enclave ``wmk`` hot path + Argon2id passphrase recovery cold path),
- :mod:`mordred_hermes.keyvault.file_container` (``MVLT``) encrypts each
  file's bytes under that master,
- :mod:`mordred_hermes.keyvault.manifest` (``MVMF``) is the authenticated
  registry of enrolled files + their ciphertext digests + a generation,
- :mod:`mordred_hermes.keyvault.anchor` pins ``SHA-256(wmk)`` + generation
  in a device-bound store an offline attacker can read but not write.

On-disk layout under ``root/``::

    manifest.<gen>.mvmf   one authenticated manifest per generation
    blobs/<sha256>.blob   content-addressed MVLT ciphertexts
    recovery.mrkv         Argon2id passphrase recovery sidecar (cold path)
    .lock                 fcntl.flock target for write transactions

**Commit model (crash safety + anti-rollback).** The device-bound anchor
names which generation is authoritative, so the anchor flip is the single
commit point of an :meth:`OpenVault.enroll_file` transaction:

1. write the new content-addressed ciphertext blob,
2. write ``manifest.<N+1>.mvmf``,
3. **flip the anchor to generation N+1** ← commit,
4. (best-effort) garbage-collect the superseded manifest + orphan blobs.

A crash before step 3 leaves the anchor pinning generation N: reopening
loads ``manifest.<N>``, the half-written generation is ignored, and the
vault is neither bricked nor rolled forward (Codex review P1-c). Because
the anchor pins the canonical wmk fingerprint and the authoritative
generation, an offline attacker can neither substitute a wmk they minted
against the (public) SE key (P1-a) nor roll the whole vault back to an
older validly-MAC'd snapshot (P1-b) — both move a value only the locked
device can write.

**Fail-closed.** An enrolled name MUST decrypt: a name absent from the
manifest, a missing blob, a blob that does not match its content address,
or an AEAD failure all raise :class:`VaultError`; the vault never falls
back to reading a file as plaintext.

**Threat ceiling (B2 / unattended SE).** This protects offline disk reads
and offline disk swaps (stolen / powered-off / imaged / backup). It does
NOT protect against a same-uid attacker on a running, unlocked machine —
an unattended wrapping key lets any same-uid process unwrap the master.
That tradeoff is accepted for hands-free operation.

It imports :mod:`cryptography` through the cross-platform ``keyvault`` extra.
Device custody remains abstracted behind the injected native backend and
anchor store.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from types import TracebackType

from . import anchor, file_container, manifest, vault_master
from ._storage import atomic_write, ensure_lock_file, keyvault_lock, safe_read
from .anchor import AnchorStore
from .kek import MasterKey, open_master_key
from .wrap import NativeBackend

_RECOVERY_NAME = "recovery.mrkv"
_LOCK_NAME = ".lock"
_BLOBS_DIR = "blobs"
_DIR_MODE = 0o700


class VaultError(Exception):
    """A vault operation failed closed.

    Raised for vault-level faults: an uninitialized / already-initialized
    root, a missing authoritative manifest, a name that is not enrolled, a
    ciphertext blob that is missing or does not match its content address,
    an AEAD failure, or use of a closed vault. Distinct from
    :class:`mordred_hermes.keyvault.anchor.AnchorError` (freshness-pin
    failures) and :class:`mordred_hermes.keyvault.manifest.ManifestError`
    (manifest authentication failures), which propagate as themselves so a
    caller can tell a tamper attempt from an operational error — but all
    three are hard failures that prevent the vault from opening or reading.
    """


def _manifest_path(root: Path, generation: int) -> Path:
    return root / f"manifest.{generation}.mvmf"


def _all_manifest_generations(root: Path) -> list[int]:
    """Every ``manifest.<gen>.mvmf`` generation present on disk (unsorted)."""
    generations: list[int] = []
    for p in root.glob("manifest.*.mvmf"):
        middle = p.name[len("manifest.") : -len(".mvmf")]
        if middle.isdigit():
            generations.append(int(middle))
    return generations


def _latest_manifest_generation(root: Path) -> int | None:
    """Highest ``manifest.<gen>.mvmf`` generation on disk, or ``None`` if none.

    The cold-path fallback when there is no device-bound anchor to name the
    authoritative generation. (Normal :func:`open_vault` never guesses — the
    anchor names it.) :func:`_load_recovery_matched_unverified` refines this to
    the newest generation the recovery sidecar actually certifies.
    """
    generations = _all_manifest_generations(root)
    return max(generations) if generations else None


def _blob_path(root: Path, digest: str) -> Path:
    return root / _BLOBS_DIR / f"{digest}.blob"


def _ensure_dir(path: Path) -> None:
    # lstat-based: a symlink (even one pointing at a real 0700 dir) is refused
    # so an offline-planted symlink cannot redirect the vault tree's chmod /
    # writes outside the 0700 root (codex impl-review P2). The residual
    # lstat->mkdir/chmod TOCTOU only matters to a live same-uid attacker, who
    # is out of scope.
    if path.is_symlink():
        raise VaultError(f"refusing to use a symlinked vault path: {path}")
    if not path.exists():
        path.mkdir(mode=_DIR_MODE, parents=True)
    elif not path.is_dir():
        raise VaultError(f"vault path exists but is not a directory: {path}")
    os.chmod(path, _DIR_MODE)


def _ensure_lock(root: Path) -> None:
    # keyvault_lock opens .lock without O_CREAT, so materialize it first;
    # creation races and symlink refusal live in _storage.ensure_lock_file.
    ensure_lock_file(root / _LOCK_NAME)


def artifacts_present(root: Path) -> bool:
    """Whether vault manifest artifacts (``manifest.*.mvmf``) remain at ``root``.

    The anchor-deletion tell shared by the startup shims
    (:mod:`._runtime_env` / :mod:`._config_bootstrap`): the device-bound
    anchor is the one vault component an offline attacker can *delete* but
    not forge, so "anchor missing while authenticated manifests are still on
    disk" is anomalous — treating it as "no vault here" would let an anchor
    deletion silently downgrade the process to whatever plaintext remains.
    Only the detection is shared; each caller decides the outcome (both
    shims fail closed with their own messages, and a missing anchor with NO
    artifacts stays a clean "no vault at this root").
    """
    return any(root.glob("manifest.*.mvmf"))


def _load_pinned_unverified(
    root: Path,
    *,
    store: AnchorStore,
    anchor_label: str,
    missing_detail: str,
) -> tuple[bytes, manifest.VaultManifest]:
    """Device-path open preamble shared by :func:`open_vault` and the device
    branch of :func:`change_passphrase`: read the device-bound anchor, load
    the manifest generation it pins, and pin-check it.

    The pin-check runs BEFORE anything is unwrapped: the ``wmk`` the caller
    is about to feed the Enclave must match the fingerprint the (unwritable)
    anchor holds, and the manifest's generation must match the authoritative
    generation (defeats P1-a substitution + P1-b rollback). ``missing_detail``
    finishes the missing-manifest message so each caller keeps its exact
    error string.

    Returns ``(blob, untrusted)`` — parsed but NOT yet authenticated; the
    caller still authenticates via :func:`manifest.decode` under the master.
    """
    record = anchor.read_anchor(store, anchor_label)
    try:
        blob = safe_read(_manifest_path(root, record.generation))
    except FileNotFoundError as e:
        raise VaultError(
            f"authoritative manifest for generation {record.generation} is missing — {missing_detail}"
        ) from e
    untrusted = manifest.parse_unverified(blob)
    # Pin-check against the record read above: ONE Keychain read per open.
    # Re-reading here added nothing (the record was just read and nothing is
    # locked between the two reads) but cost a second Keychain access, and with
    # it a second macOS access dialog whenever the item's ACL does not trust
    # the calling binary.
    anchor.verify_pinned(record, wmk=untrusted.wmk, generation=untrusted.generation)
    return blob, untrusted


def _load_latest_unverified(root: Path, *, action: str) -> tuple[int, bytes, manifest.VaultManifest]:
    """Cold-path open preamble shared by :func:`recover_vault`,
    :func:`recover_to_device`, and the cold branch of :func:`change_passphrase`:
    pick the newest on-disk manifest and parse it unverified.

    These paths have no device-bound anchor to name the authoritative
    generation, so the newest ``manifest.<gen>.mvmf`` is the fallback; the
    manifest is only trusted after :func:`manifest.decode` authenticates it
    under the passphrase-recovered master. ``action`` finishes the
    vanished-manifest message ("cannot recover this vault" / "cannot re-key
    this vault" / "cannot rotate") so each caller keeps its exact error string.
    """
    generation = _latest_manifest_generation(root)
    if generation is None:
        raise VaultError("no manifest found at this root — not a vault, or all manifests are missing")
    try:
        blob = safe_read(_manifest_path(root, generation))
    except FileNotFoundError as e:
        raise VaultError(f"manifest for generation {generation} vanished — {action}") from e
    return generation, blob, manifest.parse_unverified(blob)


def _read_recovery_blob(root: Path, *, action: str) -> bytes:
    """Read the passphrase recovery sidecar, failing closed with the caller's
    exact message tail when it is missing."""
    try:
        return safe_read(root / _RECOVERY_NAME)
    except FileNotFoundError as e:
        raise VaultError(f"recovery sidecar (recovery.mrkv) is missing — {action}") from e


def _load_recovery_matched_unverified(
    root: Path, recovery_blob: bytes, *, action: str
) -> tuple[int, bytes, manifest.VaultManifest]:
    """Cold-path manifest selection that tolerates a crash mid recover_to_device.

    :func:`recover_to_device` writes ``manifest.<new_gen>`` (bound to the NEW
    ``wmk``) BEFORE it rewrites the recovery sidecar (also the new ``wmk``);
    those two files cannot be updated atomically together. A crash in that
    window leaves the newest manifest bound to a ``wmk`` the still-old sidecar
    does not certify, so picking strictly the newest manifest
    (:func:`_load_latest_unverified`) would raise
    :class:`recovery.RecoveryDigestMismatch` on every recovery entry point even
    though the older, self-consistent generation is fully intact on disk.

    We therefore pick the NEWEST generation whose ``SHA-256(wmk)`` matches the
    sidecar's embedded verification digest — the generation the passphrase can
    actually open. When none match (a genuinely substituted / rolled-back
    ``wmk``, or an empty root), we fall back to :func:`_load_latest_unverified`
    so the same ``RecoveryDigestMismatch`` / "no manifest" errors still surface
    downstream rather than a silent wrong pick. The chosen manifest is
    authenticated under the passphrase-recovered master by the caller, so this
    selection never weakens the tamper guarantees.
    """
    for generation in sorted(_all_manifest_generations(root), reverse=True):
        try:
            blob = safe_read(_manifest_path(root, generation))
        except FileNotFoundError:
            continue
        untrusted = manifest.parse_unverified(blob)
        if vault_master.recovery_blob_matches_wmk(recovery_blob, untrusted.wmk):
            return generation, blob, untrusted
    return _load_latest_unverified(root, action=action)


def init_vault(
    root: Path,
    *,
    key_id: str,
    passphrase: str,
    backend: NativeBackend,
    store: AnchorStore,
    anchor_label: str,
) -> OpenVault:
    """Create a fresh, empty vault at ``root`` and return it opened.

    Seals one master under the existing Secure-Enclave wrapping key
    ``key_id`` (SE ``wmk`` + passphrase recovery), writes the recovery
    sidecar and the generation-0 manifest, then flips the device-bound
    anchor to generation 0 — the same commit point an enroll uses, so a
    crashed init (no anchor) simply allows a clean re-init.

    Raises:
        VaultError: a vault is already initialized at ``root`` (its anchor
            exists in ``store``).
        ValueError: ``passphrase`` is empty.
        WrapKeyNotFound: no SE wrapping key exists for ``key_id``.
    """
    root = Path(root)
    _ensure_dir(root)
    _ensure_dir(root / _BLOBS_DIR)
    _ensure_lock(root)

    sealed, master = vault_master.seal(key_id=key_id, passphrase=passphrase, backend=backend)
    try:
        # The clobber-check and the writes are one critical section: checking
        # the anchor outside the lock would let two concurrent inits both pass
        # it and then race their writes, silently destroying the first vault.
        with keyvault_lock(root):
            if store.read(anchor_label) is not None:
                raise VaultError(f"a vault is already initialized for anchor label {anchor_label!r}")
            atomic_write(root / _RECOVERY_NAME, sealed.recovery)
            empty = manifest.VaultManifest(key_id=key_id, wmk=sealed.wmk, files={}, generation=0)
            atomic_write(_manifest_path(root, 0), manifest.encode(empty, master))
            anchor.write_anchor(store, anchor_label, wmk=sealed.wmk, generation=0)
    except BaseException:
        master.close()
        raise
    return OpenVault(
        root=root,
        key_id=key_id,
        master=master,
        manifest_=empty,
        store=store,
        anchor_label=anchor_label,
        wmk=sealed.wmk,
    )


def open_vault(
    root: Path,
    *,
    key_id: str,
    backend: NativeBackend,
    store: AnchorStore,
    anchor_label: str,
) -> OpenVault:
    """Open an existing vault, verifying freshness before trusting anything.

    Sequence (the two-phase bootstrap):

    1. read the device-bound anchor → the authoritative generation N (and
       the pinned wmk fingerprint),
    2. load ``manifest.<N>`` and ``parse_unverified`` it to extract ``wmk``,
    3. :func:`anchor.verify_pinned` — reject unless ``SHA-256(wmk)`` and the
       manifest's generation match the pins (defeats P1-a + P1-b),
    4. SE-unwrap the now-trusted ``wmk`` to obtain the master,
    5. :func:`manifest.decode` to authenticate the full manifest under it.

    Raises:
        AnchorMissing / AnchorMismatch / AnchorCorrupt: freshness-pin
            failure (all subclasses of ``AnchorError``).
        ManifestError: the manifest failed authentication under the master.
        VaultError: the authoritative manifest file is missing.
        WrapKeyNotFound / WrapAuthCancelled / ...: SE unwrap failures.
    """
    root = Path(root)
    blob, untrusted = _load_pinned_unverified(
        root,
        store=store,
        anchor_label=anchor_label,
        missing_detail="vault is corrupt or was rolled back below its anchor",
    )

    master = open_master_key(untrusted.wmk, key_id, backend=backend)
    try:
        verified = manifest.decode(blob, master)
    except BaseException:
        master.close()
        raise
    return OpenVault(
        root=root,
        key_id=key_id,
        master=master,
        manifest_=verified,
        store=store,
        anchor_label=anchor_label,
        wmk=untrusted.wmk,
    )


def recover_vault(root: Path, passphrase: str) -> OpenVault:
    """Open a vault from its passphrase recovery sidecar (cold path).

    For when the device — and therefore the Secure-Enclave wrapping key AND
    the device-bound anchor — is gone (new machine, lost key, non-macOS).
    Uses neither the SE backend nor the anchor store:

    1. pick the newest ``manifest.<gen>.mvmf`` whose ``wmk`` the recovery
       sidecar certifies (no anchor to name it; tolerant of a crash mid
       :func:`recover_to_device` — see :func:`_load_recovery_matched_unverified`),
    2. ``parse_unverified`` to extract ``wmk``,
    3. read ``recovery.mrkv`` and :func:`vault_master.open_passphrase` —
       its baked-in ``SHA-256(wmk)`` verification digest still binds the
       sidecar to the real ``wmk``, so a substituted manifest ``wmk`` raises
       :class:`~mordred_hermes.keyvault.recovery.RecoveryDigestMismatch`
       before the Argon2 cost; a wrong passphrase raises ``InvalidTag``,
    4. :func:`manifest.decode` authenticates the manifest under the recovered
       master.

    Accepted weakening vs :func:`open_vault`: with no device-bound anchor,
    recovery cannot guarantee freshness — an offline attacker who rolled the
    on-disk snapshot back to an older (validly-MAC'd, same-wmk) generation is
    undetectable here. The returned vault is therefore READ-ONLY: enrolling
    requires re-keying onto a new device first (a separate operation).

    Raises:
        VaultError: no manifest on disk, or the recovery sidecar is missing.
        recovery.RecoveryDigestMismatch: the manifest's ``wmk`` was substituted.
        cryptography.exceptions.InvalidTag: wrong passphrase.
        ManifestError: the manifest failed authentication under the master.
    """
    root = Path(root)
    recovery_blob = _read_recovery_blob(root, action="cannot recover this vault")
    _generation, blob, untrusted = _load_recovery_matched_unverified(
        root, recovery_blob, action="cannot recover this vault"
    )

    master = vault_master.open_passphrase(recovery_blob, passphrase, wmk=untrusted.wmk)
    try:
        verified = manifest.decode(blob, master)
    except BaseException:
        master.close()
        raise
    return OpenVault(
        root=root,
        key_id=verified.key_id,
        master=master,
        manifest_=verified,
        store=None,
        anchor_label="",
        wmk=untrusted.wmk,
    )


def recover_to_device(
    root: Path,
    passphrase: str,
    *,
    backend: NativeBackend,
    store: AnchorStore,
    key_id: str,
    anchor_label: str,
) -> OpenVault:
    """Cold-open a vault via its passphrase AND re-key it onto THIS device.

    The migrate-to-a-new-machine command. A vault directory copied to a new host
    has lost both the original Secure-Enclave wrapping key and the device-bound
    anchor, so :func:`recover_vault` can only open it READ-ONLY (no anchor to
    commit against). This restores the writable hot path locally:

    1. pick the newest ``manifest.<gen>.mvmf`` on disk (no anchor names it, like
       :func:`recover_vault`) and ``parse_unverified`` it for the old ``wmk`` +
       generation,
    2. :func:`vault_master.reseal_onto_device` — open the master from the
       recovery sidecar under *passphrase* (verify-before-decrypt against
       ``SHA-256(old_wmk)``), re-wrap the SAME master under a fresh wrapping key
       for ``key_id`` on this device, and re-mint the recovery sidecar against
       the new ``wmk``,
    3. re-encode the manifest under the (unchanged) master with the new ``wmk``
       at a new generation, carrying the SAME enrolled files,
    4. **persist the new manifest generation + the re-bound recovery sidecar
       BEFORE flipping the anchor** — the anchor flip is the single commit point,
       so a crash before it leaves the old generation authoritative (and the
       vault still cold-recoverable via the unchanged old sidecar... — see note),
    5. :func:`anchor.write_anchor` makes the new generation authoritative (the
       device-bind),
    6. garbage-collect the superseded generation (best-effort, post-commit,
       mirroring :meth:`OpenVault._gc`).

    The whole sequence runs under the vault lock so a concurrent writer cannot
    interleave. Crash-safety note: the new-generation manifest (bound to the new
    ``wmk``) is written BEFORE the re-bound recovery sidecar, and these two files
    cannot be updated atomically together. A crash between them leaves the newest
    manifest bound to a ``wmk`` the still-old sidecar does not certify. Recovery
    is therefore digest-guided (:func:`_load_recovery_matched_unverified`): it
    selects the newest generation whose ``SHA-256(wmk)`` matches the sidecar, so
    a re-run of ``recover`` (or :func:`recover_vault`) transparently re-keys from
    the older, self-consistent generation and the vault is never bricked by this
    window. The returned vault is fully device-anchored, so
    :meth:`OpenVault.enroll_file` works immediately.

    Raises:
        VaultError: no manifest / recovery sidecar at ``root``.
        recovery.RecoveryDigestMismatch: the manifest's ``wmk`` was substituted.
        cryptography.exceptions.InvalidTag: wrong *passphrase*.
        ManifestError: the manifest failed authentication under the recovered master.
        WrapError: the new device wrapping key could not be generated / used.
    """
    root = Path(root)
    _ensure_lock(root)
    with keyvault_lock(root):
        recovery_blob = _read_recovery_blob(root, action="cannot re-key this vault")
        generation, blob, untrusted = _load_recovery_matched_unverified(
            root, recovery_blob, action="cannot re-key this vault"
        )

        # Open the master under the passphrase + verify the manifest under it, so
        # we re-encode only an authenticated file set (never a forged manifest).
        master = vault_master.open_passphrase(recovery_blob, passphrase, wmk=untrusted.wmk)
        try:
            verified = manifest.decode(blob, master)
        except BaseException:
            master.close()
            raise

        try:
            # Re-key: re-wrap the SAME master under this device's (fresh) key and
            # re-bind the recovery sidecar to the new wmk.
            sealed = vault_master.reseal_onto_device(
                recovery_blob, passphrase, old_wmk=untrusted.wmk, key_id=key_id, backend=backend
            )
            new_generation = verified.generation + 1
            new_manifest = manifest.VaultManifest(
                key_id=key_id, wmk=sealed.wmk, files=dict(verified.files), generation=new_generation
            )
            # ---- write the new generation + the re-bound sidecar BEFORE the commit ----
            atomic_write(_manifest_path(root, new_generation), manifest.encode(new_manifest, master))
            atomic_write(root / _RECOVERY_NAME, sealed.recovery)
            # ---- commit: the anchor flip makes the new generation authoritative ----
            anchor.write_anchor(store, anchor_label, wmk=sealed.wmk, generation=new_generation)
        except BaseException:
            master.close()
            raise

        opened = OpenVault(
            root=root,
            key_id=key_id,
            master=master,
            manifest_=new_manifest,
            store=store,
            anchor_label=anchor_label,
            wmk=sealed.wmk,
        )
        # GC the superseded generation last (post-commit, best-effort), mirroring
        # enroll_file / change_passphrase. Reuses the live handle's _gc so the
        # current-manifest blob set is the keep-set.
        opened._gc(superseded_generation=generation)
        return opened


def change_passphrase(
    root: Path,
    *,
    new_passphrase: str,
    old_passphrase: str | None = None,
    key_id: str,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    anchor_label: str,
) -> None:
    """Rotate the recovery passphrase WITHOUT changing the master key.

    Re-seals the existing master under *new_passphrase* and atomically replaces
    the recovery sidecar (``recovery.mrkv``). The device key (``wmk``), the
    manifest, the generation, the anchor, and every enrolled file are untouched —
    only the cold-path sidecar changes, so no file is re-encrypted and the
    everyday device-key open is unaffected.

    Authorization:

    - **default (``old_passphrase is None``)** — the device wrapping key
      authorizes the rotation (the "forgot the passphrase but this machine still
      works" path). The anchor is verified first (freshness pin) before the
      trusted ``wmk`` is unwrapped. Requires ``backend`` and ``store``.
    - **``old_passphrase`` given** — the rotation is authorized by the current
      recovery blob instead (device-independent / a vault copied here); the newest
      on-disk manifest supplies the ``wmk`` (mirroring :func:`recover_vault`), and
      ``backend`` / ``store`` are unused.

    Locking: the device path performs the SE unwrap — which can block on an
    interactive Touch ID / passcode prompt indefinitely, with no timeout —
    BEFORE taking the vault lock, mirroring :func:`open_vault`'s
    unwrap-then-lock order. Holding the flock across a user wait would starve
    every other contender (a second CLI invocation, the extension gateway's
    signing executor) with no diagnostic. The pinned ``wmk`` is re-checked
    under the lock before the sidecar is replaced: if a concurrent re-key
    (:func:`recover_to_device`) won the race during the prompt, the rotation
    fails closed instead of clobbering the freshly minted sidecar with one
    digest-bound to the superseded (and GC'd) ``wmk`` — which would brick the
    cold path. The cold path's Argon2 rewrap is bounded (no user interaction),
    so its read-rewrap-write runs entirely under the lock. ``atomic_write``
    replaces the sidecar by temp+rename, so a crash leaves the previous
    (still-valid) blob in place.

    Raises:
        VaultError: no vault / manifest / recovery sidecar at ``root``, the
            device path was requested without a backend + store, or the vault
            was re-keyed concurrently while awaiting device authorization.
        ValueError: *new_passphrase* is empty.
        AnchorError: device-path freshness pin failed (missing / mismatched).
        recovery.RecoveryDigestMismatch / cryptography InvalidTag: wrong
            *old_passphrase* (or a substituted manifest ``wmk``).
    """
    root = Path(root)
    # keyvault_lock opens .lock without O_CREAT, so it must already exist. Mirror
    # init_vault / enroll_file and materialize it first: a vault whose .lock was
    # dropped (manual cleanup, or a backup that skipped the dotfile) would
    # otherwise fail the rotation with an uncaught FileNotFoundError.
    _ensure_lock(root)

    if old_passphrase is None:
        # Device-key path: pin-check the anchor, then trust the manifest wmk.
        if backend is None or store is None:
            raise VaultError("device-key rotation requires a backend and an anchor store")
        _read_recovery_blob(root, action="not a vault, or it is corrupt")
        # The unwrap inside rewrap_from_device is the interactive (Touch ID)
        # step — run it outside the lock; see the docstring's locking note.
        _blob, untrusted = _load_pinned_unverified(
            root, store=store, anchor_label=anchor_label, missing_detail="vault is corrupt"
        )
        new_recovery = vault_master.rewrap_from_device(
            key_id=key_id, new_passphrase=new_passphrase, backend=backend, wmk=untrusted.wmk
        )
        with keyvault_lock(root):
            # Re-pin under the lock: a re-key that landed during the prompt
            # minted a new wmk, and our sidecar certifies only the old one.
            _blob, current = _load_pinned_unverified(
                root, store=store, anchor_label=anchor_label, missing_detail="vault is corrupt"
            )
            if current.wmk != untrusted.wmk:
                raise VaultError(
                    "the vault was re-keyed while the rotation was awaiting device "
                    "authorization; rerun change-passphrase against the new state"
                )
            atomic_write(root / _RECOVERY_NAME, new_recovery)
    else:
        with keyvault_lock(root):
            recovery_blob = _read_recovery_blob(root, action="not a vault, or it is corrupt")
            # Cold path: the sidecar's SHA-256(wmk) digest binds it to the real
            # wmk, so pick the newest manifest the sidecar certifies (tolerant of
            # a crash mid recover_to_device; no anchor to name it here).
            _generation, _blob, untrusted = _load_recovery_matched_unverified(
                root, recovery_blob, action="cannot rotate"
            )
            new_recovery = vault_master.rewrap_from_passphrase(
                recovery_blob, old_passphrase, new_passphrase, wmk=untrusted.wmk
            )
            atomic_write(root / _RECOVERY_NAME, new_recovery)


class OpenVault:
    """A live handle to an opened vault.

    Holds the in-RAM master (closed on :meth:`close`) and the currently
    committed manifest. Read/enroll go through this handle; nothing here
    persists plaintext to disk. Usable as a context manager.
    """

    __slots__ = ("_closed", "_key_id", "_label", "_manifest", "_master", "_root", "_store", "_wmk")

    def __init__(
        self,
        *,
        root: Path,
        key_id: str,
        master: MasterKey,
        manifest_: manifest.VaultManifest,
        store: AnchorStore | None,
        anchor_label: str,
        wmk: bytes,
    ) -> None:
        self._root = root
        self._key_id = key_id
        self._master = master
        self._manifest = manifest_
        self._store = store
        self._label = anchor_label
        self._wmk = wmk
        self._closed = False

    def _check(self) -> None:
        if self._closed:
            raise VaultError("vault is closed")

    @property
    def generation(self) -> int:
        """The currently committed generation."""
        self._check()
        return self._manifest.generation

    def list_files(self) -> list[str]:
        """The logical names enrolled in the current manifest."""
        self._check()
        return list(self._manifest.files.keys())

    def read_file(self, name: str) -> bytes:
        """Decrypt and return the bytes of enrolled file ``name``.

        Fail-closed: a name absent from the manifest, a missing blob, a
        blob whose content does not match the manifest's content-address,
        or an AEAD failure all raise :class:`VaultError`.
        """
        self._check()
        digest = self._manifest.files.get(name)
        if digest is None:
            raise VaultError(f"{name!r} is not enrolled in this vault")
        bpath = _blob_path(self._root, digest)
        # No exists() pre-check: it races a concurrent gc, and safe_read's
        # FileNotFoundError is the authoritative "blob is gone" signal. Catch it
        # so the fail-closed read path only ever raises VaultError.
        try:
            blob = safe_read(bpath)
        except FileNotFoundError as e:
            raise VaultError(f"ciphertext blob for {name!r} is missing (digest {digest})") from e
        if not hmac.compare_digest(hashlib.sha256(blob).hexdigest(), digest):
            raise VaultError(f"ciphertext blob for {name!r} does not match its content address — rejected")
        try:
            return file_container.decode(blob, self._master, name=name)
        except file_container.EncryptedFileError as e:
            raise VaultError(f"failed to authenticate / decrypt {name!r}") from e

    def _commit_new_manifest(
        self,
        store: AnchorStore,
        new_manifest: manifest.VaultManifest,
        *,
        blobs: tuple[tuple[Path, bytes], ...] = (),
    ) -> None:
        """Commit ``new_manifest`` under the keyvault lock — shared by enroll/unenroll.

        Re-derives the authoritative state from the device anchor under the lock
        and fails closed if another writer advanced it: writing ``manifest.<N+1>``
        over the newer state and flipping the anchor back would roll the vault
        back and let :meth:`_gc` drop the newer writer's blobs (codex impl-review
        P1: stale-writer rollback). The anchor is the source of truth (an offline
        attacker cannot move it), so an advance here is a legitimate concurrent
        writer: fail closed and require a reopen.

        Writes any new content ``blobs`` (enroll supplies the ciphertext blob;
        unenroll supplies none) then the new manifest, then flips the anchor —
        the single commit point that makes ``new_manifest.generation``
        authoritative. A crash before the flip leaves the previous generation
        committed; :meth:`_gc` then drops the superseded manifest + orphan blobs.
        """
        new_generation = new_manifest.generation
        _ensure_lock(self._root)
        with keyvault_lock(self._root):
            pinned = anchor.read_anchor(store, self._label)
            stale_generation = pinned.generation != self._manifest.generation
            wmk_changed = not hmac.compare_digest(pinned.wmk_sha256, anchor.wmk_fingerprint(self._wmk))
            if stale_generation or wmk_changed:
                raise VaultError(
                    f"stale vault handle: in-memory generation {self._manifest.generation} no longer matches the "
                    f"device anchor (generation {pinned.generation}) — another writer advanced the vault; reopen it"
                )
            for blob_path, blob in blobs:
                atomic_write(blob_path, blob)
            atomic_write(_manifest_path(self._root, new_generation), manifest.encode(new_manifest, self._master))
            # ---- commit: the anchor flip makes generation N+1 authoritative ----
            anchor.write_anchor(store, self._label, wmk=self._wmk, generation=new_generation)
            self._manifest = new_manifest
            self._gc(superseded_generation=new_generation - 1)

    def enroll_file(self, name: str, plaintext: bytes) -> None:
        """Encrypt ``plaintext`` as enrolled file ``name`` and commit it.

        Bumps the generation, writes the content-addressed blob and the new
        manifest, then flips the anchor (the commit point). A crash before
        the flip leaves the previous generation committed.

        Raises:
            VaultError: the vault is closed, or was opened in recovery mode
                (no device anchor to commit against — re-key first).
        """
        self._check()
        if self._store is None:
            raise VaultError(
                "vault opened in recovery mode (no device-bound anchor) — re-key onto a device before enrolling"
            )
        store = self._store
        blob = file_container.encode(self._master, plaintext, key_id=self._key_id, wmk=self._wmk, name=name)
        digest = hashlib.sha256(blob).hexdigest()
        new_generation = self._manifest.generation + 1
        new_files = dict(self._manifest.files)
        new_files[name] = digest
        new_manifest = manifest.VaultManifest(
            key_id=self._key_id, wmk=self._wmk, files=new_files, generation=new_generation
        )
        self._commit_new_manifest(store, new_manifest, blobs=((_blob_path(self._root, digest), blob),))

    def unenroll_file(self, name: str) -> None:
        """Remove enrolled file ``name`` and commit — the mirror of :meth:`enroll_file`.

        Drops ``name`` from the manifest, bumps the generation, writes the new
        manifest, then flips the anchor (the commit point). The superseded blob is
        no longer referenced, so :meth:`_gc` garbage-collects it after the commit.
        A crash before the flip leaves the previous generation committed.

        Removing a name that is not enrolled is a clean no-op: nothing is written
        and the generation does not advance (so ``purge`` is idempotent).

        Raises:
            VaultError: the vault is closed, was opened in recovery mode (no device
                anchor to commit against), or the handle is stale (another writer
                advanced the vault since this handle last committed).
        """
        self._check()
        if name not in self._manifest.files:
            return  # nothing enrolled under this name — idempotent no-op, no churn
        if self._store is None:
            raise VaultError(
                "vault opened in recovery mode (no device-bound anchor) — re-key onto a device before unenrolling"
            )
        store = self._store
        new_generation = self._manifest.generation + 1
        new_files = dict(self._manifest.files)
        del new_files[name]
        new_manifest = manifest.VaultManifest(
            key_id=self._key_id, wmk=self._wmk, files=new_files, generation=new_generation
        )
        self._commit_new_manifest(store, new_manifest)

    def _gc(self, *, superseded_generation: int) -> None:
        """Best-effort: drop the superseded manifest + any orphan blobs.

        Runs only AFTER the anchor commit, so a failure here cannot lose
        committed data — it only leaves recoverable clutter. Blobs still
        referenced by the current manifest are never removed.
        """
        try:
            old = _manifest_path(self._root, superseded_generation)
            if old.exists():
                old.unlink()
            kept = set(self._manifest.files.values())
            for b in (self._root / _BLOBS_DIR).glob("*.blob"):
                if b.stem not in kept:
                    b.unlink()
        except OSError:
            pass

    def close(self) -> None:
        """Zero the in-RAM master and block further use. Idempotent."""
        if not self._closed:
            self._master.close()
            self._closed = True

    def __enter__(self) -> OpenVault:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        self.close()
