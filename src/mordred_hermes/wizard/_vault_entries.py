"""At-rest vault file commands: inspect and enroll.

The commands that read a vault's listing / contents or enroll plaintext into it,
as opposed to creating or re-keying it (those live in
:mod:`mordred_hermes.wizard._vault_lifecycle`):

* :func:`status` -- list a vault's generation + enrolled names (reads the
  on-disk manifest directly; never opens the vault, never prompts).
* :func:`cat` -- write one enrolled file's decrypted bytes to stdout (cold path).
* :func:`add` -- enroll one plaintext file (hot path, device key).
* :func:`add_and_verify` -- :func:`add` plus read the enrolled copy back through the
  same open (one device-key unlock) for callers that must verify before deleting
  the plaintext.
* :func:`migrate` -- batch-enroll several plaintext files in one open (hot path).

They share the open / display helpers in
:mod:`mordred_hermes.wizard._vault_open`; the argparse adapters that wrap them
live in :mod:`mordred_hermes.wizard.vault_cli`, which re-exports these so
existing callers and tests resolve them unchanged. Heavy cryptography-backed
imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from . import _term
from ._vault_open import _display_name, _open_cold_path, _open_hot_path_or_report

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO

# Upper bound for a manifest read in `status` (real manifests are a few KBs;
# the bytes are parsed unauthenticated, so refuse absurd sizes outright).
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def status(*, root: Path, prompt_io: PromptIO | None = None, as_json: bool = False) -> int:
    """Print a vault's generation and enrolled file names -- never prompts.

    Every status-shaped command in this CLI reads only what is on disk and
    never opens the vault or asks for a passphrase (the convention noted at
    the top of ``encryption_cli.py``); this one used to be the exception,
    unconditionally cold-opening via :func:`_open_cold_path`. It now reads the
    newest ``manifest.<gen>.mvmf`` body directly with
    :func:`...keyvault.manifest.parse_unverified` -- the same technique
    :func:`mordred_hermes.wizard.encryption_cli._enrolled_names` uses for the
    ``encryption status`` enrolled-name reads -- so no master key, device key,
    or passphrase is needed. ``prompt_io`` is accepted only for
    backward-compatible call sites; it is never used, and never will be
    called.

    Trade accepted for that: the manifest is read UNAUTHENTICATED (its MAC
    can only be checked under the master key, which needs a key of some kind
    to unwrap). A tampered tag or a substituted ``wmk`` is therefore not
    caught here -- only a command that actually opens the vault (``cat`` /
    ``add`` / ...) would catch that. The reported generation/names are
    operational metadata, not secret, so surfacing them unauthenticated is
    the same trade the rest of the CLI's status surface already makes.

    Returns 0 when a manifest is present and parses (including an
    empty/no-files vault); 1 when there is no vault at ``root`` or its
    manifest cannot be parsed (reason on stderr). File *contents* are never
    read, so this never fails on a wrong/missing passphrase, a corrupt
    recovery sidecar, or a missing device key -- see :func:`cat` for the
    command that does need those.
    """
    import json

    from ..keyvault import manifest, vault

    generation = vault._latest_manifest_generation(root)
    if generation is None:
        _term.emit_error(f"no vault at {root} — run `vault init` first.")
        return 1

    # The bytes are untrusted (see above) and parsed pre-authentication, so
    # bound the read (a real manifest is KBs; refuse a multi-GB decoy) and
    # catch everything json.loads can raise on crafted input — ValueError
    # covers JSONDecodeError; deeply-nested arrays raise RecursionError,
    # which is NOT a ValueError and would otherwise traceback.
    try:
        with vault._manifest_path(root, generation).open("rb") as fh:
            blob = fh.read(_MAX_MANIFEST_BYTES + 1)
        if len(blob) > _MAX_MANIFEST_BYTES:
            _term.emit_error(
                f"cannot read vault manifest at {root}: implausibly large "
                f"(over {_MAX_MANIFEST_BYTES // (1024 * 1024)} MiB) — not a vault manifest."
            )
            return 1
        parsed = manifest.parse_unverified(blob)
    except (OSError, manifest.ManifestError, ValueError, RecursionError) as exc:
        _term.emit_error(f"cannot read vault manifest at {root}: {exc}")
        return 1

    names = sorted(parsed.files)
    if as_json:
        body = {
            "root": str(root),
            "generation": parsed.generation,
            "files": names,
            "read_only": True,
            "authenticated": False,
        }
        print(json.dumps(body, indent=2))
        return 0
    print(f"Vault at {root}")
    print(f"  generation: {parsed.generation}")
    print(f"  files: {len(names)}")
    for name in names:
        print(f"    {_display_name(name)}")
    print("  (read-only: read from the on-disk manifest, unauthenticated — no passphrase needed or asked for)")
    return 0


def cat(*, root: Path, name: str, prompt_io: PromptIO | None = None) -> int:
    """Write one enrolled file's decrypted bytes to stdout (cold path).

    Opens read-only via :func:`_open_cold_path`, decrypts file ``name``, and
    writes its raw bytes to stdout — binary-safe, byte-exact, no trailing
    newline added. Fail-closed: a failed open, or a name that is absent /
    unreadable / fails its content-address or AEAD check, prints a reason to
    stderr and returns 1. Returns 0 on success.
    """
    from ..keyvault import vault

    opened = _open_cold_path(root, prompt_io=prompt_io)
    if opened is None:
        return 1
    with opened:
        try:
            data = opened.read_file(name)
        except vault.VaultError as exc:
            _term.emit_error(f"cannot read {name!r}: {exc}")
            return 1

    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        # Downstream closed early (e.g. `vault cat … | head`); not an error.
        return 0
    except OSError as exc:
        _term.emit_error(f"failed writing {name!r} to stdout: {exc}")
        return 1
    return 0


def _enroll_one(
    *,
    root: Path,
    name: str,
    plaintext: bytes,
    backend: NativeBackend | None,
    store: AnchorStore | None,
    read_back: bool,
    flow_session: FlowSession | None = None,
) -> tuple[int, int | None, bytes | None]:
    """Open the vault hot path once, enroll ``plaintext`` under ``name``, and close.

    A **single** device-key unlock (the Secure Enclave / software-fallback ECDH —
    one Touch ID prompt) covers the whole open: the enroll and, when ``read_back``
    is set, reading the freshly enrolled bytes back through the *same* handle. The
    read-back is the vault's decrypted copy of ``name`` (proof the enroll
    round-trips), which a caller that must delete the plaintext can compare against
    the on-disk file without forcing a second unlock.

    Returns ``(rc, generation, read_back_bytes)``. On ``rc != 0`` the generation
    and bytes are ``None`` (the reason is already on stderr); ``read_back_bytes``
    is ``None`` whenever ``read_back`` is false.

    With a ``flow_session`` the flow's already open vault is reused (no unlock
    at all), or the one opened here is kept for the flow's later steps.
    """
    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError

    opened = _open_hot_path_or_report(root, backend=backend, store=store, flow_session=flow_session)
    if opened is None:
        return 1, None, None

    with opened:
        try:
            opened.enroll_file(name, plaintext)
            generation = opened.generation
            enrolled = opened.read_file(name) if read_back else None
        except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
            _term.emit_error(f"cannot add {name!r}: {exc}")
            return 1, None, None

    return 0, generation, enrolled


def add(
    *,
    root: Path,
    name: str,
    source: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> int:
    """Enroll ``source``'s bytes into the vault at ``root`` under ``name``.

    Opens the vault on the **hot path** (the device wrapping key — Secure
    Enclave or its software fallback, no passphrase) via
    :func:`...vault.open_vault`, then commits the encrypted file. Enrolling an
    existing ``name`` supersedes it (a new generation).

    Note: the plaintext ``source`` file is **not** removed — the operator owns
    shredding it if the on-disk plaintext is no longer wanted.

    ``backend`` / ``store`` default to the production implementations; tests
    inject fakes. Returns 0 on success, 1 on an uninitialised / unverifiable
    vault, an unreadable source, or a device key-store error.
    """
    try:
        plaintext = source.read_bytes()
    except OSError as exc:
        _term.emit_error(f"cannot read source file {source}: {exc}")
        return 1

    rc, generation, _ = _enroll_one(
        root=root,
        name=name,
        plaintext=plaintext,
        backend=backend,
        store=store,
        read_back=False,
        flow_session=flow_session,
    )
    if rc != 0:
        return rc

    print(f"Added {name!r} to the vault at {root} (now at generation {generation}).")
    return 0


def add_and_verify(
    *,
    root: Path,
    name: str,
    source: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> tuple[int, bytes | None]:
    """:func:`add`, plus the vault's decrypted copy of ``name`` read back in the
    *same* open — one device-key unlock (one Touch ID) for both enroll and verify.

    For callers that remove the plaintext after enrolling (the ``.env`` at-rest
    toggle): the returned bytes are what the vault decrypts ``name`` to, so the
    caller can confirm the still-on-disk plaintext matches the enrolled copy before
    deleting it — the pre-delete safety check that previously cost a second vault
    open (a second Touch ID). Returns ``(rc, enrolled_bytes)``; on ``rc != 0`` the
    bytes are ``None`` (reason already on stderr).
    """
    try:
        plaintext = source.read_bytes()
    except OSError as exc:
        _term.emit_error(f"cannot read source file {source}: {exc}")
        return 1, None

    rc, generation, enrolled = _enroll_one(
        root=root,
        name=name,
        plaintext=plaintext,
        backend=backend,
        store=store,
        read_back=True,
        flow_session=flow_session,
    )
    if rc != 0:
        return rc, None

    print(f"Added {name!r} to the vault at {root} (now at generation {generation}).")
    return 0, enrolled


def migrate(
    *,
    root: Path,
    sources: list[Path],
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Batch-import each plaintext file in ``sources`` into the vault at ``root``.

    A batch :func:`add`: opens the vault **once** on the hot path (the device
    wrapping key — Secure Enclave or its software fallback, no passphrase) and
    enrolls every source under its basename (``source.name``), so importing the
    operator's existing plaintext (``~/.hermes/.env`` / ``config.yaml``) is one
    command.

    **Read-all-then-enroll-all**: every source is read up front, so an
    unreadable path or a duplicate basename aborts *before* the vault is touched
    — a typo never leaves a half-migrated vault. (A rare device error mid-enroll
    can still leave the files committed before it enrolled; each
    :meth:`enroll_file` is its own crash-safe generation.) A consequence is that
    all source plaintexts coexist in RAM from the read phase until return —
    acceptable under the §2 threat model, which excludes live-RAM attackers.
    Like :func:`add`, the plaintext sources are **not** removed — the operator
    owns shredding them.

    ``backend`` / ``store`` default to the production implementations; tests
    inject fakes. Returns 0 on success (an empty ``sources`` is a no-op success),
    1 on a duplicate name, an unreadable source, an uninitialised / unverifiable
    vault, or a device key-store error.
    """
    if not sources:
        print("Nothing to migrate.")
        return 0

    # Each source enrolls under its basename; a name claimed by two sources is
    # ambiguous (which one wins?) — refuse before any I/O, enroll nothing.
    by_name: dict[str, Path] = {}
    for source in sources:
        name = source.name
        if name in by_name:
            _term.emit_error(
                f"refusing to migrate: {name!r} maps to more than one source "
                f"({by_name[name]}, {source}) — migrate them under distinct names."
            )
            return 1
        by_name[name] = source

    # Read every plaintext first so a bad path fails the whole run before the
    # first commit (read-all-then-enroll-all: no partially migrated vault).
    plaintexts: list[tuple[str, bytes]] = []
    for name, source in by_name.items():
        try:
            plaintexts.append((name, source.read_bytes()))
        except OSError as exc:
            _term.emit_error(f"cannot read source file {source}: {exc}")
            return 1

    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError

    opened = _open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return 1

    enrolled = 0
    with opened:
        try:
            for name, plaintext in plaintexts:
                opened.enroll_file(name, plaintext)
                enrolled += 1
            generation = opened.generation
        except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
            # `enrolled` is the index of the file that failed (incremented only after
            # a successful enroll). Bounds-guard the lookup so a failure raised
            # anywhere in the try — even after the loop — still fails closed with a
            # message rather than an IndexError traceback.
            failed = plaintexts[enrolled][0] if enrolled < len(plaintexts) else "<unknown>"
            _term.emit_error(f"cannot migrate {failed!r} ({enrolled} of {len(plaintexts)} already enrolled): {exc}")
            return 1

    listed = ", ".join(_display_name(n) for n, _ in plaintexts)
    print(f"Migrated {len(plaintexts)} file(s) into the vault at {root} (now at generation {generation}): {listed}.")
    return 0
