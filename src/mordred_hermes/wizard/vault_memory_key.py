"""``hermes mordred vault set-memory-key`` — the agent-memory on-ramp.

Extracted from :mod:`mordred_hermes.wizard.vault_cli` for cohesion: this module
owns everything specific to ``HERMES_MEMORY_KEY`` (generation / validation, the
``.env`` merge logic, and the ``set-memory-key`` orchestration). It reuses the
shared vault helpers (``_resolve_root`` / ``_open_hot_path_or_report``) from
``vault_cli`` — a one-directional import, so there is no cycle.

Heavy imports (the cryptography-backed vault modules) stay function-local so
this module imports on any platform, matching ``vault_cli.py``.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .._home import hermes_home as _hermes_home
from . import _term
from .vault_cli import _open_hot_path_or_report, _resolve_root

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.vault import OpenVault
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession

_MEMORY_KEY_ENV = "HERMES_MEMORY_KEY"


def _generate_memory_key() -> str:
    """A fresh URL-safe base64 256-bit key for ``HERMES_MEMORY_KEY``.

    The key contract Mordred's memory-encryption runtime reads — a URL-safe
    base64 encoding of 32 random bytes (AES-256); no Hermes release reads this
    variable, only :mod:`mordred_hermes.keyvault.memory_crypto`. The format
    contract is pinned by ``tests/test_keyvault_memory_integration.py``.
    """
    import base64
    import secrets

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _is_valid_memory_key(value: str | None) -> bool:
    """Whether ``value`` decodes to a 32-byte AES-256 key.

    Accepts plain URL-safe base64, or a ``base64:`` / ``hex:`` prefix; exactly
    32 bytes — the contract a memory-encryption runtime keyed by this variable
    must honour. A key this command treats as "already set" must be usable by
    that runtime — an empty or wrong-length assignment is *not* usable and
    should be replaced.
    """
    if not value:
        return False
    import base64

    raw = value.strip()
    # dotenv strips one pair of surrounding quotes; mirror that so a quoted key
    # (e.g. HERMES_MEMORY_KEY="base64:...") is validated as the runtime sees it.
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        raw = raw[1:-1]
    if raw.startswith("base64:"):
        raw = raw[len("base64:") :].strip()
    elif raw.startswith("hex:"):
        try:
            return len(bytes.fromhex(raw[len("hex:") :].strip())) == 32
        except ValueError:
            return False
    padding = "=" * (-len(raw) % 4)
    try:
        return len(base64.urlsafe_b64decode(raw + padding)) == 32
    except (ValueError, TypeError):
        return False


def _effective_memory_key(text: str) -> str | None:
    """The ``HERMES_MEMORY_KEY`` value the runtime shim would use, or ``None``.

    Parsed with ``dotenv_values`` (last-wins, no interpolation, quotes stripped) —
    exactly the value :func:`...keyvault._runtime_env.inject_vault_env` injects at
    startup, matching what a future memory-encryption runtime would key on.
    """
    import io

    from dotenv import dotenv_values

    return dotenv_values(stream=io.StringIO(text), interpolate=False).get(_MEMORY_KEY_ENV)


def _ambient_memory_key() -> str | None:
    """An existing valid ``HERMES_MEMORY_KEY`` from the live env or the plaintext home ``.env``.

    A user who already enabled ``memory.encryption`` has their key in
    ``os.environ`` (Hermes loads ``~/.hermes/.env`` into the environment at
    startup) or still in the plaintext ``~/.hermes/.env`` not yet migrated into the
    vault. ``set-memory-key`` must **adopt** that key rather than mint a new one —
    a fresh key would override theirs at startup and orphan memories encrypted
    under it. Returns the env value first (it is what the memory tool reads), then
    the plaintext ``.env`` value; ``None`` if neither holds a usable key.
    """
    env_value = os.environ.get(_MEMORY_KEY_ENV)
    if _is_valid_memory_key(env_value):
        return env_value
    try:
        text = (_hermes_home() / ".env").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    candidate = _effective_memory_key(text)
    return candidate if _is_valid_memory_key(candidate) else None


def _any_valid_memory_key(text: str) -> bool:
    """Whether *any* ``HERMES_MEMORY_KEY`` binding in the ``.env`` is a usable key.

    Distinct from the *effective* (last-wins) value: a malformed ``.env`` whose
    last binding is invalid may still carry a valid earlier one that encrypted
    existing memories. That ambiguity is a refuse-or-rotate signal, not something
    to silently overwrite. Uses ``python-dotenv``'s own parser, so a value's
    quotes / trailing comment / ``export`` prefix are handled exactly as the
    runtime would.
    """
    import io

    from dotenv.parser import parse_stream

    return any(
        binding.key == _MEMORY_KEY_ENV and _is_valid_memory_key(binding.value)
        for binding in parse_stream(io.StringIO(text))
    )


def _env_with_memory_key(text: str, value: str) -> str:
    """Return ``.env`` text with exactly one effective ``HERMES_MEMORY_KEY``.

    **Drops every ``HERMES_MEMORY_KEY`` binding** ``python-dotenv`` recognises —
    assignment, bare key (``KEY`` → ``None``), ``export``-prefixed, quoted, or
    comment-trailed — preserving all other lines **verbatim** (via the parser's
    original text), then appends a single fresh assignment as the last (effective)
    entry. Delegating removal to dotenv's own parser means a stray form can't be
    left behind to shadow the written key. Ends with a trailing newline.
    """
    import io

    from dotenv.parser import parse_stream

    kept = "".join(
        binding.original.string for binding in parse_stream(io.StringIO(text)) if binding.key != _MEMORY_KEY_ENV
    )
    if kept and not kept.endswith("\n"):
        kept += "\n"
    return f"{kept}{_MEMORY_KEY_ENV}={value}\n"


def _print_memory_config_hint() -> None:
    """Tell the operator what the stored key does and does not do (never prints the key)."""
    print(
        f"The key stays protected at rest by the vault; the runtime shim injects {_MEMORY_KEY_ENV} into the "
        "environment at startup, where Mordred's memory hook reads it. Storing the key does not seal "
        "anything by itself — turn agent-memory encryption on with "
        "`hermes-mordred encryption enable memory` (it arms the hook and seals existing memory files)."
    )


def set_memory_key(
    *,
    root: Path,
    rotate: bool = False,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """``vault set-memory-key``: :func:`ensure_memory_key` without the key value.

    The CLI surface only needs the exit code; the value stays with the one
    caller that must act on it (``encryption enable memory``, which seals
    existing files with it through the same single vault open).
    """
    rc, _value = ensure_memory_key(root=root, rotate=rotate, backend=backend, store=store)
    return rc


def ensure_memory_key(
    *,
    root: Path,
    rotate: bool = False,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> tuple[int, str | None]:
    """Ensure the vault ``.env`` carries a usable ``HERMES_MEMORY_KEY``, and report it.

    Returns ``(exit_code, key_value)`` — the value is the effective key the
    runtime shim will inject (``None`` whenever the exit code is 1), so a
    caller that must seal files with it does not have to open the vault a
    second time (a second Touch ID prompt). It is never printed.

    The key Mordred's memory-encryption runtime is keyed by (AES-256-GCM, see
    :mod:`mordred_hermes.keyvault.memory_crypto`). Keeping it in the vault
    ``.env`` means the device wrapping key protects it at rest and the runtime
    decrypt shim (:mod:`mordred_hermes.keyvault._runtime_env`) injects it into
    the environment at startup.

    Opens the vault on the **hot path** (the device wrapping key — Secure Enclave
    or its software fallback, no passphrase) and decides off the *effective*
    (dotenv last-wins) ``HERMES_MEMORY_KEY``, so it never silently switches the key
    already in effect:

    - **Already usable** (the effective value decodes to 32 bytes) and no
      ``rotate`` → no-op; the ``.env`` is left untouched.
    - **No usable key** → write one and re-enroll, collapsing the file to a single
      assignment. Without ``rotate`` it **adopts** a key the user is already using
      (live env, then the plaintext home ``.env``) so migrating into the vault
      keeps existing encrypted memories readable; otherwise it mints a fresh key.
    - **Malformed** (the effective value is invalid but an earlier assignment is a
      valid key) and no ``rotate`` → **refuse** (rc 1) rather than guess which key
      encrypted existing memories.
    - ``rotate`` → always mint a fresh key, warning that memories encrypted under
      the previous key can no longer be decrypted.

    ``backend`` / ``store`` default to the production implementations; tests inject
    fakes. Returns 0 on success (no-op, store, or adoption), 1 on an uninitialised
    / unverifiable vault, a non-UTF-8 or unreadable enrolled ``.env``, a
    malformed-``.env`` refusal, or a device key-store error.

    With a ``flow_session`` (e.g. ``encryption enable memory`` right after
    ``enable env`` in one setup run) the flow's already open vault is reused,
    so this costs no second unlock / Touch ID.
    """
    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError

    opened = _open_hot_path_or_report(root, backend=backend, store=store, flow_session=flow_session)
    if opened is None:
        return 1, None

    with opened:
        existing = _read_enrolled_env(opened, root)
        if existing is None:
            return 1, None

        # Decide off the *effective* (dotenv last-wins) value — exactly what the
        # runtime shim keys memory on — so we never silently switch the key Hermes
        # is actually using.
        effective = _effective_memory_key(existing)
        if _is_valid_memory_key(effective) and not rotate:
            # The runtime already has a usable key; leave the file untouched.
            print(
                f"{_MEMORY_KEY_ENV} is already set in the vault .env at {root} — leaving it unchanged "
                "(pass --rotate to replace it)."
            )
            _print_memory_config_hint()
            return 0, effective

        # No usable *effective* key, yet some assignment is a valid key: the .env is
        # malformed (e.g. a valid key shadowed by a later invalid duplicate). We
        # cannot know which key encrypted existing memories, so refuse rather than
        # guess — and never regenerate, which would orphan recoverable data.
        if not rotate and _any_valid_memory_key(existing):
            _term.emit_error(
                f"the vault .env at {root} has a {_MEMORY_KEY_ENV} whose effective (last) value is not a "
                f"usable 32-byte key, but an earlier assignment is. Refusing to guess which key encrypted "
                f"existing memories: fix the .env by hand, or pass --rotate to replace it (which orphans "
                f"memories encrypted under the old key)."
            )
            return 1, None

        # Choose the key to write. Without --rotate, ADOPT a key the user is already
        # using (live env / plaintext home .env) so migrating into the vault keeps
        # existing encrypted memories readable; mint a fresh key only for genuine
        # first-time setup. With --rotate, always mint fresh.
        adopted = None if rotate else _ambient_memory_key()
        chosen = adopted if adopted is not None else _generate_memory_key()

        # Rotation (always fresh) orphans whatever usable key was in effect — in the
        # vault .env or the ambient env. A first-time / adopting store orphans nothing.
        orphan_risk = rotate and (_any_valid_memory_key(existing) or _ambient_memory_key() is not None)

        new_text = _env_with_memory_key(existing, chosen)
        try:
            opened.enroll_file(".env", new_text.encode("utf-8"))
            generation = opened.generation
        except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
            _term.emit_error(f"cannot store {_MEMORY_KEY_ENV}: {exc}")
            return 1, None

        verb = _store_verb_label(adopted=adopted, orphan_risk=orphan_risk)
        print(f"{verb} {_MEMORY_KEY_ENV} in the vault .env at {root} (now at generation {generation}).")
        if orphan_risk:
            # Rotation replaces a *usable* key, orphaning memories encrypted under it
            # (upstream has no auto re-key), so AES-GCM decryption of existing files
            # fails on the next run. Warn loudly — re-keying / clearing is the
            # operator's job. (Replacing an absent/invalid key encrypted nothing.)
            _term.emit_warn(
                "rotated the memory key. Agent-memory files already encrypted under the previous "
                "key (~/.hermes/memories/*.md) can no longer be decrypted — re-encrypt or clear them before "
                "the next run."
            )
        _print_memory_config_hint()
        return 0, chosen


def _read_enrolled_env(opened: OpenVault, root: Path) -> str | None:
    """Return the enrolled ``.env`` text (``""`` when absent), or ``None`` on a
    read failure (the reason is printed to stderr; the caller fails closed).
    """
    from ..keyvault import vault

    if ".env" not in opened.list_files():
        return ""
    try:
        return opened.read_file(".env").decode("utf-8")
    except UnicodeDecodeError:
        _term.emit_error(f"the enrolled .env at {root} is not valid UTF-8 — cannot merge {_MEMORY_KEY_ENV}.")
        return None
    except (vault.VaultError, OSError) as exc:
        # OSError covers _storage.KeyvaultPermissionError (bad mode / symlink /
        # I/O) so a read failure fails closed with rc 1, like open / enroll.
        _term.emit_error(f"cannot read the enrolled .env at {root}: {exc}")
        return None


def _store_verb_label(*, adopted: str | None, orphan_risk: bool) -> str:
    """Past-tense verb for the success line: adopt an existing key, rotate, or store."""
    if adopted is not None:
        return "Adopted the existing"
    if orphan_risk:
        return "Rotated"
    return "Stored"


def cli_set_memory_key(args: argparse.Namespace) -> int:
    """argparse handler for ``vault set-memory-key [--root PATH] [--rotate]``."""
    return set_memory_key(root=_resolve_root(getattr(args, "root", None)), rotate=bool(getattr(args, "rotate", False)))


__all__ = ["cli_set_memory_key", "ensure_memory_key", "set_memory_key"]
