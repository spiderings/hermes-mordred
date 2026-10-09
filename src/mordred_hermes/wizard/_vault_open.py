"""Shared open / identity helpers for the at-rest vault CLI.

These are the side-effect-light primitives reused by the vault commands in
:mod:`mordred_hermes.wizard._vault_lifecycle` and
:mod:`mordred_hermes.wizard._vault_entries`:

* :func:`_resolve_root` / :func:`_vault_identity` -- the shared root / identity
  derivation (delegating to :mod:`..keyvault._identity`) the runtime decrypt
  shim also uses, so the CLI and the shim agree on a vault for a given input.
* :func:`_open_cold_path` -- read-only open via the passphrase recovery sidecar.
* :func:`_open_hot_path_or_report` -- device-key (Secure Enclave / software
  fallback) open, fail-closed with a printed reason.
* :func:`_build_device_auth` -- tolerant SE-backend + keychain-store construction.
* :func:`_display_name` -- control-character-safe rendering of enrolled names.

``keyvault_cli.py`` keeps the parallel shape for the legacy keyvault; the heavy
cryptography-backed imports stay function-local so this module imports on any
platform. :mod:`mordred_hermes.wizard.vault_cli` re-exports the public-by-use
names (``_resolve_root`` / ``_open_hot_path_or_report`` / ``_vault_identity``).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..keyvault import _identity
from . import _term
from ._defaults import resolve_backend, resolve_prompt_io, resolve_store

if TYPE_CHECKING:
    from ..keyvault.anchor import AnchorStore
    from ..keyvault.vault import OpenVault
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO


def _vault_present(root: Path) -> bool:
    """Whether a vault exists at ``root`` (a manifest on disk) — no key needed."""
    return any(root.glob("manifest.*.mvmf"))


def _resolve_root(root: str | None) -> Path:
    """Resolve the vault root, defaulting to ``<hermes home>/mordred/vault``.

    Delegates to :func:`mordred_hermes.keyvault._identity.resolve_root` — the
    shared derivation the runtime decrypt shim also uses — so the CLI and the
    shim resolve the same root (and thus the same :func:`_vault_identity`) for a
    given input. A user-supplied root is resolved to an absolute, normalized path
    so spelling differences (relative path, ``..``, cwd) never yield a different
    vault identity.
    """
    return _identity.resolve_root(root)


def _display_name(name: str) -> str:
    """Render an enrolled name safely for the terminal.

    Enrolled names are arbitrary strings; one containing control characters
    (e.g. ANSI escapes) would otherwise inject into the operator's terminal
    when listed. Non-printable names are shown backslash-escaped.
    """
    return name if name.isprintable() else name.encode("unicode_escape").decode("ascii")


def _vault_identity(root: Path) -> str:
    """Stable id (SE wrapping-key tag + Keychain anchor account) for a vault root.

    Delegates to :func:`mordred_hermes.keyvault._identity.vault_identity` — the
    shared derivation the runtime decrypt shim also uses, so the CLI and the shim
    open the same vault for a given root.
    """
    return _identity.vault_identity(root)


def _open_cold_path(root: Path, *, prompt_io: PromptIO | None) -> OpenVault | None:
    """Open a vault read-only via the passphrase recovery sidecar.

    Prompts for the passphrase and opens through
    :func:`...vault.recover_vault` — no Secure-Enclave backend, no device
    anchor. Fail-closed: a non-vault root, a missing recovery sidecar, a wrong
    passphrase, or a tampered manifest/sidecar each print a reason to stderr
    and return ``None``. On success returns the opened (read-only) vault; the
    caller owns closing it.
    """
    from cryptography.exceptions import InvalidTag

    from ..keyvault import backup, manifest, recovery, vault

    prompt_io = resolve_prompt_io(prompt_io)
    passphrase = prompt_io.ask_password("Vault passphrase")

    try:
        return vault.recover_vault(root, passphrase)
    except vault.VaultError as exc:
        _term.emit_error(f"Not a recoverable vault at {root}: {exc}")
        return None
    except recovery.RecoveryDigestMismatch:
        _term.emit_error(
            "Vault rejected: the recovery sidecar does not match the manifest (substituted wmk / tampering)."
        )
        return None
    except manifest.ManifestError:
        _term.emit_error("Vault rejected: the manifest failed authentication (tampering).")
        return None
    except backup.BackupCorrupt as exc:
        _term.emit_error(f"Vault rejected: the recovery sidecar is corrupt — {exc}")
        return None
    except InvalidTag:
        _term.emit_error("Wrong passphrase — vault not opened.")
        return None
    except OSError as exc:
        _term.emit_error(f"Cannot read vault at {root}: {exc}")
        return None
    finally:
        # CPython cannot zero an immutable str in place; dropping the reference
        # shortens the exposure window, it does not scrub the bytes.
        del passphrase


def _open_hot_path_or_report(
    root: Path,
    *,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> OpenVault | None:
    """Open the vault at ``root`` on the **hot path**, or report and return ``None``.

    The shared open used by :func:`add` / :func:`migrate` / :func:`set_memory_key`:
    opens via the device wrapping key (Secure Enclave or its software fallback,
    no passphrase). ``backend`` / ``store`` default to the production
    implementations; tests inject fakes. On any fail-closed open error a reason is
    printed to stderr and ``None`` is returned (a freshness-pin mismatch is
    surfaced as possible tampering, an uninitialised vault points at ``vault
    init``). The caller owns closing the returned vault.

    The fail-closed ``except`` chain is
    :func:`mordred_hermes.keyvault._vault_open_report.report_hot_open_failure`,
    shared with ``keyvault._env_reseal._open_hot_or_report`` (which used to
    carry a byte-for-byte copy of it). The dependency direction is unchanged —
    ``wizard`` imports down into ``keyvault``, never the reverse — and the
    ``vault.open_vault`` call stays here because tests pin it with
    ``monkeypatch.setattr(vault, "open_vault", ...)``. The reporter emits
    through the root :mod:`mordred_hermes._term` (its own import), not this
    module's ``_term`` alias — patch ``mordred_hermes._term.emit_error`` to
    intercept those messages.

    With a ``flow_session`` (a guided flow's shared state), the flow's already
    open vault is lent instead of unwrapping the master again, and a vault
    opened here is kept in the flow for its later steps; either way the caller
    gets a view whose ``close`` / ``with`` exit leaves the handle open (the
    flow closes it when it ends). One unwrap -- one Touch ID -- per flow.
    """
    from ..keyvault import vault
    from ..keyvault._vault_open_report import report_hot_open_failure

    if flow_session is not None:
        lent = flow_session.lend_vault(root)
        if lent is not None:
            return lent

    key_id = anchor_label = _vault_identity(root)
    backend = resolve_backend(backend)
    store = resolve_store(store)

    with report_hot_open_failure(root):
        opened = vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
        return opened if flow_session is None else flow_session.keep_vault(root, opened)
    return None


def _build_device_auth(
    backend: NativeBackend | None, store: AnchorStore | None
) -> tuple[NativeBackend | None, AnchorStore | None]:
    """Construct the SE backend + keychain store for the device rotation path.

    Tolerant by design: off-macOS the SE backend / keychain modules don't import,
    so a failure returns ``(None, None)`` and the caller falls through to the
    passphrase (cold) path instead of crashing before it. Injected values
    (tests / callers that already have them) are returned unchanged.
    """
    try:
        backend = resolve_backend(backend)
        store = resolve_store(store)
    except ImportError:
        return None, None
    return backend, store
