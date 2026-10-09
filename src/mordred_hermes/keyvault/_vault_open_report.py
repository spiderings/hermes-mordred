"""Shared fail-closed reporting for a hot-path ``vault.open_vault`` call.

Two hot-path openers existed with byte-for-byte identical ``except`` chains:

* :func:`mordred_hermes.wizard._vault_open._open_hot_path_or_report` — the
  wizard CLI's shared open for ``vault add`` / ``migrate`` / ``set_memory_key``.
* :func:`mordred_hermes.keyvault._env_reseal._open_hot_or_report` — the
  keyvault-local mirror the session hooks use.

``_env_reseal``'s module docstring explains why the second one exists at all:
``keyvault`` must never import ``wizard`` (~150 call sites go the other way,
and ``keyvault.register``'s session hooks would otherwise drag
``mordred_wizard`` in just to heal a stray plaintext ``.env``). That constraint
is unchanged here — the shared piece lives on the ``keyvault`` side, and
``wizard`` imports *down* into it, so the dependency still runs
``wizard -> keyvault``.

What is shared is only the error mapping, deliberately **not** the
``vault.open_vault`` call itself. Tests pin that call (
``monkeypatch.setattr(vault, "open_vault", racing_open)`` in
``test_keyvault_env_reseal.py`` / ``test_keyvault_config_bootstrap.py`` /
``test_wizard_vault_cli_memory_key.py``), and each opener keeps its own
argument construction (``vault_identity`` vs ``_vault_identity``, its own
``resolve_backend`` / ``resolve_store`` seams). So this module exposes a
context manager that each opener wraps around its own call:

    with report_hot_open_failure(root):
        return vault.open_vault(...)
    return None

Every message below is byte-identical to the two copies it replaces, including
the em-dashes and the backticked ``vault init`` hint.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path

from .. import _term


@contextlib.contextmanager
def report_hot_open_failure(root: Path) -> Iterator[None]:
    """Print a fail-closed reason for a hot-path open failure and swallow it.

    Suppresses exactly the exception set both openers treated as "the vault did
    not open, tell the operator why and return ``None``"; anything else (a
    programming error, a cancelled Touch ID prompt, ``KeyboardInterrupt``)
    propagates untouched, so a real bug still keeps its traceback.

    The ordering of the clauses is load-bearing and matches the originals:

    * :exc:`~mordred_hermes.keyvault.anchor.AnchorMissing` first — an absent
      anchor is an *uninitialised* vault, not a failure, so it gets the
      actionable ``vault init`` hint rather than a scary one.
    * ``AnchorMismatch`` / ``AnchorCorrupt`` before their ``AnchorError`` base —
      a freshness-pin mismatch is the anchor's entire purpose, so it is
      surfaced as possible tampering / rollback instead of being flattened into
      the generic "cannot open" message by the broader clause below it.
    * ``AnchorError`` / ``VaultError`` / ``ManifestError`` / :exc:`OSError` —
      the generic fail-closed bucket.
    * :exc:`~mordred_hermes.keyvault._exceptions.WrapError` last, with its own
      message: it means the *device key store* (Secure Enclave / Keychain)
      failed, which is a different remedy from a bad vault on disk.

    The heavy imports stay function-local, matching both call sites: this
    module must import on any platform, whether or not the ``[keyvault]``
    cryptography extra is installed.
    """
    from . import anchor, manifest, vault
    from ._exceptions import WrapError

    try:
        yield
    except anchor.AnchorMissing:
        _term.emit_error(f"no vault at {root} — run `vault init` first.")
    except (anchor.AnchorMismatch, anchor.AnchorCorrupt) as exc:
        # A freshness-pin mismatch is the anchor's whole purpose — surface it as
        # possible tampering / rollback, not a generic open failure.
        _term.emit_error(f"vault freshness check failed at {root} (possible tampering): {exc}")
    except (anchor.AnchorError, vault.VaultError, manifest.ManifestError, OSError) as exc:
        _term.emit_error(f"cannot open vault at {root}: {exc}")
    except WrapError as exc:
        _term.emit_error(f"cannot open vault at {root}: device key store error — {exc}")
