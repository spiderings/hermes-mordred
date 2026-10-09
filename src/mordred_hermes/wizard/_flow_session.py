"""State shared by the steps of ONE interactive flow, kept in memory only.

A guided flow (``hermes-mordred setup``, ``encryption enable all``, the
Telegram setup's memory-encryption step, the Hermes Desktop setup page) runs
several sub-commands in one process. Each of them used to act as if it ran
alone, so the operator paid for the same thing more than once:

* **passphrase** -- ``setup`` creates both the keyvault (its ceremony asks for a
  Passphrase) and the at-rest vault (it asks for a recovery passphrase), so one
  run asked the operator to choose and confirm a passphrase twice. The first
  creation step now remembers the passphrase it just had confirmed and a later
  creation step in the same flow reuses it.
* **vault unlock** -- ``encryption enable env`` and ``encryption enable memory``
  each opened the vault on the hot path, and every open is one Secure Enclave
  ECDH (one Touch ID / macOS password dialog with an attended device key). The
  flow now keeps the first opened (or freshly created) vault handle and lends
  it to later steps, so a flow unlocks the vault at most once -- and not at all
  when the flow itself just created the vault (creation seals under the public
  key; nothing is unwrapped).
* **unattended policy** -- the answer to setup's "allow background services"
  question now also reaches the at-rest vault's device key, which the flow
  creates later.

Nothing here is ever written to disk, the environment, argv or a keychain.
:meth:`FlowSession.close` (or leaving the ``with`` block) closes the vault
handle, which zeroes the in-RAM master, and drops the passphrase reference.
CPython cannot zero an immutable ``str`` in place; dropping it shortens the
exposure window, it does not scrub the bytes.

A lent vault handle is the same :class:`~..keyvault.vault.OpenVault` the
lender opened: every write still re-checks the device anchor under the vault
lock, so a concurrent writer from another process makes the next write fail
closed ("stale vault handle") exactly as it would for any open handle.
"""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from ..keyvault.vault import OpenVault


class _LentVault:
    """A borrowed view of the flow's vault handle: using it as a context manager
    or calling :meth:`close` does NOT close the underlying handle (the flow owns
    it). Everything else is delegated."""

    __slots__ = ("_inner",)

    def __init__(self, inner: OpenVault) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __enter__(self) -> _LentVault:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def close(self) -> None:
        return None


class FlowSession:
    """In-memory state shared by the steps of one guided flow (see module doc)."""

    __slots__ = ("_passphrase", "_vault", "_vault_root", "unattended")

    def __init__(self, *, unattended: bool | None = None) -> None:
        self._passphrase: str | None = None
        self._vault: OpenVault | None = None
        self._vault_root: Path | None = None
        #: Authorization policy for device keys this flow creates: ``True`` =
        #: usable without a per-use Touch ID / password prompt, ``False`` =
        #: prompt on every use, ``None`` = the backend default
        #: (``MORDRED_SEKEY_UNATTENDED``, else prompt on every use).
        self.unattended = unattended

    # -- passphrase ------------------------------------------------------------

    @property
    def passphrase(self) -> str | None:
        """The passphrase chosen and confirmed earlier in this flow, if any."""
        return self._passphrase

    def remember_passphrase(self, passphrase: str) -> None:
        """Keep a just-confirmed passphrase for later steps; empty is ignored."""
        if passphrase:
            self._passphrase = passphrase

    # -- vault handle ----------------------------------------------------------

    def lend_vault(self, root: Path) -> OpenVault | None:
        """The flow's open vault for ``root`` (a non-closing view), or ``None``."""
        if self._vault is None or self._vault_root != Path(root):
            return None
        return cast("OpenVault", _LentVault(self._vault))

    def keep_vault(self, root: Path, opened: OpenVault) -> OpenVault:
        """Take ownership of ``opened`` for the rest of the flow and lend it back."""
        if self._vault is not None and self._vault is not opened:
            self._vault.close()
        self._vault, self._vault_root = opened, Path(root)
        return cast("OpenVault", _LentVault(opened))

    # -- lifecycle -------------------------------------------------------------

    def close(self) -> None:
        """Close the vault handle (zeroes the master) and drop the passphrase."""
        vault, self._vault, self._vault_root = self._vault, None, None
        self._passphrase = None
        if vault is not None:
            vault.close()

    def __enter__(self) -> FlowSession:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        # Never render the secret (tracebacks, debug logs, test diffs).
        return (
            f"FlowSession(passphrase={'<set>' if self._passphrase else '<empty>'}, "
            f"vault={'<open>' if self._vault is not None else '<none>'}, unattended={self.unattended!r})"
        )

    def __reduce__(self) -> str | tuple[Any, ...]:
        # Refuse pickling: nothing here may leave this process's memory.
        raise TypeError("FlowSession cannot be pickled")
