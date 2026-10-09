"""Production macOS Keychain ``AnchorStore`` (design note §8.1).

The device-bound vault freshness anchor (:mod:`mordred_hermes.keyvault.anchor`)
pins two non-secret values an offline attacker can read but not write. On macOS
that store is a **Keychain generic-password** item with
``AfterFirstUnlock`` + ``ThisDeviceOnly`` accessibility — a powered-off /
stolen / imaged device cannot mint or edit it.

Unlike Secure-Enclave *key* persistence (blocked by ``errSecMissingEntitlement``
/ ``-34018`` from a non-provisioned interpreter — see ``_seckey_helper.py``),
generic-password writes succeed from a plain ``uv`` / ``pip`` Python, so this
store works in production without a provisioning profile.

Two layers, mirroring :mod:`mordred_hermes.keyvault._seckey_backend`:

1. :class:`_KeychainOps` — the narrowest possible pyobjc-touching surface
   (add / get / update / delete a generic-password by ``service`` + ``account``).
   Each method returns plain ``bytes`` / ``None`` or raises :class:`_OpsError`
   carrying the ``OSStatus``; no ``Security.framework`` object crosses the
   boundary. The production implementation imports ``Security`` lazily so this
   module imports on any platform.
2. :class:`KeychainAnchorStore` — implements
   :class:`mordred_hermes.keyvault.anchor.AnchorStore` (read / write / delete by
   label), orchestrating the add-or-update upsert and translating
   :class:`_OpsError` into a fail-closed :class:`KeychainAnchorError`.

Who owns the item (and why it matters)
--------------------------------------
Items in the (legacy, file-based) login keychain carry an access-control list.
``SecItemAdd`` records the *creating* binary as the only trusted application --
by code hash (``cdhash``), plus a ``cdhash:`` partition id for an ad-hoc-signed
binary. Any other binary that reads, updates or deletes the item makes macOS
show "<binary> wants to use your confidential information stored in ... in your
keychain", which asks for the login password; "Allow" covers that one access.

When the item was written in-process, its owner was whichever Python
interpreter happened to run: the repo's development venv, Hermes's managed
Python, a Homebrew Python... Each is ad-hoc signed with its own ``cdhash``, and
an interpreter upgrade changes it. So an anchor written by one interpreter made
every open in another one ask for the password -- a few times per flow, since
every open and every commit touches the item.

:class:`HelperAnchorStore` therefore keeps the anchor in an item that the
Secure Enclave helper (``mordred-hermes-sekey``) creates and reads (its service
is :data:`HELPER_SERVICE`, fixed inside the helper). Every Python process on the
machine goes through the same helper binary, and its build is reproducible (see
``native/sekey-helper/build.sh``), so the item's ACL keeps matching. The data-
protection keychain would avoid ACL dialogs altogether, but it requires the
``keychain-access-groups`` entitlement, which an ad-hoc-signed binary cannot
hold. :func:`default_anchor_store` picks the helper store whenever the helper is
installed; the in-process :class:`KeychainAnchorStore` remains for hosts
without it and as the source of a one-time migration.
"""

from __future__ import annotations

import contextlib
import sys
from collections.abc import Callable
from typing import Any, Final, Protocol

from . import native
from ._seckey_errors import _OpsError as _HelperOpsError
from .anchor import AnchorError

# OSStatus values we branch on (Security/SecBase.h). Mirrored from
# ``_seckey_backend.py`` rather than imported, to keep this module independent.
# (generic-password writes do NOT hit errSecMissingEntitlement / -34018 — see
# the module docstring — so unlike ``_seckey_backend`` there is no fallback path
# and no need to branch on it here.)
errSecSuccess: Final = 0
errSecItemNotFound: Final = -25300
errSecDuplicateItem: Final = -25299
errSecInteractionNotAllowed: Final = -25308

# Keychain ``kSecAttrService`` for every vault anchor item. The per-vault
# ``anchor_label`` becomes the ``kSecAttrAccount`` within this service.
DEFAULT_SERVICE: Final = "mordred-hermes.vault.anchor"

# ``kSecAttrService`` of the helper-owned anchor items. The helper hard-codes it
# (``native/sekey-helper``); it is mirrored here for documentation and tests only
# -- Python never passes a service name to the helper.
HELPER_SERVICE: Final = "mordred-hermes.vault.anchor.sekey"


class KeychainAnchorError(AnchorError):
    """A Keychain operation failed with an unexpected ``OSStatus``.

    A subclass of :class:`~mordred_hermes.keyvault.anchor.AnchorError`: a
    Keychain I/O failure *is* a failure to establish freshness, so it fails
    closed through the same ``except AnchorError`` paths the vault already
    uses — never swallowed into a "missing anchor" (which would read as a
    clean re-init opportunity). ``status`` carries the raw ``OSStatus``.
    """

    def __init__(self, status: int, message: str = "") -> None:
        self.status = status
        detail = f"{message} " if message else ""
        super().__init__(f"{detail}(OSStatus {status})")


class _OpsError(Exception):
    """A raw ``OSStatus`` failure from the pyobjc ops layer.

    Internal to this module: :class:`KeychainAnchorStore` catches it and either
    handles it (``errSecDuplicateItem`` → update, ``errSecItemNotFound`` →
    absent) or re-raises it as :class:`KeychainAnchorError`.
    """

    def __init__(self, status: int, message: str = "") -> None:
        self.status = status
        super().__init__(message or f"OSStatus {status}")


class _KeychainOps(Protocol):
    """The narrowest pyobjc-touching surface the anchor store needs."""

    def add(self, service: str, account: str, value: bytes) -> None:
        """Add a new generic-password item.

        Raises :class:`_OpsError` (``errSecDuplicateItem`` when the
        ``(service, account)`` item already exists)."""
        ...

    def get(self, service: str, account: str) -> bytes | None:
        """Return the item's data, or ``None`` when absent (``errSecItemNotFound``)."""
        ...

    def update(self, service: str, account: str, value: bytes) -> None:
        """Overwrite an existing item's data. Raises :class:`_OpsError`."""
        ...

    def delete(self, service: str, account: str) -> None:
        """Remove the item. A missing item (``errSecItemNotFound``) is success."""
        ...


def _status(result: Any) -> int:
    """Normalize a pyobjc return to an ``OSStatus`` int.

    pyobjc functions with an output parameter return ``(status, out)``;
    others return the bare status.
    """
    return int(result[0]) if isinstance(result, tuple) else int(result)


class _PyobjcKeychainOps:
    """Production :class:`_KeychainOps` over ``Security.framework``.

    ``Security`` is imported lazily (via :func:`native._lazy_import_security`,
    which raises on non-Darwin / missing pyobjc) so this module stays importable
    everywhere; the import happens only when an operation actually runs.
    """

    def _security(self) -> Any:
        return native._lazy_import_security()

    def _query(self, sec: Any, service: str, account: str) -> dict[Any, Any]:
        return {
            sec.kSecClass: sec.kSecClassGenericPassword,
            sec.kSecAttrService: service,
            sec.kSecAttrAccount: account,
        }

    def add(self, service: str, account: str, value: bytes) -> None:
        sec = self._security()
        attrs = self._query(sec, service, account)
        attrs[sec.kSecValueData] = value
        attrs[sec.kSecAttrAccessible] = sec.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        status = _status(sec.SecItemAdd(attrs, None))
        if status != errSecSuccess:
            raise _OpsError(status, "SecItemAdd failed")

    def get(self, service: str, account: str) -> bytes | None:
        sec = self._security()
        query = self._query(sec, service, account)
        query[sec.kSecReturnData] = True
        query[sec.kSecMatchLimit] = sec.kSecMatchLimitOne
        result = sec.SecItemCopyMatching(query, None)
        status = _status(result)
        if status == errSecItemNotFound:
            return None
        if status != errSecSuccess:
            raise _OpsError(status, "SecItemCopyMatching failed")
        data = result[1] if isinstance(result, tuple) and len(result) > 1 else None
        if data is None:
            # Success with no data is ambiguous (would read as a present-but-empty
            # anchor and wrongly block re-init). Treat it as a hard failure.
            raise _OpsError(status, "SecItemCopyMatching returned success but no data")
        return bytes(data)

    def update(self, service: str, account: str, value: bytes) -> None:
        sec = self._security()
        query = self._query(sec, service, account)
        # Re-assert accessibility on update so the ThisDeviceOnly guarantee the
        # threat model depends on cannot be silently inherited as something
        # weaker from a foreign / older item.
        attrs = {
            sec.kSecValueData: value,
            sec.kSecAttrAccessible: sec.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        }
        status = _status(sec.SecItemUpdate(query, attrs))
        if status != errSecSuccess:
            raise _OpsError(status, "SecItemUpdate failed")

    def delete(self, service: str, account: str) -> None:
        sec = self._security()
        status = _status(sec.SecItemDelete(self._query(sec, service, account)))
        # A missing item is success — delete is idempotent (matches the
        # AnchorStore Protocol's "no-op when already absent").
        if status not in (errSecSuccess, errSecItemNotFound):
            raise _OpsError(status, "SecItemDelete failed")

    def delete_noninteractive(self, service: str, account: str) -> None:
        """:meth:`delete`, but fail instead of showing a keychain dialog.

        Used only to clean up a migrated legacy item: leaving it behind is
        harmless (the helper item is authoritative), asking the operator for
        the login password to remove it is not worth a dialog.
        """
        sec = self._security()
        query = self._query(sec, service, account)
        ui_key = getattr(sec, "kSecUseAuthenticationUI", None)
        ui_fail = getattr(sec, "kSecUseAuthenticationUIFail", None)
        if ui_key is not None and ui_fail is not None:
            query[ui_key] = ui_fail
        status = _status(sec.SecItemDelete(query))
        if status not in (errSecSuccess, errSecItemNotFound):
            raise _OpsError(status, "SecItemDelete failed")


class KeychainAnchorStore:
    """``anchor.AnchorStore`` backed by a macOS Keychain generic-password item.

    Each vault's ``anchor_label`` is stored as the ``kSecAttrAccount`` under a
    single shared ``service``. ``ops`` defaults to the production pyobjc
    implementation; tests inject a software fake.
    """

    def __init__(self, *, service: str = DEFAULT_SERVICE, ops: _KeychainOps | None = None) -> None:
        self._service = service
        self._ops: _KeychainOps = ops if ops is not None else _PyobjcKeychainOps()

    def read(self, label: str) -> bytes | None:
        try:
            return self._ops.get(self._service, label)
        except _OpsError as exc:
            raise KeychainAnchorError(exc.status, f"reading anchor {label!r}") from exc

    def write(self, label: str, value: bytes) -> None:
        # Upsert: add a fresh item, or update in place if one already exists.
        # SecItemAdd reports errSecDuplicateItem rather than overwriting, so the
        # duplicate is the expected signal to switch to SecItemUpdate.
        try:
            self._ops.add(self._service, label, value)
            return
        except _OpsError as exc:
            if exc.status != errSecDuplicateItem:
                raise KeychainAnchorError(exc.status, f"writing anchor {label!r}") from exc
        try:
            self._ops.update(self._service, label, value)
        except _OpsError as exc:
            raise KeychainAnchorError(exc.status, f"updating anchor {label!r}") from exc

    def delete(self, label: str) -> None:
        try:
            self._ops.delete(self._service, label)
        except _OpsError as exc:
            raise KeychainAnchorError(exc.status, f"deleting anchor {label!r}") from exc

    def discard(self, label: str) -> None:
        """Best-effort, dialog-free removal of ``label`` (migration cleanup).

        Never raises and never asks the operator: an item this binary may not
        delete silently is simply left in place.
        """
        delete = getattr(self._ops, "delete_noninteractive", None)
        if delete is None:
            return
        with contextlib.suppress(_OpsError):
            delete(self._service, label)


# ---------------------------------------------------------------------------
# Helper-owned anchor items
# ---------------------------------------------------------------------------

#: ``(binary, request) -> response`` -- :func:`._seckey_helper._run_helper`'s shape.
HelperRunner = Callable[[str, dict[str, Any]], dict[str, Any]]


class _HelperAnchorUnsupported(Exception):
    """The installed helper predates the ``anchor_*`` commands."""


class _HelperAnchorOps:
    """Anchor item I/O through the ``mordred-hermes-sekey`` helper.

    One method call is one helper process. The helper itself calls
    ``SecItem*`` on a generic-password item under its fixed
    :data:`HELPER_SERVICE`, so the item's ACL trusts the helper binary, not the
    Python interpreter that asked. Only the account (the vault's anchor label)
    and the non-secret anchor bytes cross the process boundary.
    """

    def __init__(self, binary: str, *, runner: HelperRunner | None = None) -> None:
        self._binary = binary
        self._runner = runner

    def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
        runner = self._runner
        if runner is None:
            from ._seckey_helper import _run_helper

            runner = _run_helper
        try:
            return runner(self._binary, payload)
        except _HelperOpsError as exc:
            if exc.domain == "helper" and str(exc).startswith("unknown cmd"):
                raise _HelperAnchorUnsupported(str(exc)) from exc
            raise _OpsError(exc.status, f"helper {payload['cmd']} failed: {exc}") from exc

    def get(self, account: str) -> bytes | None:
        try:
            response = self._call({"cmd": "anchor_get", "account": account})
        except _OpsError as exc:
            if exc.status == errSecItemNotFound:
                return None
            raise
        value = response.get("value_hex")
        if not isinstance(value, str):
            raise _OpsError(-1, "helper response is missing value_hex")
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise _OpsError(-1, "helper returned an invalid value_hex") from exc

    def add(self, account: str, value: bytes) -> None:
        """Create the item; ``errSecDuplicateItem`` when it already exists (no overwrite)."""
        self._call({"cmd": "anchor_add", "account": account, "value_hex": value.hex()})

    def put(self, account: str, value: bytes) -> None:
        """Create or overwrite the item (one helper process, add-or-update inside)."""
        self._call({"cmd": "anchor_set", "account": account, "value_hex": value.hex()})

    def delete(self, account: str) -> None:
        self._call({"cmd": "anchor_delete", "account": account})


class HelperAnchorStore:
    """``anchor.AnchorStore`` whose Keychain item is owned by the SE helper.

    See the module docstring for why. Semantics match :class:`KeychainAnchorStore`
    (``None`` for an absent anchor, fail-closed :class:`KeychainAnchorError` on
    any other failure), plus two compatibility paths:

    * **Migration.** When the helper item is absent but the in-process
      (``legacy``) item exists, the legacy value is copied into a new helper
      item with an add-only write -- a concurrent writer that got there first
      wins, and its value is returned -- and the legacy item is then removed
      without prompting (best effort). The legacy read is the one access that
      can still raise a dialog, once per vault, when the running interpreter is
      not the one that wrote the legacy item.
    * **Older helper.** A helper built before the ``anchor_*`` commands answers
      ``unknown cmd``; the store then uses ``legacy`` for the rest of the
      process, exactly as before this change.

    The anchor pins non-secret values (``SHA-256(wmk)`` + generation), so
    nothing secret crosses the helper boundary; the item keeps
    ``AfterFirstUnlockThisDeviceOnly`` accessibility.
    """

    def __init__(self, helper: _HelperAnchorOps, *, legacy: KeychainAnchorStore | None = None) -> None:
        self._helper = helper
        self._legacy = legacy
        self._helper_supported = True

    def _legacy_or_fail(self, label: str) -> KeychainAnchorStore:
        if self._legacy is None:
            raise KeychainAnchorError(-1, f"the Secure Enclave helper cannot store anchor {label!r}; rebuild it")
        return self._legacy

    def read(self, label: str) -> bytes | None:
        if self._helper_supported:
            try:
                value = self._helper.get(label)
            except _HelperAnchorUnsupported:
                self._helper_supported = False
            except _OpsError as exc:
                raise KeychainAnchorError(exc.status, f"reading anchor {label!r}") from exc
            else:
                return value if value is not None else self._migrate(label)
        return self._legacy_or_fail(label).read(label)

    def _migrate(self, label: str) -> bytes | None:
        if self._legacy is None:
            return None
        old = self._legacy.read(label)
        if old is None:
            # A concurrent process may have migrated (and removed the legacy
            # item) between our two reads: look at the helper item once more
            # rather than report a live vault's anchor as missing.
            return self._helper_read(label)
        try:
            self._helper.add(label, old)
        except _OpsError as exc:
            if exc.status != errSecDuplicateItem:
                raise KeychainAnchorError(exc.status, f"migrating anchor {label!r}") from exc
            # Someone else created the helper item first -- theirs is newer or
            # equal, never ours to overwrite (that could roll the pin back).
            current = self._helper_read(label)
            if current is None:
                raise KeychainAnchorError(exc.status, f"migrating anchor {label!r}") from exc
            return current
        self._legacy.discard(label)
        return old

    def _helper_read(self, label: str) -> bytes | None:
        try:
            return self._helper.get(label)
        except (_OpsError, _HelperAnchorUnsupported) as exc:
            status = exc.status if isinstance(exc, _OpsError) else -1
            raise KeychainAnchorError(status, f"reading anchor {label!r}") from exc

    def write(self, label: str, value: bytes) -> None:
        if self._helper_supported:
            try:
                self._helper.put(label, value)
                return
            except _HelperAnchorUnsupported:
                self._helper_supported = False
            except _OpsError as exc:
                raise KeychainAnchorError(exc.status, f"writing anchor {label!r}") from exc
        self._legacy_or_fail(label).write(label, value)

    def delete(self, label: str) -> None:
        if self._helper_supported:
            try:
                self._helper.delete(label)
            except _HelperAnchorUnsupported:
                self._helper_supported = False
            except _OpsError as exc:
                raise KeychainAnchorError(exc.status, f"deleting anchor {label!r}") from exc
        if self._legacy is not None:
            self._legacy.delete(label)


def default_anchor_store() -> KeychainAnchorStore | HelperAnchorStore:
    """The production anchor store for this host.

    macOS with the SE helper installed: :class:`HelperAnchorStore` (the helper
    owns the item; the in-process store is only the migration source / old-
    helper fallback). Otherwise the in-process :class:`KeychainAnchorStore`.
    """
    if sys.platform == "darwin":
        from ._seckey_helper import find_sekey_helper

        binary = find_sekey_helper()
        if binary is not None:
            return HelperAnchorStore(_HelperAnchorOps(binary), legacy=KeychainAnchorStore())
    return KeychainAnchorStore()
