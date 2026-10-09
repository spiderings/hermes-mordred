"""A model of the macOS *legacy* login keychain for counting access dialogs.

The vault's freshness anchor is a generic-password item in the login keychain.
Items there carry an access-control list: the binary that created an item is
trusted (its code hash is recorded, plus a ``cdhash:`` partition id), and any
other binary that reads, updates or deletes the item makes macOS show the
"<binary> wants to use your confidential information stored in ... in your
keychain" dialog, which asks for the login password. A miss (no such item) and
an add never ask.

:class:`SimKeychain` models exactly that, per calling binary, and counts both
keychain operations and the dialogs they would raise. Two front ends drive it:

* :class:`SimPyobjcOps` -- the in-process ``Security.framework`` calls
  (``_PyobjcKeychainOps``) made by one Python interpreter;
* :class:`SimHelperRunner` -- the ``mordred-hermes-sekey`` helper's JSON
  protocol (``anchor_get`` / ``anchor_add`` / ``anchor_set`` /
  ``anchor_delete``), i.e. the helper binary is the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mordred_hermes.keyvault import _anchor_keychain
from mordred_hermes.keyvault._seckey_errors import _OpsError as _SeOpsError

errSecItemNotFound = -25300
errSecDuplicateItem = -25299
errSecInteractionNotAllowed = -25308

#: The service the helper hard-codes for anchor items (mirrors main.swift).
HELPER_SERVICE = "mordred-hermes.vault.anchor.sekey"


@dataclass
class _Item:
    value: bytes
    trusted: set[str]


@dataclass
class SimKeychain:
    """Legacy-keychain ACL model: one dialog per access by an untrusted binary.

    ``always_allow`` models the operator's choice in the dialog: ``False`` =
    "Allow" (this access only, so the next access asks again), ``True`` =
    "Always Allow" (the binary is added to the item's ACL).
    """

    always_allow: bool = False
    items: dict[tuple[str, str], _Item] = field(default_factory=dict)
    ops: list[tuple[str, str, str]] = field(default_factory=list)
    dialogs: list[tuple[str, str, str]] = field(default_factory=list)

    # -- accounting -------------------------------------------------------------

    def _authorize(self, binary: str, op: str, key: tuple[str, str], item: _Item, *, interactive: bool) -> bool:
        if binary in item.trusted:
            return True
        if not interactive:
            return False
        self.dialogs.append((binary, op, key[0]))
        if self.always_allow:
            item.trusted.add(binary)
        return True

    def reset_counts(self) -> None:
        self.ops.clear()
        self.dialogs.clear()

    @property
    def access_count(self) -> int:
        return len(self.ops)

    @property
    def dialog_count(self) -> int:
        return len(self.dialogs)

    # -- SecItem* ---------------------------------------------------------------

    def copy(self, binary: str, service: str, account: str) -> bytes | None:
        self.ops.append((binary, "SecItemCopyMatching", service))
        item = self.items.get((service, account))
        if item is None:
            return None
        self._authorize(binary, "read", (service, account), item, interactive=True)
        return item.value

    def add(self, binary: str, service: str, account: str, value: bytes) -> int:
        self.ops.append((binary, "SecItemAdd", service))
        if (service, account) in self.items:
            return errSecDuplicateItem
        self.items[(service, account)] = _Item(bytes(value), {binary})
        return 0

    def update(self, binary: str, service: str, account: str, value: bytes) -> int:
        self.ops.append((binary, "SecItemUpdate", service))
        item = self.items.get((service, account))
        if item is None:
            return errSecItemNotFound
        self._authorize(binary, "update", (service, account), item, interactive=True)
        item.value = bytes(value)
        return 0

    def delete(self, binary: str, service: str, account: str, *, interactive: bool = True) -> int:
        self.ops.append((binary, "SecItemDelete", service))
        item = self.items.get((service, account))
        if item is None:
            return 0
        if not self._authorize(binary, "delete", (service, account), item, interactive=interactive):
            return errSecInteractionNotAllowed
        del self.items[(service, account)]
        return 0

    def seed(self, service: str, account: str, value: bytes, *, creator: str) -> None:
        """Place an item created earlier by ``creator`` (no accounting)."""
        self.items[(service, account)] = _Item(bytes(value), {creator})


class SimPyobjcOps:
    """``_KeychainOps`` for one Python interpreter (``binary``) over a :class:`SimKeychain`."""

    def __init__(self, keychain: SimKeychain, binary: str) -> None:
        self._kc = keychain
        self._binary = binary

    def add(self, service: str, account: str, value: bytes) -> None:
        status = self._kc.add(self._binary, service, account, value)
        if status != 0:
            raise _anchor_keychain._OpsError(status, "SecItemAdd failed")

    def get(self, service: str, account: str) -> bytes | None:
        return self._kc.copy(self._binary, service, account)

    def update(self, service: str, account: str, value: bytes) -> None:
        status = self._kc.update(self._binary, service, account, value)
        if status != 0:
            raise _anchor_keychain._OpsError(status, "SecItemUpdate failed")

    def delete(self, service: str, account: str) -> None:
        status = self._kc.delete(self._binary, service, account)
        if status != 0:
            raise _anchor_keychain._OpsError(status, "SecItemDelete failed")

    def delete_noninteractive(self, service: str, account: str) -> None:
        status = self._kc.delete(self._binary, service, account, interactive=False)
        if status != 0:
            raise _anchor_keychain._OpsError(status, "SecItemDelete failed")


class SimHelperRunner:
    """Stands in for ``_seckey_helper._run_helper`` for the anchor commands.

    ``supports_anchor=False`` models a helper built before the anchor commands
    existed: it answers every anchor command with ``unknown cmd``.
    """

    def __init__(self, keychain: SimKeychain, binary: str = "mordred-hermes-sekey", *, supports_anchor: bool = True):
        self._kc = keychain
        self._binary = binary
        self.supports_anchor = supports_anchor
        self.calls: list[str] = []

    def __call__(self, binary: str, payload: dict[str, Any]) -> dict[str, Any]:
        cmd = payload["cmd"]
        self.calls.append(cmd)
        if not self.supports_anchor or not cmd.startswith("anchor_"):
            raise _SeOpsError(-1, "helper", f"unknown cmd: {cmd}")
        account = payload["account"]
        if cmd == "anchor_get":
            value = self._kc.copy(self._binary, HELPER_SERVICE, account)
            if value is None:
                raise _SeOpsError(errSecItemNotFound, "OSStatus", "no anchor item")
            return {"value_hex": value.hex()}
        if cmd == "anchor_add":
            status = self._kc.add(self._binary, HELPER_SERVICE, account, bytes.fromhex(payload["value_hex"]))
            if status != 0:
                raise _SeOpsError(status, "OSStatus", "anchor_add failed")
            return {"ok": True}
        if cmd == "anchor_set":  # update first, add when absent (main.swift anchorSet)
            value = bytes.fromhex(payload["value_hex"])
            status = self._kc.update(self._binary, HELPER_SERVICE, account, value)
            if status == errSecItemNotFound:
                status = self._kc.add(self._binary, HELPER_SERVICE, account, value)
                if status == errSecDuplicateItem:
                    status = self._kc.update(self._binary, HELPER_SERVICE, account, value)
            if status != 0:
                raise _SeOpsError(status, "OSStatus", "anchor_set failed")
            return {"ok": True}
        if cmd == "anchor_delete":
            status = self._kc.delete(self._binary, HELPER_SERVICE, account)
            if status != 0:
                raise _SeOpsError(status, "OSStatus", "anchor_delete failed")
            return {"ok": True}
        raise _SeOpsError(-1, "helper", f"unknown cmd: {cmd}")
