"""Portable confidential-file policy and native boundary fault tests."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from mordred_hermes import _private_fs as fs
from mordred_hermes._private_fs import _windows_paths as paths
from mordred_hermes._private_fs import _windows_security as security
from mordred_hermes._private_fs._windows_api import Metadata, OwnedHandle

USER = b"user"
SAFE = security.Descriptor(USER, False, [security.Ace(0, 0x10, 0x120089, USER)])
PRIVATE = security.Descriptor(
    USER, True, [security.Ace(0, 0, 0x1F01FF, sid) for sid in (USER, security.SYSTEM, security.ADMINISTRATORS)]
)


@pytest.mark.parametrize(
    "aces",
    [
        [],
        SAFE.aces,
        [security.Ace(0, 0x13, 0x10000000, sid) for sid in (USER, security.SYSTEM, security.ADMINISTRATORS)],
        [security.Ace(0, 0x10, 1, USER), security.Ace(0, 0, 0x80000000, USER)],
        [security.Ace(1, 0, 1, b"outside"), security.Ace(0, 0x08, 0x10000000, b"outside")],
        [security.Ace(0, 0, 0x10000000, security.OWNER_RIGHTS)],
    ],
)
def test_confidential_accepts_only_effective_safe_grants(aces):
    security.check_confidential(security.Descriptor(USER, False, aces), USER)


@pytest.mark.parametrize(
    "owner,aces",
    [
        (b"foreign", SAFE.aces),
        (USER, None),
        (USER, [security.Ace(0, 0, 1, b"outside")]),
        (USER, [security.Ace(1, 0, 1, b"outside"), security.Ace(0, 0, 1, b"outside")]),
        (USER, [security.Ace(0, 0, 1, security.TRUSTED_INSTALLER)]),
        (USER, [security.Ace(5, 0, 1, USER)]),
        (USER, [security.Ace(0, 0x20, 1, USER)]),
        (USER, [security.Ace(0, 0, 0x200, USER)]),
        (USER, [security.Ace(1, 0x08, 0x200, USER)]),
        (b"foreign", [security.Ace(0, 0, 1, security.OWNER_RIGHTS)]),
    ],
)
def test_confidential_refuses_unsafe_or_unknown_descriptor(owner, aces):
    with pytest.raises(fs.PrivateFSError) as err:
        security.check_confidential(security.Descriptor(owner, False, aces), USER)
    assert err.value.reason == "unsafe"


@dataclass
class Node:
    directory: bool
    descriptor: security.Descriptor = field(default_factory=lambda: SAFE)
    data: bytes = b""
    links: int = 1
    reparse: bool = False


class Native:
    """In-memory Win32 seam; actual policy, path walk, locks and IO stay real."""

    def __init__(self):
        self.nodes = {"C:\\": Node(True), "C:\\home": Node(True), "C:\\home\\config.yaml": Node(False, data=b"old")}
        self.handles = {}
        self.next_id = 0
        self.positions = {}
        self.fail_close = False
        self.fail_lock = False
        self.fail_lock_open = False
        self.on_read = lambda: None
        self.write_descriptors = []

    def open(self, path, *, access=0x120089, share=3, create=False):
        if path.endswith(".mordred-fs.lock") and self.fail_lock_open:
            raise fs.PrivateFSError("access_denied", "open")
        if create:
            if path in self.nodes:
                raise fs.PrivateFSError("exists", "open")
            self.nodes[path] = Node(False, PRIVATE)
        if path not in self.nodes:
            raise fs.PrivateFSError("missing", "open", native_code=2)
        self.next_id += 1
        self.handles[self.next_id] = (path, self.nodes[path])
        self.positions[self.next_id] = 0
        return OwnedHandle(self, self.next_id)

    def metadata(self, handle):
        _, node = self.handles[handle.value]
        return Metadata(
            fs.FileIdentity(1, str(id(node)).encode()), node.directory, node.reparse, node.links, len(node.data)
        )

    def descriptor(self, handle):
        return self.handles[handle.value][1].descriptor

    def user_sid(self):
        return USER

    def final_path(self, handle):
        return self.handles[handle.value][0]

    def validate_drive(self, drive):
        assert drive == "C:\\"

    def validate_volume(self, handle):
        pass

    def mkdir(self, path):
        self.nodes[path] = Node(True, PRIVATE)

    def CloseHandle(self, value):
        self.handles.pop(value)
        if self.fail_close:
            raise fs.PrivateFSError("missing", "close")
        return True

    def checked(self, result, operation):
        assert result

    def mtime_ns(self, handle):
        return 123

    def lock(self, handle):
        if self.fail_lock:
            raise fs.PrivateFSError("busy", "lock", native_code=33)

    def unlock(self, handle):
        pass

    def read(self, handle, count):
        node = self.handles[handle.value][1]
        position = self.positions[handle.value]
        data = node.data[position : position + count]
        self.positions[handle.value] += len(data)
        self.on_read()
        return data

    def write(self, handle, data):
        node = self.handles[handle.value][1]
        self.write_descriptors.append(node.descriptor)
        node.data += data
        return len(data)

    def flush(self, handle):
        pass

    def rename(self, handle, destination, *, replace):
        path, node = self.handles[handle.value]
        if destination in self.nodes and not replace:
            raise fs.PrivateFSError("exists", "rename")
        self.nodes[destination] = self.nodes.pop(path)
        self.handles[handle.value] = (destination, node)

    def names(self, handle):
        prefix = self.handles[handle.value][0] + "\\"
        return (
            name[len(prefix) :] for name in self.nodes if name.startswith(prefix) and "\\" not in name[len(prefix) :]
        )

    def discard(self, handle):
        del self.nodes[self.handles[handle.value][0]]


@pytest.fixture
def native(monkeypatch):
    api = Native()
    monkeypatch.setattr(paths, "get_api", lambda: api)
    monkeypatch.setattr(fs, "_platform", "nt")
    return api


def test_inherited_noop_preserves_parent_and_file_then_replacement_is_private(native):
    parent = native.nodes["C:\\home"].descriptor
    original = native.nodes["C:\\home\\config.yaml"].descriptor
    with fs.open_confidential_directory("C:\\home") as directory:
        assert directory.read_bytes("config.yaml", max_bytes=3) == b"old"
        assert native.nodes["C:\\home\\config.yaml"].descriptor is original
        with directory.transaction() as tx:
            tx.replace_bytes("config.yaml", b"new")
            tx.create_bytes("backup", b"old")
            assert tx.read_bytes("config.yaml", max_bytes=3) == b"new"
            assert native.nodes["C:\\home\\config.yaml"].descriptor == PRIVATE
            assert native.nodes["C:\\home\\.mordred-fs.lock"].descriptor == PRIVATE
            assert native.nodes["C:\\home"].descriptor is parent
    assert native.write_descriptors == [PRIVATE, PRIVATE]
    assert not native.handles


def test_confidential_delete_uses_expected_identity(native):
    with fs.open_confidential_directory("C:\\home") as directory, directory.transaction() as tx:
        with pytest.raises(fs.PrivateFSError):
            tx.delete_file("config.yaml", expected_identity=fs.FileIdentity(1, b"wrong"))
        identity = tx.stat("config.yaml").identity
        tx.delete_file("config.yaml", expected_identity=identity)
    assert "C:\\home\\config.yaml" not in native.nodes


@pytest.mark.parametrize("opener", ["open_optional_private_directory", "open_optional_confidential_directory"])
def test_optional_absence_keeps_parent_pinned_without_creation(native, opener):
    with getattr(fs, opener)("C:\\home\\absent") as directory:
        assert directory is None
        assert len(native.handles) == 2
    assert not native.handles
    assert "C:\\home\\absent" not in native.nodes


@pytest.mark.parametrize("opener", ["open_optional_private_directory", "open_optional_confidential_directory"])
@pytest.mark.parametrize("failure", ["intermediate", "unsafe", "cleanup"])
def test_optional_absence_never_swallows_intermediate_unsafe_or_cleanup(native, opener, failure):
    target = "C:\\home\\absent"
    if failure == "intermediate":
        target = "C:\\absent\\child"
    elif failure == "unsafe":
        native.nodes["C:\\home"].reparse = True
    else:
        native.fail_close = True
    with pytest.raises(fs.PrivateFSError), getattr(fs, opener)(target):
        pass
    assert not native.handles


@pytest.mark.parametrize("change", ["links", "reparse", "owner", "outside", "parent_mutation", "identity"])
def test_changed_security_or_binding_during_read_is_refused(native, change):
    def corrupt():
        node = native.nodes["C:\\home\\config.yaml"]
        if change == "links":
            node.links = 2
        elif change == "reparse":
            node.reparse = True
        elif change == "owner":
            node.descriptor = security.Descriptor(b"foreign", False, SAFE.aces)
        elif change == "outside":
            node.descriptor = security.Descriptor(USER, False, [security.Ace(0, 0, 1, b"outside")])
        elif change == "parent_mutation":
            native.nodes["C:\\home"].descriptor = security.Descriptor(USER, False, [security.Ace(0, 0, 2, b"outside")])
        else:
            native.nodes["C:\\home\\config.yaml"] = Node(False, data=b"old")

    native.on_read = corrupt
    with fs.open_confidential_directory("C:\\home") as directory, pytest.raises(fs.PrivateFSError) as err:
        directory.read_bytes("config.yaml", max_bytes=3)
    assert err.value.reason == "unsafe"


@pytest.mark.parametrize("failure", ["fail_lock", "fail_lock_open"])
def test_transaction_never_proceeds_without_lock(native, failure):
    setattr(native, failure, True)
    with (
        fs.open_confidential_directory("C:\\home") as directory,
        pytest.raises(fs.PrivateFSError),
        directory.transaction(blocking=False),
    ):
        pytest.fail("unlocked transaction")


def test_private_opener_remains_exact_private(native):
    with pytest.raises(fs.PrivateFSError), fs.open_private_directory("C:\\home"):
        pass


def test_create_only_missing_final_directory(native):
    with fs.open_confidential_directory("C:\\home\\new", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("secret", b"new")
    assert native.nodes["C:\\home\\new"].descriptor == PRIVATE
    with pytest.raises(fs.PrivateFSError), fs.open_confidential_directory("C:\\missing\\new", create=True):
        pass
    assert "C:\\missing" not in native.nodes


@pytest.mark.parametrize(
    "opener", ["open_confidential_directory", "open_optional_confidential_directory", "open_optional_private_directory"]
)
def test_windows_only_capabilities_explicitly_unsupported(monkeypatch, opener):
    monkeypatch.setattr(fs, "_platform", "posix")
    with pytest.raises(fs.PrivateFSError) as err:
        getattr(fs, opener)("/tmp/unused")
    assert err.value.reason == "unsupported"


@pytest.mark.parametrize("unsafe", ["outside", "owner", "links", "reparse"])
def test_existing_unsafe_file_refuses_replacement_unchanged(native, unsafe):
    node = native.nodes["C:\\home\\config.yaml"]
    if unsafe == "outside":
        node.descriptor = security.Descriptor(USER, False, [security.Ace(0, 0, 1, b"outside")])
    elif unsafe == "owner":
        node.descriptor = security.Descriptor(b"foreign", False, SAFE.aces)
    elif unsafe == "links":
        node.links = 2
    else:
        node.reparse = True
    original = node.descriptor
    with (
        fs.open_confidential_directory("C:\\home") as directory,
        directory.transaction() as tx,
        pytest.raises(fs.PrivateFSError),
    ):
        tx.replace_bytes("config.yaml", b"wrong")
    assert node.data == b"old"
    assert node.descriptor is original
    assert not native.write_descriptors


@pytest.mark.parametrize("opener", ["open_optional_private_directory", "open_optional_confidential_directory"])
def test_optional_cleanup_retains_original_body_error(native, opener):
    original = ValueError("caller failed")
    with pytest.raises(ValueError) as err, getattr(fs, opener)("C:\\home\\absent"):
        native.fail_close = True
        raise original
    assert err.value is original
    assert original.__notes__
    assert not native.handles


def test_confidential_directory_cleanup_after_publication_is_uncertain(native):
    with pytest.raises(fs.PrivateFSError) as err, fs.open_confidential_directory("C:\\home") as directory:
        with directory.transaction() as tx:
            tx.replace_bytes("config.yaml", b"new")
        native.fail_close = True
    assert err.value.operation == "close"
    assert err.value.commit_state == "uncertain"
    assert native.nodes["C:\\home\\config.yaml"].data == b"new"


def test_optional_does_not_reinterpret_unrelated_missing(native, monkeypatch):
    original = native.open

    def failed_open(path, **kwargs):
        if path == "C:\\home\\absent":
            raise fs.PrivateFSError("missing", "descriptor")
        return original(path, **kwargs)

    monkeypatch.setattr(native, "open", failed_open)
    with pytest.raises(fs.PrivateFSError) as err, fs.open_optional_confidential_directory("C:\\home\\absent"):
        pass
    assert err.value.operation == "descriptor"


def test_optional_private_existing_endpoint_stays_strict(native):
    with pytest.raises(fs.PrivateFSError), fs.open_optional_private_directory("C:\\home"):
        pass
    native.nodes["C:\\home"].descriptor = PRIVATE
    with fs.open_optional_private_directory("C:\\home") as directory:
        assert directory is not None
        with pytest.raises(fs.PrivateFSError):
            directory.read_bytes("config.yaml", max_bytes=3)


def test_published_file_acl_change_during_flush_is_uncertain(native, monkeypatch):
    def corrupt_published(handle):
        path, node = native.handles[handle.value]
        if path.endswith("config.yaml"):
            node.descriptor = SAFE

    monkeypatch.setattr(native, "flush", corrupt_published)
    with fs.open_confidential_directory("C:\\home") as directory, directory.transaction() as tx:
        with pytest.raises(fs.PrivateFSError) as err:
            tx.replace_bytes("config.yaml", b"new")
        assert err.value.commit_state == "uncertain"
    assert native.nodes["C:\\home\\config.yaml"].data == b"new"


def test_new_directory_must_verify_private_creation_descriptor(native, monkeypatch):
    def unsafe_creation(path):
        native.nodes[path] = Node(True, SAFE)

    monkeypatch.setattr(native, "mkdir", unsafe_creation)
    with pytest.raises(fs.PrivateFSError), fs.open_confidential_directory("C:\\home\\new", create=True):
        pass


@pytest.mark.parametrize("private", [False, True])
def test_windows_directory_identity_uses_live_checked_capability(native, private):
    if private:
        native.nodes["C:\\home"].descriptor = PRIVATE
    opener = fs.open_private_directory if private else fs.open_confidential_directory
    with opener("C:\\home") as directory:
        identity = directory.directory_identity()
        assert identity == fs.FileIdentity(1, str(id(native.nodes["C:\\home"])).encode())
        assert directory.directory_identity() == identity
    with pytest.raises(RuntimeError):
        directory.directory_identity()


@pytest.mark.parametrize("private", [False, True])
@pytest.mark.parametrize("change", ["thread", "process", "acl", "identity", "path", "ancestor"])
def test_windows_directory_identity_revalidates_all_boundaries(native, monkeypatch, private, change):
    from concurrent.futures import ThreadPoolExecutor

    from mordred_hermes._private_fs import _windows_io as win

    if private:
        native.nodes["C:\\home"].descriptor = PRIVATE
    opener = fs.open_private_directory if private else fs.open_confidential_directory
    with opener("C:\\home") as directory:
        assert directory.directory_identity()
        if change == "thread":
            with ThreadPoolExecutor(max_workers=1) as executor, pytest.raises(RuntimeError):
                executor.submit(directory.directory_identity).result()
            return
        if change == "process":
            monkeypatch.setattr(win.os, "getpid", lambda: -1)
        elif change == "acl":
            native.nodes["C:\\home"].descriptor = security.Descriptor(USER, False, [security.Ace(0, 0, 2, b"outside")])
        elif change == "ancestor":
            native.nodes["C:\\"].descriptor = security.Descriptor(USER, False, [security.Ace(0, 0, 2, b"outside")])
        else:
            value = directory.checked.handle.value
            path, node = native.handles[value]
            native.handles[value] = (
                (path, Node(True, PRIVATE if private else SAFE)) if change == "identity" else ("C:\\elsewhere", node)
            )
        with pytest.raises(RuntimeError if change == "process" else fs.PrivateFSError):
            directory.directory_identity()


@pytest.mark.parametrize("private", [False, True])
@pytest.mark.parametrize("change", ["thread", "process", "acl", "identity", "path"])
def test_windows_transaction_identity_checks_owning_directory(native, monkeypatch, private, change):
    from concurrent.futures import ThreadPoolExecutor

    from mordred_hermes._private_fs import _windows_io as win

    if private:
        native.nodes["C:\\home"].descriptor = PRIVATE
    opener = fs.open_private_directory if private else fs.open_confidential_directory
    with opener("C:\\home") as directory:
        with directory.transaction() as transaction:
            assert transaction.directory_identity() == directory.directory_identity()
            if change == "thread":
                with ThreadPoolExecutor(max_workers=1) as executor, pytest.raises(RuntimeError):
                    executor.submit(transaction.directory_identity).result()
            else:
                with monkeypatch.context() as patch:
                    if change == "process":
                        patch.setattr(win.os, "getpid", lambda: -1)
                    elif change == "acl":
                        native.nodes["C:\\home"].descriptor = security.Descriptor(
                            USER, False, [security.Ace(0, 0, 2, b"outside")]
                        )
                    else:
                        value = directory.checked.handle.value
                        path, node = native.handles[value]
                        native.handles[value] = (
                            (path, Node(True, PRIVATE if private else SAFE))
                            if change == "identity"
                            else ("C:\\elsewhere", node)
                        )
                    with pytest.raises(RuntimeError if change == "process" else fs.PrivateFSError):
                        transaction.directory_identity()
        with pytest.raises(RuntimeError):
            transaction.directory_identity()


@pytest.mark.parametrize("private", [False, True])
def test_transaction_asserts_immutable_private_admission(native, private):
    from dataclasses import FrozenInstanceError

    native.nodes["C:\\home"].descriptor = PRIVATE
    opener = fs.open_private_directory if private else fs.open_confidential_directory
    with opener("C:\\home") as directory, directory.transaction() as tx:
        if private:
            tx.assert_private_admission()
        else:
            with pytest.raises(fs.PrivateFSError) as err:
                tx.assert_private_admission()
            assert (err.value.reason, err.value.operation) == ("unsafe", "private_admission")
        with pytest.raises(FrozenInstanceError):
            directory.checked.confidential = not private
    with pytest.raises(RuntimeError):
        tx.assert_private_admission()


@pytest.mark.parametrize("transaction", [False, True])
def test_confidential_inventory_bounds_namespace_and_preserves_parent(native, transaction):
    from contextlib import nullcontext

    native.nodes["C:\\home\\memory.md"] = Node(False, data=b"memory")
    original = native.nodes["C:\\home"].descriptor
    with fs.open_confidential_directory("C:\\home") as directory:
        with directory.transaction() if transaction else nullcontext(directory) as view:
            assert view.list_names(max_entries=2) == ("config.yaml", "memory.md")
            with pytest.raises(fs.PrivateFSError) as caught:
                view.list_names(max_entries=1)
            assert caught.value.operation == "list_limit"
            with pytest.raises(ValueError):
                view.list_names(max_entries=True)
        assert native.nodes["C:\\home"].descriptor is original
    with pytest.raises(RuntimeError):
        view.list_names(max_entries=2)


@pytest.mark.parametrize("change", ["acl", "identity", "failure"])
def test_confidential_inventory_revalidates_after_enumeration(native, monkeypatch, change):
    def names(handle):
        yield "config.yaml"
        if change == "acl":
            native.nodes["C:\\home"].descriptor = security.Descriptor(USER, False, [security.Ace(0, 0, 2, b"outside")])
        elif change == "identity":
            path, _ = native.handles[handle.value]
            native.handles[handle.value] = (path, Node(True))
        else:
            raise fs.PrivateFSError("access_denied", "enumeration")

    monkeypatch.setattr(native, "names", names)
    with fs.open_confidential_directory("C:\\home") as directory, pytest.raises(fs.PrivateFSError):
        directory.list_names(max_entries=2)
