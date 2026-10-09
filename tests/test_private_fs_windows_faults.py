"""Portable Windows policy tests; native calls are covered on actual Windows."""

from __future__ import annotations

import importlib
import importlib.util

import pytest


@pytest.fixture
def security():
    assert importlib.util.find_spec("mordred_hermes._private_fs._windows_security") is not None
    return importlib.import_module("mordred_hermes._private_fs._windows_security")


@pytest.mark.parametrize(
    "change", ["owner", "null", "unprotected", "inherited", "broad", "deny", "missing", "propagating"]
)
def test_private_descriptor_refuses_unsafe_grants(security, change: str) -> None:
    s = security
    user = b"user"
    aces = [s.Ace(0, 0, 0x1F01FF, sid) for sid in (user, s.SYSTEM, s.ADMINISTRATORS)]
    owner = user
    protected = True
    if change == "owner":
        owner = b"other"
    elif change == "null":
        aces = None
    elif change == "unprotected":
        protected = False
    elif change == "inherited":
        aces[0] = s.Ace(0, 0x10, 0x1F01FF, user)
    elif change == "broad":
        aces.append(s.Ace(0, 0, 1, b"everyone"))
    elif change == "deny":
        aces.append(s.Ace(1, 0, 1, b"everyone"))
    elif change == "missing":
        aces.pop()
    elif change == "propagating":
        aces[0] = s.Ace(0, 3, 0x1F01FF, user)
    with pytest.raises(s.PrivateFSError) as err:
        s.check_private(s.Descriptor(owner, protected, aces), user)
    assert err.value.reason == "unsafe"


def test_exact_private_descriptor_accepts_order_independent_trustees(security) -> None:
    s = security
    aces = [s.Ace(0, 0, 0x1F01FF, sid) for sid in (s.ADMINISTRATORS, b"user", s.SYSTEM)]
    s.check_private(s.Descriptor(b"user", True, aces), b"user")


@pytest.mark.parametrize("mask", [0x40, 0x10000, 0x40000, 0x80000, 0x100, 0x40000000, 0x10000000])
def test_untrusted_ancestor_mutation_is_refused(security, mask: int) -> None:
    s = security
    with pytest.raises(s.PrivateFSError):
        s.check_ancestor(s.Descriptor(s.SYSTEM, False, [s.Ace(0, 0, mask, b"other")]), b"user", creating_child=False)


def test_normal_system_ancestor_is_distinct_from_private_policy(security) -> None:
    s = security
    aces = [
        s.Ace(0, 0x13, 0x1F01FF, s.SYSTEM),
        s.Ace(0, 0x0B, 0x10000000, b"creator"),
        s.Ace(0, 0x13, 0x1200A9, b"users"),
        s.Ace(0, 0x02, 4, b"users"),
    ]
    d = s.Descriptor(s.TRUSTED_INSTALLER, False, aces)
    s.check_ancestor(d, b"user", creating_child=False)
    with pytest.raises(s.PrivateFSError):
        s.check_ancestor(d, b"user", creating_child=True)


def test_owner_rights_ancestor_grant_applies_only_to_validated_owner(security) -> None:
    s = security
    owner_rights = bytes.fromhex("010100000000000304000000")
    descriptor = s.Descriptor(b"user", False, [s.Ace(0, 3, 0x1F01FF, owner_rights)])
    s.check_ancestor(descriptor, b"user", creating_child=True)
    with pytest.raises(s.PrivateFSError):
        s.check_ancestor(s.Descriptor(b"other", False, descriptor.aces), b"user", creating_child=True)


@pytest.mark.parametrize("outcome", ["retained", "published", "unqueryable"])
def test_publication_reconciliation_controls_retry_safety(outcome: str) -> None:
    from types import SimpleNamespace

    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes._private_fs._windows_io import publish

    state = {"attempted": False}

    class Api:
        def final_path(self, handle):
            if state["attempted"] and outcome == "unqueryable":
                raise PrivateFSError("io", "query")
            return "old-staging" if not state["attempted"] or outcome == "retained" else "published"

        def rename(self, handle, destination, *, replace):
            state["attempted"] = True
            raise PrivateFSError("io", "rename", native_code=1117)

    with pytest.raises(PrivateFSError) as err:
        publish(SimpleNamespace(api=Api()), SimpleNamespace(path="checked-directory"), "secret", replace=True)
    assert err.value.commit_state == ("not_committed" if outcome == "retained" else "uncertain")
    assert err.value.native_code == 1117


@pytest.mark.parametrize("operation", ["metadata", "descriptor", "user_sid"])
def test_failed_native_security_query_never_accepts_object(operation: str) -> None:
    from types import SimpleNamespace

    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes._private_fs._windows_security import ADMINISTRATORS, SYSTEM, Ace, Descriptor, validate_private

    def fail():
        raise PrivateFSError("io", "security_query", native_code=1117)

    methods = {
        "metadata": lambda: SimpleNamespace(directory=False, reparse=False, links=1),
        "descriptor": lambda: Descriptor(
            b"user", True, [Ace(0, 0, 0x1F01FF, s) for s in (b"user", SYSTEM, ADMINISTRATORS)]
        ),
        "user_sid": lambda: b"user",
    }
    methods[operation] = fail
    api = SimpleNamespace(
        metadata=lambda h: methods["metadata"](),
        descriptor=lambda h: methods["descriptor"](),
        user_sid=methods["user_sid"],
    )
    with pytest.raises(PrivateFSError) as err:
        validate_private(SimpleNamespace(api=api), directory=False)
    assert err.value.native_code == 1117


def test_owned_handle_closes_once_even_when_close_reports_error() -> None:
    from types import SimpleNamespace

    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes._private_fs._windows_api import OwnedHandle

    closed = []

    def close(value):
        closed.append(value)
        return False

    def checked(result, operation):
        raise PrivateFSError("io", operation, native_code=6)

    handle = OwnedHandle(SimpleNamespace(CloseHandle=close, checked=checked), 123)
    with pytest.raises(PrivateFSError):
        handle.close()
    handle.close()
    assert closed == [123]


def test_native_handle_cleanup_preserves_body_error() -> None:
    from types import SimpleNamespace

    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes._private_fs._windows_api import OwnedHandle

    def failed_close(result, operation):
        raise PrivateFSError("io", operation, native_code=6)

    handle = OwnedHandle(SimpleNamespace(CloseHandle=lambda value: False, checked=failed_close), 123)
    with pytest.raises(ValueError, match="body"), handle:
        raise ValueError("body")
    assert handle.value is None
