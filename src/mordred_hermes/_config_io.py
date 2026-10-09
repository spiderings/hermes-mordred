"""Windows canonical config/policy coordination over checked capabilities.

Never enter this coordinator while holding a lower-level mordred transaction.
Success is established only when the outermost session exits successfully. See
``docs/dev/WINDOWS_CONFIG_IO.md`` for caller and recovery obligations.
"""

from __future__ import annotations

import os
import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeVar

from ._private_fs import (
    ConfidentialDirectory,
    ConfidentialTransaction,
    FileIdentity,
    FileMetadata,
    PrivateDirectory,
    PrivateFSError,
    PrivateTransaction,
    open_confidential_directory,
    open_optional_confidential_directory,
    open_optional_private_directory,
    open_private_directory,
)
from ._private_fs._types import reserved, validate_leaf, validate_limit

CONFIG_LIMIT = POLICY_LIMIT = DOTENV_LIMIT = 8 * 1024 * 1024
MARKER_LIMIT = 4096
_Result = TypeVar("_Result")
POLICY_TRANSACTION_MARKER = ".policy-write.pending"


@dataclass(frozen=True)
class CanonicalPaths:
    home: Path
    config_name: str = "config.yaml"
    mordred_name: str = "mordred"
    policy_name: str = "policy.json"

    def __post_init__(self) -> None:
        if not self.home.is_absolute() or ".." in self.home.parts:
            raise ValueError("canonical home must be absolute without parent aliases")
        for name in (self.config_name, self.mordred_name, self.policy_name):
            validate_leaf(name)
            if name.endswith((" ", ".")) or "~" in name:
                raise ValueError("ambiguous canonical leaf")
        if self.config_name.casefold() in {self.mordred_name.casefold(), ".env", POLICY_TRANSACTION_MARKER}:
            raise ValueError("conflicting canonical leaves")
        if self.policy_name.casefold() == POLICY_TRANSACTION_MARKER:
            raise ValueError("policy cannot be the pending marker")

    def _key(self) -> tuple[str, str, str, str]:
        return (
            str(self.home).casefold(),
            self.config_name.casefold(),
            self.mordred_name.casefold(),
            self.policy_name.casefold(),
        )


@dataclass(frozen=True)
class CheckedContents:
    data: bytes
    metadata: FileMetadata


@dataclass(frozen=True)
class CanonicalSnapshot:
    config: CheckedContents | None
    policy: CheckedContents | None


class PolicyPendingError(OSError):
    """A checked marker prevents ordinary readers from using the pair."""


_lock = threading.RLock()
_local = threading.local()


def _after_fork() -> None:
    global _lock, _local
    _lock = threading.RLock()
    _local = threading.local()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def _read(tx: ConfidentialTransaction | None, name: str, limit: int) -> CheckedContents | None:
    validate_leaf(name)
    validate_limit(limit)
    if tx is None:
        return None
    try:
        before = tx.stat(name)
    except PrivateFSError as exc:
        if exc.reason == "missing" and exc.commit_state == "not_committed":
            return None
        raise
    if before.size > limit:
        raise PrivateFSError("unsafe", "oversize")
    data = tx.read_bytes(name, max_bytes=limit)
    after = tx.stat(name)
    if before != after or len(data) != after.size:
        raise PrivateFSError("unsafe", "read_changed")
    return CheckedContents(data, after)


class _State:
    def __init__(self, paths: CanonicalPaths, stack: ExitStack) -> None:
        self.paths, self.stack = paths, stack
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.live = True
        self.failure: BaseException | None = None
        self.published = False
        self.home: ConfidentialDirectory | None = None
        self.policy: PrivateDirectory | None = None
        self.home_tx: ConfidentialTransaction | None = None
        self.policy_tx: PrivateTransaction | None = None
        self.create = False
        self.home_identity: FileIdentity | None = None
        self.policy_identity: FileIdentity | None = None
        self.policy_opened = False
        self.update: PolicyUpdate | None = None

    def check(self) -> None:
        if not self.live or self.pid != os.getpid() or self.thread != threading.get_ident():
            raise RuntimeError("canonical session is closed or foreign")
        if self.failure is not None:
            raise self.failure
        if self.home is not None and self.home.directory_identity() != self.home_identity:
            raise PrivateFSError("unsafe", "home_identity")
        if self.policy is not None and self.policy.directory_identity() != self.policy_identity:
            raise PrivateFSError("unsafe", "policy_identity")

    def remember_mutation_failure(self, exc: BaseException, *, published: bool) -> None:
        if published and isinstance(exc, PrivateFSError):
            exc.commit_state = "uncertain"
        if self.failure is None and (
            published or (isinstance(exc, PrivateFSError) and exc.commit_state == "uncertain")
        ):
            self.failure = exc

    def extend(self, create: bool, *, blocking: bool) -> None:
        self.check()
        if self.policy_opened:
            if create and self.policy is None:
                raise ValueError("cannot upgrade checked absence to creation in a nested session")
            return
        self.policy_opened = True
        if self.home is None:
            return
        try:
            path = self.paths.home / self.paths.mordred_name
            directory = self.stack.enter_context(
                open_private_directory(path, create=True) if create else open_optional_private_directory(path)
            )
            self.policy = directory
            if directory is not None:
                self.policy_identity = directory.directory_identity()
                self.policy_tx = self.stack.enter_context(directory.transaction(blocking=blocking))
        except BaseException as exc:
            # A failed extension must never masquerade as an absent policy scope.
            self.failure = exc
            raise


@contextmanager
def _nested_session(
    active: _State, paths: CanonicalPaths, scope: Literal["home", "policy"], create: bool, blocking: bool
) -> Iterator[CanonicalSession]:
    active.check()
    try:
        if active.paths._key() != paths._key():
            raise ValueError("nested canonical sessions must use the same home and leaves")
        # Opening checked handles revalidates this spelling; never reacquire a lock.
        with open_optional_confidential_directory(paths.home) as alias:
            identity = alias.directory_identity() if alias is not None else None
            if identity != active.home_identity:
                raise PrivateFSError("unsafe", "nested_home_identity")
        if create and active.home is None:
            raise ValueError("cannot create inside a checked-absent session")
        if scope == "policy":
            active.extend(create, blocking=blocking)
        session = CanonicalSession(active, blocking=blocking)
        try:
            yield session
            active.check()
        finally:
            session._live = False
    except PrivateFSError as exc:
        active.remember_mutation_failure(exc, published=False)
        raise


@contextmanager
def canonical_session(
    paths: CanonicalPaths, *, scope: Literal["home", "policy"], create: bool = False, blocking: bool = True
) -> Iterator[CanonicalSession]:
    if scope not in ("home", "policy"):
        raise ValueError("unknown canonical scope")
    active: _State | None = getattr(_local, "state", None)
    if active is not None:
        with _nested_session(active, paths, scope, create, blocking) as session:
            yield session
        return
    if not _lock.acquire(blocking=blocking):
        raise PrivateFSError("busy", "canonical_lock")
    state: _State | None = None
    try:
        with ExitStack() as stack:
            state = _State(paths, stack)
            state.create = create
            directory = stack.enter_context(
                open_confidential_directory(paths.home, create=True)
                if create
                else open_optional_confidential_directory(paths.home)
            )
            state.home = directory
            if directory is not None:
                state.home_identity = directory.directory_identity()
                state.home_tx = stack.enter_context(directory.transaction(blocking=blocking))
            if scope == "policy":
                state.extend(create, blocking=blocking)
            _local.state = state
            session = CanonicalSession(state, blocking=blocking)
            try:
                yield session
                state.check()
            finally:
                session._live = False
                state.live = False
                _local.state = None
    except BaseException as exc:
        failure = state.failure if state is not None and state.failure is not None else exc
        if state is not None and state.published and isinstance(failure, PrivateFSError):
            failure.commit_state = "uncertain"
        if failure is not exc:
            failure.add_note(f"canonical session cleanup also failed: {type(exc).__name__}")
            raise failure from exc
        raise
    finally:
        _lock.release()


class CanonicalSession:
    def __init__(self, state: _State, *, blocking: bool = True) -> None:
        self._state = state
        self._blocking = blocking
        self._live = True

    def _check(self, *, policy: bool = False) -> _State:
        if not self._live:
            raise RuntimeError("canonical session is closed")
        self._state.check()
        if policy and not self._state.policy_opened:
            raise RuntimeError("policy scope required")
        return self._state

    def home_directory_identity(self) -> FileIdentity | None:
        """Return the live checked home binding, or its already-checked absence."""
        return self._check().home_identity

    @contextmanager
    def borrow_mordred_transaction(self) -> Iterator[PrivateTransaction]:
        """Lend non-policy leaves under existing home -> mordred locks."""
        state = self._check()
        state.extend(state.create, blocking=self._blocking)
        self._guard(recovery=False)
        if state.policy_tx is None:
            raise PrivateFSError("missing", "mordred_transaction")
        loan = _MordredTransaction(self, state.policy_tx)
        try:
            loan.assert_private_admission()
            yield loan
        except BaseException as exc:
            state.remember_mutation_failure(exc, published=False)
            raise
        finally:
            loan._live = False

    @contextmanager
    def publication_receipt(self) -> Iterator[PublicationReceipt]:
        """Track child publication without lending filesystem or lock authority."""
        state = self._check()
        receipt = PublicationReceipt(self)
        try:
            yield receipt
        except BaseException as exc:
            state.remember_mutation_failure(exc, published=receipt._published)
            raise
        finally:
            receipt._live = False

    def _marker(self) -> CheckedContents | None:
        state = self._check(policy=True)
        return _read(state.policy_tx, POLICY_TRANSACTION_MARKER, MARKER_LIMIT)

    def _guard(self, *, recovery: bool = True) -> None:
        marker = self._marker()
        update = self._state.update
        if marker is not None and not (recovery and update is not None and update._session is self and update._recover):
            raise PolicyPendingError("pending policy publication requires configure reconciliation")

    def read_home(self, name: str, *, max_bytes: int) -> CheckedContents | None:
        state = self._check()
        if name.casefold() == state.paths.config_name.casefold():
            self._guard()
            limit = CONFIG_LIMIT
        else:
            self._home_leaf(name)
            limit = DOTENV_LIMIT
        result = _read(state.home_tx, name, min(max_bytes, limit))
        self._check()
        return result

    def read_policy(self, *, max_bytes: int) -> CheckedContents | None:
        state = self._check(policy=True)
        self._guard()
        result = _read(state.policy_tx, state.paths.policy_name, min(max_bytes, POLICY_LIMIT))
        self._check()
        return result

    def _home_leaf(self, name: str) -> bool:
        validate_leaf(name)
        if name.casefold() == self._state.paths.config_name.casefold():
            raise ValueError("canonical config mutations require the policy pair protocol")
        if name == ".env":
            return False
        patterns = (self._state.paths.config_name, ".env")
        if any(
            re.fullmatch(re.escape(prefix) + r"\.mordred-uninstall-[A-Za-z0-9_-]+\.bak", name) for prefix in patterns
        ):
            return True
        raise ValueError("only dotenv and explicit uninstall backup leaves are allowed")

    def write_home(self, name: str, data: bytes) -> None:
        state = self._check()
        backup = self._home_leaf(name)
        if len(data) > DOTENV_LIMIT:
            raise PrivateFSError("unsafe", "oversize")
        if state.home_tx is None:
            raise PrivateFSError("missing", "home")
        original = _read(state.home_tx, name, DOTENV_LIMIT)
        if not backup and original is not None and original.data == data:
            return
        published = False
        try:
            if backup or original is None:
                state.home_tx.create_bytes(name, data)
            else:
                state.home_tx.replace_bytes(name, data)
            published = state.published = True
            result = _read(state.home_tx, name, DOTENV_LIMIT)
            if result is None or result.data != data:
                raise PrivateFSError("unsafe", "home_verification", commit_state="uncertain")
        except BaseException as exc:
            state.remember_mutation_failure(exc, published=published)
            raise

    def create_policy_backup(self, name: str, data: bytes) -> None:
        """Create and verify an exact-private uninstall secret backup, never replace."""
        state = self._check(policy=True)
        validate_leaf(name)
        if name.casefold() in {state.paths.policy_name.casefold(), POLICY_TRANSACTION_MARKER}:
            raise ValueError("canonical policy mutations require the pair protocol")
        if re.fullmatch(r"env-removed-[A-Za-z0-9_-]+\.env", name) is None:
            raise ValueError("invalid policy backup leaf")
        if not isinstance(data, bytes) or len(data) > DOTENV_LIMIT:
            raise ValueError("backup must be bounded bytes")
        self._guard()
        if state.policy_tx is None:
            raise PrivateFSError("missing", "policy")
        published = False
        try:
            state.policy_tx.create_bytes(name, data)
            published = state.published = True
            result = _read(state.policy_tx, name, DOTENV_LIMIT)
            if result is None or result.data != data:
                raise PrivateFSError("unsafe", "backup_verification", commit_state="uncertain")
        except BaseException as exc:
            state.remember_mutation_failure(exc, published=published)
            raise

    def delete_home(self, name: str, *, expected_identity: FileIdentity) -> None:
        state = self._check()
        self._home_leaf(name)
        if state.home_tx is None:
            raise PrivateFSError("missing", "home")
        published = False
        try:
            state.home_tx.delete_file(name, expected_identity=expected_identity)
            published = state.published = True
            if _read(state.home_tx, name, DOTENV_LIMIT) is not None:
                raise PrivateFSError("unsafe", "home_delete_verification", commit_state="uncertain")
        except BaseException as exc:
            state.remember_mutation_failure(exc, published=published)
            raise

    def _pair(self, *, recovery: bool) -> CanonicalSnapshot:
        state = self._check(policy=True)
        self._guard(recovery=recovery)
        result = CanonicalSnapshot(
            _read(state.home_tx, state.paths.config_name, CONFIG_LIMIT),
            _read(state.policy_tx, state.paths.policy_name, POLICY_LIMIT),
        )
        self._guard(recovery=recovery)
        self._check()
        return result

    def read_pair(self) -> CanonicalSnapshot:
        return self._pair(recovery=True)

    @contextmanager
    def policy_update(self, *, recover_pending: bool = False) -> Iterator[PolicyUpdate]:
        state = self._check(policy=True)
        if state.update is not None:
            raise RuntimeError("a policy update is already active")
        update = PolicyUpdate(self, recover_pending)
        state.update = update
        try:
            yield update
        finally:
            update._live = False
            state.update = None


class _MordredTransaction:
    """Lifetime-bound loan; the underlying transaction never leaves C2."""

    def __init__(self, session: CanonicalSession, transaction: PrivateTransaction) -> None:
        self._session = session
        self._transaction = transaction
        self._live = True

    def _check(self) -> _State:
        if not self._live:
            raise RuntimeError("mordred transaction loan is closed")
        state = self._session._state
        try:
            self._session._check(policy=True)
            self._session._guard(recovery=False)
            self._transaction.assert_private_admission()
            if self._transaction.directory_identity() != state.policy_identity:
                raise PrivateFSError("unsafe", "loan_directory_identity")
            return state
        except BaseException as exc:
            state.remember_mutation_failure(exc, published=False)
            raise

    def _protected(self, name: str) -> bool:
        folded = name.casefold()
        leaves = {
            self._session._state.paths.policy_name.casefold(),
            "policy.json",
            POLICY_TRANSACTION_MARKER,
            ".policy-write.lock",
        }
        return (
            folded in leaves
            or reserved(name)
            or any(folded.startswith(leaf + ".") and folded.endswith(".tmp") for leaf in leaves)
        )

    def _leaf(self, name: str) -> None:
        validate_leaf(name)
        if self._protected(name):
            raise ValueError("coordinator-owned leaf cannot be borrowed")

    def _invoke(self, operation: Callable[[], _Result], *, mutation: bool = False) -> _Result:
        state = self._check()
        published = False
        try:
            result = operation()
            if mutation:
                published = state.published = True
            self._check()
            return result
        except BaseException as exc:
            state.remember_mutation_failure(exc, published=published)
            raise

    def assert_private_admission(self) -> None:
        self._check()

    def directory_identity(self) -> FileIdentity:
        return self._invoke(self._transaction.directory_identity)

    def stat(self, name: str) -> FileMetadata:
        self._leaf(name)
        return self._invoke(lambda: self._transaction.stat(name))

    def read_bytes(self, name: str, *, max_bytes: int) -> bytes:
        self._leaf(name)
        return self._invoke(lambda: self._transaction.read_bytes(name, max_bytes=max_bytes))

    def read_prefix(self, name: str, *, max_bytes: int) -> bytes:
        self._leaf(name)
        return self._invoke(lambda: self._transaction.read_prefix(name, max_bytes=max_bytes))

    def list_names(self, *, max_entries: int) -> tuple[str, ...]:
        validate_limit(max_entries)
        return self._invoke(
            lambda: tuple(
                name for name in self._transaction.list_names(max_entries=max_entries) if not self._protected(name)
            )
        )

    def create_bytes(self, name: str, data: bytes) -> None:
        self._leaf(name)
        self._invoke(lambda: self._transaction.create_bytes(name, data), mutation=True)

    def replace_bytes(self, name: str, data: bytes) -> None:
        self._leaf(name)
        self._invoke(lambda: self._transaction.replace_bytes(name, data), mutation=True)

    def append_bytes(self, name: str, data: bytes) -> None:
        self._leaf(name)
        self._invoke(lambda: self._transaction.append_bytes(name, data), mutation=True)

    def delete_file(self, name: str, *, expected_identity: FileIdentity | None = None) -> None:
        self._leaf(name)
        self._invoke(lambda: self._transaction.delete_file(name, expected_identity=expected_identity), mutation=True)

    def rename_file(self, name: str, destination: str, *, expected_identity: FileIdentity | None = None) -> None:
        self._leaf(name)
        self._leaf(destination)
        self._invoke(
            lambda: self._transaction.rename_file(name, destination, expected_identity=expected_identity), mutation=True
        )


class PublicationReceipt:
    """Monotonic outcome reporting for a separately locked child; no IO authority."""

    def __init__(self, session: CanonicalSession) -> None:
        self._session = session
        self._live = True
        self._published = False

    def _check(self) -> _State:
        state = self._session._state
        if (
            not self._live
            or not self._session._live
            or not state.live
            or state.pid != os.getpid()
            or state.thread != threading.get_ident()
        ):
            raise RuntimeError("publication receipt is closed or foreign")
        if state.failure is not None:
            raise state.failure
        # Reporting must precede parent filesystem revalidation: a child may
        # already have published when a parent identity/security check fails.
        return state

    def mark_published(self) -> None:
        state = self._check()
        self._published = state.published = True

    def mark_uncertain(self, error: PrivateFSError) -> None:
        state = self._check()
        if not isinstance(error, PrivateFSError):
            raise TypeError("uncertain receipt requires a classified filesystem failure")
        self._published = state.published = True
        state.remember_mutation_failure(error, published=True)


class PolicyUpdate:
    def __init__(self, session: CanonicalSession, recover: bool) -> None:
        self._session = session
        self._recover = recover
        self._live = True
        self._attempted = False
        self._marker_original = session._marker()
        if self._marker_original is not None and not recover:
            raise PolicyPendingError("pending policy publication requires configure reconciliation")
        state = session._state
        self._original = CanonicalSnapshot(
            _read(state.home_tx, state.paths.config_name, CONFIG_LIMIT),
            _read(state.policy_tx, state.paths.policy_name, POLICY_LIMIT),
        )
        self._config = self._original.config.data if self._original.config else None
        self._policy = self._original.policy.data if self._original.policy else None

    def _check(self) -> _State:
        state = self._session._check(policy=True)
        if not self._live or state.update is not self or self._attempted:
            raise RuntimeError("policy update is closed or commit already attempted")
        return state

    def put_config(self, data: bytes) -> None:
        self._check()
        if not isinstance(data, bytes) or len(data) > CONFIG_LIMIT:
            raise ValueError("config must be bounded bytes")
        self._config = data

    def put_policy(self, data: bytes) -> None:
        self._check()
        if not isinstance(data, bytes) or len(data) > POLICY_LIMIT:
            raise ValueError("policy must be bounded bytes")
        self._policy = data

    def delete_config(self, *, expected_identity: FileIdentity) -> None:
        self._check()
        if self._original.config is None or self._original.config.metadata.identity != expected_identity:
            raise PrivateFSError("unsafe", "delete_config_identity")
        self._config = None

    def delete_policy(self, *, expected_identity: FileIdentity) -> None:
        self._check()
        if self._original.policy is None or self._original.policy.metadata.identity != expected_identity:
            raise PrivateFSError("unsafe", "delete_policy_identity")
        self._policy = None

    def commit(self) -> None:
        state = self._check()
        self._attempted = True
        try:
            self._commit(state)
        except BaseException as exc:
            state.failure = exc
            if state.published and isinstance(exc, PrivateFSError):
                exc.commit_state = "uncertain"
            raise

    def _commit(self, state: _State) -> None:
        current = CanonicalSnapshot(
            _read(state.home_tx, state.paths.config_name, CONFIG_LIMIT),
            _read(state.policy_tx, state.paths.policy_name, POLICY_LIMIT),
        )
        if current != self._original or self._session._marker() != self._marker_original:
            raise PrivateFSError("unsafe", "original_changed")
        desired = (self._config, self._policy)
        originals = (current.config, current.policy)
        if self._marker_original is None and desired == tuple(x.data if x else None for x in originals):
            return
        home, policy = state.home_tx, state.policy_tx
        if home is None or policy is None:
            raise PrivateFSError("missing", "policy_update_directory")
        record = f"version=1 pid={os.getpid()} time_ns={time.time_ns()}\n".encode("ascii")
        if self._marker_original is None:
            policy.create_bytes(POLICY_TRANSACTION_MARKER, record)
        else:
            policy.replace_bytes(POLICY_TRANSACTION_MARKER, record)
        state.published = True
        marker = _read(policy, POLICY_TRANSACTION_MARKER, MARKER_LIMIT)
        if marker is None or marker.data != record:
            raise PrivateFSError("unsafe", "marker_verification")
        members = (
            (home, state.paths.config_name, current.config, self._config),
            (policy, state.paths.policy_name, current.policy, self._policy),
        )
        for tx, name, original, data in members:
            _publish_member(tx, name, original, data)
        result = (
            _read(home, state.paths.config_name, CONFIG_LIMIT),
            _read(policy, state.paths.policy_name, POLICY_LIMIT),
        )
        if tuple(x.data if x else None for x in result) != desired:
            raise PrivateFSError("unsafe", "pair_verification")
        state.check()
        policy.delete_file(POLICY_TRANSACTION_MARKER, expected_identity=marker.metadata.identity)
        if _read(policy, POLICY_TRANSACTION_MARKER, MARKER_LIMIT) is not None:
            raise PrivateFSError("unsafe", "marker_delete_verification")


def _publish_member(
    tx: ConfidentialTransaction, name: str, original: CheckedContents | None, data: bytes | None
) -> None:
    if original is not None and original.data == data:
        return
    if data is None:
        if original is not None:
            tx.delete_file(name, expected_identity=original.metadata.identity)
    elif original is None:
        tx.create_bytes(name, data)
    else:
        tx.replace_bytes(name, data)


def read_canonical_snapshot(paths: CanonicalPaths) -> CanonicalSnapshot:
    """Read a pair under nonblocking locks; never expose recovery bypass."""
    with canonical_session(paths, scope="policy", blocking=False) as session:
        result = session._pair(recovery=False)
    return result


def read_policy_marker(paths: CanonicalPaths) -> CheckedContents | None:
    """Bounded checked diagnostics, with the same nonblocking lock order."""
    with canonical_session(paths, scope="policy", blocking=False) as session:
        result = session._marker()
    return result
