"""Windows CNG custody with checked ownership and durable role journals.

Enrollment is explicit and inert: this module never arms memory hooks. Runtime
lookups never generate, import ambient keys, infer native absence, or repair ACLs.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

from .._config_io import CanonicalPaths, CanonicalSession, canonical_session
from .._private_fs import (
    FileIdentity,
    PrivateFSError,
    PrivateTransaction,
    current_principal_id,
    open_optional_confidential_directory,
)
from . import wrap
from ._memory_storage import inventory_memory_files
from ._runtime_probe import require_stopped_windows_gateways
from ._windows_profile import (
    LIMIT,
    MAX_EPOCH,
    ROLES,
    Manifest,
    Pending,
    Role,
    RoleRecord,
    RoleState,
    encode_manifest,
    encode_pending,
    new_manifest,
    new_record,
    parse_manifest,
    parse_pending,
)
from ._windows_profile import (
    CustodyError as CustodyError,
)
from .memory_crypto import MemoryCryptoError, looks_like_magic_line, unseal
from .wrap import NativeBackend

MANIFEST = "windows-custody.json"
WRAPPED = "memory-key.wrapped"
MARKER = "memory-vault.marker"
OPTOUT = "memory-vault.optout"


@dataclass(frozen=True)
class GenerationLease:
    profile_nonce: str
    role: Role
    generation: str
    epoch: int
    key_id: str
    native_key_id: str
    public_sha256: str


def windows_backend() -> NativeBackend:
    from . import _seckey_helper
    from ._seckey_backend import _SecKeyBackend

    ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_winkey_helper)
    if ops is None:
        raise CustodyError("Windows TPM helper unavailable; install the package-bound helper")
    return _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)


def _read(tx: PrivateTransaction | None, name: str, limit: int = LIMIT) -> bytes | None:
    if tx is None:
        return None
    try:
        tx.stat(name)
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return None
        raise
    return tx.read_bytes(name, max_bytes=limit)


def _pending_name(role: Role) -> str:
    if role not in ROLES:
        raise CustodyError("unknown custody role")
    return f"windows-{role}.pending.json"


def _fingerprint(public: bytes) -> str:
    # Validate a real uncompressed P-256 point before recording authority.
    from cryptography.hazmat.primitives.asymmetric import ec

    if len(public) != 65 or public[0] != 4:
        raise CustodyError("invalid native public key")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
    except ValueError as exc:
        raise CustodyError("invalid native public key") from exc
    return hashlib.sha256(public).hexdigest()


@contextmanager
def windows_custody_session(
    home: Path,
    *,
    create: bool = False,
    canonical: CanonicalSession | None = None,
    backend: NativeBackend | None = None,
) -> Iterator[WindowsCustodySession]:
    """Own home -> mordred, or join an explicitly supplied checked coordinator."""
    with ExitStack() as stack:
        if canonical is None:
            canonical = stack.enter_context(canonical_session(CanonicalPaths(home), scope="policy", create=create))
        else:
            # Directory admission/identity only: never recursively acquire the home lock.
            with open_optional_confidential_directory(home) as directory:
                identity = None if directory is None else directory.directory_identity()
                if identity != canonical.home_directory_identity():
                    raise CustodyError("canonical session belongs to another physical home")
        identity = canonical.home_directory_identity()
        tx = None
        if identity is not None:
            try:
                tx = stack.enter_context(canonical.borrow_mordred_transaction())
            except PrivateFSError as exc:
                if exc.reason != "missing" or create:
                    raise
        session = WindowsCustodySession(home, canonical, tx, identity, current_principal_id(), backend)
        try:
            yield session
            session.check()
        finally:
            session._live = False


class WindowsCustodySession:
    def __init__(
        self,
        home: Path,
        canonical: CanonicalSession,
        tx: PrivateTransaction | None,
        identity: FileIdentity | None,
        sid: bytes,
        backend: NativeBackend | None,
    ) -> None:
        self.home = home
        self.canonical = canonical
        self._tx = tx
        self._identity = identity
        self._sid = sid
        self._backend = backend
        self._live = True

    def check(self) -> None:
        if not self._live:
            raise RuntimeError("Windows custody session is closed")
        if self.canonical.home_directory_identity() != self._identity or current_principal_id() != self._sid:
            raise CustodyError("Windows custody session identity changed")
        if self._tx is not None:
            self._tx.assert_private_admission()

    @property
    def backend(self) -> NativeBackend:
        self.check()
        if self._backend is None:
            self._backend = windows_backend()
        return self._backend

    def _transaction(self) -> PrivateTransaction:
        self.check()
        if self._tx is None:
            raise CustodyError("custody mutation requires an authorized existing directory")
        return self._tx

    def _manifest(self) -> Manifest | None:
        self.check()
        data = _read(self._tx, MANIFEST)
        if data is None:
            return None
        if self._identity is None:
            raise CustodyError("retained custody has no checked home")
        return parse_manifest(data, self._identity, self._sid)

    def _pending(self, manifest: Manifest, role: Role) -> Pending | None:
        data = _read(self._tx, _pending_name(role))
        return None if data is None else parse_pending(data, manifest, role)

    def _publish(self, name: str, data: bytes, *, create: bool = False) -> None:
        tx = self._transaction()
        with self.canonical.publication_receipt() as receipt:
            if create:
                tx.create_bytes(name, data)
            else:
                tx.replace_bytes(name, data)
            receipt.mark_published()
            if tx.read_bytes(name, max_bytes=LIMIT) != data:
                raise PrivateFSError("unsafe", "custody_publication", commit_state="uncertain")

    def _save(self, manifest: Manifest, *, create: bool = False) -> None:
        # Apply the same strict parser to in-memory proposals before publication.
        data = encode_manifest(manifest)
        parse_manifest(data, manifest.home, manifest.sid)
        self._publish(MANIFEST, data, create=create)

    def _journal(self, pending: Pending, *, create: bool = False) -> None:
        self._publish(_pending_name(pending.role), encode_pending(pending), create=create)

    def _remove(self, name: str) -> None:
        tx = self._transaction()
        tx.delete_file(name, expected_identity=tx.stat(name).identity)

    def _validate_memory(self, key: bytes | None) -> None:
        if key is not None and (not isinstance(key, bytes) or len(key) != 32):
            raise CustodyError("memory key must be exactly 32 bytes")
        if self._identity is None:
            return
        for snapshot in inventory_memory_files(self.home):
            if looks_like_magic_line(snapshot.data.decode("utf-8", "surrogateescape")):
                if key is None:
                    raise CustodyError("sealed memory requires explicit authenticated key adoption")
                try:
                    unseal(snapshot.data, key=key, name=snapshot.name)
                except MemoryCryptoError as exc:
                    raise CustodyError("retained memory does not authenticate") from exc

    def _fresh_memory(self, key: bytes | None) -> None:
        for name in (WRAPPED, MARKER, OPTOUT, _pending_name("memory")):
            if _read(self._tx, name) is not None:
                raise CustodyError("retained memory custody requires reconciliation, never regeneration")
        self._validate_memory(key)

    def _ensure_manifest(self) -> Manifest:
        manifest = self._manifest()
        if manifest is None:
            if any(_read(self._tx, _pending_name(role)) is not None for role in ROLES):
                raise CustodyError("orphan custody journal must be preserved")
            if self._identity is None:
                raise CustodyError("custody requires a checked existing home")
            manifest = new_manifest(self._identity, self._sid)
            self._save(manifest, create=True)
        return manifest

    def lease(self, role: Role, *, generation: str | None = None) -> GenerationLease:
        manifest = self._manifest()
        if manifest is None:
            raise CustodyError("custody ownership is absent")
        if self._pending(manifest, role) is not None:
            raise CustodyError("custody role has an unresolved journal")
        state = manifest.role(role)
        record = state.current
        if generation is not None:
            record = next(
                (
                    r
                    for r in state.retained + (() if state.current is None else (state.current,))
                    if r.generation == generation
                ),
                None,
            )
        if record is None or record.public_sha256 is None:
            raise CustodyError("custody generation is not owned")
        return GenerationLease(
            manifest.profile_nonce,
            role,
            record.generation,
            record.epoch,
            record.key_id,
            record.native_key_id,
            record.public_sha256,
        )

    def validate_lease(self, lease: GenerationLease) -> None:
        if self.lease(lease.role, generation=lease.generation) != lease:
            raise CustodyError("custody generation lease changed")

    def backend_for(self, lease: GenerationLease) -> NativeBackend:
        self.validate_lease(lease)
        backend = self.backend
        if _fingerprint(backend.get_enclave_public_key(lease.native_key_id)) != lease.public_sha256:
            raise CustodyError("native public key differs from retained ownership")
        return backend

    def load_memory_key(self) -> bytes:
        lease = self.lease("memory")
        blob = _read(self._tx, WRAPPED, wrap.HEADER_LEN)
        if blob is None:
            raise CustodyError("retained memory ownership has lost its wrapper; refusing regeneration")
        return wrap.unwrap_dek(
            blob, lease.native_key_id, backend=self.backend_for(lease), audit_sink=lambda entry: None
        )

    def resolve_memory_key(self) -> bytes | None:
        manifest = self._manifest()
        if manifest is not None and manifest.role("memory") != RoleState():
            return self.load_memory_key()
        self._fresh_memory(None)
        # Orphan journals for other roles still cannot be hidden as fresh state.
        if manifest is None and any(_read(self._tx, _pending_name(role)) is not None for role in ROLES):
            raise CustodyError("orphan custody state")
        return None

    def _begin(self, role: Role, *, retain_current: bool = False) -> tuple[Manifest, Pending]:
        manifest = self._ensure_manifest()
        if self._pending(manifest, role) is not None:
            raise CustodyError("pending custody enrollment requires explicit reconciliation")
        state = manifest.role(role)
        if (state.current is not None or state.retained) and not retain_current:
            raise CustodyError("custody role already has retained ownership")
        if retain_current and role == "memory":
            raise CustodyError("memory generation rotation requires migration")
        if retain_current and state.current is not None and sum(len(manifest.role(r).retained) for r in ROLES) >= 64:
            raise CustodyError("retained custody generation limit reached")
        pending = Pending(manifest.profile_nonce, role, "create", "intent", new_record(manifest, role))
        self._journal(pending, create=True)
        return manifest, pending

    def _verify(self, pending: Pending, *, generated_public: bytes | None = None) -> Pending:
        public = self.backend.get_enclave_public_key(pending.record.native_key_id)
        fingerprint = _fingerprint(public)
        if generated_public is not None and generated_public != public:
            raise CustodyError("native creation public key changed")
        if pending.record.public_sha256 is not None and pending.record.public_sha256 != fingerprint:
            raise CustodyError("journaled native public key changed")
        # A public lookup is not positive possession; prove exact ECDH in RAM.
        challenge = secrets.token_bytes(32)
        proof = wrap.wrap_dek(challenge, pending.record.native_key_id, backend=self.backend)
        if (
            wrap.unwrap_dek(proof, pending.record.native_key_id, backend=self.backend, audit_sink=lambda entry: None)
            != challenge
        ):
            raise CustodyError("native possession proof failed")
        verified = replace(pending, phase="verified", record=replace(pending.record, public_sha256=fingerprint))
        self._journal(verified)
        return verified

    def _commit(self, manifest: Manifest, pending: Pending) -> GenerationLease:
        state = manifest.role(pending.role)
        if state.current != pending.record:
            retained = state.retained + (() if state.current is None else (state.current,))
            manifest = manifest.with_role(
                pending.role, RoleState(pending.record, retained), epoch=max(manifest.epoch, pending.record.epoch)
            )
            self._save(manifest)
        self._remove(_pending_name(pending.role))
        return self.lease(pending.role)

    def _publish_memory_key(self, pending: Pending, key: bytes) -> None:
        blob = wrap.wrap_dek(key, pending.record.native_key_id, backend=self.backend)
        if (
            wrap.unwrap_dek(blob, pending.record.native_key_id, backend=self.backend, audit_sink=lambda entry: None)
            != key
        ):
            raise CustodyError("memory wrap verification failed")
        self._publish(WRAPPED, blob, create=True)

    def enroll_memory(self, *, adopted_key: bytes | None = None) -> bytes:
        self.check()
        self._fresh_memory(adopted_key)
        backend = self.backend  # Discover the executable before any native intent exists.
        manifest, pending = self._begin("memory")
        with self.canonical.publication_receipt() as receipt:
            # The native call can publish even if its response is lost. Keep
            # subsequent ledger failures sticky through the owning coordinator.
            receipt.mark_published()
            public = backend.generate_enclave_key(pending.record.native_key_id, unattended=True)
            pending = self._verify(pending, generated_public=public)
            key = secrets.token_bytes(32) if adopted_key is None else adopted_key
            self._publish_memory_key(pending, key)
            self._commit(manifest, pending)
            return key

    def enroll_role(self, role: Role, *, retain_current: bool = False) -> GenerationLease:
        if role == "memory":
            raise CustodyError("use explicit memory enrollment")
        backend = self.backend
        manifest, pending = self._begin(role, retain_current=retain_current)
        with self.canonical.publication_receipt() as receipt:
            receipt.mark_published()
            public = backend.generate_enclave_key(pending.record.native_key_id, unattended=True)
            return self._commit(manifest, self._verify(pending, generated_public=public))

    def _delete_guard(self, role: Role, *, erase_authorized: bool, deleted: bool = False) -> None:
        if role == "memory":
            require_stopped_windows_gateways(self.home)
            if _read(self._tx, MARKER) is not None or (not deleted and _read(self._tx, OPTOUT) is None):
                raise CustodyError("memory must be explicitly disabled before deleting custody")
            self._validate_memory(None)
        elif not erase_authorized:
            raise CustodyError("retained audit or Telegram history requires explicit erasure authorization")

    def delete_role(self, lease: GenerationLease, *, erase_authorized: bool = False) -> None:
        self.validate_lease(lease)
        self._delete_guard(lease.role, erase_authorized=erase_authorized)
        manifest = self._manifest()
        assert manifest is not None
        if manifest.epoch == MAX_EPOCH:
            raise CustodyError("custody lifecycle epoch exhausted; refusing irreversible deletion")
        record = RoleRecord(lease.generation, lease.epoch, lease.key_id, lease.native_key_id, lease.public_sha256)
        pending = Pending(manifest.profile_nonce, lease.role, "delete", "intent", record)
        backend = self.backend_for(lease)
        self._journal(pending, create=True)
        with self.canonical.publication_receipt() as receipt:
            receipt.mark_published()
            backend.delete_enclave_key(lease.native_key_id)
            pending = replace(pending, phase="deleted")
            self._journal(pending)
            self._finish_delete(manifest, pending)

    def _finish_delete(self, manifest: Manifest, pending: Pending) -> None:
        if pending.phase != "deleted":
            raise CustodyError("native deletion has not been positively recorded")
        if pending.role == "memory":
            if _read(self._tx, WRAPPED, wrap.HEADER_LEN) is not None:
                self._remove(WRAPPED)
            if _read(self._tx, OPTOUT) is not None:
                self._remove(OPTOUT)
        state = manifest.role(pending.role)
        current = state.current
        if current is not None and current.generation == pending.record.generation:
            if current != pending.record:
                raise CustodyError("deletion journal conflicts with current ownership")
            current = None
        retained = tuple(row for row in state.retained if row.generation != pending.record.generation)
        if current != state.current or retained != state.retained:
            self._save(manifest.with_role(pending.role, RoleState(current, retained), epoch=manifest.epoch + 1))
        self._remove(_pending_name(pending.role))

    def reconcile_pending(
        self,
        role: Role,
        *,
        adopted_key: bytes | None = None,
        erase_authorized: bool = False,
    ) -> GenerationLease | None:
        manifest = self._manifest()
        if manifest is None:
            raise CustodyError("journal cannot be reconciled without bound profile ownership")
        pending = self._pending(manifest, role)
        if pending is None:
            raise CustodyError("no custody journal to reconcile")
        if pending.operation == "delete":
            self._delete_guard(role, erase_authorized=erase_authorized, deleted=pending.phase == "deleted")
            if pending.phase != "deleted":
                # A missing key after a lost deletion result is ambiguous. Do not
                # retry an irreversible native action or infer successful absence.
                raise CustodyError("native deletion outcome is unresolved; preserve the intent journal")
            self._finish_delete(manifest, pending)
            return None
        current = manifest.role(role).current
        if current is not None and current.generation == pending.record.generation and current != pending.record:
            raise CustodyError("journal conflicts with committed custody")
        blob = _read(self._tx, WRAPPED, wrap.HEADER_LEN) if role == "memory" else None
        key = adopted_key
        if role == "memory":
            key = self._recovery_memory_key(pending, blob, adopted_key)
        pending = self._verify(pending)
        if role == "memory" and blob is None:
            self._publish_memory_key(pending, secrets.token_bytes(32) if key is None else key)
        return self._commit(manifest, pending)

    def _recovery_memory_key(self, pending: Pending, blob: bytes | None, adopted_key: bytes | None) -> bytes | None:
        key = adopted_key
        if blob is not None:
            key = wrap.unwrap_dek(
                blob, pending.record.native_key_id, backend=self.backend, audit_sink=lambda entry: None
            )
            if adopted_key is not None and adopted_key != key:
                raise CustodyError("adopted key conflicts with retained wrapper")
        elif _read(self._tx, MARKER) is not None or _read(self._tx, OPTOUT) is not None:
            raise CustodyError("retained memory marker without wrapper cannot be reconciled")
        self._validate_memory(key)
        return key


def load_windows_memory_key(*, home: Path, backend: NativeBackend | None = None) -> bytes:
    with windows_custody_session(home, backend=backend) as session:
        return session.load_memory_key()


def resolve_windows_memory_key(*, home: Path) -> bytes | None:
    with windows_custody_session(home) as session:
        return session.resolve_memory_key()
