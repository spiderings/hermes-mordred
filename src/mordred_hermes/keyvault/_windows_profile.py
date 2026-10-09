"""Strict immutable Windows custody ownership; no path-based native authority."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, replace
from typing import Literal, cast

from .._private_fs import FileIdentity

Role = Literal["memory", "audit", "telegram"]
ROLES: tuple[Role, ...] = ("memory", "audit", "telegram")
LOGICAL_IDS = {
    "memory": "mordred.memory",
    "audit": "mordred.audit-log",
    "telegram": "mordred-hermes.telegram.credentials.v1",
}
LIMIT = 65536
MAX_EPOCH = (1 << 53) - 1


class CustodyError(RuntimeError):
    """Retained or uncertain custody must be preserved, never regenerated."""


@dataclass(frozen=True)
class RoleRecord:
    generation: str
    epoch: int
    key_id: str
    native_key_id: str
    public_sha256: str | None


@dataclass(frozen=True)
class RoleState:
    current: RoleRecord | None = None
    retained: tuple[RoleRecord, ...] = ()


@dataclass(frozen=True)
class Manifest:
    home: FileIdentity
    sid: bytes
    profile_nonce: str
    epoch: int
    roles: tuple[RoleState, RoleState, RoleState]

    def role(self, role: Role) -> RoleState:
        return self.roles[ROLES.index(role)]

    def with_role(self, role: Role, state: RoleState, *, epoch: int) -> Manifest:
        roles = list(self.roles)
        roles[ROLES.index(role)] = state
        return replace(self, roles=cast(tuple[RoleState, RoleState, RoleState], tuple(roles)), epoch=epoch)


@dataclass(frozen=True)
class Pending:
    profile_nonce: str
    role: Role
    operation: Literal["create", "delete"]
    phase: Literal["intent", "verified", "deleted"]
    record: RoleRecord


def _object(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields or any(not isinstance(k, str) for k in value):
        raise CustodyError("invalid custody object fields")
    return cast(dict[str, object], value)


def _integer(value: object, maximum: int = MAX_EPOCH) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise CustodyError("invalid custody integer")
    return value


def _hex(value: object, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise CustodyError("invalid custody binary field")
    try:
        data = bytes.fromhex(value)
    except ValueError:
        raise CustodyError("invalid custody hex") from None
    if data.hex() != value or (size is not None and len(data) != size):
        raise CustodyError("invalid custody hex length or encoding")
    return data


def _sid(value: bytes) -> bytes:
    if len(value) < 8 or value[0] != 1 or not 1 <= value[1] <= 15 or len(value) != 8 + value[1] * 4:
        raise CustodyError("invalid custody SID")
    return value


def _identity(identity: FileIdentity) -> FileIdentity:
    _integer(identity.volume, (1 << 64) - 1)
    if not isinstance(identity.file_id, bytes) or len(identity.file_id) != 16:
        raise CustodyError("invalid custody file identity")
    return identity


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CustodyError("duplicate custody JSON key")
        result[key] = value
    return result


def _decode(data: bytes) -> object:
    if len(data) > LIMIT:
        raise CustodyError("custody record exceeds bound")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CustodyError("malformed custody JSON") from exc


def _encode(value: object) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(data) > LIMIT:
        raise CustodyError("custody record exceeds bound")
    return data


def native_selector(manifest: Manifest, role: Role, generation: str) -> str:
    if role not in ROLES:
        raise CustodyError("unknown custody role")
    fields = (
        _identity(manifest.home).volume.to_bytes(8, "big"),
        manifest.home.file_id,
        _sid(manifest.sid),
        _hex(manifest.profile_nonce, 32),
        role.encode("ascii"),
        _hex(generation, 32),
    )
    encoded = b"mordred-hermes.windows-custody.v1\0" + b"".join(len(f).to_bytes(4, "big") + f for f in fields)
    return "mordred-hermes.windows.v1." + hashlib.sha256(encoded).hexdigest()


def new_manifest(identity: FileIdentity, sid: bytes, *, nonce: bytes | None = None) -> Manifest:
    nonce = secrets.token_bytes(32) if nonce is None else nonce
    _hex(nonce.hex(), 32)
    return Manifest(_identity(identity), _sid(sid), nonce.hex(), 0, (RoleState(), RoleState(), RoleState()))


def new_record(manifest: Manifest, role: Role, *, generation: bytes | None = None) -> RoleRecord:
    generation = secrets.token_bytes(32) if generation is None else generation
    epoch = _integer(manifest.epoch + 1)
    return RoleRecord(
        generation.hex(), epoch, LOGICAL_IDS[role], native_selector(manifest, role, generation.hex()), None
    )


def _record(value: object, manifest: Manifest, role: Role, *, pending: bool = False) -> RoleRecord:
    obj = _object(value, {"generation", "epoch", "key_id", "native_key_id", "public_sha256"})
    generation = _hex(obj["generation"], 32).hex()
    epoch = _integer(obj["epoch"])
    if epoch == 0 or (not pending and epoch > manifest.epoch):
        raise CustodyError("invalid custody role epoch")
    native = native_selector(manifest, role, generation)
    if obj["key_id"] != LOGICAL_IDS[role] or obj["native_key_id"] != native:
        raise CustodyError("custody role selector mismatch")
    fingerprint = obj["public_sha256"]
    if fingerprint is not None:
        fingerprint = _hex(fingerprint, 32).hex()
    elif not pending:
        raise CustodyError("missing custody public fingerprint")
    return RoleRecord(generation, epoch, LOGICAL_IDS[role], native, fingerprint)


def encode_manifest(manifest: Manifest) -> bytes:
    return _encode(
        {
            "version": 1,
            "home": {"volume": manifest.home.volume, "file_id": manifest.home.file_id.hex()},
            "sid": manifest.sid.hex(),
            "profile_nonce": manifest.profile_nonce,
            "epoch": manifest.epoch,
            "roles": {role: asdict(manifest.role(role)) for role in ROLES},
        }
    )


def parse_manifest(data: bytes, identity: FileIdentity, sid: bytes) -> Manifest:
    obj = _object(_decode(data), {"version", "home", "sid", "profile_nonce", "epoch", "roles"})
    if type(obj["version"]) is not int or obj["version"] != 1:
        raise CustodyError("unsupported custody version")
    home = _object(obj["home"], {"volume", "file_id"})
    bound = FileIdentity(_integer(home["volume"], (1 << 64) - 1), _hex(home["file_id"], 16))
    owner = _sid(_hex(obj["sid"]))
    if bound != _identity(identity) or owner != _sid(sid):
        raise CustodyError("custody belongs to another physical home or token")
    manifest = Manifest(
        bound,
        owner,
        _hex(obj["profile_nonce"], 32).hex(),
        _integer(obj["epoch"]),
        (RoleState(), RoleState(), RoleState()),
    )
    roles = _object(obj["roles"], set(ROLES))
    generations: set[str] = set()
    retained_count = 0
    for role in ROLES:
        state = _object(roles[role], {"current", "retained"})
        retained = state["retained"]
        if not isinstance(retained, list):
            raise CustodyError("invalid retained custody records")
        retained_count += len(retained)
        if retained_count > 64:
            raise CustodyError("too many retained custody generations")
        current = None if state["current"] is None else _record(state["current"], manifest, role)
        records = tuple(_record(row, manifest, role) for row in retained)
        for record in records + (() if current is None else (current,)):
            if record.generation in generations:
                raise CustodyError("duplicate custody generation")
            generations.add(record.generation)
        manifest = manifest.with_role(role, RoleState(current, records), epoch=manifest.epoch)
    return manifest


def encode_pending(pending: Pending) -> bytes:
    return _encode({"version": 1, **asdict(pending)})


def parse_pending(data: bytes, manifest: Manifest, role: Role) -> Pending:
    obj = _object(_decode(data), {"version", "profile_nonce", "role", "operation", "phase", "record"})
    if (
        type(obj["version"]) is not int
        or obj["version"] != 1
        or obj["profile_nonce"] != manifest.profile_nonce
        or obj["role"] != role
    ):
        raise CustodyError("custody journal profile or role mismatch")
    operation, phase = obj["operation"], obj["phase"]
    if not isinstance(operation, str) or not isinstance(phase, str):
        raise CustodyError("invalid custody journal phase")
    if (operation, phase) not in {
        ("create", "intent"),
        ("create", "verified"),
        ("delete", "intent"),
        ("delete", "deleted"),
    }:
        raise CustodyError("invalid custody journal phase")
    record = _record(obj["record"], manifest, role, pending=True)
    if record.public_sha256 is None and (operation, phase) != ("create", "intent"):
        raise CustodyError("missing journal public fingerprint")
    _validate_pending_ownership(manifest, role, record, operation, phase)
    return Pending(
        manifest.profile_nonce,
        role,
        cast(Literal["create", "delete"], operation),
        cast(Literal["intent", "verified", "deleted"], phase),
        record,
    )


def _validate_pending_ownership(
    manifest: Manifest,
    role: Role,
    record: RoleRecord,
    operation: object,
    phase: object,
) -> None:
    state = manifest.role(role)
    records = state.retained + (() if state.current is None else (state.current,))
    matching = next((row for row in records if row.generation == record.generation), None)
    if any(
        row.generation == record.generation
        for other_role in ROLES
        if other_role != role
        for other in (manifest.role(other_role),)
        for row in other.retained + (() if other.current is None else (other.current,))
    ):
        raise CustodyError("journal generation belongs to another role")
    if operation == "delete":
        if record.epoch > manifest.epoch or (matching is not None and matching != record):
            raise CustodyError("deletion journal conflicts with ownership")
        if matching is None and (phase != "deleted" or (role == "memory" and state.current is not None)):
            raise CustodyError("deletion journal has no matching generation")
        return
    if record.epoch > manifest.epoch + 1:
        raise CustodyError("enrollment journal epoch is invalid")
    if matching is not None:
        if matching != state.current or matching != record or phase != "verified":
            raise CustodyError("enrollment journal conflicts with committed ownership")
    elif state.current is not None and (role == "memory" or record.epoch <= state.current.epoch):
        raise CustodyError("enrollment journal conflicts with current generation")
