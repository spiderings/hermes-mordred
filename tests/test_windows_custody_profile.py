"""Physical-profile schema refuses aliases forged from paths or permissive JSON."""

import json

import pytest

from mordred_hermes._private_fs import FileIdentity


def module():
    from mordred_hermes.keyvault import _windows_profile

    return _windows_profile


IDENTITY = FileIdentity(17, bytes.fromhex("0123456789abcdef0123456789abcdef"))
SID = bytes.fromhex("010200000000000515000000e8030000")


def test_same_physical_profile_derives_stable_separate_role_selectors():
    p = module()
    profile = p.new_manifest(IDENTITY, SID, nonce=bytes(32))
    a = p.new_record(profile, "memory", generation=bytes([1]) * 32)
    b = p.new_record(profile, "audit", generation=bytes([1]) * 32)
    assert a.native_key_id != b.native_key_id
    assert len(a.native_key_id.rsplit(".", 1)[1]) == 64
    assert p.parse_manifest(p.encode_manifest(profile), IDENTITY, SID) == profile
    assert p.new_record(profile, "memory", generation=bytes([1]) * 32) == a


@pytest.mark.parametrize("change", ["home", "sid"])
def test_copy_to_another_physical_home_or_token_refuses(change):
    p = module()
    blob = p.encode_manifest(p.new_manifest(IDENTITY, SID))
    identity = FileIdentity(18, IDENTITY.file_id) if change == "home" else IDENTITY
    sid = bytes.fromhex("010200000000000515000000e9030000") if change == "sid" else SID
    with pytest.raises(p.CustodyError):
        p.parse_manifest(blob, identity, sid)


@pytest.mark.parametrize("change", ["duplicate", "extra", "bool_epoch", "sid", "identity", "nonce", "role", "oversize"])
def test_corrupt_manifest_never_becomes_fresh(change):
    p = module()
    blob = p.encode_manifest(p.new_manifest(IDENTITY, SID))
    obj = json.loads(blob)
    if change == "duplicate":
        blob = blob.replace(b'"version":1', b'"version":1,"version":1')
    elif change == "oversize":
        blob += b" " * 65536
    else:
        if change == "extra":
            obj["unknown"] = 1
        if change == "bool_epoch":
            obj["epoch"] = True
        if change == "sid":
            obj["sid"] = "01"
        if change == "identity":
            obj["home"]["file_id"] = "00"
        if change == "nonce":
            obj["profile_nonce"] = "AA" * 32
        if change == "role":
            obj["roles"]["wallet"] = obj["roles"]["memory"]
        blob = json.dumps(obj).encode()
    with pytest.raises(p.CustodyError):
        p.parse_manifest(blob, IDENTITY, SID)


def test_record_selector_fingerprint_and_journal_are_bound():
    from dataclasses import replace

    p = module()
    manifest = p.new_manifest(IDENTITY, SID)
    record = p.new_record(manifest, "memory")
    journal = p.Pending(manifest.profile_nonce, "memory", "create", "intent", record)
    assert p.parse_pending(p.encode_pending(journal), manifest, "memory") == journal
    forged = replace(record, native_key_id="mordred-hermes.windows.v1." + "0" * 64)
    with pytest.raises(p.CustodyError):
        p.parse_pending(p.encode_pending(replace(journal, record=forged)), manifest, "memory")
    with pytest.raises(p.CustodyError):
        p.parse_pending(p.encode_pending(replace(journal, phase="verified")), manifest, "memory")


@pytest.mark.parametrize(
    "field,value",
    [
        ("epoch", True),
        ("epoch", 9007199254740992),
        ("public_sha256", "aa"),
        ("key_id", "wallet"),
        ("generation", "ab" * 31),
    ],
)
def test_invalid_committed_role_record_refuses(field, value):
    from dataclasses import replace

    p = module()
    manifest = p.new_manifest(IDENTITY, SID)
    record = replace(p.new_record(manifest, "audit"), public_sha256="ab" * 32)
    manifest = manifest.with_role("audit", p.RoleState(record), epoch=1)
    obj = json.loads(p.encode_manifest(manifest))
    obj["roles"]["audit"]["current"][field] = value
    with pytest.raises(p.CustodyError):
        p.parse_manifest(json.dumps(obj).encode(), IDENTITY, SID)


def test_delete_journal_cannot_remove_another_memory_generation():
    from dataclasses import replace

    p = module()
    manifest = p.new_manifest(IDENTITY, SID)
    current = replace(p.new_record(manifest, "memory"), public_sha256="ab" * 32)
    manifest = manifest.with_role("memory", p.RoleState(current), epoch=1)
    another = replace(p.new_record(manifest, "memory"), public_sha256="cd" * 32)
    pending = p.Pending(manifest.profile_nonce, "memory", "delete", "deleted", another)
    with pytest.raises(p.CustodyError):
        p.parse_pending(p.encode_pending(pending), manifest, "memory")


def test_retained_record_bound_and_duplicate_generation_refuse():
    from dataclasses import replace

    p = module()
    manifest = p.new_manifest(IDENTITY, SID)
    records = tuple(
        replace(p.new_record(manifest, "audit", generation=i.to_bytes(32, "big")), public_sha256="ab" * 32)
        for i in range(65)
    )
    allowed = manifest.with_role("audit", p.RoleState(None, records[:64]), epoch=1)
    assert p.parse_manifest(p.encode_manifest(allowed), IDENTITY, SID) == allowed
    overflow = manifest.with_role("audit", p.RoleState(None, records), epoch=1)
    with pytest.raises(p.CustodyError):
        p.parse_manifest(p.encode_manifest(overflow), IDENTITY, SID)
    duplicate = manifest.with_role("audit", p.RoleState(records[0], records[:1]), epoch=1)
    with pytest.raises(p.CustodyError):
        p.parse_manifest(p.encode_manifest(duplicate), IDENTITY, SID)


@pytest.mark.parametrize("field", ["operation", "phase"])
@pytest.mark.parametrize("value", [[], {}])
def test_unhashable_journal_fields_use_custody_failure_contract(field, value):
    p = module()
    manifest = p.new_manifest(IDENTITY, SID)
    pending = p.Pending(manifest.profile_nonce, "memory", "create", "intent", p.new_record(manifest, "memory"))
    obj = json.loads(p.encode_pending(pending))
    obj[field] = value
    with pytest.raises(p.CustodyError):
        p.parse_pending(json.dumps(obj).encode(), manifest, "memory")
