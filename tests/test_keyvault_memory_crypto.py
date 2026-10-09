"""Unit tests for the frozen agent-memory wire format (:mod:`keyvault.memory_crypto`).

The format is what every sealed ``~/.hermes/memories/*.md`` on disk is encoded
with, so these tests pin the bytes (magic line, ASCII body, trailing newline) as
much as the crypto: a change that still round-trips in-process but shifts the
layout would orphan files already at rest.
"""

from __future__ import annotations

import base64

import pytest

from mordred_hermes.keyvault.memory_crypto import (
    MAGIC,
    MemoryCryptoError,
    MemoryKeyError,
    aad_for,
    decode_key,
    is_sealed,
    looks_like_magic_line,
    seal,
    unseal,
)

_KEY = bytes(range(32))
_OTHER_KEY = bytes(range(32, 64))
_PLAINTEXT = b"the cat is on the mat\n\xc2\xa7\nsecond entry"


def test_round_trip() -> None:
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    assert unseal(blob, key=_KEY, name="MEMORY.md") == _PLAINTEXT


def test_round_trip_empty_plaintext() -> None:
    # An emptied store still writes a sealed file, never a bare empty one.
    blob = seal(b"", key=_KEY, name="MEMORY.md")
    assert is_sealed(blob)
    assert unseal(blob, key=_KEY, name="MEMORY.md") == b""


def test_wire_layout_is_ascii_and_newline_terminated() -> None:
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    assert blob.startswith(MAGIC + b"\n")
    assert blob.endswith(b"\n")
    blob.decode("ascii")  # must survive the upstream utf-8 reader unchanged
    assert _PLAINTEXT not in blob


def test_two_seals_of_the_same_plaintext_differ() -> None:
    first = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    second = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    assert first != second  # fresh nonce per seal


def test_wrong_key_fails() -> None:
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    with pytest.raises(MemoryCryptoError):
        unseal(blob, key=_OTHER_KEY, name="MEMORY.md")


def test_wrong_name_fails() -> None:
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    with pytest.raises(MemoryCryptoError):
        unseal(blob, key=_KEY, name="USER.md")


def test_flipped_byte_fails() -> None:
    blob = bytearray(seal(_PLAINTEXT, key=_KEY, name="MEMORY.md"))
    body_start = len(MAGIC) + 1
    blob[body_start] = ord("A") if blob[body_start] != ord("A") else ord("B")
    with pytest.raises(MemoryCryptoError):
        unseal(bytes(blob), key=_KEY, name="MEMORY.md")


def test_missing_magic_fails() -> None:
    with pytest.raises(MemoryCryptoError):
        unseal(b"just some plaintext memory\n", key=_KEY, name="MEMORY.md")


def test_malformed_base64_fails() -> None:
    with pytest.raises(MemoryCryptoError):
        unseal(MAGIC + b"\n!!!!not base64!!!!\n", key=_KEY, name="MEMORY.md")


def test_body_shorter_than_nonce_and_tag_fails() -> None:
    short = base64.urlsafe_b64encode(b"x" * 27)  # < 12 nonce + 16 tag
    with pytest.raises(MemoryCryptoError):
        unseal(MAGIC + b"\n" + short + b"\n", key=_KEY, name="MEMORY.md")


def test_unseal_tolerates_bom_whitespace_and_stripping() -> None:
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    assert unseal(b"\xef\xbb\xbf" + blob, key=_KEY, name="MEMORY.md") == _PLAINTEXT
    assert unseal(b"\n  " + blob + b"\n\n", key=_KEY, name="MEMORY.md") == _PLAINTEXT
    # The upstream reader hands entries back stripped.
    assert unseal(blob.strip(), key=_KEY, name="MEMORY.md") == _PLAINTEXT


def test_non_32_byte_key_rejected_by_seal_and_unseal() -> None:
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    with pytest.raises(MemoryKeyError):
        seal(_PLAINTEXT, key=_KEY[:31], name="MEMORY.md")
    with pytest.raises(MemoryKeyError):
        unseal(blob, key=_KEY[:31], name="MEMORY.md")


def test_aad_for_binds_the_basename() -> None:
    assert aad_for("MEMORY.md") == b"hermes-memory-v1:MEMORY.md"
    assert aad_for("MEMORY.md.bak.1699999999") == b"hermes-memory-v1:MEMORY.md.bak.1699999999"


def test_is_sealed_classification() -> None:
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    assert is_sealed(blob)
    assert is_sealed(blob.decode("ascii"))
    assert is_sealed(b"\xef\xbb\xbf" + blob)  # BOM-prefixed
    assert is_sealed(blob + b"\n")  # trailing newline
    assert is_sealed(blob.strip())  # stripped by the upstream entry parser
    assert not is_sealed(b"the cat is on the mat")
    assert not is_sealed(b"")
    assert not is_sealed(b"HERMES-MEMORY-ENC-v2\nxxxx\n")
    assert not is_sealed(b"HERMES-MEMORY-ENC-v1 trailing\nxxxx\n")


@pytest.mark.parametrize(
    "value",
    [
        base64.urlsafe_b64encode(_KEY).decode("ascii"),
        "base64:" + base64.urlsafe_b64encode(_KEY).decode("ascii"),
        "hex:" + _KEY.hex(),
        '"' + base64.urlsafe_b64encode(_KEY).decode("ascii") + '"',
        "'base64:" + base64.urlsafe_b64encode(_KEY).decode("ascii") + "'",
        "  " + base64.urlsafe_b64encode(_KEY).decode("ascii") + "  ",
        base64.urlsafe_b64encode(_KEY).decode("ascii").rstrip("="),  # unpadded
    ],
)
def test_decode_key_accepts(value: str) -> None:
    assert decode_key(value) == _KEY


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        base64.urlsafe_b64encode(bytes(31)).decode("ascii"),
        base64.urlsafe_b64encode(bytes(33)).decode("ascii"),
        "hex:" + bytes(31).hex(),
        "hex:not-hex-at-all",
        "not-a-key",
    ],
)
def test_decode_key_rejects(value: str) -> None:
    with pytest.raises(MemoryKeyError):
        decode_key(value)


def test_decode_key_error_is_a_memory_crypto_error() -> None:
    assert issubclass(MemoryKeyError, MemoryCryptoError)


def test_is_sealed_requires_the_whole_structure() -> None:
    """A memory entry that merely *starts* with the magic is not a seal.

    An operator (or the model) can write that text into MEMORY.md; classifying it
    as sealed would make the file unreadable and hand the write path a "sealed"
    file it cannot open.
    """
    body = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")[len(MAGIC) + 1 :]
    assert not is_sealed(MAGIC)  # magic with nothing after it
    assert not is_sealed(MAGIC + b" \n" + body)  # no newline directly after the magic
    assert not is_sealed(MAGIC + b"\nnot base64 at all!")  # body outside the alphabet
    assert not is_sealed(MAGIC + b"\n" + body[:8])  # too short to hold a nonce and a tag
    assert not is_sealed(MAGIC + b"\n" + body[:20] + b"\n" + body[20:])  # split body
    assert is_sealed(MAGIC + b"\n" + body)


def test_crlf_converted_seal_is_still_a_seal() -> None:
    """A seal that has been through a Windows editor, ``git core.autocrlf``, or an
    ``rsync --crlf`` comes back with ``\\r\\n``. Every text reader in the chain
    decodes that in universal-newline mode and still sees a seal, so a byte-level
    classifier that disagreed produced two views of one file — and the write side
    published plaintext over the sealed bytes.
    """
    blob = seal(_PLAINTEXT, key=_KEY, name="MEMORY.md")
    crlf = blob.replace(b"\n", b"\r\n")
    assert crlf != blob

    assert is_sealed(crlf)
    assert is_sealed(b"\xef\xbb\xbf" + crlf)
    assert looks_like_magic_line(crlf.decode("ascii"))
    assert unseal(crlf, key=_KEY, name="MEMORY.md") == _PLAINTEXT


def test_looks_like_magic_line_is_prefix_only() -> None:
    assert looks_like_magic_line(MAGIC.decode())
    assert looks_like_magic_line("\ufeff" + MAGIC.decode() + "\nanything at all")
    assert looks_like_magic_line("  " + MAGIC.decode())
    assert not looks_like_magic_line("HERMES-MEMORY-ENC-v0")
    assert not looks_like_magic_line("a note about " + MAGIC.decode())
    assert not looks_like_magic_line("")
