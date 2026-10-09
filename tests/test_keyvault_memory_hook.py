"""Unit tests for the agent-memory encryption hook (:mod:`keyvault._memory_hook`).

Upstream ``tools/memory_tool.py`` exposes three different seam shapes across the
Hermes releases we support, and wrapping the *wrong* one silently destroys memory
(a sealed file read as "empty" is overwritten by the next write). So the fakes
below re-implement each shape's ``_read_file`` / ``_read_raw_checked`` /
``_write_file`` / ``_detect_external_drift`` with the upstream bodies:

* **A** — hermes-agent main / 0.20+ (checked raw read, drift takes ``raw``)
* **B** — 0.16-0.19 (``_read_file`` reads raw itself, drift re-reads the file)
* **C** — 0.13-0.15 (no drift detection at all)

Each fake is a fresh subclass per test, so a wrapper installed on one test's
class cannot leak into another. The shape-A / shape-B readers route through
``cls.`` rather than a hard-bound class name for the same reason upstream routes
through ``MemoryStore.``: the wrapper must be picked up at call time.
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import os
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mordred_hermes.keyvault import _memory_hook
from mordred_hermes.keyvault._memory_hook import (
    MemoryEncryptionUnavailable,
    classify_seam,
    install_journey_guard,
    install_memory_hook,
    install_memory_import_hook,
    memory_hook_installed,
    memory_marker_path,
    memory_optout_marker_path,
    memory_seam_shape,
    seam_check,
    warn_when_memory_is_locked,
)
from mordred_hermes.keyvault.memory_crypto import MAGIC, is_sealed, seal, unseal

ENTRY_DELIMITER = "\n§\n"
KEY = bytes(range(32))
KEY_ENV = base64.urlsafe_b64encode(KEY).decode("ascii")
OTHER_KEY_ENV = base64.urlsafe_b64encode(bytes(range(32, 64))).decode("ascii")

SHAPES = ["A", "B", "C"]


# --------------------------------------------------------------------------
# Fake upstream modules
# --------------------------------------------------------------------------


class _FakeStoreCommon:
    """State + the two seams every shape shares."""

    mem_dir: Path  # set on the per-test subclass

    def __init__(self, memory_char_limit: int = 2200, user_char_limit: int = 1375) -> None:
        self.memory_entries: list[str] = []
        self.user_entries: list[str] = []
        self.memory_char_limit = memory_char_limit
        self.user_char_limit = user_char_limit

    @classmethod
    def _path_for(cls, target: str) -> Path:
        return cls.mem_dir / ("USER.md" if target == "user" else "MEMORY.md")

    def _char_limit(self, target: str) -> int:
        return self.user_char_limit if target == "user" else self.memory_char_limit

    def _entries_for(self, target: str) -> list[str]:
        return self.user_entries if target == "user" else self.memory_entries

    def _set_entries(self, target: str, entries: list[str]) -> None:
        if target == "user":
            self.user_entries = entries
        else:
            self.memory_entries = entries

    def save_to_disk(self, target: str) -> None:
        self._write_file(self._path_for(target), self._entries_for(target))

    @staticmethod
    def _write_file(path: Path, entries: list[str]) -> None:
        content = ENTRY_DELIMITER.join(entries) if entries else ""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(content, encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            raise RuntimeError(f"Failed to write memory file {path}: {exc}") from exc


class _FakeStoreC(_FakeStoreCommon):
    """Shape C (0.13-0.15): ``_read_file`` reads raw itself; no drift detection."""

    @classmethod
    def _read_file(cls, path: Path) -> list[str]:
        if not path.exists():
            return []
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return []
        if not raw.strip():
            return []
        entries = [e.strip() for e in raw.split(ENTRY_DELIMITER)]
        return [e for e in entries if e]

    def _reload_target(self, target: str) -> None:
        fresh = list(dict.fromkeys(self._read_file(self._path_for(target))))
        self._set_entries(target, fresh)


class _FakeStoreB(_FakeStoreC):
    """Shape B (0.16-0.19): C plus a drift check that re-reads the file itself."""

    def _detect_external_drift(self, target: str) -> str | None:
        path = self._path_for(target)
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        if not raw.strip():
            return None
        parsed = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
        roundtrip = ENTRY_DELIMITER.join(parsed)
        max_entry_len = max((len(e) for e in parsed), default=0)
        if raw.strip() == roundtrip and max_entry_len <= self._char_limit(target):
            return None
        bak_path = path.with_suffix(path.suffix + f".bak.{int(time.time())}")
        try:
            bak_path.write_text(raw, encoding="utf-8")
        except OSError:
            return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
        return str(bak_path)

    def _reload_target(self, target: str, *, skip_drift: bool = False) -> str | None:  # type: ignore[override]
        bak = None if skip_drift else self._detect_external_drift(target)
        fresh = list(dict.fromkeys(self._read_file(self._path_for(target))))
        self._set_entries(target, fresh)
        return bak


class _FakeStoreA(_FakeStoreCommon):
    """Shape A (main / 0.20+): checked raw read; drift operates on that snapshot."""

    @staticmethod
    def _read_raw_checked(path: Path) -> tuple[str, bool]:
        if not path.exists():
            return "", True
        try:
            return path.read_text(encoding="utf-8-sig"), True
        except (OSError, UnicodeDecodeError):
            return "", False

    @staticmethod
    def _parse_entries(raw: str) -> list[str]:
        if not raw.strip():
            return []
        return [e for e in (part.strip() for part in raw.split(ENTRY_DELIMITER)) if e]

    @classmethod
    def _read_entries_checked(cls, path: Path) -> tuple[list[str], bool]:
        raw, read_ok = cls._read_raw_checked(path)
        if not read_ok:
            return [], False
        return cls._parse_entries(raw), True

    @classmethod
    def _read_file(cls, path: Path) -> list[str]:
        return cls._read_entries_checked(path)[0]

    def _detect_external_drift(self, target: str, raw: str) -> str | None:
        path = self._path_for(target)
        if not raw.strip():
            return None
        parsed = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
        roundtrip = ENTRY_DELIMITER.join(parsed)
        max_entry_len = max((len(e) for e in parsed), default=0)
        if raw.strip() == roundtrip and max_entry_len <= self._char_limit(target):
            return None
        bak_path = path.with_suffix(path.suffix + f".bak.{int(time.time())}")
        try:
            bak_path.write_text(raw, encoding="utf-8")
        except OSError:
            return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
        return str(bak_path)

    def _reload_target(self, target: str, *, skip_drift: bool = False) -> str | None:
        path = self._path_for(target)
        raw, read_ok = self._read_raw_checked(path)
        if not read_ok:
            return "READ FAILED"
        bak = None if skip_drift else self._detect_external_drift(target, raw)
        self._set_entries(target, list(dict.fromkeys(self._parse_entries(raw))))
        return bak


_BASES: dict[str, type[_FakeStoreCommon]] = {"A": _FakeStoreA, "B": _FakeStoreB, "C": _FakeStoreC}


def _fake_module(shape: str, mem_dir: Path) -> ModuleType:
    """A fresh fake ``tools.memory_tool`` of ``shape`` writing under ``mem_dir``."""
    module = ModuleType(f"fake_memory_tool_{shape.lower()}")
    module.ENTRY_DELIMITER = ENTRY_DELIMITER  # type: ignore[attr-defined]
    module.MemoryStore = type("MemoryStore", (_BASES[shape],), {"mem_dir": mem_dir})  # type: ignore[attr-defined]
    return module


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_plaintext_notes() -> Iterator[None]:
    """The plaintext-seen set is module-global (one warning per path per process)."""
    _memory_hook._PLAINTEXT_SEEN.clear()
    yield
    _memory_hook._PLAINTEXT_SEEN.clear()


@pytest.fixture
def mem_dir(tmp_path: Path) -> Path:
    path = tmp_path / "memories"
    path.mkdir()
    return path


@pytest.fixture(params=SHAPES)
def shape(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def _arm(home: Path) -> None:
    marker = memory_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("", encoding="utf-8")


def _install(
    module: ModuleType,
    home: Path,
    *,
    key: str | None = KEY_ENV,
    armed: bool = True,
    environ: dict[str, str] | None = None,
) -> tuple[bool, dict[str, str]]:
    if armed:
        _arm(home)
    env = {} if environ is None else environ
    if key is not None:
        env["HERMES_MEMORY_KEY"] = key
    ok = install_memory_hook(home=home, memory_tool_module=module, environ=env)
    return ok, env


def _memory_path(module: ModuleType) -> Path:
    return Path(module.MemoryStore._path_for("memory"))


# --------------------------------------------------------------------------
# Seam classification
# --------------------------------------------------------------------------


def test_classify_seam_recognises_each_shape(shape: str, mem_dir: Path) -> None:
    assert classify_seam(_fake_module(shape, mem_dir)) == (shape, "")


def test_classify_seam_rejects_missing_write_file(mem_dir: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.MemoryStore._write_file = None  # present but not callable
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "_write_file" in reason


def test_classify_seam_rejects_wrong_parameter_names(mem_dir: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.MemoryStore._write_file = staticmethod(lambda p, lines: None)
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "_write_file" in reason


def test_classify_seam_rejects_non_str_delimiter(mem_dir: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = b"\n\xc2\xa7\n"
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "ENTRY_DELIMITER" in reason


def test_classify_seam_rejects_mixed_shape(mem_dir: Path) -> None:
    # `_read_raw_checked` says shape A, but the drift signature is shape B's.
    module = _fake_module("B", mem_dir)
    module.MemoryStore._read_raw_checked = staticmethod(lambda path: ("", True))
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "_detect_external_drift" in reason


def test_classify_seam_rejects_missing_memory_store() -> None:
    module = ModuleType("fake_memory_tool_empty")
    shape, reason = classify_seam(module)
    assert shape == ""
    assert "MemoryStore" in reason


def test_memory_seam_shape_reports_the_shape(shape: str, mem_dir: Path) -> None:
    assert memory_seam_shape(_fake_module(shape, mem_dir)) == shape


@pytest.mark.parametrize("drift_shape", ["A", "B"])
@pytest.mark.parametrize("missing", ["_path_for", "_char_limit"])
def test_classify_seam_pins_the_drift_wrappers_dependencies(mem_dir: Path, drift_shape: str, missing: str) -> None:
    """The A/B drift wrappers replicate upstream's logic and call these two
    themselves. Unchecked, a variant that renamed one classified fine and then
    raised ``AttributeError`` from inside a ``replace`` — after installation had
    already promised the seam was understood."""
    module = _fake_module(drift_shape, mem_dir)
    setattr(module.MemoryStore, missing, None)

    seam, reason = classify_seam(module)

    assert seam == ""
    assert missing in reason


@pytest.mark.parametrize("drift_shape", ["A", "B"])
def test_classify_seam_rejects_a_renamed_drift_dependency(mem_dir: Path, drift_shape: str) -> None:
    module = _fake_module(drift_shape, mem_dir)
    module.MemoryStore._char_limit = lambda self, which: 2200

    seam, reason = classify_seam(module)

    assert seam == ""
    assert "_char_limit takes ('self', 'which')" in reason


def test_shape_c_classifies_without_the_drift_dependencies(mem_dir: Path) -> None:
    """Shape C has no drift wrapper, so it must not be held to the drift helpers."""
    module = _fake_module("C", mem_dir)
    module.MemoryStore._path_for = None
    module.MemoryStore._char_limit = None

    assert classify_seam(module) == ("C", "")


# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------


def test_install_is_idempotent(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    assert _install(module, tmp_path)[0] is True
    first_write = module.MemoryStore._write_file
    assert install_memory_hook(home=tmp_path, memory_tool_module=module, environ={}) is True
    assert module.MemoryStore._write_file is first_write
    assert memory_hook_installed(module) is True


def test_install_stamps_static_seams_as_staticmethods(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    # Reassigned as a plain function, `self._write_file(path, entries)` would bind
    # `self` to `path` — the whole seam would silently take the wrong arguments.
    assert isinstance(module.MemoryStore.__dict__["_write_file"], staticmethod)


def test_install_fails_open_on_unsupported_seam_when_not_armed(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = None
    assert install_memory_hook(home=tmp_path, memory_tool_module=module, environ={}) is False
    assert memory_hook_installed(module) is False


def test_install_refuses_to_start_on_unsupported_seam_when_armed(
    mem_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = None
    _arm(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        install_memory_hook(home=tmp_path, memory_tool_module=module, environ={"HERMES_MEMORY_KEY": KEY_ENV})
    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert "refusing to start" in stderr
    assert "HERMES_SAFE_MODE" in stderr


def test_optout_marker_disarms_the_hook(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    optout = memory_optout_marker_path(tmp_path)
    optout.parent.mkdir(parents=True, exist_ok=True)
    optout.write_text("", encoding="utf-8")

    path = _memory_path(module)
    module.MemoryStore._write_file(path, ["plain entry"])
    assert path.read_text(encoding="utf-8") == "plain entry"


# --------------------------------------------------------------------------
# Write seam
# --------------------------------------------------------------------------


def test_not_armed_write_and_read_are_byte_identical(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    wrapped = _fake_module(shape, mem_dir)
    control = _fake_module(shape, mem_dir / "control")
    _install(wrapped, tmp_path, armed=False)

    entries = ["first entry", "second entry"]
    wrapped_path = _memory_path(wrapped)
    control_path = _memory_path(control)
    wrapped.MemoryStore._write_file(wrapped_path, entries)
    control.MemoryStore._write_file(control_path, entries)

    assert wrapped_path.read_bytes() == control_path.read_bytes()
    assert wrapped.MemoryStore._read_file(wrapped_path) == control.MemoryStore._read_file(control_path) == entries


def test_armed_write_seals_the_file(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)

    module.MemoryStore._write_file(path, ["the cat is on the mat", "second entry"])

    data = path.read_bytes()
    assert data.startswith(MAGIC + b"\n")
    assert b"cat is on the mat" not in data
    assert unseal(data, key=KEY, name="MEMORY.md").decode("utf-8") == "the cat is on the mat\n§\nsecond entry"


def test_sealed_blob_survives_the_single_entry_join(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    # The wrapper hands the sealed text back to upstream as a ONE-entry list, so
    # upstream's `delimiter.join(entries)` must be the identity for it.
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    module.MemoryStore._write_file(path, ["only entry"])
    sealed = path.read_text(encoding="utf-8")
    assert ENTRY_DELIMITER.join([sealed]) == sealed
    assert ENTRY_DELIMITER not in sealed


def test_armed_write_without_a_key_raises_and_leaves_the_file(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=None)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    before = path.read_bytes()

    with pytest.raises(MemoryEncryptionUnavailable):
        module.MemoryStore._write_file(path, ["new entry"])

    assert path.read_bytes() == before


def test_armed_write_with_an_unusable_key_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    # A malformed key is "no key" — never a silent plaintext write.
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key="base64:not-a-32-byte-key")
    with pytest.raises(MemoryEncryptionUnavailable):
        module.MemoryStore._write_file(_memory_path(module), ["new entry"])


def test_memory_encryption_unavailable_is_a_runtime_error() -> None:
    # Upstream catches RuntimeError around memory writes, so the refusal is
    # reported to the model instead of crashing the process.
    assert issubclass(MemoryEncryptionUnavailable, RuntimeError)


# --------------------------------------------------------------------------
# Read seam
# --------------------------------------------------------------------------


def test_armed_read_returns_the_plaintext_entries(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    path.write_bytes(seal("first entry\n§\nsecond entry".encode(), key=KEY, name="MEMORY.md"))

    assert module.MemoryStore._read_file(path) == ["first entry", "second entry"]


def test_armed_read_of_a_plaintext_file_passes_through_and_is_noted(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    path.write_text("legacy entry", encoding="utf-8")

    assert module.MemoryStore._read_file(path) == ["legacy entry"]
    assert str(path) in _memory_hook._PLAINTEXT_SEEN


def test_read_of_an_absent_file_is_unchanged(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    assert module.MemoryStore._read_file(mem_dir / "MEMORY.md") == []
    assert not _memory_hook._PLAINTEXT_SEEN


def test_read_of_a_sealed_file_without_a_key_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=None)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))

    with pytest.raises(MemoryEncryptionUnavailable, match="HERMES_MEMORY_KEY"):
        module.MemoryStore._read_file(path)


def test_read_of_a_plaintext_file_without_a_key_still_works(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=None)
    path = _memory_path(module)
    path.write_text("legacy entry", encoding="utf-8")
    assert module.MemoryStore._read_file(path) == ["legacy entry"]


def test_read_of_a_wrong_key_file_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=OTHER_KEY_ENV)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))

    with pytest.raises(MemoryEncryptionUnavailable, match="authenticate"):
        module.MemoryStore._read_file(path)


def test_read_of_a_tampered_file_raises(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    sealed = bytearray(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    sealed[-4] = ord("A") if sealed[-4] != ord("A") else ord("B")
    path.write_bytes(bytes(sealed))

    with pytest.raises(MemoryEncryptionUnavailable):
        module.MemoryStore._read_file(path)


def test_read_of_a_sealed_file_while_disarmed_still_decrypts(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    # Turning the marker off must not make already-sealed memories unreadable.
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    assert module.MemoryStore._read_file(path) == ["prior entry"]


def test_shape_a_read_preserves_the_read_ok_contract(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)

    assert module.MemoryStore._read_raw_checked(path) == ("", True)  # absent → clean empty

    path.write_bytes(b"\xff\xfe not utf-8")
    assert module.MemoryStore._read_raw_checked(path) == ("", False)  # unreadable → abort

    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    assert module.MemoryStore._read_raw_checked(path) == ("prior entry", True)


# --------------------------------------------------------------------------
# Three-state read: sealed / plaintext / broken seal
# --------------------------------------------------------------------------


def _broken_seal(flavour: str, text: str = "prior entry") -> bytes:
    """A seal a shell append, a truncation, or a re-wrap has damaged.

    All three still *start* with the magic line, and all three used to classify as
    plaintext — handing upstream the ciphertext as one entry, with AEAD's whole
    point (tamper evidence) silently skipped.
    """
    blob = seal(text.encode("utf-8"), key=KEY, name="MEMORY.md")
    body = blob[len(MAGIC) + 1 :].strip()
    return {
        "appended": blob + b"a note appended by a shell redirect\n",
        # -3 leaves a base64 length of 1 (mod 4): no padding makes it decodable.
        "truncated": blob.strip()[:-3],
        "rewrapped": MAGIC + b"\n" + body[:20] + b"\n" + body[20:] + b"\n",
    }[flavour]


@pytest.mark.parametrize("flavour", ["appended", "truncated", "rewrapped"])
def test_read_of_a_structurally_broken_seal_refuses(shape: str, mem_dir: Path, tmp_path: Path, flavour: str) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    data = _broken_seal(flavour)
    assert not is_sealed(data)  # what used to make this read as one plaintext entry
    path.write_bytes(data)

    with pytest.raises(MemoryEncryptionUnavailable, match="structure is broken"):
        module.MemoryStore._read_file(path)


def test_read_of_a_broken_seal_refuses_while_disarmed_and_keyless(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    """The process that would do the damage is exactly the one with no key: it
    reads the ciphertext as an entry and writes it back mangled."""
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False, key=None)
    path = _memory_path(module)
    path.write_bytes(_broken_seal("appended"))

    with pytest.raises(MemoryEncryptionUnavailable, match="structure is broken"):
        module.MemoryStore._read_file(path)


def test_shape_a_read_raw_checked_refuses_a_broken_seal(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    path.write_bytes(_broken_seal("truncated"))

    with pytest.raises(MemoryEncryptionUnavailable, match="structure is broken"):
        module.MemoryStore._read_raw_checked(path)


def test_an_impersonating_entry_below_the_first_stays_readable(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    """Only the file's *first* bytes are classified, so an entry carrying the magic
    anywhere else is ordinary plaintext and must still be readable."""
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    entries = ["an ordinary entry", f"{MAGIC.decode()}\nnot base64 at all"]
    path.write_text(ENTRY_DELIMITER.join(entries), encoding="utf-8")

    assert module.MemoryStore._read_file(path) == entries


def test_broken_seal_fires_the_locked_memory_warning(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The M4 diagnosis has to cover this state too: upstream swallows the failed
    load either way, so a broken seal is as silent as a missing key."""
    home = _memories_home(tmp_path)
    (home / "memories" / "MEMORY.md").write_bytes(_broken_seal("appended"))

    assert warn_when_memory_is_locked(home=home, environ={"HERMES_MEMORY_KEY": KEY_ENV}) is True

    err = capsys.readouterr().err
    assert "structure is broken" in err
    assert "MEMORY.md" in err


# --------------------------------------------------------------------------
# Drift detection
# --------------------------------------------------------------------------


def test_shape_a_drift_seals_the_plaintext_backup(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore()
    path = _memory_path(module)
    raw = "x" * (store.memory_char_limit + 10)  # oversize entry = drift
    path.write_text(raw, encoding="utf-8")

    result = store._detect_external_drift("memory", raw)

    bak = Path(str(result))
    assert bak.is_file()
    assert is_sealed(bak.read_bytes())
    assert unseal(bak.read_bytes(), key=KEY, name=bak.name).decode("utf-8") == raw


def test_shape_a_drift_passes_a_clean_result_through(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore()

    assert store._detect_external_drift("memory", "clean entry") is None
    assert list(mem_dir.glob("*.bak.*")) == []


def test_shape_a_drift_reports_a_failed_backup(mem_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore()

    def _boom(path: Path, data: bytes) -> None:
        raise OSError("no space left on device")

    monkeypatch.setattr(_memory_hook, "_write_private", _boom)

    result = store._detect_external_drift("memory", "x" * 9000)

    assert str(result).endswith("(BACKUP FAILED — file unchanged on disk)")
    assert list(mem_dir.glob("*.bak.*")) == []


def test_shape_a_drift_never_writes_a_plaintext_backup(
    mem_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The H3 regression: upstream's own drift path writes the ``.bak`` with a bare
    ``Path.write_text`` of the *decrypted* snapshot. Watch the writes as they
    happen — a final-state check cannot see a plaintext file that is later sealed."""
    module = _fake_module("A", mem_dir)
    _install(module, tmp_path, armed=False)  # sealed on disk is enough; arming is not needed
    path = _memory_path(module)
    raw = "x" * 9000
    path.write_bytes(seal(raw.encode("utf-8"), key=KEY, name="MEMORY.md"))

    written: list[bytes] = []
    real_write_private = _memory_hook._write_private

    def _record(target: Path, data: bytes) -> None:
        written.append(data)
        real_write_private(target, data)

    def _forbidden(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("the drift backup must not be written in the clear")

    monkeypatch.setattr(_memory_hook, "_write_private", _record)
    monkeypatch.setattr(Path, "write_text", _forbidden)

    result = module.MemoryStore()._detect_external_drift("memory", raw)

    assert written and all(is_sealed(data) for data in written)
    bak = Path(str(result))
    assert unseal(bak.read_bytes(), key=KEY, name=bak.name).decode("utf-8") == raw


def test_shape_a_drift_delegates_for_a_plaintext_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("A", mem_dir)
    calls: list[str] = []
    original = module.MemoryStore._detect_external_drift

    def _spy(self: Any, target: str, raw: str) -> str | None:
        calls.append(target)
        return original(self, target, raw)

    module.MemoryStore._detect_external_drift = _spy
    _install(module, tmp_path, armed=False)
    path = _memory_path(module)
    raw = "x" * 9000
    path.write_text(raw, encoding="utf-8")

    result = module.MemoryStore()._detect_external_drift("memory", raw)

    assert calls == ["memory"]
    assert not is_sealed(Path(str(result)).read_bytes())


def test_shape_b_drift_does_not_false_positive_on_a_sealed_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore(memory_char_limit=80)
    path = _memory_path(module)
    plaintext = "first entry\n§\nsecond entry"
    path.write_bytes(seal(plaintext.encode(), key=KEY, name="MEMORY.md"))
    # The sealed text is far longer than the char limit; the check must run on
    # the plaintext or every replace/remove would be refused.
    assert len(path.read_text(encoding="utf-8")) > store.memory_char_limit

    assert store._detect_external_drift("memory") is None


def test_shape_b_drift_backs_up_a_sealed_file_with_an_oversize_entry(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore(memory_char_limit=40)
    path = _memory_path(module)
    plaintext = "x" * 100
    path.write_bytes(seal(plaintext.encode(), key=KEY, name="MEMORY.md"))

    result = store._detect_external_drift("memory")

    bak = Path(str(result))
    assert bak.is_file()
    assert bak.name.startswith("MEMORY.md.bak.")
    assert unseal(bak.read_bytes(), key=KEY, name=bak.name).decode("utf-8") == plaintext


def test_shape_b_drift_delegates_for_a_plaintext_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    calls: list[str] = []
    original = module.MemoryStore._detect_external_drift

    def _spy(self: Any, target: str) -> str | None:
        calls.append(target)
        return original(self, target)

    module.MemoryStore._detect_external_drift = _spy
    _install(module, tmp_path)
    store = module.MemoryStore(memory_char_limit=40)
    path = _memory_path(module)
    path.write_text("x" * 100, encoding="utf-8")

    result = store._detect_external_drift("memory")

    assert calls == ["memory"]
    assert Path(str(result)).is_file()
    assert not is_sealed(Path(str(result)).read_bytes())


def test_shape_b_drift_delegates_for_an_absent_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path)
    store = module.MemoryStore()
    assert store._detect_external_drift("memory") is None


def test_shape_b_drift_raises_for_an_undecryptable_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("B", mem_dir)
    _install(module, tmp_path, key=OTHER_KEY_ENV)
    path = _memory_path(module)
    path.write_bytes(seal(b"prior entry", key=KEY, name="MEMORY.md"))
    store = module.MemoryStore()

    with pytest.raises(MemoryEncryptionUnavailable):
        store._detect_external_drift("memory")


def test_shape_c_has_no_drift_wrapper(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module("C", mem_dir)
    _install(module, tmp_path)
    assert not hasattr(module.MemoryStore, "_detect_external_drift")


# --------------------------------------------------------------------------
# End-to-end mutate cycle (the data-loss regression)
# --------------------------------------------------------------------------


def test_mutate_cycle_keeps_prior_entries(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)

    first = module.MemoryStore()
    first._set_entries("memory", ["first entry"])
    first.save_to_disk("memory")

    second = module.MemoryStore()
    assert second._reload_target("memory") is None
    assert second._entries_for("memory") == ["first entry"]

    second._set_entries("memory", [*second._entries_for("memory"), "second entry"])
    second.save_to_disk("memory")

    third = module.MemoryStore()
    third._reload_target("memory")
    assert third._entries_for("memory") == ["first entry", "second entry"]
    assert is_sealed(path.read_bytes())


# --------------------------------------------------------------------------
# Sticky sealing: a sealed file is never overwritten with plaintext
# --------------------------------------------------------------------------


def _seed_sealed(module: ModuleType, text: str = "prior entry") -> Path:
    path = _memory_path(module)
    path.write_bytes(seal(text.encode("utf-8"), key=KEY, name=path.name))
    return path


def test_disarmed_write_over_a_sealed_file_stays_sealed(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False)
    path = _seed_sealed(module)

    module.MemoryStore._write_file(path, ["new entry"])

    assert is_sealed(path.read_bytes())
    assert unseal(path.read_bytes(), key=KEY, name="MEMORY.md") == b"new entry"


def test_disarmed_write_over_a_sealed_file_without_a_key_refuses(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False, key=None)
    path = _seed_sealed(module)
    before = path.read_bytes()

    with pytest.raises(MemoryEncryptionUnavailable, match="refusing to overwrite sealed"):
        module.MemoryStore._write_file(path, ["new entry"])

    assert path.read_bytes() == before


def test_safe_mode_write_over_a_sealed_file_stays_sealed(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, environ={"HERMES_SAFE_MODE": "1"})
    path = _seed_sealed(module)

    module.MemoryStore._write_file(path, ["new entry"])

    assert is_sealed(path.read_bytes())


def test_safe_mode_write_over_a_sealed_file_without_a_key_refuses(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, key=None, environ={"HERMES_SAFE_MODE": "1"})
    path = _seed_sealed(module)
    before = path.read_bytes()

    with pytest.raises(MemoryEncryptionUnavailable, match="refusing to overwrite sealed"):
        module.MemoryStore._write_file(path, ["new entry"])

    assert path.read_bytes() == before


def test_disarmed_write_over_a_plaintext_file_stays_plaintext(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False)
    path = _memory_path(module)
    path.write_text("legacy entry", encoding="utf-8")

    module.MemoryStore._write_file(path, ["new entry"])

    assert path.read_text(encoding="utf-8") == "new entry"


def test_safe_mode_still_wraps_a_supported_seam(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    # Safe mode means "no new sealing, no refusal to start" — not "no protection":
    # unwrapping would let upstream truncate an already-sealed file.
    module = _fake_module(shape, mem_dir)
    _arm(tmp_path)
    ok = install_memory_hook(
        home=tmp_path,
        memory_tool_module=module,
        environ={"HERMES_MEMORY_KEY": KEY_ENV, "HERMES_SAFE_MODE": "1"},
    )

    assert ok is True
    assert memory_hook_installed(module) is True
    path = _memory_path(module)
    module.MemoryStore._write_file(path, ["new entry"])
    assert path.read_text(encoding="utf-8") == "new entry"  # armed off: no NEW sealing


# --------------------------------------------------------------------------
# One on-disk view for every classifier (CRLF)
# --------------------------------------------------------------------------


def _seed_crlf_seal(module: ModuleType, text: str = "first entry\n§\nsecond entry") -> Path:
    """A seal that has been through a CRLF-converting round trip (editor, git, rsync)."""
    path = _memory_path(module)
    path.write_bytes(seal(text.encode("utf-8"), key=KEY, name=path.name).replace(b"\n", b"\r\n"))
    return path


def test_crlf_seal_is_read_as_a_seal(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _seed_crlf_seal(module)

    assert module.MemoryStore._read_file(path) == ["first entry", "second entry"]


def test_crlf_seal_is_classified_as_sealed_by_the_write_side(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    """The read seam decodes in universal-newline mode, so a byte-level classifier
    called the same file plaintext — and a disarmed write then published plaintext
    over sealed bytes."""
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _seed_crlf_seal(module)

    assert _memory_hook._sealed_on_disk(path) is True


def test_disarmed_write_over_a_crlf_seal_without_a_key_refuses(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False, key=None)
    path = _seed_crlf_seal(module)
    before = path.read_bytes()

    with pytest.raises(MemoryEncryptionUnavailable, match="refusing to overwrite sealed"):
        module.MemoryStore._write_file(path, ["the model's new entry"])

    assert path.read_bytes() == before


def test_disarmed_write_over_a_crlf_seal_reseals_it(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False)
    path = _seed_crlf_seal(module)

    module.MemoryStore._write_file(path, ["the model's new entry"])

    assert is_sealed(path.read_bytes())
    assert unseal(path.read_bytes(), key=KEY, name="MEMORY.md") == b"the model's new entry"


# --------------------------------------------------------------------------
# Magic-line impersonation
# --------------------------------------------------------------------------


def test_plaintext_write_refuses_a_first_entry_that_impersonates_the_header(
    shape: str, mem_dir: Path, tmp_path: Path
) -> None:
    """Only entry 0 can put the magic at the head of the file, and only a plaintext
    write puts an entry there verbatim — the file would then read as a seal."""
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False)
    path = _memory_path(module)

    with pytest.raises(MemoryEncryptionUnavailable, match="sealed-memory header") as excinfo:
        module.MemoryStore._write_file(path, [f"  {MAGIC.decode()}\nZm9v", "harmless"])

    assert str(path) in str(excinfo.value)
    assert "memory action=remove" in str(excinfo.value)
    assert not path.exists()


def test_plaintext_write_allows_an_impersonating_entry_that_is_not_first(
    shape: str, mem_dir: Path, tmp_path: Path
) -> None:
    """The refusal used to be unconditional, so one stored entry bricked every
    write. Anywhere but position 0 the magic cannot reach the file's head."""
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path, armed=False)
    path = _memory_path(module)

    module.MemoryStore._write_file(path, ["first", "second", f"{MAGIC.decode()}\nZm9v"])

    assert not _memory_hook._sealed_on_disk(path)
    assert not path.read_text(encoding="utf-8").startswith(MAGIC.decode())
    assert module.MemoryStore._read_file(path) == ["first", "second", f"{MAGIC.decode()}\nZm9v"]


def test_sealed_write_of_a_store_holding_an_impersonating_entry_succeeds(
    shape: str, mem_dir: Path, tmp_path: Path
) -> None:
    """Inside the ciphertext the blob is inert, so refusing here only bricked
    ``add`` on an encrypted store — and escaped the tool's error-dict contract."""
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    path = _memory_path(module)
    entries = [f"{MAGIC.decode()}\nnotes about the sealed memory format", "an ordinary entry"]

    module.MemoryStore._write_file(path, entries)

    assert is_sealed(path.read_bytes())
    assert module.MemoryStore._read_file(path) == entries


# --------------------------------------------------------------------------
# Import hook
# --------------------------------------------------------------------------


_FAKE_MEMORY_TOOL_SRC = '''\
"""A shape-B ``tools.memory_tool`` stand-in imported through the real machinery."""

from pathlib import Path

ENTRY_DELIMITER = "\\n\\u00a7\\n"


class MemoryStore:
    @staticmethod
    def _write_file(path, entries):
        content = ENTRY_DELIMITER.join(entries) if entries else ""
        Path(path).write_text(content, encoding="utf-8")

    @staticmethod
    def _read_file(path):
        target = Path(path)
        if not target.exists():
            return []
        raw = target.read_text(encoding="utf-8")
        return [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]

    def _detect_external_drift(self, target):
        return None

    @staticmethod
    def _path_for(target):
        return Path(__file__).with_name("USER.md" if target == "user" else "MEMORY.md")

    def _char_limit(self, target):
        return 2200
'''

_UNSUPPORTED_MEMORY_TOOL_SRC = '''\
"""A ``tools.memory_tool`` stand-in whose seam Mordred cannot classify."""

ENTRY_DELIMITER = None


class MemoryStore:
    @staticmethod
    def _write_file(path, entries):
        pass

    @staticmethod
    def _read_file(path):
        return []
'''

_FAKE_LEARNING_MUTATIONS_SRC = '''\
"""An ``agent.learning_mutations`` stand-in imported through the real machinery."""

_MEMORY_FILES = {"memory": "MEMORY.md", "profile": "USER.md"}


def parse_node_kind(node_id):
    return "memory" if node_id.startswith("memory:") else "skill"


def delete_node(node_id):
    return {"ok": True, "message": "deleted"}


def edit_node(node_id, content):
    return {"ok": True, "message": "updated"}
'''


@contextlib.contextmanager
def _fake_upstream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, memory_tool_src: str) -> Iterator[Path]:
    """A throwaway ``tools`` / ``agent`` package on ``sys.path`` with the finder installed.

    The real ``tools`` package is importable in this venv, so its modules are
    evicted for the duration and restored afterwards — otherwise the fakes below
    would never be reached (and the finder would wrap the live class).
    """
    site = tmp_path / "site"
    for package, module_name, source in (
        ("tools", "memory_tool", memory_tool_src),
        ("agent", "learning_mutations", _FAKE_LEARNING_MUTATIONS_SRC),
    ):
        (site / package).mkdir(parents=True)
        (site / package / "__init__.py").write_text("", encoding="utf-8")
        (site / package / f"{module_name}.py").write_text(source, encoding="utf-8")

    prefixes = ("tools", "agent")
    saved = {name: mod for name, mod in sys.modules.items() if name.split(".")[0] in prefixes}
    for name in saved:
        del sys.modules[name]
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    importlib.invalidate_caches()
    try:
        yield site
    finally:
        for name in [n for n in sys.modules if n.split(".")[0] in prefixes]:
            del sys.modules[name]
        sys.modules.update(saved)
        _uninstall_import_hook()


@pytest.fixture
def import_hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """The supported (shape-B) fake upstream."""
    with _fake_upstream(tmp_path, monkeypatch, _FAKE_MEMORY_TOOL_SRC) as site:
        yield site


@pytest.fixture
def unsupported_import_hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """The same machinery over a seam ``classify_seam`` refuses."""
    with _fake_upstream(tmp_path, monkeypatch, _UNSUPPORTED_MEMORY_TOOL_SRC) as site:
        yield site


def _uninstall_import_hook() -> None:
    sys.meta_path[:] = [f for f in sys.meta_path if not isinstance(f, _memory_hook._PostImportFinder)]
    _memory_hook._IMPORT_HOOK = None


def test_import_hook_wraps_the_seam_on_import(import_hook: Path) -> None:
    assert install_memory_import_hook() is True

    module = importlib.import_module("tools.memory_tool")

    assert memory_hook_installed(module) is True


def test_import_hook_wraps_an_already_imported_module(import_hook: Path) -> None:
    module = importlib.import_module("tools.memory_tool")
    assert memory_hook_installed(module) is False

    assert install_memory_import_hook() is True

    assert memory_hook_installed(module) is True


def test_import_hook_ignores_every_other_module(import_hook: Path) -> None:
    install_memory_import_hook()
    finder = sys.meta_path[0]
    assert isinstance(finder, _memory_hook._PostImportFinder)

    assert finder.find_spec("json", None, None) is None
    assert finder.find_spec("tools", None, None) is None
    # ...and an unrelated import still works through the untouched machinery.
    assert importlib.import_module("json") is sys.modules["json"]


def test_import_hook_is_idempotent(import_hook: Path) -> None:
    install_memory_import_hook()
    install_memory_import_hook()

    assert sum(isinstance(f, _memory_hook._PostImportFinder) for f in sys.meta_path) == 1


def test_import_hook_installs_the_journey_guard(import_hook: Path) -> None:
    install_memory_import_hook()

    module = importlib.import_module("agent.learning_mutations")

    assert getattr(module.delete_node, _memory_hook._WRAPPED_FLAG, False) is True
    assert getattr(module.edit_node, _memory_hook._WRAPPED_FLAG, False) is True


def test_import_hook_reinstalls_after_an_external_meta_path_reset(import_hook: Path) -> None:
    """A host (or a test harness) that snapshots and restores ``sys.meta_path``
    silently drops the finder; keying only off the module global made the
    re-install a no-op that reported success while the seam stayed unarmed."""
    install_memory_import_hook()
    sys.meta_path[:] = [f for f in sys.meta_path if not isinstance(f, _memory_hook._PostImportFinder)]

    assert install_memory_import_hook() is True
    assert sum(isinstance(f, _memory_hook._PostImportFinder) for f in sys.meta_path) == 1

    module = importlib.import_module("tools.memory_tool")
    assert memory_hook_installed(module) is True


def test_a_failing_post_import_action_does_not_break_the_import(
    import_hook: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A bug in our own action must not take an upstream module with it: raising out
    of ``exec_module`` leaves the module out of ``sys.modules`` entirely."""

    def _boom(_module: ModuleType) -> None:
        raise ValueError("hook bug")

    monkeypatch.setitem(_memory_hook._POST_IMPORT_ACTIONS, "agent.learning_mutations", _boom)
    install_memory_import_hook()

    with caplog.at_level("ERROR", logger=_memory_hook.__name__):
        module = importlib.import_module("agent.learning_mutations")

    assert module.delete_node("memory:memory:0") == {"ok": True, "message": "deleted"}
    assert sys.modules["agent.learning_mutations"] is module
    assert "hook bug" in caplog.text


def test_a_failing_action_on_the_catch_up_path_does_not_break_install(
    import_hook: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The already-imported sweep runs inside the fail-closed ``.pth`` bootstrap, so a
    bug there would refuse startup for every Hermes process — same containment as
    ``exec_module``. The deliberate ``SystemExit`` refusal must still propagate."""

    def _boom(_module: ModuleType) -> None:
        raise ValueError("catch-up bug")

    module = importlib.import_module("agent.learning_mutations")
    assert sys.modules["agent.learning_mutations"] is module
    monkeypatch.setitem(_memory_hook._POST_IMPORT_ACTIONS, "agent.learning_mutations", _boom)

    with caplog.at_level("ERROR", logger=_memory_hook.__name__):
        assert install_memory_import_hook() is True
    assert "catch-up bug" in caplog.text

    def _refuse(_module: ModuleType) -> None:
        raise SystemExit(1)

    monkeypatch.setitem(_memory_hook._POST_IMPORT_ACTIONS, "agent.learning_mutations", _refuse)
    with pytest.raises(SystemExit):
        install_memory_import_hook()


def test_classification_import_reports_an_unsupported_seam_without_exiting(
    unsupported_import_hook: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``seam_check`` and the ``--probe`` main exist to diagnose exactly this state.
    Stopping the process from the finder's action killed the diagnostic instead —
    an armed operator with an unsupported seam had no way left to ask why."""
    _arm(tmp_path / "home")
    install_memory_import_hook()

    with caplog.at_level("WARNING", logger=_memory_hook.__name__):
        ok, reason = seam_check()

    assert ok is False
    assert "ENTRY_DELIMITER" in reason
    assert "classification call" in caplog.text


def test_classification_import_still_wraps_a_supported_seam(import_hook: Path, tmp_path: Path) -> None:
    """The suppression only skips the refusal; a seam we understand is still wrapped."""
    _arm(tmp_path / "home")

    install_memory_import_hook()
    assert seam_check() == (True, "")

    assert memory_hook_installed(sys.modules["tools.memory_tool"]) is True


def test_a_normal_import_of_an_unsupported_seam_still_refuses(unsupported_import_hook: Path, tmp_path: Path) -> None:
    """C2 is kept: only ``_load_memory_tool``-mediated imports are exempt, so an
    agent process or a gateway importing the seam normally still fails closed."""
    _arm(tmp_path / "home")
    install_memory_import_hook()

    with pytest.raises(SystemExit) as excinfo:
        importlib.import_module("tools.memory_tool")

    assert excinfo.value.code == 1


# --------------------------------------------------------------------------
# Journey guard (learning_mutations)
# --------------------------------------------------------------------------


def _fake_mutations_module(mem_dir: Path) -> ModuleType:
    """A fake ``agent.learning_mutations`` whose mutations record their calls."""
    module = ModuleType("fake_learning_mutations")
    calls: list[str] = []

    def parse_node_kind(node_id: str) -> str:
        return "memory" if node_id.startswith("memory:") else "skill"

    def delete_node(node_id: str) -> dict[str, Any]:
        calls.append(f"delete:{node_id}")
        return {"ok": True, "message": "deleted"}

    def edit_node(node_id: str, content: str) -> dict[str, Any]:
        calls.append(f"edit:{node_id}")
        return {"ok": True, "message": "updated"}

    module.calls = calls  # type: ignore[attr-defined]
    module.parse_node_kind = parse_node_kind  # type: ignore[attr-defined]
    module.delete_node = delete_node  # type: ignore[attr-defined]
    module.edit_node = edit_node  # type: ignore[attr-defined]
    module._MEMORY_FILES = {"memory": "MEMORY.md", "profile": "USER.md"}  # type: ignore[attr-defined]
    module._memories_dir = lambda: mem_dir  # type: ignore[attr-defined]
    return module


def test_journey_guard_refuses_to_delete_from_a_sealed_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_mutations_module(mem_dir)
    (mem_dir / "MEMORY.md").write_bytes(seal(b"first entry", key=KEY, name="MEMORY.md"))
    assert install_journey_guard(module, home=tmp_path) is True

    result = module.delete_node("memory:memory:0")

    assert result["ok"] is False
    assert "sealed by Mordred" in result["message"]
    assert module.calls == []  # upstream never ran: the entry survives


def test_journey_guard_refuses_to_edit_a_sealed_file(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_mutations_module(mem_dir)
    (mem_dir / "USER.md").write_bytes(seal(b"profile", key=KEY, name="USER.md"))
    install_journey_guard(module, home=tmp_path)

    result = module.edit_node("memory:profile:3", "new body")

    assert result["ok"] is False
    assert module.calls == []


def test_journey_guard_passes_a_plaintext_memory_through(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_mutations_module(mem_dir)
    (mem_dir / "MEMORY.md").write_text("first entry", encoding="utf-8")
    install_journey_guard(module, home=tmp_path)

    assert module.delete_node("memory:memory:0") == {"ok": True, "message": "deleted"}
    assert module.calls == ["delete:memory:memory:0"]


def test_journey_guard_leaves_skill_nodes_untouched(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_mutations_module(mem_dir)
    (mem_dir / "MEMORY.md").write_bytes(seal(b"first entry", key=KEY, name="MEMORY.md"))
    install_journey_guard(module, home=tmp_path)

    assert module.delete_node("debugging-hermes-desktop")["ok"] is True
    assert module.calls == ["delete:debugging-hermes-desktop"]


def test_journey_guard_skips_a_mismatched_signature(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_mutations_module(mem_dir)
    original = module.delete_node
    module.delete_node = lambda node: {"ok": True}  # type: ignore[assignment]

    assert install_journey_guard(module, home=tmp_path) is False
    assert module.delete_node is not original
    assert getattr(module.edit_node, _memory_hook._WRAPPED_FLAG, False) is False


def test_journey_guard_is_idempotent(mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_mutations_module(mem_dir)
    install_journey_guard(module, home=tmp_path)
    wrapped = module.delete_node
    install_journey_guard(module, home=tmp_path)

    assert module.delete_node is wrapped


# --------------------------------------------------------------------------
# Un-swallowable refusal
# --------------------------------------------------------------------------


def test_unsupported_seam_refusal_hard_exits_off_the_main_thread(
    mem_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `threading.excepthook` swallows a SystemExit raised on a worker thread, so
    # discovery running off-main must exit the process outright.
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = None
    _arm(tmp_path)
    codes: list[int] = []
    monkeypatch.setattr(os, "_exit", lambda code: codes.append(code))

    def _run() -> None:
        install_memory_hook(home=tmp_path, memory_tool_module=module, environ={"HERMES_MEMORY_KEY": KEY_ENV})

    worker = threading.Thread(target=_run)
    worker.start()
    worker.join()

    assert codes == [1]


def test_hard_exit_flushes_stdout_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``os._exit`` skips interpreter shutdown, so whatever the host had buffered on
    stdout is lost unless we flush it ourselves."""

    class _Stdout:
        def __init__(self) -> None:
            self.flushes = 0

        def write(self, text: str) -> int:
            return len(text)

        def flush(self) -> None:
            self.flushes += 1

    _arm(tmp_path)
    recorder = _Stdout()
    codes: list[int] = []
    monkeypatch.setattr(sys, "stdout", recorder)
    monkeypatch.setattr(os, "_exit", lambda code: codes.append(code))

    def _run() -> None:
        _memory_hook._refuse_or_ignore("synthetic reason", home=tmp_path, environ={})

    worker = threading.Thread(target=_run)
    worker.start()
    worker.join()

    assert codes == [1]
    assert recorder.flushes == 1


def test_unsupported_seam_in_safe_mode_warns_instead_of_refusing(
    mem_dir: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = None
    _arm(tmp_path)

    with caplog.at_level("WARNING", logger=_memory_hook.__name__):
        ok = install_memory_hook(
            home=tmp_path,
            memory_tool_module=module,
            environ={"HERMES_MEMORY_KEY": KEY_ENV, "HERMES_SAFE_MODE": "1"},
        )

    assert ok is False
    assert "HERMES_SAFE_MODE" in caplog.text


# --------------------------------------------------------------------------
# Sealed-but-unopenable warning at session start
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_locked_warning() -> Iterator[None]:
    _memory_hook._LOCKED_WARNED.clear()
    yield
    _memory_hook._LOCKED_WARNED.clear()


def _memories_home(tmp_path: Path) -> Path:
    (tmp_path / "memories").mkdir(parents=True, exist_ok=True)
    return tmp_path


def test_locked_memory_warning_fires_without_a_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = _memories_home(tmp_path)
    (home / "memories" / "MEMORY.md").write_bytes(seal(b"entry", key=KEY, name="MEMORY.md"))

    assert warn_when_memory_is_locked(home=home, environ={}) is True

    err = capsys.readouterr().err
    assert "agent memory is sealed" in err
    assert "HERMES_MEMORY_KEY" in err


def test_locked_memory_warning_fires_for_a_wrong_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = _memories_home(tmp_path)
    (home / "memories" / "MEMORY.md").write_bytes(seal(b"entry", key=KEY, name="MEMORY.md"))

    assert warn_when_memory_is_locked(home=home, environ={"HERMES_MEMORY_KEY": OTHER_KEY_ENV}) is True
    assert "agent memory is sealed" in capsys.readouterr().err


def test_locked_memory_warning_is_quiet_when_the_key_opens_the_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _memories_home(tmp_path)
    (home / "memories" / "MEMORY.md").write_bytes(seal(b"entry", key=KEY, name="MEMORY.md"))

    assert warn_when_memory_is_locked(home=home, environ={"HERMES_MEMORY_KEY": KEY_ENV}) is False
    assert capsys.readouterr().err == ""


def test_locked_memory_warning_is_quiet_for_plaintext_memory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _memories_home(tmp_path)
    (home / "memories" / "MEMORY.md").write_text("legacy entry", encoding="utf-8")

    assert warn_when_memory_is_locked(home=home, environ={}) is False
    assert capsys.readouterr().err == ""


def test_locked_memory_warning_fires_once_per_process(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = _memories_home(tmp_path)
    (home / "memories" / "MEMORY.md").write_bytes(seal(b"entry", key=KEY, name="MEMORY.md"))

    assert warn_when_memory_is_locked(home=home, environ={}) is True
    capsys.readouterr()
    assert warn_when_memory_is_locked(home=home, environ={}) is False
    assert capsys.readouterr().err == ""


# --------------------------------------------------------------------------
# Delimiter safety
# --------------------------------------------------------------------------


@pytest.mark.parametrize("delimiter", ["\n---\n", "==", "\n", "MEM\n", ""])
def test_classify_seam_rejects_a_delimiter_that_could_occur_in_a_sealed_blob(mem_dir: Path, delimiter: str) -> None:
    module = _fake_module("B", mem_dir)
    module.ENTRY_DELIMITER = delimiter
    shape, reason = classify_seam(module)
    assert shape == ""
    assert reason == "ENTRY_DELIMITER could occur inside a sealed blob"


def test_classify_seam_accepts_the_upstream_delimiter(mem_dir: Path) -> None:
    assert classify_seam(_fake_module("B", mem_dir)) == ("B", "")


# --------------------------------------------------------------------------
# Small items: live home, install completeness, durable rename
# --------------------------------------------------------------------------


def test_home_is_resolved_per_call_when_not_injected(
    shape: str, mem_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An in-process profile switch changes HERMES_HOME; arming must follow it
    # rather than staying pinned to the home this process started in.
    unarmed = tmp_path / "first"
    armed = tmp_path / "second"
    armed.mkdir()
    _arm(armed)
    live = [unarmed]
    monkeypatch.setattr(_memory_hook, "_hermes_home", lambda: live[-1])

    module = _fake_module(shape, mem_dir)
    assert install_memory_hook(memory_tool_module=module, environ={"HERMES_MEMORY_KEY": KEY_ENV}) is True
    path = _memory_path(module)

    module.MemoryStore._write_file(path, ["new entry"])
    assert not is_sealed(path.read_bytes())

    live.append(armed)  # profile switch, same wrapper
    module.MemoryStore._write_file(path, ["new entry"])
    assert is_sealed(path.read_bytes())


def test_memory_hook_installed_requires_every_seam_of_the_shape(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    assert memory_hook_installed(module) is True

    other = _fake_module(shape, mem_dir)
    other.MemoryStore._write_file = module.MemoryStore._write_file  # only the write seam is wrapped
    assert memory_hook_installed(other) is False


def test_seams_are_never_wrapped_twice(shape: str, mem_dir: Path, tmp_path: Path) -> None:
    """A double-wrapped write hands the inner wrapper's sealed blob to the outer one
    as a plaintext entry, and the write dies. ``_wrap_seam`` holds a lock so two
    installers racing (discovery on a worker vs. the import hook on main) cannot
    both read "not wrapped"."""
    module = _fake_module(shape, mem_dir)
    _install(module, tmp_path)
    _install(module, tmp_path)

    inner = module.MemoryStore.__dict__["_write_file"].__func__.__wrapped__
    assert not getattr(inner, _memory_hook._WRAPPED_FLAG, False)

    path = _memory_path(module)
    module.MemoryStore._write_file(path, ["only entry"])
    assert unseal(path.read_bytes(), key=KEY, name="MEMORY.md") == b"only entry"


def test_write_private_fsyncs_the_parent_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # fsync on the file persists the bytes; only fsync on the directory persists
    # the rename that publishes them.
    synced: list[int] = []
    real_fsync = os.fsync

    def _record(fd: int) -> None:
        synced.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _record)
    opened: list[str] = []
    real_open = os.open

    def _spy_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        opened.append(str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", _spy_open)

    _memory_hook._write_private(tmp_path / "MEMORY.md", b"payload")

    assert str(tmp_path) in opened
    assert len(synced) == 2  # the file and its directory


@pytest.fixture(autouse=True)
def _macos_key_custody_contract(monkeypatch):
    """These regressions exercise macOS env/vault custody on every CI OS."""
    import mordred_hermes.keyvault._memory_hook as module
    from tests._helpers import PlatformSys

    monkeypatch.setattr(module, "sys", PlatformSys("darwin"))
