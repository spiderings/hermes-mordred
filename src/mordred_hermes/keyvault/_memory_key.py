"""Linux memory-key custody. TPM only; no file vault, ambient fallback or cache."""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import os
import secrets
import stat
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path

from . import _storage, wrap
from ._exceptions import WrapError, WrapKeyNotFound
from .memory_crypto import MemoryCryptoError, decode_key, looks_like_magic_line, unseal
from .wrap import NativeBackend

MEMORY_KEY_PROVIDER_VERSION = 1


class MemoryKeyError(RuntimeError):
    """Custody failed; callers must preserve ciphertext and refuse access."""


def memory_key_path(home: Path) -> Path:
    return home / "mordred" / "memory-key.wrapped"


def memory_key_id(home: Path) -> str:
    return "mordred-hermes.memory.v1." + hashlib.sha256(str(home.resolve()).encode()).hexdigest()[:16]


def linux_memory_backend(home: Path) -> NativeBackend:
    from . import _seckey_helper
    from ._seckey_backend import _SecKeyBackend

    ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_tpmkey_helper)
    if ops is None:
        raise MemoryKeyError("TPM helper unavailable; run `hermes-mordred keyvault enable-tpm`")
    # Explicit binding overrides ambient store selection: this key belongs to home.
    ops = ops.with_store_override("MORDRED_TPMKEY_STORE", home / "mordred" / "keyvault" / "tpm")
    return _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)


def _private_parent(home: Path, *, create: bool = False) -> Path:
    parent = memory_key_path(home).parent
    if create:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        # Provisioning holds memory_key_lock, which has validated this directory.
        parent.chmod(0o700)
    _storage._check_dir_mode(parent)
    return parent


@contextlib.contextmanager
def memory_key_lock(home: Path) -> Iterator[None]:
    """Serialize provisioning and lifecycle operations within a profile."""
    try:
        parent = memory_key_path(home).parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        mode = parent.lstat().st_mode
        # A lock contains no secret. Ordinary plaintext profiles may have a
        # 0755 parent; custody itself still requires exactly 0700.
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & 0o022:
            raise MemoryKeyError("unsafe memory lock directory")
        path = parent / "memory-key.lock"
        _storage.ensure_lock_file(path)
        with _storage._advisory_file_lock(path, label="memory key"):
            yield
    except (OSError, ValueError, WrapError) as exc:
        raise MemoryKeyError("TPM memory key unavailable or invalid; existing data was not replaced") from exc


def _load(home: Path, backend: NativeBackend) -> bytes:
    _private_parent(home)
    blob = _storage.safe_read(memory_key_path(home))
    return wrap.unwrap_dek(blob, memory_key_id(home), backend=backend, audit_sink=lambda entry: None)


def load_linux_memory_key(*, home: Path, backend: NativeBackend | None = None) -> bytes:
    try:
        return _load(home, backend if backend is not None else linux_memory_backend(home))
    except (OSError, ValueError, WrapError) as exc:
        raise MemoryKeyError("TPM memory key unavailable or invalid; restore access to the original TPM") from exc


def linux_memory_managed(home: Path) -> bool:
    parent = memory_key_path(home).parent
    return any(
        path.exists() or path.is_symlink()
        for path in (memory_key_path(home), parent / "memory-vault.marker", parent / "memory-vault.optout")
    )


def linux_memory_files(home: Path) -> list[Path]:
    """Enumerate completely or refuse; glob suppresses permission/I/O failures."""
    memories = home / "memories"
    try:
        mode = memories.lstat().st_mode
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(mode):
        raise MemoryKeyError("refusing a non-directory or symlinked memory directory")
    paths = []
    for path in memories.iterdir():
        if not (fnmatch.fnmatchcase(path.name, "*.md") or fnmatch.fnmatchcase(path.name, "*.md.bak.*")):
            continue
        if not stat.S_ISREG(path.lstat().st_mode):
            raise MemoryKeyError("refusing a non-regular memory file")
        paths.append(path)
    return sorted(paths)


def _validate_adoption(home: Path, key: bytes | None) -> None:
    """Authenticate all existing seals before accepting an explicitly supplied key."""
    if key is not None and len(key) != 32:
        raise MemoryKeyError("memory key must be 32 bytes")
    for path in linux_memory_files(home):
        data = path.read_bytes()
        if looks_like_magic_line(data.decode("utf-8", "surrogateescape")):
            if key is None:
                raise MemoryKeyError("sealed memory exists; explicit authenticated key adoption is required")
            try:
                unseal(data, key=key, name=path.name)
            except MemoryCryptoError as exc:
                raise MemoryKeyError("existing memory does not authenticate with the supplied key") from exc


def _publish(path: Path, blob: bytes) -> None:
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".memory-key-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        # link is atomic and refuses to replace an existing file, even on a race.
        os.link(temporary, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.unlink(temporary)


def ensure_linux_memory_key(
    *,
    home: Path,
    adopted_key: bytes | None = None,
    backend: NativeBackend | None = None,
) -> bytes:
    with memory_key_lock(home):
        _private_parent(home, create=True)
        selected = backend if backend is not None else linux_memory_backend(home)
        path = memory_key_path(home)
        if path.exists() or path.is_symlink():
            existing = _load(home, selected)
            _validate_adoption(home, existing)
            return existing
        if (path.parent / "memory-vault.marker").exists():
            raise MemoryKeyError("armed profile has lost its wrapped key; refusing regeneration")
        _validate_adoption(home, adopted_key)
        key_id = memory_key_id(home)
        try:
            selected.get_enclave_public_key(key_id)
        except WrapKeyNotFound:
            selected.generate_enclave_key(key_id, unattended=True)
        key = adopted_key if adopted_key is not None else secrets.token_bytes(32)
        blob = wrap.wrap_dek(key, key_id, backend=selected)
        # Verify actual TPM access before publishing: a public-key lookup is insufficient.
        if wrap.unwrap_dek(blob, key_id, backend=selected, audit_sink=lambda entry: None) != key:
            raise MemoryKeyError("TPM memory key verification failed")
        _publish(path, blob)
        return key


def delete_linux_memory_key(*, home: Path, backend: NativeBackend | None = None) -> None:
    with memory_key_lock(home):
        selected = backend if backend is not None else linux_memory_backend(home)
        path = memory_key_path(home)
        if path.exists() or path.is_symlink():
            _storage.safe_read(path)
        selected.delete_enclave_key(memory_key_id(home))
        path.unlink(missing_ok=True)


def resolve_memory_key(*, home: Path, platform: str, environ: Mapping[str, str]) -> bytes | None:
    if platform == "win32":
        from ._windows_custody import CustodyError, resolve_windows_memory_key

        try:
            return resolve_windows_memory_key(home=home)
        except (CustodyError, OSError, ValueError, WrapError, wrap.NativeBackendError) as exc:
            raise MemoryKeyError("Windows memory custody unavailable; existing data was not replaced") from exc
    if platform == "linux" and linux_memory_managed(home):
        return load_linux_memory_key(home=home)
    value = environ.get("HERMES_MEMORY_KEY")
    if not value:
        return None
    try:
        return decode_key(value)
    except MemoryCryptoError:
        return None
