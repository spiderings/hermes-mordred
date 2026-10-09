"""Tests for ``keyvault.log_encryption``.

SPEC.md §Audit log policy and §Encrypted audit-log wire format require:

- :class:`EncryptedWriter` is an AES-GCM-encrypting implementation of the
  Phase 1 ``Writer`` Protocol frozen in
  :mod:`mordred_hermes.privacy_check.audit`. Phase 4 factory-swaps it in
  for :class:`~mordred_hermes.privacy_check.audit.NDJSONWriter`.
- The audit-log data-encryption key (DEK) is **keyvault-wrapped** — only
  the wrapped blob touches disk (in the file header); the plaintext DEK
  lives in process memory for the writer's lifetime.
- Each entry is encrypted independently and written as one base64 line so
  a single ``append`` stays whole-entry atomic and no whole-file rewrite
  is ever needed.
- :func:`decrypt_log_file` is the reader side the ``audit decrypt`` CLI
  (PR8) drives; it unwraps the DEK through the Secure Enclave
  authorization boundary (``wrap.unwrap_dek``).

These tests use a software ``FakeBackend`` P-256 keypair store (copied
from ``test_keyvault_wrap.py``) in place of the Secure Enclave so the
crypto / wire-format paths are exercised with real AES-GCM + AES-KW.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.keyvault import log_encryption as le
from mordred_hermes.keyvault._exceptions import WrapError, WrapKeyAlreadyExists, WrapKeyNotFound
from mordred_hermes.keyvault.wrap import NativeBackendError, NativeErrorCode
from mordred_hermes.privacy_check.audit import NDJSONWriter

AuditSink = Callable[[dict[str, Any]], None]

_FIRST_PROCESS_WRITER = r"""
import base64
import sys
import time
from pathlib import Path

from mordred_hermes.keyvault.log_encryption import EncryptedWriter

class PublicBackend:
    def __init__(self, encoded_public_key):
        self.public_key = base64.b64decode(encoded_public_key)

    def get_enclave_public_key(self, _key_id):
        return self.public_key

log_path = Path(sys.argv[1])
ready_path = Path(sys.argv[2])
release_path = Path(sys.argv[3])
backend = PublicBackend(sys.argv[4])
writer = EncryptedWriter(log_path, backend=backend)
writer.append({"event": "process-a-1"})
ready_path.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 15
while not release_path.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("timed out waiting for process B")
    time.sleep(0.01)
writer.append({"event": "process-a-2"})
writer.close()
"""

_SECOND_PROCESS_WRITER = r"""
import base64
import sys
from pathlib import Path

from mordred_hermes.keyvault.log_encryption import EncryptedWriter

class PublicBackend:
    def __init__(self, encoded_public_key):
        self.public_key = base64.b64decode(encoded_public_key)

    def get_enclave_public_key(self, _key_id):
        return self.public_key

if len(sys.argv) == 4:
    Path(sys.argv[3]).write_text("started", encoding="utf-8")
writer = EncryptedWriter(
    Path(sys.argv[1]),
    backend=PublicBackend(sys.argv[2]),
)
writer.append({"event": "process-b-1"})
writer.close()
"""

_PARTIAL_ENCRYPTED_WRITER = r"""
import base64
import os
import sys
import time
from pathlib import Path

from mordred_hermes.keyvault import log_encryption as le

class PublicBackend:
    def __init__(self, encoded_public_key):
        self.public_key = base64.b64decode(encoded_public_key)

    def get_enclave_public_key(self, _key_id):
        return self.public_key

log_path = Path(sys.argv[1])
ready_path = Path(sys.argv[2])
release_path = Path(sys.argv[3])
backend = PublicBackend(sys.argv[4])
real_write = os.write
calls = 0

def write_fully(fd, data):
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = real_write(fd, view[offset:])
        if written <= 0:
            raise OSError("real write made no progress")
        offset += written
    return len(view)

def partial_entry_then_zero(fd, data):
    global calls
    calls += 1
    if calls == 1:
        return write_fully(fd, data)
    if calls == 2:
        written = real_write(fd, data[:7])
        ready_path.write_text("partial", encoding="utf-8")
        deadline = time.monotonic() + 15
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out waiting to release partial encrypted append")
            time.sleep(0.01)
        return written
    return 0

le.os.write = partial_entry_then_zero
try:
    le.EncryptedWriter(log_path, backend=backend).append({"event": "partial-process"})
except OSError as exc:
    if "returned 0 bytes" not in str(exc):
        raise
else:
    raise AssertionError("partial encrypted append unexpectedly succeeded")
"""


class FakeBackend:
    """Software P-256 keypair store standing in for the Secure Enclave.

    Mirrors ``test_keyvault_wrap.FakeBackend`` — ``enclave_ecdh`` performs
    real ECDH; ``denied_reason`` simulates an authorization-prompt denial.
    """

    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        self.denied_reason: NativeErrorCode | None = None
        self.calls: list[tuple[str, str]] = []

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        self.calls.append(("generate", key_id))
        if key_id in self._keys:
            raise WrapKeyAlreadyExists(f"key {key_id!r} already exists")
        priv = ec.generate_private_key(ec.SECP256R1())
        self._keys[key_id] = priv
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        self.calls.append(("get_pub", key_id))
        if key_id not in self._keys:
            raise WrapKeyNotFound(f"no key for {key_id!r}")
        return self._keys[key_id].public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def delete_enclave_key(self, key_id: str) -> None:
        self.calls.append(("delete", key_id))
        self._keys.pop(key_id, None)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        self.calls.append(("ecdh", key_id))
        if self.denied_reason is not None:
            raise NativeBackendError(self.denied_reason)
        if key_id not in self._keys:
            raise WrapKeyNotFound(f"no key for {key_id!r}")
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self._keys[key_id].exchange(ec.ECDH(), peer)


@pytest.fixture
def backend() -> FakeBackend:
    """A FakeBackend with the audit-log wrapping key pre-generated."""
    be = FakeBackend()
    be.generate_enclave_key(le.AUDIT_LOG_KEY_ID)
    return be


@pytest.fixture
def captured_audit() -> tuple[list[dict[str, Any]], AuditSink]:
    entries: list[dict[str, Any]] = []

    def sink(entry: dict[str, Any]) -> None:
        entries.append(entry)

    return entries, sink


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


@pytest.fixture(autouse=True)
def _isolate_default_keyvault_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep decrypt_log_file's lifecycle sidecar out of the developer profile."""
    monkeypatch.setattr(le._storage, "_hermes_home", lambda: tmp_path)


# ---------------------------------------------------------------------------
# Writer Protocol conformance + basic roundtrip
# ---------------------------------------------------------------------------


def test_encrypted_writer_satisfies_writer_surface(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    assert callable(w.append)
    assert callable(w.close)


def test_roundtrip_single_entry(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "keyvault.unwrap_authorized", "decision": "allow"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert len(entries) == 1
    assert entries[0]["event"] == "keyvault.unwrap_authorized"
    assert entries[0]["decision"] == "allow"


def test_short_os_writes_complete_header_and_entry(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sink = captured_audit
    real_write = le.os.write
    calls = 0

    def short_write(fd: int, data: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        return real_write(fd, data[:11])

    monkeypatch.setattr(le.os, "write", short_write)
    writer = le.EncryptedWriter(log_path, backend=backend)
    writer.append({"event": "short-write", "decision": "allow"})
    writer.close()

    assert calls > 2  # both the header and entry required write-all retries
    assert le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)[0]["event"] == "short-write"


@pytest.mark.parametrize("failure_phase", ["header", "entry"])
def test_zero_length_os_write_rolls_back_partial_header_or_entry(
    failure_phase: str,
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sink = captured_audit
    real_write = le.os.write
    calls = 0

    def partial_then_zero(fd: int, data: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if failure_phase == "entry" and calls == 1:
            return real_write(fd, data)  # complete the header
        if calls == 1 or (failure_phase == "entry" and calls == 2):
            return real_write(fd, data[:7])
        return 0

    monkeypatch.setattr(le.os, "write", partial_then_zero)
    writer = le.EncryptedWriter(log_path, backend=backend)

    with pytest.raises(OSError, match="0 bytes"):
        writer.append({"event": "no-progress"})

    if failure_phase == "header":
        assert log_path.read_bytes() == b""
    else:
        # The successfully-written header remains, but the partial entry does
        # not.  A later append can therefore recover without corrupting the
        # encrypted log.
        assert len(log_path.read_bytes().splitlines()) == 1

    monkeypatch.setattr(le.os, "write", real_write)
    writer.append({"event": "recovered"})
    writer.close()
    assert le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)[0]["event"] == "recovered"


def test_roundtrip_multiple_entries_preserves_order(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    for i in range(5):
        w.append({"event": "policy.strict.clearnet", "seq": i})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert [e["seq"] for e in entries] == [0, 1, 2, 3, 4]


def test_process_handoffs_rotate_each_dek_owner_without_corrupting_files(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    tmp_path: Path,
) -> None:
    """A→B→A ownership changes leave every MRAL file decryptable."""
    _, sink = captured_audit
    public_key = backend.get_enclave_public_key(le.AUDIT_LOG_KEY_ID)
    encoded_public_key = base64.b64encode(public_key).decode("ascii")
    ready = tmp_path / "process-a-ready"
    release = tmp_path / "release-process-a"
    first = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _FIRST_PROCESS_WRITER,
            str(log_path),
            str(ready),
            str(release),
            encoded_public_key,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    first_output: tuple[str, str] = ("", "")
    try:
        deadline = time.monotonic() + 15
        while not ready.exists():
            if first.poll() is not None:
                stdout, stderr = first.communicate()
                pytest.fail(f"process A exited early: {stdout=} {stderr=}")
            if time.monotonic() >= deadline:
                pytest.fail("process A did not write its first encrypted entry")
            time.sleep(0.01)

        second = subprocess.run(
            [
                sys.executable,
                "-c",
                _SECOND_PROCESS_WRITER,
                str(log_path),
                encoded_public_key,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        assert second.returncode == 0, second.stderr
    finally:
        release.touch()
        try:
            first_output = first.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            first.kill()
            first_output = first.communicate()

    assert first.returncode == 0, f"stdout={first_output[0]!r} stderr={first_output[1]!r}"
    files = [
        path for path in log_path.parent.iterdir() if path == log_path or path.name.startswith(f"{log_path.name}.")
    ]
    assert len(files) == 3
    events: list[str] = []
    for path in files:
        entries = le.decrypt_log_file(path, backend=backend, audit_sink=sink)
        events.extend(str(entry["event"]) for entry in entries)
    assert sorted(events) == ["process-a-1", "process-a-2", "process-b-1"]


def test_partial_rollback_cannot_truncate_another_encrypted_process(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    tmp_path: Path,
) -> None:
    """The process lock remains held until encrypted rollback completes."""
    _, sink = captured_audit
    public_key = backend.get_enclave_public_key(le.AUDIT_LOG_KEY_ID)
    encoded_public_key = base64.b64encode(public_key).decode("ascii")
    partial_ready = tmp_path / "partial-encrypted-ready"
    release_partial = tmp_path / "release-partial-encrypted"
    second_started = tmp_path / "second-encrypted-started"
    processes: list[subprocess.Popen[str]] = []
    outputs: dict[int, tuple[str, str]] = {}

    partial = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _PARTIAL_ENCRYPTED_WRITER,
            str(log_path),
            str(partial_ready),
            str(release_partial),
            encoded_public_key,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    processes.append(partial)
    try:
        deadline = time.monotonic() + 15
        while not partial_ready.exists():
            if partial.poll() is not None:
                stdout, stderr = partial.communicate()
                pytest.fail(f"partial encrypted writer exited early: {stdout=} {stderr=}")
            if time.monotonic() >= deadline:
                pytest.fail("encrypted writer did not reach its partial entry")
            time.sleep(0.01)

        second = subprocess.Popen(
            [
                sys.executable,
                "-c",
                _SECOND_PROCESS_WRITER,
                str(log_path),
                encoded_public_key,
                str(second_started),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        processes.append(second)
        deadline = time.monotonic() + 15
        while not second_started.exists():
            if second.poll() is not None:
                stdout, stderr = second.communicate()
                pytest.fail(f"second encrypted writer exited early: {stdout=} {stderr=}")
            if time.monotonic() >= deadline:
                pytest.fail("second encrypted writer did not start")
            time.sleep(0.01)
        with pytest.raises(subprocess.TimeoutExpired):
            second.wait(timeout=0.5)
    finally:
        release_partial.touch()
        for process in processes:
            try:
                outputs[process.pid] = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                outputs[process.pid] = process.communicate()

    for process in processes:
        stdout, stderr = outputs[process.pid]
        assert process.returncode == 0, f"{stdout=} {stderr=}"
    files = [
        path for path in log_path.parent.iterdir() if path == log_path or path.name.startswith(f"{log_path.name}.")
    ]
    events: list[str] = []
    for path in files:
        events.extend(str(entry["event"]) for entry in le.decrypt_log_file(path, backend=backend, audit_sink=sink))
    assert events == ["process-b-1"]


def test_profile_bound_writer_holds_lifecycle_through_header_publication(
    log_path: Path,
    backend: FakeBackend,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reset cannot delete the audit key between wrap and MRAL publication."""
    root = le._storage.resolve_keyvault_dir(tmp_path)
    le._storage.ensure_layout(root)
    writer = le.EncryptedWriter(log_path, backend=backend, keyvault_root=root)

    public_loaded = threading.Event()
    release_public = threading.Event()
    reset_acquired = threading.Event()
    append_errors: list[BaseException] = []
    real_get_public = backend.get_enclave_public_key

    def pausing_get_public(key_id: str) -> bytes:
        public = real_get_public(key_id)
        public_loaded.set()
        if not release_public.wait(timeout=5):
            raise AssertionError("test did not release audit public-key lookup")
        return public

    monkeypatch.setattr(backend, "get_enclave_public_key", pausing_get_public)

    def append_entry() -> None:
        try:
            writer.append({"event": "before-reset"})
        except BaseException as exc:
            append_errors.append(exc)

    def reset_lifecycle() -> None:
        with le._storage.keyvault_lifecycle_lock(root):
            reset_acquired.set()
            backend.delete_enclave_key(le.AUDIT_LOG_KEY_ID)

    append_thread = threading.Thread(target=append_entry)
    reset_thread = threading.Thread(target=reset_lifecycle)
    append_thread.start()
    assert public_loaded.wait(timeout=5)
    reset_thread.start()
    try:
        assert not reset_acquired.wait(timeout=0.1)
    finally:
        release_public.set()

    append_thread.join(timeout=5)
    reset_thread.join(timeout=5)
    assert not append_thread.is_alive()
    assert not reset_thread.is_alive()
    assert append_errors == []
    assert reset_acquired.is_set()
    assert log_path.read_bytes().count(b"\n") == 2


def test_decrypt_holds_lifecycle_through_plaintext_authentication(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reset waits until the logical decrypt has authenticated every entry."""
    _, sink = captured_audit
    le.EncryptedWriter(log_path, backend=backend).append({"event": "protected-read"})
    root = le._storage.resolve_keyvault_dir(tmp_path)
    le._storage.ensure_layout(root)

    decrypting_entry = threading.Event()
    release_decrypt = threading.Event()
    reset_acquired = threading.Event()
    decrypt_errors: list[BaseException] = []
    decrypted: list[list[dict[str, Any]]] = []
    real_decrypt = le._aes_decrypt

    def pausing_decrypt(key: bytes, blob: bytes, *, aad: bytes) -> bytes:
        decrypting_entry.set()
        if not release_decrypt.wait(timeout=5):
            raise AssertionError("test did not release audit entry decryption")
        return real_decrypt(key, blob, aad=aad)

    monkeypatch.setattr(le, "_aes_decrypt", pausing_decrypt)

    def decrypt_entry() -> None:
        try:
            decrypted.append(
                le.decrypt_log_file(
                    log_path,
                    backend=backend,
                    audit_sink=sink,
                    keyvault_home=tmp_path,
                )
            )
        except BaseException as exc:
            decrypt_errors.append(exc)

    def reset_lifecycle() -> None:
        with le._storage.keyvault_lifecycle_lock(root):
            reset_acquired.set()

    decrypt_thread = threading.Thread(target=decrypt_entry)
    reset_thread = threading.Thread(target=reset_lifecycle)
    decrypt_thread.start()
    assert decrypting_entry.wait(timeout=5)
    reset_thread.start()
    try:
        assert not reset_acquired.wait(timeout=0.1)
    finally:
        release_decrypt.set()

    decrypt_thread.join(timeout=5)
    reset_thread.join(timeout=5)
    assert not decrypt_thread.is_alive()
    assert not reset_thread.is_alive()
    assert decrypt_errors == []
    assert decrypted[0][0]["event"] == "protected-read"
    assert reset_acquired.is_set()


def test_decrypt_audit_sink_reenters_same_profile_lifecycle(
    log_path: Path,
    backend: FakeBackend,
    tmp_path: Path,
) -> None:
    """An authorized unwrap may synchronously append under the same lifecycle."""
    le.EncryptedWriter(log_path, backend=backend).append({"event": "source"})
    root = le._storage.resolve_keyvault_dir(tmp_path)
    le._storage.ensure_layout(root)
    audit_writer = le.EncryptedWriter(
        tmp_path / "unwrap-audit.log",
        backend=backend,
        keyvault_root=root,
    )

    errors: list[BaseException] = []
    decrypted: list[list[dict[str, Any]]] = []

    def decrypt_entry() -> None:
        try:
            decrypted.append(
                le.decrypt_log_file(
                    log_path,
                    backend=backend,
                    audit_sink=audit_writer.append,
                    keyvault_home=tmp_path,
                )
            )
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=decrypt_entry, daemon=True)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive(), "nested lifecycle acquisition deadlocked"
    assert errors == []
    assert decrypted[0][0]["event"] == "source"
    assert (tmp_path / "unwrap-audit.log").is_file()


def test_low_level_decrypt_snapshot_waits_for_writer_sidecar(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    le.EncryptedWriter(log_path, backend=backend).append({"event": "stable-snapshot"})
    started = threading.Event()
    finished = threading.Event()
    results: list[list[dict[str, Any]]] = []

    def decrypt() -> None:
        started.set()
        results.append(le.decrypt_log_file(log_path, backend=backend, audit_sink=sink))
        finished.set()

    with le._exclusive_audit_lock(log_path):
        thread = threading.Thread(target=decrypt)
        thread.start()
        assert started.wait(timeout=5)
        assert not finished.wait(timeout=0.1)

    thread.join(timeout=5)
    assert not thread.is_alive()
    assert results[0][0]["event"] == "stable-snapshot"


def test_low_level_rotated_decrypt_uses_active_writer_sidecar(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    le.EncryptedWriter(log_path, backend=backend).append({"event": "rotated-snapshot"})
    rotated = log_path.with_name(f"{log_path.name}.2026-05-10")
    os.replace(log_path, rotated)
    started = threading.Event()
    finished = threading.Event()
    results: list[list[dict[str, Any]]] = []

    def decrypt() -> None:
        started.set()
        results.append(le.decrypt_log_file(rotated, backend=backend, audit_sink=sink))
        finished.set()

    with le._exclusive_audit_lock(log_path):
        thread = threading.Thread(target=decrypt)
        thread.start()
        assert started.wait(timeout=5)
        assert not finished.wait(timeout=0.1)

    thread.join(timeout=5)
    assert not thread.is_alive()
    assert results[0][0]["event"] == "rotated-snapshot"


def test_low_level_decrypt_refuses_symlink_before_native_authorization(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    victim = log_path.with_name("victim.mral")
    le.EncryptedWriter(victim, backend=backend).append({"event": "victim"})
    log_path.symlink_to(victim)
    backend.calls.clear()

    with pytest.raises(OSError, match="regular file"):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)

    assert not any(operation == "ecdh" for operation, _key_id in backend.calls)


def test_low_level_decrypt_refuses_fifo_without_blocking(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    _, sink = captured_audit
    os.mkfifo(log_path)

    with pytest.raises(OSError, match="regular file"):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_plaintext_writer_fails_closed_after_encrypted_takeover(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    plaintext = NDJSONWriter(log_path)
    plaintext.append({"event": "plaintext-before-takeover"})

    encrypted = le.EncryptedWriter(log_path, backend=backend)
    encrypted.append({"event": "encrypted-owner"})

    with pytest.raises(OSError, match="MRAL-encrypted"):
        plaintext.append({"event": "must-not-splice"})

    encrypted.append({"event": "encrypted-still-valid"})
    encrypted.close()
    assert [entry["event"] for entry in le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)] == [
        "encrypted-owner",
        "encrypted-still-valid",
    ]


def test_encrypted_writer_refuses_symlink_without_touching_target(
    log_path: Path,
    backend: FakeBackend,
) -> None:
    victim = log_path.with_name("victim.log")
    victim.write_text("do-not-touch\n", encoding="utf-8")
    os.chmod(victim, 0o644)
    log_path.symlink_to(victim)

    with pytest.raises(OSError, match="regular file"):
        le.EncryptedWriter(log_path, backend=backend).append({"event": "x"})

    assert victim.read_text(encoding="utf-8") == "do-not-touch\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_encrypted_writer_refuses_fifo_without_blocking(
    log_path: Path,
    backend: FakeBackend,
) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    os.mkfifo(log_path)

    with pytest.raises(OSError, match="regular file"):
        le.EncryptedWriter(log_path, backend=backend).append({"event": "x"})


def test_encrypted_writer_refuses_symlinked_sidecar(
    log_path: Path,
    backend: FakeBackend,
) -> None:
    victim = log_path.with_name("victim.lock")
    victim.write_text("do-not-touch\n", encoding="utf-8")
    os.chmod(victim, 0o644)
    log_path.with_name(".audit.log.lock").symlink_to(victim)

    with pytest.raises(OSError, match="audit lock is unsafe"):
        le.EncryptedWriter(log_path, backend=backend).append({"event": "x"})

    assert victim.read_text(encoding="utf-8") == "do-not-touch\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_non_ascii_entry_roundtrips(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet", "note": "ネットワーク遮断"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert entries[0]["note"] == "ネットワーク遮断"


# ---------------------------------------------------------------------------
# Encryption: plaintext never hits disk
# ---------------------------------------------------------------------------


def test_append_does_not_write_plaintext(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "keyvault.unwrap_authorized", "secret_marker": "TOPSECRET-XYZ"})
    w.close()

    raw = log_path.read_bytes()
    assert b"TOPSECRET-XYZ" not in raw
    assert b"unwrap_authorized" not in raw


def test_dek_is_wrapped_not_plaintext_in_header(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    header_line = log_path.read_bytes().split(b"\n", 1)[0]
    header = json.loads(header_line)
    assert header["fmt"] == "MRAL"
    assert header["ver"] == le.FORMAT_VERSION
    assert header["key_id"] == le.AUDIT_LOG_KEY_ID

    wrapped = base64.b64decode(header["wdek"])
    # The header carries a wrap.py MRKW blob (127 bytes), not a raw DEK.
    assert wrapped[:4] == b"MRKW"
    assert len(wrapped) == 127


def test_header_is_first_line_only(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "a"})
    w.append({"event": "b"})
    w.close()

    lines = log_path.read_bytes().splitlines()
    assert len(lines) == 3  # 1 header + 2 entries
    assert json.loads(lines[0])["fmt"] == "MRAL"
    # entry lines are opaque base64, not JSON
    with pytest.raises(json.JSONDecodeError):
        json.loads(lines[1])


# ---------------------------------------------------------------------------
# ``ts`` injection contract (Writer Protocol invariant #1)
# ---------------------------------------------------------------------------

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def test_ts_injected_with_millisecond_precision(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert _TS_RE.match(entries[0]["ts"])


def test_caller_supplied_ts_is_preserved(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"ts": "2020-01-01T00:00:00.000Z", "event": "policy.strict.clearnet"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert entries[0]["ts"] == "2020-01-01T00:00:00.000Z"


# ---------------------------------------------------------------------------
# File mode (Writer Protocol invariant #3)
# ---------------------------------------------------------------------------


def test_active_file_is_mode_0600(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()
    assert (log_path.stat().st_mode & 0o777) == 0o600


def test_parent_dir_created_mode_0700(tmp_path: Path, backend: FakeBackend) -> None:
    nested = tmp_path / "mordred" / "audit.log"
    w = le.EncryptedWriter(nested, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()
    assert (nested.parent.stat().st_mode & 0o777) == 0o700


# ---------------------------------------------------------------------------
# Entry size cap
# ---------------------------------------------------------------------------


def test_oversized_entry_rejected(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    with pytest.raises(ValueError, match="bytes"):
        w.append({"event": "policy.strict.clearnet", "blob": "x" * 5000})


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tampered_entry_line_rejected(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    lines = log_path.read_bytes().splitlines()
    entry = bytearray(base64.b64decode(lines[1]))
    entry[-1] ^= 0x01  # flip a tag bit
    lines[1] = base64.b64encode(bytes(entry))
    log_path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises((le.AuditLogDecryptError, InvalidTag)):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_tampered_header_rejected(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    lines = log_path.read_bytes().splitlines()
    header = json.loads(lines[0])
    wrapped = bytearray(base64.b64decode(header["wdek"]))
    wrapped[-1] ^= 0x01  # corrupt the wrapped DEK
    header["wdek"] = base64.b64encode(bytes(wrapped)).decode()
    lines[0] = json.dumps(header).encode()
    log_path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises((le.AuditLogDecryptError, WrapError, InvalidTag)):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_plaintext_ndjson_file_is_rejected_by_reader(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    log_path.write_text('{"ts":"2026-05-16T00:00:00.000Z","event":"policy.strict.clearnet"}\n')
    with pytest.raises(le.AuditLogDecryptError):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_empty_file_is_rejected_by_reader(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    log_path.write_bytes(b"")
    with pytest.raises(le.AuditLogDecryptError):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_entry_from_another_file_cannot_be_spliced_in(
    tmp_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    """AAD binds each entry to its file header — cross-file replay fails."""
    _, sink = captured_audit
    path_a = tmp_path / "a.log"
    path_b = tmp_path / "b.log"

    wa = le.EncryptedWriter(path_a, backend=backend)
    wa.append({"event": "policy.strict.clearnet", "src": "A"})
    wa.close()
    wb = le.EncryptedWriter(path_b, backend=backend)
    wb.append({"event": "policy.strict.clearnet", "src": "B"})
    wb.close()

    stolen = path_a.read_bytes().splitlines()[1]
    b_lines = path_b.read_bytes().splitlines()
    b_lines.append(stolen)
    path_b.write_bytes(b"\n".join(b_lines) + b"\n")

    with pytest.raises((le.AuditLogDecryptError, InvalidTag)):
        le.decrypt_log_file(path_b, backend=backend, audit_sink=sink)


# ---------------------------------------------------------------------------
# Authorization boundary: unwrap emits audit
# ---------------------------------------------------------------------------


def test_decrypt_emits_unwrap_authorized_audit(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    entries, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    # wrap.unwrap_dek emits event=keyvault.unwrap_dek, reason=keyvault.unwrap_authorized
    assert any(e.get("reason") == "keyvault.unwrap_authorized" for e in entries)


def test_decrypt_denied_when_authorization_cancelled(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    backend.denied_reason = "user_cancelled"
    with pytest.raises((le.AuditLogDecryptError, WrapError)):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_writer_never_calls_authorization_boundary(log_path: Path, backend: FakeBackend) -> None:
    """``wrap_dek`` is offline — writing never triggers ``enclave_ecdh``."""
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()
    assert not any(op == "ecdh" for op, _ in backend.calls)


# ---------------------------------------------------------------------------
# Rotation + retention
# ---------------------------------------------------------------------------


def test_size_cap_rotation_produces_decryptable_files(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend, rotate_bytes=600)
    for i in range(8):
        w.append({"event": "policy.strict.clearnet", "seq": i})
    w.close()

    rotated = sorted(p for p in log_path.parent.iterdir() if p.name.startswith(f"{log_path.name}."))
    assert rotated, "expected at least one rotated file"

    # active file still decrypts
    active = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert active, "active file should hold entries"

    # rotated (gzipped) files decrypt too — fresh DEK + header each
    total = len(active)
    for rp in rotated:
        total += len(le.decrypt_log_file(rp, backend=backend, audit_sink=sink))
    assert total == 8


def test_date_change_triggers_rotation(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sink = captured_audit
    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-16")
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet", "day": 1})

    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-17")
    w.append({"event": "policy.strict.clearnet", "day": 2})
    w.close()

    rotated = [p for p in log_path.parent.iterdir() if p.name.startswith(f"{log_path.name}.")]
    assert len(rotated) == 1
    active = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert [e["day"] for e in active] == [2]


def test_rotated_gzip_file_decrypts(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sink = captured_audit
    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-16")
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet", "day": 1})
    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-17")
    w.append({"event": "policy.strict.clearnet", "day": 2})
    w.close()

    gz = log_path.with_name("audit.log.2026-05-16.gz")
    assert gz.exists()
    assert gz.read_bytes()[:2] == b"\x1f\x8b"  # gzip magic
    rotated = le.decrypt_log_file(gz, backend=backend, audit_sink=sink)
    assert [e["day"] for e in rotated] == [1]


# ---------------------------------------------------------------------------
# Pre-existing file handling
# ---------------------------------------------------------------------------


def test_legacy_plaintext_file_is_rotated_aside(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    """A pre-Phase-4 plaintext NDJSON file is moved aside, not overwritten."""
    _, sink = captured_audit
    log_path.write_text('{"ts":"2026-05-15T00:00:00.000Z","event":"legacy.entry"}\n')

    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    # active file is now a fresh encrypted log
    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert entries[0]["event"] == "policy.strict.clearnet"

    # the legacy plaintext survives in a rotated file
    rotated = [p for p in log_path.parent.iterdir() if p.name.startswith(f"{log_path.name}.")]
    assert len(rotated) == 1
    blob = rotated[0]
    data = gzip.decompress(blob.read_bytes()) if blob.suffix == ".gz" else blob.read_bytes()
    assert b"legacy.entry" in data


def test_close_zeroes_the_dek_buffer(log_path: Path, backend: FakeBackend) -> None:
    """Security (defense-in-depth): ``close()`` must wipe the audit-log DEK in
    place, not merely drop the reference.

    The DEK is long-lived — held for the active file's whole lifetime, across
    many appends — so a non-zeroable ``bytes`` would linger in the heap until
    GC. Mirroring ``kek.MasterKey``, the writer keeps it in a ``bytearray`` and
    zeroes it on ``close()``.
    """
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "keyvault.unwrap_authorized", "decision": "allow"})
    captured = w._dek  # hold a reference to the underlying key buffer
    assert captured is not None
    assert isinstance(captured, bytearray), "DEK must be kept in a zeroable bytearray"
    assert any(captured), "precondition: a freshly minted DEK is not all-zero"

    w.close()

    assert not any(captured), "DEK buffer must be zeroed in place on close(), not just dereferenced"
    assert w._dek is None
