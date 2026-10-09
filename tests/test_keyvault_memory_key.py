"""Profile isolation and fail-closed custody; the fake replaces only hardware."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from mordred_hermes.keyvault import _memory_key as mk
from mordred_hermes.keyvault.memory_crypto import seal
from tests._keyvault_fakes import FakeBackend


def test_roundtrip_permissions_and_profile_isolation(tmp_path):
    backend = FakeBackend()
    home = tmp_path / "one"
    key = mk.ensure_linux_memory_key(home=home, backend=backend)
    assert len(key) == 32
    path = mk.memory_key_path(home)
    assert len(path.read_bytes()) == 127
    assert key not in path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert mk.load_linux_memory_key(home=home, backend=backend) == key
    assert mk.ensure_linux_memory_key(home=tmp_path / "two", backend=backend) != key
    assert mk.ensure_linux_memory_key(home=home, backend=backend) == key


@pytest.mark.parametrize("damage", ["corrupt", "missing", "hardware"])
def test_corrupt_or_missing_key_never_regenerates(tmp_path, damage):
    backend = FakeBackend()
    mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    path = mk.memory_key_path(tmp_path)
    (path.parent / "memory-vault.marker").touch()
    if damage == "corrupt":
        path.write_bytes(b"broken")
    elif damage == "missing":
        path.unlink()
    else:
        backend._keys.clear()
    before = list(backend.calls)
    with pytest.raises(mk.MemoryKeyError):
        mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    assert not any(op == "generate" for op, _ in backend.calls[len(before) :])


def test_concurrent_enable_publishes_one_key(tmp_path):
    backend = FakeBackend()
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _: mk.ensure_linux_memory_key(home=tmp_path, backend=backend), range(16)))
    assert len(set(keys)) == 1
    assert sum(op == "generate" for op, _ in backend.calls) == 1


def test_no_symlink_following(tmp_path):
    backend = FakeBackend()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    home = tmp_path / "home"
    home.mkdir()
    (home / "mordred").symlink_to(outside, target_is_directory=True)
    with pytest.raises(mk.MemoryKeyError):
        mk.ensure_linux_memory_key(home=home, backend=backend)
    assert list(outside.iterdir()) == []


def test_publication_failure_preserves_existing_material(tmp_path, monkeypatch):
    backend = FakeBackend()

    def fail(*args, **kwargs):
        raise OSError("disk full")

    with monkeypatch.context() as patch:
        patch.setattr(mk.os, "link", fail)
        with pytest.raises(mk.MemoryKeyError):
            mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    assert not mk.memory_key_path(tmp_path).exists()
    key = mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    assert mk.load_linux_memory_key(home=tmp_path, backend=backend) == key
    assert sum(op == "generate" for op, _ in backend.calls) == 1


def test_sealed_memory_requires_authenticated_adoption(tmp_path):
    backend = FakeBackend()
    memories = tmp_path / "memories"
    memories.mkdir()
    data = seal(b"private memory", key=b"a" * 32, name="MEMORY.md")
    (memories / "MEMORY.md").write_bytes(data)
    for key in (None, b"b" * 32):
        with pytest.raises(mk.MemoryKeyError):
            mk.ensure_linux_memory_key(home=tmp_path, backend=backend, adopted_key=key)
    assert mk.ensure_linux_memory_key(home=tmp_path, backend=backend, adopted_key=b"a" * 32) == b"a" * 32
    assert (memories / "MEMORY.md").read_bytes() == data


def test_no_software_fallback(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(_seckey_helper, "_helper_ops_or_none", lambda finder: None)
    with pytest.raises(mk.MemoryKeyError):
        mk.ensure_linux_memory_key(home=tmp_path)


def test_managed_key_failure_never_falls_back_to_environment(tmp_path, monkeypatch):
    def encode_key(value):
        return "hex:" + value.hex()

    backend = FakeBackend()
    key = mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    monkeypatch.setattr(mk, "linux_memory_backend", lambda home: backend)
    assert (
        mk.resolve_memory_key(home=tmp_path, platform="linux", environ={"HERMES_MEMORY_KEY": encode_key(b"z" * 32)})
        == key
    )
    backend._keys.clear()
    with pytest.raises(mk.MemoryKeyError):
        mk.resolve_memory_key(home=tmp_path, platform="linux", environ={"HERMES_MEMORY_KEY": encode_key(key)})


def test_linux_hook_resolves_live_home_key(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _memory_hook as hook

    backend = FakeBackend()
    one, two = tmp_path / "one", tmp_path / "two"
    key1 = mk.ensure_linux_memory_key(home=one, backend=backend)
    key2 = mk.ensure_linux_memory_key(home=two, backend=backend)
    monkeypatch.setattr(mk, "linux_memory_backend", lambda home: backend)
    monkeypatch.setattr(hook.sys, "platform", "linux")
    monkeypatch.setenv("HERMES_HOME", str(one))
    cfg = hook._HookConfig(environ={}, delimiter="\n")
    assert cfg.key == key1
    monkeypatch.setenv("HERMES_HOME", str(two))
    assert cfg.key == key2
    backend._keys.clear()
    with pytest.raises(hook.MemoryEncryptionUnavailable):
        hook._require_key_for_sealed(cfg, two / "memories" / "MEMORY.md")


def test_linux_warning_uses_managed_key(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _memory_hook as hook

    backend = FakeBackend()
    key = mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    monkeypatch.setattr(mk, "linux_memory_backend", lambda home: backend)
    monkeypatch.setattr(hook, "sys", SimpleNamespace(platform="linux", stderr=__import__("sys").stderr))
    memories = tmp_path / "memories"
    memories.mkdir()
    (memories / "MEMORY.md").write_bytes(seal(b"private", key=key, name="MEMORY.md"))
    assert hook.warn_when_memory_is_locked(home=tmp_path, environ={}) is False
    assert not capsys.readouterr().err
    backend._keys.clear()
    assert hook.warn_when_memory_is_locked(home=tmp_path, environ={}) is True


def test_existing_key_authenticates_all_sealed_files_before_reenable(tmp_path):
    backend = FakeBackend()
    mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    path = tmp_path / "memories/MEMORY.md.bak.1"
    path.parent.mkdir()
    blob = seal(b"other key memory", key=b"z" * 32, name=path.name)
    path.write_bytes(blob)
    with pytest.raises(mk.MemoryKeyError):
        mk.ensure_linux_memory_key(home=tmp_path, backend=backend)
    assert path.read_bytes() == blob


def test_stale_store_path_cannot_write_another_profile_key(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _memory_hook as hook
    from tests._helpers import PlatformSys

    backend = FakeBackend()
    one, two = tmp_path / "one", tmp_path / "two"
    key = mk.ensure_linux_memory_key(home=one, backend=backend)
    mk.ensure_linux_memory_key(home=two, backend=backend)
    path = one / "memories/MEMORY.md"
    path.parent.mkdir()
    blob = seal(b"profile one", key=key, name=path.name)
    path.write_bytes(blob)
    monkeypatch.setattr(mk, "linux_memory_backend", lambda home: backend)
    monkeypatch.setattr(hook, "sys", PlatformSys("linux"))
    store = SimpleNamespace(_write_file=lambda path, entries: path.write_text("\n".join(entries)))
    hook._wrap_write_file(store, hook._HookConfig(environ={}, delimiter="\n", home_factory=lambda: two))
    with pytest.raises(hook.MemoryEncryptionUnavailable):
        store._write_file(path, ["wrong profile"])
    assert path.read_bytes() == blob


@pytest.mark.parametrize("parent_mode", [0o755, 0o555])
def test_plaintext_linux_read_does_not_require_private_writable_mordred(tmp_path, monkeypatch, parent_mode):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _memory_hook as hook
    from tests._helpers import PlatformSys

    parent = tmp_path / "mordred"
    parent.mkdir(mode=parent_mode)
    path = tmp_path / "memories/MEMORY.md"
    path.parent.mkdir()
    path.write_text("ordinary memory")
    monkeypatch.setattr(hook, "sys", PlatformSys("linux"))
    store = SimpleNamespace(_read_raw_checked=lambda path: (path.read_text(), True))
    hook._wrap_read_raw_checked(store, hook._HookConfig(environ={}, delimiter="\n", home_factory=lambda: tmp_path))
    try:
        assert store._read_raw_checked(path) == ("ordinary memory", True)
        assert list(parent.iterdir()) == []
    finally:
        parent.chmod(0o700)


def test_plaintext_linux_write_accepts_nonprivate_parent_but_still_locks(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _memory_hook as hook
    from tests._helpers import PlatformSys

    parent = tmp_path / "mordred"
    parent.mkdir(mode=0o755)
    path = tmp_path / "memories/MEMORY.md"
    path.parent.mkdir()
    monkeypatch.setattr(hook, "sys", PlatformSys("linux"))
    store = SimpleNamespace(_write_file=lambda path, entries: path.write_text("\n".join(entries)))
    hook._wrap_write_file(store, hook._HookConfig(environ={}, delimiter="\n", home_factory=lambda: tmp_path))
    store._write_file(path, ["ordinary memory"])
    assert path.read_text() == "ordinary memory"
    assert (parent / "memory-key.lock").stat().st_mode & 0o777 == 0o600
    assert parent.stat().st_mode & 0o777 == 0o755


def test_explicit_enable_secures_existing_nonprivate_parent(tmp_path):
    parent = tmp_path / "mordred"
    parent.mkdir(mode=0o755)
    key = mk.ensure_linux_memory_key(home=tmp_path, backend=FakeBackend())
    assert len(key) == 32
    assert parent.stat().st_mode & 0o777 == 0o700
