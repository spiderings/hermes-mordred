from __future__ import annotations

import os

import pytest

from mordred_hermes.wizard import _windows_install as install


@pytest.fixture(autouse=True)
def require_native_foundation(request, monkeypatch):
    isolated_contract = request.node.name.startswith(("test_shared_", "test_windows_publisher_refuses"))
    if os.name == "nt" and not isolated_contract:
        try:
            install._confidential_opener()
        except OSError:
            pytest.skip("Windows publisher acceptance pending shared C1b ACL capability")
    elif os.name != "nt":
        monkeypatch.setattr(install, "_confidential_opener", lambda: _local_checked_fixture)
        import mordred_hermes._private_fs as fs

        monkeypatch.setattr(fs, "read_public_build_output", _local_public_source_fixture)


def _local_public_source_fixture(path, *, max_bytes):
    import stat

    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_size <= max_bytes
        return stream.read(max_bytes + 1)


def _local_checked_fixture(directory, *, create=False):
    """Filesystem test adapter; never ships in product code."""
    import stat
    from contextlib import contextmanager
    from types import SimpleNamespace

    class Missing(OSError):
        reason = "missing"
        commit_state = "not_committed"

    class Transaction:
        def stat(self, name):
            path = directory / name
            try:
                info = path.lstat()
            except FileNotFoundError as exc:
                raise Missing(name) from exc
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("unsafe symlink/hardlink file")
            return SimpleNamespace(identity=(info.st_dev, info.st_ino))

        def read_bytes(self, name, *, max_bytes):
            self.stat(name)
            data = (directory / name).read_bytes()
            assert len(data) <= max_bytes
            return data

        def create_bytes(self, name, data):
            with (directory / name).open("xb") as stream:
                stream.write(data)

        def replace_bytes(self, name, data):
            self.stat(name)
            (directory / name).write_bytes(data)

        def delete_file(self, name, *, expected_identity):
            assert self.stat(name).identity == expected_identity
            (directory / name).unlink()

    class Directory:
        @contextmanager
        def transaction(self):
            yield Transaction()

    @contextmanager
    def opened():
        for path in (*reversed(directory.parents), directory):
            if path.is_symlink():
                raise OSError("unsafe reparse/symlink directory")
        if create:
            directory.mkdir(parents=False, exist_ok=True)
        yield Directory()

    return opened()


def test_launcher_refuses_unknown_and_supports_verified_upgrade(tmp_path):
    python = tmp_path / "env's 日本 & space/python.exe"
    target = tmp_path / "bin"
    path = install.install_launcher(python, target)
    assert install.is_owned(path)
    assert str(python).replace("'", "''") in path.read_text(encoding="utf-8-sig")
    assert install.install_launcher(python, target) == path
    path.write_text("unknown launcher")
    with pytest.raises(OSError, match="owned"):
        install.install_launcher(python, target)
    assert path.read_text(encoding="utf-8-sig") == "unknown launcher"


def test_unknown_exe_blocks_launcher_install(tmp_path):
    # An elevated Windows token defaults raw new-file ownership to BA. This
    # fixture intends a safely admitted current-user file without our receipt.
    with install._native_transaction(tmp_path) as tx:
        tx.create_bytes("hermes-mordred.exe", b"MZ unknown")
    with pytest.raises(OSError, match="existing"):
        install.install_launcher(tmp_path / "python.exe", tmp_path)
    assert (tmp_path / "hermes-mordred.exe").read_bytes() == b"MZ unknown"
    assert not (tmp_path / "hermes-mordred.ps1").exists()


def test_helper_needs_hash_bound_manifest(tmp_path):
    source = tmp_path / "build.exe"
    source.write_bytes(b"MZ first helper")
    target = tmp_path / "bin"
    path = install.publish_helper(source, target)
    assert install.is_owned(path)
    source.write_bytes(b"MZ second helper")
    install.publish_helper(source, target)
    assert path.read_bytes() == source.read_bytes()
    path.write_bytes(b"MZ foreign helper")
    assert not install.is_owned(path)
    with pytest.raises(OSError, match="owned"):
        install.publish_helper(source, target)
    assert path.read_bytes() == b"MZ foreign helper"


def test_helper_digest_mismatch_preserves_source_and_owned_helper(tmp_path):
    source = tmp_path / "build.exe"
    source.write_bytes(b"MZ original")
    path = install.publish_helper(source, tmp_path / "bin")
    receipt = install.receipt_path(path).read_bytes()
    source.write_bytes(b"MZ changed after build hash")
    with pytest.raises(OSError, match="hash"):
        install.publish_helper(source, path.parent, expected_sha256="0" * 64)
    assert source.read_bytes() == b"MZ changed after build hash"
    assert path.read_bytes() == b"MZ original"
    assert install.receipt_path(path).read_bytes() == receipt


def test_hardlinked_public_build_preserves_source_but_stored_helper_refuses_links(tmp_path):
    source = tmp_path / "build.exe"
    source.write_bytes(b"MZ Cargo public image")
    alias = tmp_path / "Cargo-deps.exe"
    os.link(source, alias)
    path = install.publish_helper(source, tmp_path / "bin")
    assert source.stat().st_nlink == alias.stat().st_nlink == 2
    assert source.read_bytes() == alias.read_bytes() == path.read_bytes()
    receipt = install.receipt_path(path).read_bytes()
    os.link(path, path.with_name("stored-alias.exe"))
    with pytest.raises(OSError):
        install.publish_helper(source, path.parent)
    assert path.read_bytes() == source.read_bytes()
    assert install.receipt_path(path).read_bytes() == receipt


def test_reparse_and_hardlink_destinations_refuse(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    if os.name == "nt":
        import subprocess

        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(real)], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stdout + result.stderr
    else:
        alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(OSError) as refused:
        install.install_launcher(tmp_path / "python.exe", alias)
    if os.name == "nt":
        # The shared filesystem exposes classified reasons, not path details.
        assert refused.value.reason == "unsafe"
    else:
        assert "reparse" in str(refused.value) or "symlink" in str(refused.value)
    assert not list(real.iterdir())


def test_uninstall_revalidates_ownership_and_preserves_modified_file(tmp_path):
    path = install.install_launcher(tmp_path / "python.exe", tmp_path)
    assert install.is_owned(path)
    path.write_text("modified")
    with pytest.raises(OSError):
        install.remove_owned(path)
    assert path.exists()


def test_owned_remove_also_removes_receipt(tmp_path):
    path = install.install_launcher(tmp_path / "python.exe", tmp_path)
    install.remove_owned(path)
    assert not path.exists()
    assert not install.receipt_path(path).exists()


def test_windows_publisher_refuses_without_shared_acl_capability(monkeypatch, tmp_path):
    monkeypatch.setattr(
        install,
        "_confidential_opener",
        lambda: (_ for _ in ()).throw(OSError("shared C1b trusted-parent filesystem capability required")),
        raising=False,
    )
    with pytest.raises(OSError, match="C1b"):
        install.install_launcher(tmp_path / "python.exe", tmp_path / "bin")
    assert not (tmp_path / "bin/hermes-mordred.ps1").exists()


@pytest.fixture
def shared_store(monkeypatch, tmp_path):
    from contextlib import contextmanager
    from types import SimpleNamespace

    files = {}
    operations = []

    class Missing(OSError):
        reason = "missing"
        commit_state = "not_committed"

    class Transaction:
        def stat(self, name):
            if name not in files:
                raise Missing(name)
            return SimpleNamespace(identity=files[name][0])

        def read_bytes(self, name, *, max_bytes):
            self.stat(name)
            content = files[name][1]
            assert len(content) <= max_bytes
            return content

        def create_bytes(self, name, data):
            assert name not in files
            operations.append(("create", name))
            files[name] = (len(operations), data)

        def replace_bytes(self, name, data):
            assert name in files
            operations.append(("replace", name))
            files[name] = (len(operations), data)

        def delete_file(self, name, *, expected_identity):
            assert expected_identity == self.stat(name).identity
            operations.append(("delete", name))
            del files[name]

    class Directory:
        @contextmanager
        def transaction(self):
            yield Transaction()

    @contextmanager
    def open_directory(path, *, create=False):
        yield Directory()

    monkeypatch.setattr(install, "_confidential_opener", lambda: open_directory)
    return files, operations


def test_shared_transaction_publishes_verifies_upgrades_and_deletes(shared_store, tmp_path):
    files, operations = shared_store
    path = install.install_launcher(tmp_path / "python.exe", tmp_path / "bin")
    assert install.is_owned(path)
    assert path.name in files and install.receipt_path(path).name in files
    install.install_launcher(tmp_path / "new-python.exe", tmp_path / "bin")
    assert install.is_owned(path)
    assert ("replace", path.name) in operations
    install.remove_owned(path)
    assert not files
    assert operations[-2:] == [("delete", path.name), ("delete", install.receipt_path(path).name)]


def test_shared_transaction_unknown_modification_refuses_upgrade(shared_store, tmp_path):
    files, operations = shared_store
    path = install.install_launcher(tmp_path / "python.exe", tmp_path / "bin")
    files[path.name] = (90, b"unknown wrapper")
    before = list(operations)
    with pytest.raises(OSError, match="owned"):
        install.install_launcher(tmp_path / "python.exe", tmp_path / "bin")
    assert operations == before
    assert files[path.name][1] == b"unknown wrapper"


def test_shared_transaction_unclassified_absence_never_creates(monkeypatch, tmp_path):
    from contextlib import contextmanager

    class Broken:
        def stat(self, name):
            raise FileNotFoundError("unchecked parent missing")

        def create_bytes(self, name, data):
            pytest.fail("unchecked absence must not publish")

    @contextmanager
    def broken(*args, **kw):
        yield Broken()

    monkeypatch.setattr(install, "_native_transaction", broken)
    with pytest.raises(FileNotFoundError, match="unchecked parent"):
        install._publish(tmp_path / "wrapper.ps1", b"wrapper")


@pytest.mark.parametrize("phase", ["receipt", "scope_exit"])
def test_shared_failure_after_artifact_publication_propagates_without_retry(monkeypatch, tmp_path, phase):
    from contextlib import contextmanager
    from types import SimpleNamespace

    files = {}
    operations = []

    class Failure(OSError):
        reason = "io_error"
        commit_state = "uncertain"

    failure = Failure(phase)

    class Missing(OSError):
        reason = "missing"
        commit_state = "not_committed"

    class Transaction:
        def stat(self, name):
            if name not in files:
                raise Missing(name)
            return SimpleNamespace(identity=name)

        def read_bytes(self, name, *, max_bytes):
            self.stat(name)
            return files[name]

        def create_bytes(self, name, content):
            operations.append(("create", name))
            if phase == "receipt" and name.endswith(".mordred-owner.json"):
                raise failure
            files[name] = content

        def delete_file(self, name, **kw):
            pytest.fail("must not guess a rollback")

    class Directory:
        @contextmanager
        def transaction(self):
            yield Transaction()

    @contextmanager
    def opened(path, *, create=False):
        yield Directory()
        if phase == "scope_exit":
            raise failure

    monkeypatch.setattr(install, "_confidential_opener", lambda: opened)
    source = tmp_path / "built.exe"
    source.write_bytes(b"MZ retained fresh helper")
    with pytest.raises(Failure) as captured:
        install.publish_helper(source, tmp_path / "bin")
    assert captured.value is failure and captured.value.commit_state == "uncertain"
    artifact = "mordred-hermes-winkey.exe"
    receipt = artifact + ".mordred-owner.json"
    assert files[artifact] == source.read_bytes()
    assert operations == [("create", artifact), ("create", receipt)]
    assert (receipt in files) == (phase == "scope_exit")
