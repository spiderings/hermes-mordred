"""Actual Win32 ACL/path checks; no POSIX-mode substitutes."""

from __future__ import annotations

import contextlib
import os
import subprocess
import time
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Win32 filesystem")


def test_native_private_directory_and_first_file(tmp_path: Path) -> None:
    root = tmp_path / "秘密 with spaces"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"private")
        assert d.read_bytes("secret", max_bytes=7) == b"private"
    script = (
        "$ErrorActionPreference='Stop'; $a=Get-Acl -LiteralPath $env:MORDRED_FS_ACL_TEST_PATH; "
        "if(!$a.AreAccessRulesProtected){exit 2}; "
        "if(@($a.Access|Where-Object {$_.IsInherited}).Count){exit 3}"
    )
    # Inspect with an independent Windows security API consumer.
    p = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        # pwsh -> Python -> powershell.exe otherwise inherits incompatible PS7 modules.
        env={key: value for key, value in os.environ.items() if key.casefold() != "psmodulepath"}
        | {"MORDRED_FS_ACL_TEST_PATH": str(root / "secret")},
        capture_output=True,
        text=True,
    )
    assert p.returncode == 0, p.stderr


def test_broad_acl_is_refused_without_repair(tmp_path: Path) -> None:
    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"keep")
        subprocess.run(["icacls.exe", str(root / "secret"), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
        with pytest.raises(PrivateFSError) as err:
            d.read_bytes("secret", max_bytes=100)
        assert err.value.reason == "unsafe"
        assert (root / "secret").read_bytes() == b"keep"


def test_junction_at_final_or_parent_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "private"
    with open_private_directory(root, create=True):
        pass
    link = tmp_path / "junction"
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(root)], check=True, capture_output=True)
    for path in (link, link / "new"):
        with pytest.raises(PrivateFSError) as err, open_private_directory(path, create=True):
            pass
        assert err.value.reason == "unsafe"
    assert not (root / "new").exists()


def test_hardlink_read_refused(tmp_path: Path) -> None:
    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"keep")
        os.link(root / "secret", root / "alias")
        with pytest.raises(PrivateFSError) as err:
            d.read_bytes("secret", max_bytes=100)
        assert err.value.reason == "unsafe"


@pytest.mark.parametrize(
    "path",
    [
        "C:relative",
        "\\root-relative",
        "\\\\server\\share\\private",
        "\\\\?\\C:\\private",
        "C:\\a\\..\\private",
        "C:\\a.\\private",
        "C:\\NUL.txt",
        "C:\\private:stream",
    ],
)
def test_ambiguous_or_remote_paths_refused(path: str) -> None:
    with pytest.raises(PrivateFSError) as err, open_private_directory(path, create=True):
        pass
    assert err.value.reason in ("unsafe", "unsupported")


def test_rename_error_and_failed_identity_query_never_delete_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes._private_fs._windows_api import get_api

    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
        api = get_api()
        rename = api.rename
        final_path = api.final_path
        attempted = False

        def ambiguous(handle, destination, *, replace):
            nonlocal attempted
            attempted = True
            rename(handle, destination, replace=replace)
            raise PrivateFSError("io", "rename", native_code=1117)

        def unavailable_identity(handle):
            if attempted:
                raise PrivateFSError("io", "identity", native_code=1117)
            return final_path(handle)

        monkeypatch.setattr(api, "rename", ambiguous)
        monkeypatch.setattr(api, "final_path", unavailable_identity)
        with pytest.raises(PrivateFSError) as err:
            tx.replace_bytes("secret", b"new")
        assert err.value.commit_state == "uncertain"
        assert (root / "secret").read_bytes() == b"new"


def test_close_error_after_publication_is_uncertain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    from mordred_hermes._private_fs._windows_api import get_api

    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
        api = get_api()
        rename = api.rename
        close = api.CloseHandle
        published = []

        def remember(handle, destination, *, replace):
            rename(handle, destination, replace=replace)
            published.append(handle.value)

        def failed_close(handle):
            result = close(handle)
            if published and handle == published[0]:
                published.clear()
                ctypes.set_last_error(6)
                return 0
            return result

        monkeypatch.setattr(api, "rename", remember)
        monkeypatch.setattr(api, "CloseHandle", failed_close)
        with pytest.raises(PrivateFSError) as err:
            tx.replace_bytes("secret", b"new")
        assert err.value.commit_state == "uncertain"
        assert (root / "secret").read_bytes() == b"new"


@pytest.mark.parametrize("stage", ["zero_write", "file_flush", "post_flush", "short_write"])
def test_native_staged_write_faults_preserve_complete_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    from mordred_hermes._private_fs._windows_api import get_api

    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
        api = get_api()
        write = api.write
        flush = api.flush
        calls = 0

        def fault_flush(handle):
            nonlocal calls
            calls += 1
            if calls == (2 if stage == "post_flush" else 1):
                raise PrivateFSError("io", "flush", native_code=1117)
            flush(handle)

        if stage == "zero_write":
            monkeypatch.setattr(api, "write", lambda handle, data: 0)
        elif stage == "short_write":
            monkeypatch.setattr(api, "write", lambda handle, data: write(handle, data[:2]))
        else:
            monkeypatch.setattr(api, "flush", fault_flush)
        if stage == "short_write":
            tx.replace_bytes("secret", b"complete new")
        else:
            with pytest.raises(PrivateFSError) as err:
                tx.replace_bytes("secret", b"complete new")
            assert err.value.commit_state == ("uncertain" if stage == "post_flush" else "not_committed")
        assert (root / "secret").read_bytes() == (b"complete new" if stage in ("short_write", "post_flush") else b"old")


def test_native_held_target_refusal_preserves_old_bytes(tmp_path: Path) -> None:
    from mordred_hermes._private_fs._windows_api import get_api

    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
        with get_api().open(str(root / "secret"), access=0x120089, share=3):
            with pytest.raises(PrivateFSError) as err:
                tx.replace_bytes("secret", b"new")
            assert err.value.commit_state == "not_committed"
            assert (root / "secret").read_bytes() == b"old"
        assert not list(root.glob(".mordred-fs-tmp-*"))


@pytest.mark.parametrize("change", ["inheritance", "null_dacl", "empty_dacl", "readonly"])
def test_native_unsafe_file_states_are_refused(tmp_path: Path, change: str) -> None:
    import ctypes as c

    from mordred_hermes._private_fs._windows_api import DWORD, HANDLE, PTR, get_api

    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
        target = root / "secret"
        if change == "inheritance":
            subprocess.run(["icacls.exe", str(target), "/inheritance:e"], check=True, capture_output=True)
        elif change == "readonly":
            subprocess.run(["attrib.exe", "+R", str(target)], check=True, capture_output=True)
        else:
            api = get_api()
            setter = api.security.SetSecurityInfo
            setter.argtypes = [HANDLE, c.c_int, DWORD, PTR, PTR, PTR, PTR]
            setter.restype = DWORD
            acl = c.create_string_buffer(b"\x02\x00\x08\x00\x00\x00\x00\x00")
            with api.open(str(target), access=0x60080) as handle:
                assert (
                    setter(handle.value, 1, 0x80000004, None, None, None if change == "null_dacl" else acl, None) == 0
                )
        try:
            with pytest.raises(PrivateFSError):
                tx.replace_bytes("secret", b"new")
        finally:
            if change == "readonly":
                subprocess.run(["attrib.exe", "-R", str(target)], check=True, capture_output=True)


@pytest.mark.parametrize("name", [".MORDRED-FS.LOCK", ".MORDRED-FS-TMP-forged"])
def test_reserved_names_refused_through_case_alias(tmp_path: Path, name: str) -> None:
    with open_private_directory(tmp_path / "private", create=True) as d, d.transaction() as tx:
        with pytest.raises(PrivateFSError) as err:
            tx.create_bytes(name, b"bad")
        assert err.value.reason == "unsafe"


@pytest.mark.parametrize("phase", ["staged", "published"])
def test_process_killed_at_publication_boundary_keeps_complete_file(tmp_path: Path, phase: str) -> None:
    import queue
    import sys
    import threading

    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
    worker = r"""
import sys
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes._private_fs._windows_api import get_api
api=get_api()
with open_private_directory(sys.argv[1]) as d,d.transaction() as tx:
    original=api.flush if sys.argv[2]=='staged' else api.rename
    def pause(*args,**kwargs):
        result=original(*args,**kwargs)
        print('boundary',flush=True)
        sys.stdin.readline()
        return result
    if sys.argv[2]=='staged':api.flush=pause
    else:api.rename=pause
    tx.replace_bytes('secret',b'complete new')
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", worker, str(root), phase],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    messages = queue.Queue()
    try:
        threading.Thread(target=lambda: messages.put(child.stdout.readline().strip()), daemon=True).start()
        assert messages.get(timeout=15) == "boundary"
        child.kill()
        child.wait(timeout=15)
        with open_private_directory(root) as d, _eventual_transaction(d):
            assert d.read_bytes("secret", max_bytes=100) == (b"old" if phase == "staged" else b"complete new")
        orphans = list(root.glob(".mordred-fs-tmp-*"))
        if phase == "staged":
            assert len(orphans) == 1
            from mordred_hermes._private_fs._windows_api import get_api
            from mordred_hermes._private_fs._windows_security import validate_private

            with get_api().open(str(orphans[0])) as handle:
                validate_private(handle, directory=False)
        else:
            assert not orphans
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=15)


def test_pinned_parent_cannot_be_renamed(tmp_path: Path) -> None:
    root = tmp_path / "private"
    with open_private_directory(root, create=True), pytest.raises(OSError):
        root.rename(tmp_path / "moved")
    assert root.is_dir()


def test_astral_unicode_filename_roundtrip(tmp_path: Path) -> None:
    with open_private_directory(tmp_path / "秘密 😀", create=True) as d, d.transaction() as tx:
        tx.create_bytes("記録😀.dat", b"old")
        tx.replace_bytes("記録😀.dat", b"new")
        assert d.read_bytes("記録😀.dat", max_bytes=3) == b"new"


@contextlib.contextmanager
def _eventual_transaction(directory):
    deadline = time.monotonic() + 15
    while True:
        lock = directory.transaction(blocking=False)
        try:
            lock.__enter__()
        except PrivateFSError as exc:
            if exc.reason != "busy" or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
        else:
            break
    try:
        yield
    finally:
        lock.__exit__(None, None, None)


def test_long_path_and_overlong_leaf_have_complete_file_semantics(tmp_path: Path) -> None:
    with contextlib.ExitStack() as stack:
        path = tmp_path
        for _ in range(3):
            path = path / ("nested-" + "a" * 90)
            d = stack.enter_context(open_private_directory(path, create=True))
        assert len(str(path)) > 260
        with d.transaction() as tx:
            tx.create_bytes("secret", b"keep")
            with pytest.raises(PrivateFSError) as err:
                tx.create_bytes("x" * 256, b"wrong")
            assert err.value.commit_state == "not_committed"
            assert tx.read_bytes("secret", max_bytes=4) == b"keep"


def test_short_name_alias_cannot_replace_held_sidecar(tmp_path: Path) -> None:
    import ctypes

    from mordred_hermes._private_fs._windows_api import get_api

    root = tmp_path / "private"
    short_path = get_api().kernel.GetShortPathNameW
    short_path.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    short_path.restype = ctypes.c_uint32
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        lock = root / ".mordred-fs.lock"
        buffer = ctypes.create_unicode_buffer(32768)
        assert 0 < short_path(str(lock), buffer, len(buffer)) < len(buffer)
        alias = Path(buffer.value).name
        if alias.casefold() == lock.name:
            pytest.skip("this NTFS volume does not generate a short alias for the sidecar")
        identity = lock.stat().st_ino
        with pytest.raises(PrivateFSError) as err:
            tx.replace_bytes(alias, b"wrong")
        assert err.value.commit_state == "not_committed"
        assert err.value.reason in ("busy", "access_denied", "unsafe")
        assert lock.stat().st_ino == identity


@pytest.mark.parametrize("operation", ["stat", "prefix", "delete", "rename", "append"])
@pytest.mark.parametrize("unsafe", ["acl", "junction"])
def test_native_lifecycle_refuses_unsafe_objects(tmp_path: Path, operation: str, unsafe: str) -> None:
    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"keep")
        if unsafe == "acl":
            subprocess.run(
                ["icacls.exe", str(root / "source"), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True
            )
            name = "source"
        else:
            target = tmp_path / "target"
            target.mkdir()
            subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(root / "junction"), str(target)], check=True, capture_output=True
            )
            name = "junction"
        with pytest.raises(PrivateFSError) as err:
            if operation == "stat":
                tx.stat(name)
            elif operation == "prefix":
                tx.read_prefix(name, max_bytes=1)
            elif operation == "delete":
                tx.delete_file(name)
            elif operation == "rename":
                tx.rename_file(name, "destination")
            else:
                tx.append_bytes(name, b"new")
        assert err.value.reason == "unsafe"
        assert (root / "source").read_bytes() == b"keep"


@pytest.mark.parametrize("operation", ["delete", "rename", "append"])
def test_native_lifecycle_held_handle_refuses_before_mutation(tmp_path: Path, operation: str) -> None:
    from mordred_hermes._private_fs._windows_api import get_api

    root = tmp_path / "private"
    with open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("source", b"keep")
        with get_api().open(str(root / "source"), share=7), pytest.raises(PrivateFSError) as err:
            if operation == "delete":
                tx.delete_file("source")
            elif operation == "rename":
                tx.rename_file("source", "destination")
            else:
                tx.append_bytes("source", b"new")
        assert err.value.reason == "busy"
        assert err.value.commit_state == "not_committed"
        assert tx.read_bytes("source", max_bytes=4) == b"keep"
