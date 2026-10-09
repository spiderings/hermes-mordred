"""Fresh-process and thread checks for stable private transactions."""

from __future__ import annotations

import contextlib
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory

_CHILD = """
import sys, time, subprocess
from mordred_hermes._private_fs import open_private_directory, PrivateFSError
with open_private_directory(sys.argv[1]) as d:
    mode = sys.argv[2]
    try:
        print("ready", flush=True)
        with d.transaction(blocking=(mode != "try")) as tx:
            print("locked " + str(time.monotonic_ns()), flush=True)
            if mode == "increment":
                for _ in range(10):
                    value=int(tx.read_bytes("counter", max_bytes=100))
                    tx.replace_bytes("counter", str(value+1).encode())
            elif mode == "hold":
                sys.stdin.readline()
            elif mode == "inherit":
                child=subprocess.Popen(
                    [sys.executable,"-c","import sys; sys.stdin.read()"],
                    close_fds=False,stdin=subprocess.PIPE)
                print("child " + str(child.pid),flush=True)
                sys.stdin.readline()
        if mode == "inherit":
            print("released",flush=True)
            sys.stdin.readline()
            child.communicate(timeout=15)
        elif mode == "hold":
            pass
    except PrivateFSError as exc:
        print("error " + exc.reason,flush=True)
"""


def _line(process: subprocess.Popen[str]) -> str:
    lines: queue.Queue[str] = queue.Queue()
    assert process.stdout is not None
    threading.Thread(target=lambda: lines.put(process.stdout.readline().strip()), daemon=True).start()
    return lines.get(timeout=15)


@contextlib.contextmanager
def _child(root: Path, mode: str) -> Iterator[subprocess.Popen[str]]:
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", _CHILD, str(root), mode],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert _line(process) == "ready"
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=15)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path.resolve() / "private"
    with open_private_directory(path, create=True) as d, d.transaction() as tx:
        tx.create_bytes("counter", b"0")
    return path


def test_second_process_busy(root: Path) -> None:
    with open_private_directory(root) as d, d.transaction(), _child(root, "try") as process:
        assert _line(process) == "error busy"


def test_waiter_enters_after_release(root: Path) -> None:
    with open_private_directory(root) as d, contextlib.ExitStack() as stack:
        lock = d.transaction()
        lock.__enter__()
        try:
            child = stack.enter_context(_child(root, "wait"))
            released = time.monotonic_ns()
        finally:
            lock.__exit__(None, None, None)
        status = _line(child).split()
        assert status[0] == "locked" and int(status[1]) >= released


def test_crashed_owner_releases_lock(root: Path) -> None:
    with _child(root, "hold") as child:
        assert _line(child).startswith("locked ")
        child.kill()
        child.wait(timeout=15)
        with _child(root, "wait") as next_child:
            assert _line(next_child).startswith("locked ")


def test_child_does_not_inherit_lock(root: Path) -> None:
    with _child(root, "inherit") as holder:
        assert _line(holder).startswith("locked ")
        assert _line(holder).startswith("child ")
        assert holder.stdin is not None
        holder.stdin.write("release\n")
        holder.stdin.flush()
        assert _line(holder) == "released"
        with open_private_directory(root) as d, d.transaction(blocking=False):
            pass
        holder.stdin.write("finish\n")
        holder.stdin.flush()
        assert holder.wait(timeout=15) == 0


def test_recursive_transaction_refused(root: Path) -> None:
    with (
        open_private_directory(root) as first,
        open_private_directory(root) as second,
        first.transaction(),
        pytest.raises(RuntimeError),
        second.transaction(),
    ):
        pass


def test_two_threads_serialize(root: Path) -> None:
    result: queue.Queue[str] = queue.Queue()

    def attempt() -> None:
        with open_private_directory(root) as d:
            try:
                with d.transaction(blocking=False):
                    result.put("wrongly acquired")
            except PrivateFSError as exc:
                result.put(exc.reason)

    with open_private_directory(root) as d, d.transaction():
        thread = threading.Thread(target=attempt, daemon=True)
        thread.start()
        assert result.get(timeout=15) == "busy"
        thread.join(timeout=15)


@pytest.mark.skipif(os.name != "nt", reason="Windows case-insensitive alias")
def test_case_alias_serializes(root: Path) -> None:
    with open_private_directory(root) as d, d.transaction(), _child(Path(str(root).upper()), "try") as process:
        assert _line(process) == "error busy"


def test_concurrent_transactional_read_modify_write(root: Path) -> None:
    with contextlib.ExitStack() as stack:
        children = [stack.enter_context(_child(root, "increment")) for _ in range(4)]
        for child in children:
            assert _line(child).startswith("locked ")
            assert child.wait(timeout=15) == 0
    with open_private_directory(root) as d:
        assert d.read_bytes("counter", max_bytes=100) == b"40"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork-without-exec")
def test_forked_child_cannot_retain_parent_lock(root: Path) -> None:
    released, command = os.pipe()
    child = None
    try:
        with open_private_directory(root) as d, d.transaction():
            child = os.fork()
            if child == 0:
                os.close(command)
                try:
                    os.read(released, 1)
                finally:
                    os._exit(0)
        with open_private_directory(root) as d, d.transaction(blocking=False):
            pass
    finally:
        if child:
            os.write(command, b"x")
            os.waitpid(child, 0)
        os.close(released)
        os.close(command)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork-without-exec")
def test_inherited_transaction_cannot_operate_in_child(root: Path) -> None:
    reader, writer = os.pipe()
    with open_private_directory(root) as d, d.transaction() as tx:
        child = os.fork()
        if child == 0:
            os.close(reader)
            try:
                try:
                    tx.read_bytes("counter", max_bytes=100)
                except RuntimeError:
                    os.write(writer, b"refused")
                else:
                    os.write(writer, b"unsafe inherited transaction")
            finally:
                os._exit(0)
        try:
            os.waitpid(child, 0)
            assert os.read(reader, 100) == b"refused"
        finally:
            os.close(reader)
            os.close(writer)


def test_reserved_case_alias_cannot_replace_live_lock(root: Path) -> None:
    with open_private_directory(root) as d, d.transaction() as tx:
        before = (root / ".mordred-fs.lock").stat().st_ino
        with pytest.raises(PrivateFSError) as err:
            tx.replace_bytes(".MORDRED-FS.LOCK", b"new lock")
        assert err.value.reason == "unsafe"
        assert (root / ".mordred-fs.lock").stat().st_ino == before
        with _child(root, "try") as child:
            assert _line(child) == "error busy"


def test_concurrent_checked_append_preserves_every_record(root: Path) -> None:
    program = """
import sys
from mordred_hermes._private_fs import open_private_directory
with open_private_directory(sys.argv[1]) as d:
    for _ in range(10):
        with d.transaction() as tx:
            tx.append_bytes("records", (sys.argv[2] + "\\n").encode())
"""
    with open_private_directory(root) as d, d.transaction() as tx:
        tx.create_bytes("records", b"")
    children = [
        subprocess.Popen(
            [sys.executable, "-c", program, str(root), str(i)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for i in range(4)
    ]
    try:
        for child in children:
            _stdout, stderr = child.communicate(timeout=30)
            assert child.returncode == 0, stderr.decode()
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=15)
    with open_private_directory(root) as d:
        records = d.read_bytes("records", max_bytes=100).splitlines()
    assert len(records) == 40
    for i in range(4):
        assert records.count(str(i).encode()) == 10
