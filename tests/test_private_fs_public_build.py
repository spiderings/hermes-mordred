"""Public immutable build-source reads never relax stored-file admission."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from mordred_hermes._private_fs import FileIdentity, PrivateFSError
from mordred_hermes._private_fs._windows_api import Metadata
from mordred_hermes._private_fs._windows_security import FULL_CONTROL, Ace, Descriptor


def test_public_source_capability_is_exported():
    import mordred_hermes._private_fs as fs

    assert callable(getattr(fs, "read_public_build_output", None))


def test_public_source_capability_is_windows_only(monkeypatch):
    import mordred_hermes._private_fs as fs

    monkeypatch.setattr(fs, "_platform", "posix")
    with pytest.raises(PrivateFSError) as refused:
        fs.read_public_build_output("unused/helper.exe", max_bytes=100)
    assert refused.value.reason == "unsupported"


@pytest.fixture
def source_backend(monkeypatch):
    from mordred_hermes._private_fs import _windows_public as reader

    content = b"MZ public Cargo executable"
    user = b"user"
    path = r"\\?\Volume{fixture}\build\helper.exe"
    trace = []
    state = {
        "metadata": Metadata(FileIdentity(7, b"file"), False, False, 2, len(content)),
        "descriptor": Descriptor(user, False, [Ace(0, 0, FULL_CONTROL, user)]),
        "failure": None,
    }

    class Api:
        @contextmanager
        def open(self, candidate, *, share):
            assert candidate == path and share == 1
            trace.append("open")
            try:
                yield SimpleNamespace(api=self)
            finally:
                trace.append("close")
                if state["failure"] == "file_close":
                    raise PrivateFSError("io", "close")

        def metadata(self, handle):
            return state["metadata"]

        def descriptor(self, handle):
            return state["descriptor"]

        def user_sid(self):
            return user

        def final_path(self, handle):
            return path

        def read(self, handle, count):
            trace.append("read")
            if state["failure"] == "changed":
                state["metadata"] = Metadata(FileIdentity(7, b"changed"), False, False, 2, len(content))
            return content

    api = Api()
    parent = SimpleNamespace(
        path=r"\\?\Volume{fixture}\build",
        identity=FileIdentity(7, b"dir"),
        handle=SimpleNamespace(api=api),
        check=lambda: trace.append("parent_check"),
    )

    @contextmanager
    def checked(*args, **kwargs):
        assert kwargs == {"confidential": True}
        try:
            yield parent
        finally:
            trace.append("parent_close")
            if state["failure"] == "parent_close":
                raise PrivateFSError("io", "directory_close")

    monkeypatch.setattr(reader, "checked_directory_optional", checked)
    return reader, state, trace, content


def test_public_hardlinked_source_returns_only_after_scopes_close(source_backend):
    reader, _state, trace, content = source_backend
    assert reader.read_public_build_output("build/helper.exe", max_bytes=100) == content
    assert trace.count("read") == 1 and trace[-1] == "parent_close"
    assert trace.count("open") == trace.count("close")


def test_public_source_allows_foreign_read_only_grants(source_backend):
    reader, state, _trace, content = source_backend
    state["descriptor"].aces.append(Ace(0, 0, 0x120089, b"outside"))
    assert reader.read_public_build_output("build/helper.exe", max_bytes=100) == content


@pytest.mark.parametrize("failure", ["changed", "file_close", "parent_close"])
def test_public_source_postcheck_and_cleanup_failures_return_no_bytes(source_backend, failure):
    reader, state, trace, _content = source_backend
    state["failure"] = failure
    with pytest.raises(PrivateFSError):
        reader.read_public_build_output("build/helper.exe", max_bytes=100)
    assert trace.count("read") == 1


@pytest.mark.parametrize("unsafe", ["reparse", "directory", "foreign_write", "oversized"])
def test_public_source_refuses_unsafe_objects_before_read(source_backend, unsafe):
    reader, state, trace, _content = source_backend
    if unsafe == "foreign_write":
        state["descriptor"] = Descriptor(b"user", False, [Ace(0, 0, FULL_CONTROL, b"outside")])
    else:
        meta = state["metadata"]
        state["metadata"] = Metadata(
            meta.identity, unsafe == "directory", unsafe == "reparse", 2, 1000 if unsafe == "oversized" else meta.size
        )
    with pytest.raises(PrivateFSError) as captured:
        reader.read_public_build_output("build/helper.exe", max_bytes=100)
    assert captured.value.reason == "unsafe"
    assert "read" not in trace
    assert trace[-1] == "parent_close" and trace.count("open") == trace.count("close")


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, 64 * 1024 * 1024 + 1])
def test_public_source_bound_is_checked_before_open(source_backend, limit):
    reader, _state, trace, _content = source_backend
    with pytest.raises(PrivateFSError) as refused:
        reader.read_public_build_output("build/helper.exe", max_bytes=limit)
    assert refused.value.reason == "unsafe" and not trace
