"""Windows process discovery refuses uncertainty without leaking process secrets."""

from __future__ import annotations

import os
from pathlib import Path

import psutil
import pytest

from mordred_hermes.keyvault import _runtime_probe as runtime


class Process:
    def __init__(self, pid=42, *, owner="HOST\\alice", name="python.exe", argv=None, denied=None, gone=False, born=1.0):
        self.pid, self.owner, self.image = pid, owner, name
        self.argv = (
            argv if argv is not None else [r"C:\日本 space\python.exe", "-m", "hermes_cli.main", "gateway", "run"]
        )
        self.denied, self.gone, self.born = denied, gone, born

    def value(self, field, value):
        if self.gone:
            raise psutil.NoSuchProcess(self.pid)
        if field == self.denied:
            raise psutil.AccessDenied(self.pid, name="TOP_SECRET")
        return value

    def username(self):
        return self.value("owner", self.owner)

    def name(self):
        return self.value("name", self.image)

    def exe(self):
        return self.value("exe", self.argv[0])

    def cmdline(self):
        return self.value("argv", self.argv)

    def create_time(self):
        return self.value("born", self.born)


def scan(monkeypatch, tmp_path, processes, *, replacement=None, hints=()):
    from mordred_hermes.keyvault import _windows_processes as win

    current = Process(os.getpid(), argv=["python.exe", "-m", "pytest"])
    table = {p.pid: p for p in processes}
    monkeypatch.setattr(psutil, "pids", lambda: list(table))
    monkeypatch.setattr(
        psutil, "Process", lambda pid=None: current if pid in (None, os.getpid()) else (replacement or table[pid])
    )
    monkeypatch.setattr(win, "_read_state_pid", lambda home: None)
    monkeypatch.setattr(win, "_gateway_python", lambda exe: Path(exe))
    return win.inspect_windows_gateway_runtimes(tmp_path, hinted_pids=hints)


def test_windows_inventory_contract_exists():
    assert hasattr(runtime, "require_stopped_windows_gateways")


def test_live_unicode_argv_is_gateway_without_shell_parsing(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process()])
    assert found.state == "known"
    assert [(p.pid, str(p.python)) for p in found.runtimes] == [(42, r"C:\日本 space\python.exe")]


@pytest.mark.parametrize("field", ["owner", "name", "exe", "argv", "born"])
def test_denied_plausible_process_is_unknown_and_secret_free(monkeypatch, tmp_path, field):
    found = scan(monkeypatch, tmp_path, [Process(denied=field)])
    assert found.state == "unknown"
    assert found.reasons and "42" in str(found.reasons)
    assert "TOP_SECRET" not in str(found)


def test_foreign_process_is_excluded_only_with_positive_owner(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(owner="HOST\\bob", denied="argv")])
    assert found.state == "known" and found.runtimes == ()


def test_protected_system_process_does_not_hide_inventory(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(4, name="System", denied="owner")])
    assert found.state == "known" and not found.runtimes


def test_exited_process_is_not_access_denial(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(gone=True)])
    assert found.state == "known" and not found.runtimes


def test_current_user_non_gateway_does_not_block(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(argv=["python.exe", "-m", "pytest"])])
    assert found.state == "known" and not found.runtimes


def test_pid_reuse_refuses(monkeypatch, tmp_path):
    original = Process()
    calls = 0

    def born():
        nonlocal calls
        calls += 1
        return float(calls)

    original.create_time = born
    found = scan(monkeypatch, tmp_path, [original])
    assert found.state == "unknown" and not found.runtimes


def test_hint_for_unrecognized_current_user_process_refuses(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(argv=["custom.exe", "serve"])], hints=(42,))
    assert found.state == "unknown"


def test_diagnostics_are_bounded(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(pid, denied="argv") for pid in range(100, 300)])
    assert found.state == "unknown"
    assert len(found.reasons) <= 33 and len(str(found.reasons)) < 2048


@pytest.mark.parametrize(
    "state, runtimes", [("unknown", ()), ("known", (runtime.GatewayRuntime(42, Path("python.exe")),))]
)
def test_lifecycle_gate_refuses_unknown_or_running(monkeypatch, tmp_path, state, runtimes):
    from mordred_hermes.keyvault import _windows_processes as win

    monkeypatch.setattr(
        win, "inspect_windows_gateway_runtimes", lambda home: win.GatewayInventory(state, runtimes, ("pid=42:denied",))
    )
    with pytest.raises(runtime.GatewayDiscoveryUnavailable):
        runtime.require_stopped_windows_gateways(tmp_path)


def test_list_api_does_not_translate_unknown_to_empty(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(
        win, "inspect_windows_gateway_runtimes", lambda home: win.GatewayInventory("unknown", (), ("scan:denied",))
    )
    with pytest.raises(runtime.GatewayDiscoveryUnavailable):
        runtime.discover_running_gateway_runtimes(tmp_path)


def test_python_flags_cannot_hide_gateway(monkeypatch, tmp_path):
    p = Process(argv=["python.exe", "-X", "utf8", "-u", "-m", "hermes_cli.main", "gateway", "run"])
    assert scan(monkeypatch, tmp_path, [p]).runtimes


def test_unknown_state_file_does_not_mean_no_gateway(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [])

    def unreadable(home):
        raise OSError("TOP_SECRET")

    monkeypatch.setattr(win, "_read_state_pid", unreadable)
    found = win.inspect_windows_gateway_runtimes(tmp_path)
    assert found.state == "unknown" and "TOP_SECRET" not in str(found)


def test_unverified_interpreter_is_unknown(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [Process()])
    monkeypatch.setattr(win, "_gateway_python", lambda *args: None)
    assert win.inspect_windows_gateway_runtimes(tmp_path).state == "unknown"


def test_invalid_authoritative_windows_python_never_falls_back(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    fake = tmp_path / "python.exe"
    fake.write_bytes(b"not a Python environment")
    assert runtime.discover_runtime_python(tmp_path, explicit=fake) is None
    monkeypatch.setenv(runtime.RUNTIME_PYTHON_ENV, str(fake))
    assert runtime.discover_runtime_python(tmp_path) is None


def test_windows_valid_override_uses_shared_validation(monkeypatch, tmp_path):
    import json
    import subprocess

    root = tmp_path / "custom 日本"
    scripts = root / "Scripts"
    scripts.mkdir(parents=True)
    exe = scripts / "python.exe"
    exe.touch()
    (root / "pyvenv.cfg").touch()
    monkeypatch.setattr(runtime.sys, "platform", "win32")

    def run(argv, **kwargs):
        assert argv[0] == str(exe)
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(dict(executable=str(exe), prefix=str(root), hermes=True, environment=True)), ""
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert runtime.discover_runtime_python(tmp_path, explicit=exe) == exe


@pytest.mark.skipif(os.name != "nt", reason="ordinary-user Windows process acceptance")
def test_native_gateway_child_is_discovered_without_cim(tmp_path):
    import subprocess
    import sys

    from mordred_hermes.keyvault import _windows_processes as win

    # The child only sleeps: its argv models a gateway without starting one.
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "hermes_cli.main", "gateway", "run"])
    try:
        inventory = win.inspect_windows_gateway_runtimes(tmp_path)
        assert child.pid in [p.pid for p in inventory.runtimes], inventory
        with pytest.raises(runtime.GatewayDiscoveryUnavailable):
            runtime.require_stopped_windows_gateways(tmp_path)
    finally:
        child.terminate()
        child.wait(timeout=10)


def test_explicit_probe_python_is_validated_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    bogus = tmp_path / "python.exe"
    bogus.touch()
    selected, reason = runtime._resolve_runtime_python(tmp_path, bogus)
    assert selected is None and reason


@pytest.mark.parametrize("payload", [b'{"pid": true}', b'{"pid": 0}', b'{"pid": "42"}', b"not JSON"])
def test_malformed_state_pid_refuses(monkeypatch, tmp_path, payload):
    from contextlib import contextmanager

    from mordred_hermes.keyvault import _windows_processes as win

    class Directory:
        def read_bytes(self, name, *, max_bytes):
            assert name == "gateway_state.json" and max_bytes <= 65536
            return payload

    @contextmanager
    def opened(path):
        yield Directory()

    monkeypatch.setattr(win, "open_optional_confidential_directory", opened)
    with pytest.raises(ValueError):
        win._read_state_pid(tmp_path)


def test_state_argv_cannot_select_interpreter(monkeypatch, tmp_path):
    from contextlib import contextmanager

    from mordred_hermes.keyvault import _windows_processes as win

    class Directory:
        def read_bytes(self, name, *, max_bytes):
            return b'{"pid": 42, "argv": ["secret-bogus-python", "gateway", "run"]}'

    @contextmanager
    def opened(path):
        yield Directory()

    monkeypatch.setattr(win, "open_optional_confidential_directory", opened)
    assert win._read_state_pid(tmp_path) == 42


def test_enumeration_denied_refuses(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [])

    def denied():
        raise psutil.AccessDenied(name="SECRET")

    monkeypatch.setattr(psutil, "pids", denied)
    inventory = win.inspect_windows_gateway_runtimes(tmp_path)
    assert inventory.state == "unknown" and "SECRET" not in str(inventory)


def test_inventory_never_executes_gateway_interpreter(monkeypatch, tmp_path):
    import subprocess

    from mordred_hermes.keyvault import _windows_processes as win

    root = tmp_path / "gateway env"
    scripts = root / "Scripts"
    scripts.mkdir(parents=True)
    exe = scripts / "python.exe"
    exe.touch()
    (root / "pyvenv.cfg").touch()

    def no_exec(*args, **kwargs):
        raise AssertionError("Inventory cannot launch bootstrap while custody locks may be held")

    monkeypatch.setattr(subprocess, "run", no_exec)
    assert win._gateway_python(str(exe)) == exe


def test_deeply_nested_state_is_typed_unknown(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [])

    def excessive_nesting(home):
        raise RecursionError("untrusted state payload")

    monkeypatch.setattr(win, "_read_state_pid", excessive_nesting)
    assert win.inspect_windows_gateway_runtimes(tmp_path).state == "unknown"


def test_custom_python_launcher_cannot_hide_gateway(monkeypatch, tmp_path):
    process = Process(argv=["python.exe", r"C:\日本\custom-launcher.py", "gateway", "run"])
    assert scan(monkeypatch, tmp_path, [process]).runtimes
