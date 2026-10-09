"""Real process locks plus borrowed-owner inversion regression (also Windows CI)."""

from __future__ import annotations

import subprocess
import sys

from mordred_hermes import _audit_io as audit
from tests.test_audit_session import audit_path as audit_path_fixture  # noqa: F401
from tests.test_private_fs_processes import _line

_CHILD = """
import sys
from pathlib import Path
from mordred_hermes._audit_io import audit_session
from mordred_hermes._private_fs import PrivateFSError
print('ready', flush=True)
try:
    with audit_session(Path(sys.argv[1]), create=True, blocking=sys.argv[2] != 'try') as session:
        meta = session.stat(session.active_name)
        session.append(session.active_name, b'child\\n', expected_identity=meta.identity)
    print('committed', flush=True)
except PrivateFSError as exc:
    print(exc.reason, flush=True)
"""


def test_audit_cross_process_try_and_wait(audit_path):
    with audit.audit_session(audit_path) as session:
        session.create(session.active_name, b"parent\n")
        busy = subprocess.run(
            [sys.executable, "-c", _CHILD, str(audit_path), "try"], capture_output=True, text=True, timeout=15
        )
        assert busy.returncode == 0, busy.stderr
        assert busy.stdout.splitlines() == ["ready", "busy"]
        waiting = subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(audit_path), "wait"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert _line(waiting) == "ready"
            assert waiting.poll() is None
        except BaseException:
            waiting.kill()
            waiting.communicate(timeout=15)
            raise
    try:
        out, err = waiting.communicate(timeout=15)
        assert waiting.returncode == 0, err
        assert out.strip() == "committed"
    finally:
        if waiting.poll() is None:
            waiting.kill()
            waiting.communicate(timeout=15)
    assert audit.read_audit_snapshot(audit_path, max_bytes=100).data == b"parent\nchild\n"


def test_waiting_thread_cannot_block_explicit_owner_borrow(audit_path):
    # Run potential deadlock in a killable process; no hung test-runner thread.
    script = """
import sys, threading
from contextlib import contextmanager
from pathlib import Path
from mordred_hermes._audit_io import audit_session
from mordred_hermes import _private_fs as fs
from mordred_hermes._private_fs import open_private_directory
path=Path(sys.argv[1])
started=threading.Event()
errors=[]
def waiter():
    try:
        with audit_session(path, create=True): pass
    except BaseException as exc: errors.append(exc)
with open_private_directory(path.parent) as directory, directory.transaction() as tx:
    @contextmanager
    def tracked_open(*args, **kwargs):
        with open_private_directory(*args, **kwargs) as checked:
            original=checked.transaction
            @contextmanager
            def tracked_transaction(**options):
                started.set()
                with original(**options) as transaction: yield transaction
            checked.transaction=tracked_transaction
            yield checked
    fs.open_private_directory=tracked_open
    thread=threading.Thread(target=waiter, daemon=True)
    thread.start()
    assert started.wait(5)
    with audit_session(path, create=True, transaction=tx) as session:
        session.create('borrowed', b'valid')
thread.join(5)
assert not thread.is_alive() and not errors, errors
"""
    result = subprocess.run([sys.executable, "-c", script, str(audit_path)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_minimal_import_has_no_consumer_or_crypto_dependencies():
    script = """
import sys
import mordred_hermes._audit_io
import mordred_hermes._log_rotation
assert not any(name.startswith(('mordred_hermes.keyvault', 'mordred_hermes.privacy_check',
    'mordred_hermes.wizard', 'cryptography')) for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
