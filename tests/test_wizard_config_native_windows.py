"""Native public Windows writer acceptance; host doubles do not replace this suite."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from mordred_hermes._config_io import CanonicalPaths, PolicyPendingError, read_canonical_snapshot
from mordred_hermes._private_fs import PrivateFSError
from mordred_hermes.wizard._uninstall_config import apply_config_cleanup, apply_env_cleanup
from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter
from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter
from mordred_hermes.wizard.policy_writer import PolicySnapshot, PolicyWriter
from tests.test_config_io_windows import line
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows public configuration writers")


@pytest.fixture
def writer(shared_home):
    # The inherited fixture supplies profile-style permissions and a Unicode,
    # space-containing path. Replace its generic byte fixture with valid YAML.
    (shared_home / "config.yaml").write_bytes(b'# retained\nmodel: "original"\n')
    return PolicyWriter(shared_home / "config.yaml", shared_home / "mordred" / "policy.json", shared_home / "mordred")


def private_file(path):
    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    with get_api().open(str(path)) as handle:
        validate_private(handle, directory=False)


@pytest.mark.parametrize("nested_backup", [False, True])
def test_native_configure_rerun_and_private_backups(writer, nested_backup):
    w = writer
    program = """
import argparse
from mordred_hermes.wizard.configure import cli_handler
raise SystemExit(cli_handler(argparse.Namespace(non_interactive=True, policy='strict')))
"""
    kwargs = dict(
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=os.environ | {"HERMES_HOME": str(w.config_path.parent)},
    )
    parent = descriptor(w.config_path.parent)
    subprocess.run([sys.executable, "-c", program], **kwargs)
    before = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
    config_acl = descriptor(w.config_path)
    subprocess.run([sys.executable, "-c", program], **kwargs)
    assert read_canonical_snapshot(CanonicalPaths(w.config_path.parent)) == before
    assert descriptor(w.config_path) == config_acl
    assert descriptor(w.config_path.parent) == parent
    JSONCredentialsWriter().write_network(
        w.mordred_dir / "credentials" / "network.json",
        mullvad_account_id_env="MORDRED_ACCOUNT",
        mullvad_relay_country="auto",
        mullvad_killswitch=True,
    )
    DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_ACCOUNT", value="test-secret")
    config = apply_config_cleanup(w.config_path, lock_dir=w.mordred_dir, stamp="native")
    save_dir = w.mordred_dir / "uninstall" if nested_backup else w.mordred_dir
    env = apply_env_cleanup(w.config_path.parent / ".env", save_dir=save_dir, stamp="native")
    assert config.backup and env.saved_to == save_dir / "env-removed-native.env"
    for path in (
        w.config_path,
        w.policy_json_path,
        config.backup,
        env.saved_to,
        w.mordred_dir / "credentials" / "network.json",
    ):
        private_file(path)
    DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_ACCOUNT", value="new-secret")
    with pytest.raises(PrivateFSError, match="exists"):
        apply_env_cleanup(w.config_path.parent / ".env", save_dir=save_dir, stamp="native")
    assert "new-secret" in (w.config_path.parent / ".env").read_text()


def test_native_fresh_process_config_and_dotenv_updates(writer):
    w = writer
    w.write(PolicySnapshot("strict"))
    program = """
import sys
from pathlib import Path
from mordred_hermes.wizard.policy_writer import PolicyWriter
from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter
home=Path(sys.argv[1]); index=sys.argv[2]
w=PolicyWriter(home/'config.yaml', home/'mordred'/'policy.json', home/'mordred')
w.merge_mordred_sections({'mordred_wizard': {'worker'+index: True}})
DotEnvFileWriter().upsert(home/'.env', key='WORKER_'+index, value='retained')
"""
    children = [
        subprocess.Popen(
            [sys.executable, "-c", program, str(w.config_path.parent), str(i)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for i in range(4)
    ]
    try:
        for child in children:
            _stdout, stderr = child.communicate(timeout=45)
            assert child.returncode == 0, stderr
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
    config = w.config_path.read_text()
    dotenv = (w.config_path.parent / ".env").read_text()
    for i in range(4):
        assert f"worker{i}: true" in config
        assert f"WORKER_{i}=retained" in dotenv


def test_native_public_writer_crash_and_explicit_recovery(writer):
    w = writer
    program = """
import sys
from pathlib import Path
from mordred_hermes._private_fs import _windows_io
from mordred_hermes.wizard.policy_writer import PolicyWriter, PolicySnapshot
original=_windows_io._Transaction.create_bytes
def paused(self, name, data):
    if name=='policy.json':
        print('partial', flush=True)
        sys.stdin.readline()
    return original(self, name, data)
_windows_io._Transaction.create_bytes=paused
home=Path(sys.argv[1])
PolicyWriter(home/'config.yaml', home/'mordred'/'policy.json', home/'mordred').write(PolicySnapshot('strict'))
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", program, str(w.config_path.parent)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert line(child) == "partial"
        child.kill()
        child.communicate(timeout=20)
        with pytest.raises(PolicyPendingError):
            w.merge_mordred_sections({"mordred_wizard": {"done": True}})
        w.write(PolicySnapshot("strict"))
        pair = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
        assert json.loads(pair.policy.data)["policy"] == "strict"
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=20)


def test_native_unsafe_config_acl_is_refused_without_repair(writer):
    w = writer
    original = w.config_path.read_bytes()
    subprocess.run(["icacls.exe", str(w.config_path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = descriptor(w.config_path)
    with pytest.raises(PrivateFSError, match="unsafe"):
        w.write(PolicySnapshot("off"))
    assert w.config_path.read_bytes() == original
    assert descriptor(w.config_path) == before


def test_native_unsafe_pending_marker_cannot_be_recovered(writer):
    from mordred_hermes._private_fs import open_private_directory

    w = writer
    w.write(PolicySnapshot("strict"))
    with open_private_directory(w.mordred_dir) as directory, directory.transaction() as transaction:
        transaction.create_bytes(".policy-write.pending", b"interrupted")
    marker = w.mordred_dir / ".policy-write.pending"
    subprocess.run(["icacls.exe", str(marker), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = w.config_path.read_bytes(), w.policy_json_path.read_bytes(), descriptor(marker)
    with pytest.raises(PrivateFSError, match="unsafe"):
        w.write(PolicySnapshot("off"))
    assert (w.config_path.read_bytes(), w.policy_json_path.read_bytes(), descriptor(marker)) == before


def test_native_hardlinked_config_refused_by_public_writer(writer):
    w = writer
    os.link(w.config_path, w.config_path.with_name("operator-alias.yaml"))
    before = w.config_path.read_bytes()
    with pytest.raises(PrivateFSError, match="unsafe"):
        w.write(PolicySnapshot("off"))
    assert w.config_path.read_bytes() == before


def test_native_busy_explicit_backup_destination_preserves_source(writer):
    w = writer
    w.write(PolicySnapshot("strict"))
    dotenv = w.config_path.parent / ".env"
    DotEnvFileWriter().upsert(dotenv, key="MORDRED_ACCOUNT", value="test-secret")
    before = dotenv.read_bytes()
    destination = w.mordred_dir / "uninstall"
    program = """
import sys
from pathlib import Path
from mordred_hermes._private_fs import open_private_directory
with open_private_directory(Path(sys.argv[1]), create=True) as d, d.transaction():
    print('locked', flush=True)
    sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", program, str(destination)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert line(child) == "locked"
        with pytest.raises(PrivateFSError, match="busy"):
            apply_env_cleanup(dotenv, save_dir=destination, stamp="native")
        assert dotenv.read_bytes() == before
        assert not (destination / "env-removed-native.env").exists()
    finally:
        child.kill()
        child.communicate(timeout=20)
