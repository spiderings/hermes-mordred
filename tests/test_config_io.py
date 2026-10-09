"""Exercise the coordinator above injectable checked filesystem capabilities."""

from __future__ import annotations

import threading
from contextlib import contextmanager

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._private_fs import FileIdentity, FileMetadata, PrivateFSError


class Directory:
    def __init__(self, backend, name):
        self.backend = backend
        self.name = name
        self.files = {}
        self.ident = backend.identity()
        self.locked = False

    def directory_identity(self):
        self.backend.event(f"{self.name}:identity")
        return self.ident

    @contextmanager
    def transaction(self, *, blocking=True):
        self.backend.event(f"{self.name}:lock")
        assert not self.locked, "recursive foundation lock"
        self.locked = True
        self.backend.blocking.append(blocking)
        try:
            yield self
        finally:
            self.locked = False
            self.backend.event(f"{self.name}:unlock")

    def stat(self, name):
        self.backend.event(f"{self.name}:stat:{name}")
        if name not in self.files:
            raise PrivateFSError("missing", "stat")
        data, identity = self.files[name]
        return FileMetadata(identity, len(data), 1)

    def read_bytes(self, name, *, max_bytes):
        self.backend.event(f"{self.name}:read:{name}")
        data = self.files[name][0]
        if len(data) > max_bytes:
            raise PrivateFSError("unsafe", "oversize")
        return data

    def create_bytes(self, name, data):
        self.backend.event(f"{self.name}:create:{name}")
        if name in self.files:
            raise PrivateFSError("exists", "create")
        self.files[name] = data, self.backend.identity()

    def replace_bytes(self, name, data):
        self.backend.event(f"{self.name}:replace:{name}")
        self.files[name] = data, self.backend.identity()

    def delete_file(self, name, *, expected_identity=None):
        self.backend.event(f"{self.name}:delete:{name}")
        if self.stat(name).identity != expected_identity:
            raise PrivateFSError("unsafe", "identity")
        del self.files[name]


class Backend:
    def __init__(self):
        self.serial = 0
        self.events = []
        self.blocking = []
        self.fault = None
        self.hook = None
        self.home = Directory(self, "home")
        self.policy = Directory(self, "policy")
        self.home_present = True
        self.policy_present = True

    def identity(self):
        self.serial += 1
        return FileIdentity(1, self.serial.to_bytes(8, "little"))

    def event(self, event):
        self.events.append(event)
        if self.hook:
            self.hook(event)
        if self.fault == event:
            raise PrivateFSError("io", event)

    @contextmanager
    def open_home(self, path, *, create=False):
        self.event("home:open")
        if create:
            self.home_present = True
        try:
            yield self.home if self.home_present else None
        finally:
            self.event("home:close")

    @contextmanager
    def open_policy(self, path, *, create=False):
        assert self.home.locked
        self.event("policy:open")
        if create:
            self.policy_present = True
        try:
            yield self.policy if self.policy_present else None
        finally:
            self.event("policy:close")


@pytest.fixture
def fs(monkeypatch, tmp_path):
    backend = Backend()
    monkeypatch.setattr(cio, "open_confidential_directory", backend.open_home)
    monkeypatch.setattr(cio, "open_optional_confidential_directory", backend.open_home)
    monkeypatch.setattr(cio, "open_private_directory", backend.open_policy)
    monkeypatch.setattr(cio, "open_optional_private_directory", backend.open_policy)
    return backend, cio.CanonicalPaths(tmp_path / "home")


def test_nested_scope_extends_and_releases_in_reverse(fs):
    b, paths = fs
    with cio.canonical_session(paths, scope="home") as outer:
        with cio.canonical_session(paths, scope="policy") as inner:
            assert inner.read_pair().config is None
        assert b.policy.locked
        assert outer.read_home(".env", max_bytes=8) is None
    assert [e for e in b.events if e.endswith((":lock", ":unlock"))] == [
        "home:lock",
        "policy:lock",
        "policy:unlock",
        "home:unlock",
    ]
    with pytest.raises(RuntimeError):
        inner.read_pair()
    with pytest.raises(RuntimeError):
        outer.read_pair()


def test_nested_other_home_and_identity_change_refused(fs):
    b, paths = fs
    with cio.canonical_session(paths, scope="home"):
        with (
            pytest.raises((ValueError, PrivateFSError)),
            cio.canonical_session(cio.CanonicalPaths(paths.home / "other"), scope="home"),
        ):
            pass
        old = b.home.ident
        b.home.ident = b.identity()
        with pytest.raises(PrivateFSError), cio.canonical_session(paths, scope="home"):
            pass
        b.home.ident = old


def test_foreign_thread_session_refused(fs):
    _, paths = fs
    errors = []
    with cio.canonical_session(paths, scope="home") as session:

        def run():
            try:
                session.read_home(".env", max_bytes=8)
            except RuntimeError as exc:
                errors.append(exc)

        t = threading.Thread(target=run)
        t.start()
        t.join()
    assert len(errors) == 1


@pytest.mark.parametrize(
    "home,mordred,config,policy",
    [
        (False, False, False, False),
        (True, False, True, False),
        (True, True, False, False),
        (True, True, True, False),
        (True, True, False, True),
        (True, True, True, True),
    ],
)
def test_snapshot_absence_permutations(fs, home, mordred, config, policy):
    b, paths = fs
    b.home_present, b.policy_present = home, mordred
    if config:
        b.home.create_bytes("config.yaml", b"config")
    if policy:
        b.policy.create_bytes("policy.json", b"policy")
    snapshot = cio.read_canonical_snapshot(paths)
    assert (snapshot.config.data if snapshot.config else None) == (b"config" if config else None)
    assert (snapshot.policy.data if snapshot.policy else None) == (b"policy" if policy else None)
    assert all(blocking is False for blocking in b.blocking)
    assert b.home_present == home and b.policy_present == mordred


@pytest.mark.parametrize("event", ["home:open", "home:close", "policy:open", "policy:close", "home:lock"])
def test_errors_never_become_absence(fs, event):
    b, paths = fs
    b.fault = event
    with pytest.raises(PrivateFSError):
        cio.read_canonical_snapshot(paths)


def test_staging_no_commit_and_noop_preserve_files(fs):
    b, paths = fs
    b.home.create_bytes("config.yaml", b"old")
    original = b.home.files.copy()
    with cio.canonical_session(paths, scope="policy") as session:
        with session.policy_update() as update:
            update.put_config(b"new")
        assert b.home.files == original
        with session.policy_update() as update:
            update.put_config(b"old")
            update.commit()
            with pytest.raises(RuntimeError):
                update.commit()
    assert b.home.files == original
    assert b.policy.files == {}


def test_explicit_pair_commit_and_identity_delete(fs):
    b, paths = fs
    with cio.canonical_session(paths, scope="policy") as session:
        with session.policy_update() as update:
            update.put_config(b"new")
            update.put_policy(b"{}")
            update.commit()
        snap = session.read_pair()
        with session.policy_update() as update:
            update.delete_config(expected_identity=snap.config.metadata.identity)
            update.commit()
    assert b.home.files == {}
    assert b.policy.files["policy.json"][0] == b"{}"
    assert ".policy-write.pending" not in b.policy.files


@pytest.mark.parametrize(
    "event,marker",
    [
        ("policy:create:.policy-write.pending", False),
        ("policy:read:.policy-write.pending", True),
        ("home:create:config.yaml", True),
        ("policy:create:policy.json", True),
        ("policy:delete:.policy-write.pending", True),
        ("policy:unlock", False),
        ("policy:close", False),
        ("home:unlock", False),
        ("home:close", False),
    ],
)
def test_commit_faults_are_reported_without_rollback(fs, event, marker):
    b, paths = fs
    with (
        pytest.raises(PrivateFSError),
        cio.canonical_session(paths, scope="policy") as session,
        session.policy_update() as update,
    ):
        update.put_config(b"new")
        update.put_policy(b"{}")
        b.fault = event
        update.commit()
    assert (".policy-write.pending" in b.policy.files) is marker


def test_verify_pair_failure_retains_marker(fs):
    b, paths = fs

    def corrupt(event):
        if event == "policy:create:policy.json":
            b.home.files["config.yaml"] = b"bad", b.identity()

    b.hook = corrupt
    with (
        pytest.raises(PrivateFSError),
        cio.canonical_session(paths, scope="policy") as session,
        session.policy_update() as update,
    ):
        update.put_config(b"new")
        update.put_policy(b"{}")
        update.commit()
    assert ".policy-write.pending" in b.policy.files


def test_stale_safe_recovery_requires_owning_update(fs):
    b, paths = fs
    b.policy.create_bytes(".policy-write.pending", b"stale")
    with pytest.raises(cio.PolicyPendingError):
        cio.read_canonical_snapshot(paths)
    with cio.canonical_session(paths, scope="policy") as session:
        with pytest.raises(cio.PolicyPendingError), session.policy_update():
            pass
        with session.policy_update(recover_pending=True) as update:
            assert session.read_pair().config is None
            with pytest.raises(cio.PolicyPendingError):
                cio.read_canonical_snapshot(paths)
            update.commit()
    assert ".policy-write.pending" not in b.policy.files


def test_marker_identity_replacement_refuses_finalization(fs):
    b, paths = fs

    def swap(event):
        if event == "policy:delete:.policy-write.pending":
            b.policy.files[".policy-write.pending"] = b"other", b.identity()

    b.hook = swap
    with (
        pytest.raises(PrivateFSError),
        cio.canonical_session(paths, scope="policy") as session,
        session.policy_update() as update,
    ):
        update.put_config(b"new")
        update.commit()
    assert b.policy.files[".policy-write.pending"][0] == b"other"


def test_home_write_bounds_backup_and_config_refusal(fs):
    b, paths = fs
    with cio.canonical_session(paths, scope="home") as session:
        for name in ["config.yaml", "CONFIG.YAML", "../bad", "arbitrary", "mordred/x"]:
            with pytest.raises((ValueError, PrivateFSError)):
                session.write_home(name, b"bad")
        session.write_home(".env", b"secret")
        session.write_home("config.yaml.mordred-uninstall-123.bak", b"backup")
        with pytest.raises(PrivateFSError):
            session.write_home("config.yaml.mordred-uninstall-123.bak", b"overwrite")
        contents = session.read_home(".env", max_bytes=8)
        session.delete_home(".env", expected_identity=contents.metadata.identity)
    assert ".env" not in b.home.files


def test_oversize_and_unsafe_marker_cannot_be_recovered(fs):
    b, paths = fs
    b.policy.create_bytes(".policy-write.pending", b"x" * 4097)
    with (
        pytest.raises(PrivateFSError),
        cio.canonical_session(paths, scope="policy") as session,
        session.policy_update(recover_pending=True),
    ):
        pass
    assert len(b.policy.files[".policy-write.pending"][0]) == 4097


def test_failed_scope_extension_cannot_be_reused_as_absence(fs):
    b, paths = fs
    with pytest.raises(PrivateFSError), cio.canonical_session(paths, scope="home") as session:
        b.fault = "policy:open"
        with pytest.raises(PrivateFSError), cio.canonical_session(paths, scope="policy"):
            pass
        b.fault = None
        session.read_pair()


def test_missing_stat_with_uncertain_cleanup_is_not_absence(fs):
    b, paths = fs

    def uncertain(event):
        if event == "home:stat:config.yaml":
            raise PrivateFSError("missing", "stat", commit_state="uncertain")

    b.hook = uncertain
    with pytest.raises(PrivateFSError) as err:
        cio.read_canonical_snapshot(paths)
    assert err.value.commit_state == "uncertain"


def test_snapshot_busy_in_other_thread(fs):
    _, paths = fs
    errors = []
    with cio.canonical_session(paths, scope="home"):

        def run():
            try:
                cio.read_canonical_snapshot(paths)
            except PrivateFSError as exc:
                errors.append(exc.reason)

        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert errors == ["busy"]


def test_process_identity_change_invalidates_session(fs, monkeypatch):
    _, paths = fs
    with (
        pytest.raises(RuntimeError),
        cio.canonical_session(paths, scope="home") as session,
        monkeypatch.context() as scoped,
    ):
        scoped.setattr(cio.os, "getpid", lambda: -1)
        session.read_home(".env", max_bytes=8)


def test_expired_update_and_custom_leaf_pair(fs):
    b, paths = fs
    custom = cio.CanonicalPaths(paths.home, config_name="custom.yaml", policy_name="custom.json")
    with cio.canonical_session(custom, scope="policy") as session:
        with session.policy_update() as update:
            update.put_config(b"custom")
            update.put_policy(b"{}")
            update.commit()
        with pytest.raises(RuntimeError):
            update.put_config(b"late")
    assert b.home.files["custom.yaml"][0] == b"custom"
    assert cio.read_canonical_snapshot(custom).policy.data == b"{}"


def test_original_changed_before_commit_prevents_marker(fs):
    b, paths = fs
    b.home.create_bytes("config.yaml", b"old")
    with (
        pytest.raises(PrivateFSError),
        cio.canonical_session(paths, scope="policy") as session,
        session.policy_update() as update,
    ):
        update.put_config(b"new")
        b.home.files["config.yaml"] = b"other", b.identity()
        update.commit()
    assert ".policy-write.pending" not in b.policy.files
    assert b.home.files["config.yaml"][0] == b"other"


def test_read_marker_is_bounded_and_checked(fs):
    b, paths = fs
    b.policy.create_bytes(".policy-write.pending", b"diagnostic")
    assert cio.read_policy_marker(paths).data == b"diagnostic"
    b.policy.files[".policy-write.pending"] = b"x" * 4097, b.identity()
    with pytest.raises(PrivateFSError):
        cio.read_policy_marker(paths)


def test_post_marker_delete_failure_reports_uncertainty(fs):
    b, paths = fs

    def fail_after_delete(event):
        if (
            event == "policy:stat:.policy-write.pending"
            and "policy:delete:.policy-write.pending" in b.events
            and ".policy-write.pending" not in b.policy.files
        ):
            raise PrivateFSError("io", "post_delete")

    b.hook = fail_after_delete
    with (
        pytest.raises(PrivateFSError) as err,
        cio.canonical_session(paths, scope="policy") as session,
        session.policy_update() as update,
    ):
        update.put_config(b"new")
        update.commit()
    assert err.value.commit_state == "uncertain"
    assert ".policy-write.pending" not in b.policy.files
    assert b.home.files["config.yaml"][0] == b"new"


def test_recovery_read_requires_owning_session(fs):
    b, paths = fs
    b.policy.create_bytes(".policy-write.pending", b"stale")
    with cio.canonical_session(paths, scope="policy") as owner, owner.policy_update(recover_pending=True):
        assert owner.read_pair().policy is None
        with cio.canonical_session(paths, scope="policy") as other, pytest.raises(cio.PolicyPendingError):
            other.read_pair()


@pytest.mark.parametrize(
    "home_present,policy_present,event", [(False, False, "home:close"), (True, False, "policy:close")]
)
def test_absent_directory_cleanup_must_finish_before_snapshot(fs, home_present, policy_present, event):
    b, paths = fs
    b.home_present, b.policy_present = home_present, policy_present
    b.fault = event
    with pytest.raises(PrivateFSError):
        cio.read_canonical_snapshot(paths)


@pytest.mark.parametrize("reason", ["busy", "unsafe", "access_denied", "unsupported"])
def test_foundation_errors_are_preserved(fs, reason):
    b, paths = fs

    def refuse(event):
        if event == "home:lock":
            raise PrivateFSError(reason, "lock")

    b.hook = refuse
    with pytest.raises(PrivateFSError) as err:
        cio.read_canonical_snapshot(paths)
    assert err.value.reason == reason


@pytest.mark.parametrize("operation", ["write", "delete", "commit"])
@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_caught_uncertain_mutation_survives_outer_exit(fs, operation, cleanup_failure):
    b, paths = fs
    b.home.create_bytes(".env", b"old")
    original = PrivateFSError("io", "injected_mutation", commit_state="uncertain")
    event = {"write": "home:replace:.env", "delete": "home:delete:.env", "commit": "home:create:config.yaml"}[operation]

    def refuse(actual):
        if actual == event:
            raise original

    b.hook = refuse
    with pytest.raises(PrivateFSError) as outer, cio.canonical_session(paths, scope="policy") as session:
        with pytest.raises(PrivateFSError) as caught:
            if operation == "write":
                session.write_home(".env", b"new")
            elif operation == "delete":
                session.delete_home(".env", expected_identity=b.home.stat(".env").identity)
            else:
                with session.policy_update() as update:
                    update.put_config(b"new")
                    update.commit()
        assert caught.value is original
        with pytest.raises(PrivateFSError) as subsequent:
            session.read_home(".env", max_bytes=10)
        assert subsequent.value is original
        b.hook = None
        if cleanup_failure:
            b.fault = "home:close"
    assert outer.value is original
    assert outer.value.commit_state == "uncertain"


def test_nested_snapshot_extension_remains_nonblocking(fs):
    b, paths = fs
    with cio.canonical_session(paths, scope="home", blocking=True):
        assert cio.read_canonical_snapshot(paths).config is None
    assert b.blocking == [True, False]


@pytest.mark.parametrize("operation", ["write", "delete"])
@pytest.mark.parametrize("spelling", [".env.mordred-uninstall-123.bak", ".ENV.MORDRED-UNINSTALL-123.BAK"])
def test_backup_shaped_config_cannot_bypass_pair_protocol(fs, operation, spelling):
    b, paths = fs
    custom = cio.CanonicalPaths(paths.home, config_name=".env.mordred-uninstall-123.bak")
    b.home.create_bytes(spelling, b"original")
    original = b.home.files.copy()
    with cio.canonical_session(custom, scope="home") as session, pytest.raises(ValueError):
        if operation == "write":
            session.write_home(spelling, b"new")
        else:
            session.delete_home(spelling, expected_identity=b.home.stat(spelling).identity)
    assert b.home.files == original


@pytest.mark.parametrize("operation", ["write", "delete"])
def test_caught_post_publication_verification_failure_is_retained(fs, operation):
    b, paths = fs
    if operation == "delete":
        b.home.create_bytes(".env", b"old")
    failure = PrivateFSError("io", "verification")
    changed = False

    def fail_verification(event):
        nonlocal changed
        if event == f"home:{'create' if operation == 'write' else 'delete'}:.env":
            changed = True
        if changed and (event == "home:read:.env" or (operation == "delete" and ".env" not in b.home.files)):
            raise failure

    with pytest.raises(PrivateFSError) as outer, cio.canonical_session(paths, scope="home") as session:
        identity = b.home.stat(".env").identity if operation == "delete" else None
        b.hook = fail_verification
        with pytest.raises(PrivateFSError) as inner:
            if operation == "write":
                session.write_home(".env", b"new")
            else:
                session.delete_home(".env", expected_identity=identity)
        assert inner.value is failure
        b.hook = None
    assert outer.value is failure
    assert failure.commit_state == "uncertain"


def test_backup_shaped_config_cannot_be_created_through_home_writer(fs):
    b, paths = fs
    custom = cio.CanonicalPaths(paths.home, config_name=".env.mordred-uninstall-123.bak")
    with cio.canonical_session(custom, scope="home") as session, pytest.raises(ValueError):
        session.write_home(custom.config_name, b"new")
    assert b.home.files == {} and b.policy.files == {}


def test_caught_nested_cleanup_uncertainty_survives_outer_exit(fs):
    b, paths = fs
    failure = PrivateFSError("io", "nested_cleanup", commit_state="uncertain")

    def fail_once(event):
        if event == "home:close":
            b.hook = None
            raise failure

    with pytest.raises(PrivateFSError) as outer, cio.canonical_session(paths, scope="home") as session:
        b.hook = fail_once
        with pytest.raises(PrivateFSError) as nested, cio.canonical_session(paths, scope="home"):
            pass
        assert nested.value is failure
        with pytest.raises(PrivateFSError) as subsequent:
            session.read_home(".env", max_bytes=8)
        assert subsequent.value is failure
    assert outer.value is failure and outer.value.commit_state == "uncertain"


def test_nested_ordinary_read_refusal_does_not_claim_mutation_uncertainty(fs):
    b, paths = fs
    b.home.create_bytes(".env", b"old")
    failure = PrivateFSError("access_denied", "read")

    def refuse(event):
        if event == "home:read:.env":
            raise failure

    with cio.canonical_session(paths, scope="home") as outer:
        b.hook = refuse
        with pytest.raises(PrivateFSError) as error, cio.canonical_session(paths, scope="home") as inner:
            inner.read_home(".env", max_bytes=8)
        b.hook = None
        assert error.value is failure and failure.commit_state == "not_committed"
        assert outer.read_home(".env", max_bytes=8).data == b"old"


def test_policy_backup_checked_no_replace_and_canonical_exclusion(fs):
    b, paths = fs
    with cio.canonical_session(paths, scope="policy", create=True) as session:
        session.create_policy_backup("env-removed-2026.env", b"secret")
        with pytest.raises(cio.PrivateFSError, match="exists"):
            session.create_policy_backup("env-removed-2026.env", b"other")
    assert b.policy.files["env-removed-2026.env"][0] == b"secret"
    custom = cio.CanonicalPaths(paths.home, policy_name="env-removed-2026.env")
    with cio.canonical_session(custom, scope="policy") as session, pytest.raises(ValueError):
        session.create_policy_backup("ENV-REMOVED-2026.ENV", b"overwrite")


def test_policy_backup_verification_failure_poisoned(fs):
    b, paths = fs
    with (
        pytest.raises(cio.PrivateFSError) as error,
        cio.canonical_session(paths, scope="policy", create=True) as session,
    ):

        def fail_after_create(event):
            if event == "policy:create:env-removed-now.env":
                b.fault = "policy:read:env-removed-now.env"

        b.hook = fail_after_create
        with pytest.raises(cio.PrivateFSError):
            session.create_policy_backup("env-removed-now.env", b"secret")
    assert error.value.commit_state == "uncertain"
