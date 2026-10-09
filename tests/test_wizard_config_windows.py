"""Windows writer consumers over the real canonical coordinator."""

from __future__ import annotations

import json

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes.wizard import _uninstall_config as cleanup
from mordred_hermes.wizard import configure, egress_cli
from mordred_hermes.wizard import credentials_writer as credentials
from mordred_hermes.wizard import env_file_writer as env
from mordred_hermes.wizard import policy_writer as pw
from tests.test_config_io import fs as fs


@pytest.fixture
def writer(fs, monkeypatch):
    backend, paths = fs
    monkeypatch.setattr(pw, "_windows", lambda: True, raising=False)
    monkeypatch.setattr(env, "_windows", lambda: True, raising=False)
    return backend, pw.PolicyWriter(
        paths.home / paths.config_name, paths.home / "mordred" / "policy.json", paths.home / "mordred"
    )


def put(directory, name, data):
    directory.files[name] = data, directory.backend.identity()


def test_write_preserves_yaml_overrides_and_noop_identity(writer):
    b, w = writer
    put(b.home, "config.yaml", b'# retained\nmodel: "quoted"\nplugins:\n  enabled: [other, mordred_network]\n')
    put(b.policy, "policy.json", b'{"provider_overrides": ["opaque-invalid"]}')
    w.write(pw.PolicySnapshot("strict"))
    config = b.home.files["config.yaml"][0].decode()
    assert "# retained" in config and 'model: "quoted"' in config
    assert "other" in config and "mordred_network" not in config
    assert json.loads(b.policy.files["policy.json"][0])["provider_overrides"] == ["opaque-invalid"]
    before = b.home.files.copy(), b.policy.files.copy()
    w.write(pw.PolicySnapshot("strict"))
    assert (b.home.files, b.policy.files) == before
    assert ".policy-write.pending" not in b.policy.files


@pytest.mark.parametrize(
    "member,data", [("config", b"[unterminated"), ("config", b"[]"), ("policy", b"{oops"), ("policy", b"[]")]
)
@pytest.mark.parametrize("operation", ["write", "emit", "upsert", "merge", "migrate"])
def test_whole_malformed_pair_refused_without_publication(writer, member, data, operation):
    b, w = writer
    put(b.home, "config.yaml", b"{}")
    put(b.policy, "policy.json", b"{}")
    put(b.home if member == "config" else b.policy, "config.yaml" if member == "config" else "policy.json", data)
    before = b.home.files.copy(), b.policy.files.copy()
    with pytest.raises(ValueError):
        invoke(w, operation)
    assert (b.home.files, b.policy.files) == before


def invoke(w, operation):
    if operation == "write":
        w.write(pw.PolicySnapshot("strict"))
    elif operation == "emit":
        w.emit_policy_json(pw.PolicySnapshot("strict"))
    elif operation == "migrate":
        w.migrate_plugin_identity(create_missing=True)
    else:
        getattr(w, f"{operation}_mordred_sections")({"mordred_wizard": {"done": True}})


@pytest.mark.parametrize("operation", ["emit", "upsert", "merge", "migrate"])
def test_only_full_write_recovers_pending_pair(writer, operation):
    b, w = writer
    put(b.policy, ".policy-write.pending", b"prior interrupted update")
    with pytest.raises(cio.PolicyPendingError):
        invoke(w, operation)
    w.write(pw.PolicySnapshot("strict"))
    assert ".policy-write.pending" not in b.policy.files


def test_dotenv_checked_rmw_preserves_export_style(writer):
    b, w = writer
    put(b.home, ".env", b"# retained\nexport MORDRED_TOKEN=old\nOTHER=value\n")
    env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_TOKEN", value="new")
    assert b.home.files[".env"][0] == b"# retained\nexport MORDRED_TOKEN=new\nOTHER=value\n"


def test_dotenv_surrogate_rejected_before_any_filesystem_work(writer):
    b, w = writer
    with pytest.raises(UnicodeError):
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_TOKEN", value="\ud800")
    assert b.events == []


def test_cleanup_rereads_and_backs_up_current_pair(writer, monkeypatch):

    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True, raising=False)
    put(b.home, "config.yaml", b"plugins:\n  enabled: [mordred, other]\n")
    plan = cleanup.plan_config_cleanup(w.config_path)
    assert plan.changed
    put(b.home, "config.yaml", b"# new edit\nmodel: newer\nplugins:\n  enabled: [mordred, other]\n")
    result = cleanup.apply_config_cleanup(w.config_path, lock_dir=w.mordred_dir, stamp="now")
    assert result.error is None
    assert b"newer" in b.home.files["config.yaml"][0]
    assert b"mordred" not in b.home.files["config.yaml"][0]
    assert b.home.files["config.yaml.mordred-uninstall-now.bak"][0].startswith(b"# new edit")


def test_cleanup_env_preserves_published_backup_path_and_collision_source(writer, monkeypatch):

    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True, raising=False)
    put(b.home, ".env", b"OTHER=kept\nMORDRED_TOKEN=secret\n")
    result = cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir, stamp="now")
    assert result.saved_to == w.mordred_dir / "env-removed-now.env"
    assert b.home.files[".env"][0] == b"OTHER=kept\n"
    assert b"MORDRED_TOKEN=secret" in b.policy.files["env-removed-now.env"][0]
    put(b.home, ".env", b"MORDRED_TOKEN=new\n")
    with pytest.raises(cio.PrivateFSError, match="exists"):
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir, stamp="now")
    assert b.home.files[".env"][0] == b"MORDRED_TOKEN=new\n"


@pytest.fixture
def child(writer, monkeypatch):
    from contextlib import contextmanager

    from tests.test_config_io import Directory

    b, w = writer
    d = Directory(b, "child")

    @contextmanager
    def opener(path, *, create=False):
        assert b.home.locked and b.policy.locked
        assert path not in (w.mordred_dir, w.config_path.parent)
        yield d

    monkeypatch.setattr(credentials, "_windows", lambda: True, raising=False)
    monkeypatch.setattr(cleanup, "_windows", lambda: True, raising=False)
    monkeypatch.setattr(pw, "open_private_directory", opener, raising=False)
    return b, w, d


def test_credentials_checked_child_and_noop(child):
    from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter

    _b, w, d = child
    target = w.mordred_dir / "credentials" / "network.json"
    kwargs = dict(mullvad_account_id_env="MORDRED_ACCOUNT", mullvad_relay_country="auto", mullvad_killswitch=True)
    JSONCredentialsWriter().write_network(target, **kwargs)
    before = d.files.copy()
    JSONCredentialsWriter().write_network(target, **kwargs)
    assert d.files == before
    assert json.loads(d.files["network.json"][0])["mullvad"]["account_id_env"] == "MORDRED_ACCOUNT"


def test_explicit_backup_directory_kept_and_outer_cleanup_uncertain(child):

    b, w, d = child
    put(b.home, ".env", b"MORDRED_TOKEN=secret\n")
    savedir = w.mordred_dir / "backups"
    b.fault = "home:close"
    with pytest.raises(cio.PrivateFSError) as error:
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=savedir, stamp="now")
    assert d.files["env-removed-now.env"][0].endswith(b"MORDRED_TOKEN=secret\n")
    assert error.value.commit_state == "uncertain"


def test_configure_flags_resolve_from_locked_current_pair(writer, monkeypatch):
    import argparse

    b, w = writer
    put(b.policy, "policy.json", b'{"policy":"lenient", "local_llm_model_id":"kept"}')
    put(b.home, "config.yaml", b"plugins:\n  mordred_llm_guard:\n    harness_primary: other\n")
    monkeypatch.setattr(configure, "PolicyWriter", lambda: w)
    monkeypatch.setattr(configure, "_windows", lambda: True, raising=False)
    assert configure.cli_handler(argparse.Namespace(non_interactive=True, policy="strict")) == 0
    body = json.loads(b.policy.files["policy.json"][0])
    assert body["policy"] == "strict" and body["local_llm_model_id"] == "kept"


def test_egress_edits_preserve_checked_unrelated_fields(writer, monkeypatch):

    b, w = writer
    put(
        b.home,
        "config.yaml",
        b"plugins:\n  mordred_privacy_check:\n    tool_egress:\n      taint: false\n      blocklist: [example.org]\n",
    )
    monkeypatch.setattr(egress_cli, "_windows", lambda: True, raising=False)
    assert egress_cli.egress_set("ask", config_path=w.config_path) == 0
    assert b"example.org" in b.home.files["config.yaml"][0]
    assert b"taint: false" in b.home.files["config.yaml"][0]
    assert b"level: ask" in b.home.files["config.yaml"][0]


def test_generic_windows_writer_does_not_enable_unmigrated_lifecycle(writer):
    _, w = writer
    with pytest.raises(cio.PrivateFSError, match="unsupported"):
        pw._atomic_write_text(w.mordred_dir / "memory-enabled", "enabled")


@pytest.mark.parametrize("data", [b"", b"null", b"42", b"\xff"])
def test_present_nonmapping_config_never_becomes_fresh_state(writer, data):
    b, w = writer
    put(b.home, "config.yaml", data)
    with pytest.raises((ValueError, UnicodeError)):
        w.write(pw.PolicySnapshot("strict"))
    assert b.home.files["config.yaml"][0] == data
    assert "policy.json" not in b.policy.files


@pytest.mark.parametrize("fault", ["policy:create:policy.json", "policy:delete:.policy-write.pending", "home:close"])
def test_public_writer_publication_fault_keeps_uncertainty(writer, fault):
    b, w = writer
    b.fault = fault
    with pytest.raises(cio.PrivateFSError) as error:
        w.write(pw.PolicySnapshot("strict"))
    assert error.value.commit_state == "uncertain"
    if fault != "home:close":
        assert ".policy-write.pending" in b.policy.files


@pytest.mark.parametrize("data", [b"\xff", b"x" * (cio.DOTENV_LIMIT + 1)])
def test_bad_dotenv_source_stays_unchanged(writer, data):
    b, w = writer
    put(b.home, ".env", data)
    with pytest.raises((UnicodeError, cio.PrivateFSError)):
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="KEY", value="new")
    assert b.home.files[".env"][0] == data


def test_custom_pair_names_and_split_roots(writer):
    b, w = writer
    custom = pw.PolicyWriter(
        w.config_path.with_name("custom.yaml"), w.policy_json_path.with_name("custom.json"), w.mordred_dir
    )
    custom.write(pw.PolicySnapshot("strict"))
    assert b"policy: strict" in b.home.files["custom.yaml"][0]
    assert json.loads(b.policy.files["custom.json"][0])["policy"] == "strict"
    custom.mordred_dir = custom.mordred_dir / "elsewhere"
    with pytest.raises(ValueError):
        custom.write(pw.PolicySnapshot("off"))


@pytest.mark.parametrize("stamp", ["../escape", "x.y", "", "colon:stream"])
def test_cleanup_stamp_rejected_before_reads(writer, monkeypatch, stamp):

    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True)
    with pytest.raises(ValueError):
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir, stamp=stamp)
    assert not b.events


def test_dotenv_newline_key_is_rejected_before_mutation(writer):
    b, w = writer
    with pytest.raises(ValueError):
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="KEY\n", value="secret")
    assert not b.events


def test_credentials_newline_reference_is_rejected_before_mutation(child):
    b, w, _d = child
    with pytest.raises(ValueError):
        credentials.JSONCredentialsWriter().write_network(
            w.mordred_dir / "credentials" / "network.json",
            mullvad_account_id_env="MORDRED_ACCOUNT\n",
            mullvad_relay_country="auto",
            mullvad_killswitch=True,
        )
    assert not b.events


def test_credentials_rejection_does_not_disclose_secret_candidate(child):
    _b, w, _d = child
    secret = "1234-5678-private-account"
    with pytest.raises(ValueError) as error:
        credentials.JSONCredentialsWriter().write_network(
            w.mordred_dir / "credentials" / "network.json",
            mullvad_account_id_env=secret,
            mullvad_relay_country="auto",
            mullvad_killswitch=True,
        )
    assert secret not in str(error.value)


def test_busy_explicit_backup_destination_refuses_without_wait_or_source_change(child, monkeypatch):
    from contextlib import contextmanager

    b, w, d = child
    put(b.home, ".env", b"MORDRED_TOKEN=secret\n")

    @contextmanager
    def held_destination(*, blocking=True):
        if blocking:
            raise AssertionError("explicit backup acquisition would wait while holding canonical locks")
        raise cio.PrivateFSError("busy", "private_lock")
        yield  # pragma: no cover

    monkeypatch.setattr(d, "transaction", held_destination)
    with pytest.raises(cio.PrivateFSError, match="busy"):
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir / "custom-backup", stamp="now")
    assert b.home.files[".env"][0] == b"MORDRED_TOKEN=secret\n"
    assert d.files == {}
