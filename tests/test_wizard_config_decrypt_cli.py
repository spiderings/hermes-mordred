"""Tests for ``hermes mordred vault {enable,disable}-config-decrypt`` (v2-F8 Phase 3).

The operator on-ramp for config.yaml at-rest: ``enable`` enrolls
``<home>/config.yaml`` into the vault and writes the opt-in marker the startup
hook keys on; ``disable`` removes the marker and guarantees a readable plaintext
config.yaml is back on disk (recovery), leaving the vault copy intact.

Built on the shared software fakes so the real init → enroll → hot-path-open path
runs on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, vault
from mordred_hermes.keyvault._config_bootstrap import _marker_path
from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.wizard import _runtime_gate, config_decrypt_cli

from ._helpers import _init_empty_vault
from ._keyvault_fakes import FakeAnchorStore, FakeBackend, FixedPassphrasePromptIO

_PASSPHRASE = "correct horse battery staple"
_CONFIG = b"model: gpt-x\napi_key: should-stay-encrypted\n"


@pytest.fixture(autouse=True)
def _no_running_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default running-gateway discovery to "none found".

    The enable tests exercise the enroll/marker logic; the gateway check has its
    own class below, and no test may read this host's real process table.
    """
    monkeypatch.setattr(_runtime_gate, "_default_gateway_discovery", lambda *, home: [])


def _read_vault_config(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> bytes | None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        return opened.read_file("config.yaml") if "config.yaml" in opened.list_files() else None


class TestEnable:
    def test_enrolls_config_and_writes_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)

        rc = config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)
        assert rc == 0
        assert _marker_path(home).exists()
        assert _read_vault_config(root, backend, store) == _CONFIG

    def test_enable_message_confirms_when_hook_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # enable runs via the same interpreter whose startup would seal config.yaml,
        # so it reports whether THIS runtime's decrypt hook is present (UX 2026-06-17).
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        monkeypatch.setattr(config_decrypt_cli, "config_hook_installed", lambda: True)

        assert config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store) == 0
        out = capsys.readouterr().out
        assert "decrypt hook is installed" in out
        assert "Next: run `hermes-mordred encryption status` once." in out
        assert "plaintext config.yaml will be resealed and removed" in out
        assert "`encryption enable config` for this first seal" in out
        assert "NOT installed" not in out

    def test_enable_message_warns_when_hook_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        monkeypatch.setattr(config_decrypt_cli, "config_hook_installed", lambda: False)

        assert config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store) == 0
        out = capsys.readouterr().out
        assert "NOT installed" in out
        assert "(re)installing the hermes-mordred" in out
        assert "hermes-mordred encryption status" not in out

    def test_missing_config_is_error_and_no_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        # no config.yaml on disk

        rc = config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)
        assert rc == 1
        assert not _marker_path(home).exists()

    def test_missing_vault_is_auto_created_then_enrolled(self, tmp_path: Path) -> None:
        """A first enable on a fresh install creates the vault inline (prompting
        once for a passphrase), then enrolls — no manual ``vault init`` needed."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_bytes(_CONFIG)
        backend, store = FakeBackend(), FakeAnchorStore()

        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="linux",
            backend=backend,
            store=store,
            prompt_io=FixedPassphrasePromptIO(_PASSPHRASE),
        )
        assert rc == 0
        assert _marker_path(home).exists()
        assert _read_vault_config(root, backend, store) == _CONFIG

    def test_vault_create_refused_leaves_no_marker(self, tmp_path: Path) -> None:
        """An empty passphrase refuses the vault create: nothing is enrolled and
        config.yaml is never marked vault-managed (fail-closed)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_bytes(_CONFIG)

        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="linux",
            backend=FakeBackend(),
            store=FakeAnchorStore(),
            prompt_io=FixedPassphrasePromptIO(""),
        )
        assert rc == 1
        assert not _marker_path(home).exists()


class TestDisable:
    def test_removes_marker_keeps_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)

        rc = config_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not _marker_path(home).exists()
        assert (home / "config.yaml").read_bytes() == _CONFIG  # plaintext kept

    def test_recovers_plaintext_when_sealed_away(self, tmp_path: Path) -> None:
        """If the plaintext was sealed (removed) while managed, disable decrypts it back."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)
        (home / "config.yaml").unlink()  # simulate a sealed (reseal-on-exit) state

        rc = config_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not _marker_path(home).exists()
        assert (home / "config.yaml").read_bytes() == _CONFIG  # recovered from the vault

    def test_idempotent_without_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_bytes(_CONFIG)  # plain, unmanaged
        rc = config_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0
        assert (home / "config.yaml").read_bytes() == _CONFIG

    def test_idempotent_unmanaged_empty_home(self, tmp_path: Path) -> None:
        """disable on a never-managed home (no marker, no config, no vault) is a clean no-op.

        It must NOT try to open a non-existent vault and report a misleading
        'run vault init' — there is simply nothing to un-manage."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        rc = config_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0

    def test_recovery_open_failure_returns_1(self, tmp_path: Path) -> None:
        """marker present + plaintext sealed away, but the vault can't be opened → rc 1 (fail-closed)."""
        from mordred_hermes.keyvault._config_bootstrap import _marker_path

        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        marker = _marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        # config.yaml absent AND the vault was never initialised → hot-path open fails
        rc = config_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1


class TestPurge:
    def test_unenrolls_and_keeps_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)

        rc = config_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not _marker_path(home).exists()
        assert (home / "config.yaml").read_bytes() == _CONFIG  # plaintext kept
        assert _read_vault_config(root, backend, store) is None  # removed from the vault

    def test_restores_sealed_plaintext_then_unenrolls(self, tmp_path: Path) -> None:
        """Safe order: a sealed-away plaintext is recovered BEFORE the vault copy is dropped."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)
        (home / "config.yaml").unlink()  # sealed (reseal-on-exit removed the plaintext)

        rc = config_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / "config.yaml").read_bytes() == _CONFIG  # recovered, not lost
        assert _read_vault_config(root, backend, store) is None

    def test_idempotent_unmanaged(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        rc = config_decrypt_cli.purge(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0

    def test_refuses_when_managed_but_no_vault_and_no_plaintext(self, tmp_path: Path) -> None:
        """Marker present, plaintext absent, vault gone → don't silently drop into 'defaults'."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        marker = _marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        # no config.yaml on disk, no vault manifest at root
        rc = config_decrypt_cli.purge(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert _marker_path(home).exists()  # marker NOT dropped — fail-closed preserved


class TestCliAdapters:
    def test_cli_enable_resolves_home_and_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import argparse

        seen: dict[str, object] = {}

        def _enable(*, home: Path, root: Path, **_: object) -> int:
            seen["home"], seen["root"] = home, root
            return 0

        monkeypatch.setattr(config_decrypt_cli, "_hermes_home", lambda: tmp_path / "home")
        monkeypatch.setattr(config_decrypt_cli, "enable", _enable)
        assert config_decrypt_cli.cli_enable(argparse.Namespace(root=None)) == 0
        assert seen["home"] == tmp_path / "home"
        assert seen["root"] == (tmp_path / "home" / "mordred" / "vault")

    def test_cli_disable_resolves_home_and_explicit_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import argparse

        seen: dict[str, object] = {}

        def _disable(*, home: Path, root: Path, **_: object) -> int:
            seen["home"], seen["root"] = home, root
            return 0

        monkeypatch.setattr(config_decrypt_cli, "_hermes_home", lambda: tmp_path / "home")
        monkeypatch.setattr(config_decrypt_cli, "disable", _disable)
        # an explicit --root overrides the home-derived default
        assert config_decrypt_cli.cli_disable(argparse.Namespace(root=str(tmp_path / "custom"))) == 0
        assert seen["home"] == tmp_path / "home"
        assert seen["root"] == (tmp_path / "custom")


# -----------------------------------------------------------------------------
# runtime gate — refuse to arm the config.yaml seal when the `hermes` runtime
# cannot decrypt it at startup (parity with env_decrypt_cli's gate).
# -----------------------------------------------------------------------------
def _boom_probe(*, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
    raise AssertionError("runtime probe must not be consulted on this path")


class TestRuntimeGate:
    """macOS fail-closed gate: enabling arms reseal-on-exit, which removes the
    plaintext config.yaml. So enable must first prove the interpreter that runs
    ``hermes`` can re-materialize it at startup. When it cannot, ``enable``
    refuses and leaves every byte of state untouched.
    """

    def _setup(self, tmp_path: Path) -> tuple[Path, Path, FakeBackend, FakeAnchorStore]:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        return root, home, backend, store

    def test_refuses_and_keeps_state_when_runtime_cannot_decrypt(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = self._setup(tmp_path)
        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=lambda *, home, runtime_python=None: (
                False,
                "config-decrypt .pth hook not installed in this runtime",
            ),
        )
        assert rc == 1
        assert (home / "config.yaml").read_bytes() == _CONFIG  # plaintext untouched
        assert _read_vault_config(root, backend, store) is None  # nothing enrolled
        assert not _marker_path(home).exists()  # marker never written
        out = capsys.readouterr()
        assert "refusing to vault-seal config.yaml" in (out.err + out.out)

    def test_force_bypasses_the_gate(self, tmp_path: Path) -> None:
        root, home, backend, store = self._setup(tmp_path)
        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=_boom_probe,  # must not be consulted under force
            force_runtime_unverified=True,
        )
        assert rc == 0
        assert _marker_path(home).exists()
        assert _read_vault_config(root, backend, store) == _CONFIG  # enrolled despite unverified runtime

    def test_gate_not_applied_off_macos(self, tmp_path: Path) -> None:
        root, home, backend, store = self._setup(tmp_path)
        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="linux",
            backend=backend,
            store=store,
            runtime_probe=_boom_probe,  # off macOS the gate never runs
        )
        assert rc == 0
        assert _marker_path(home).exists()
        assert _read_vault_config(root, backend, store) == _CONFIG

    def test_proceeds_when_runtime_can_decrypt(self, tmp_path: Path) -> None:
        root, home, backend, store = self._setup(tmp_path)
        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=lambda *, home, runtime_python=None: (True, "ok"),
        )
        assert rc == 0
        assert _marker_path(home).exists()
        assert _read_vault_config(root, backend, store) == _CONFIG


class TestRunningGatewayGate:
    """A gateway running from a different interpreter that lacks the ``.pth`` hook
    must block the marker: arming reseal-on-exit would strand that process with a
    config.yaml it cannot materialize (the 2026-06-25 incident shape).
    """

    def _setup(self, tmp_path: Path) -> tuple[Path, Path, FakeBackend, FakeAnchorStore]:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        return root, home, backend, store

    def _gateway_python(self, tmp_path: Path) -> Path:
        bindir = tmp_path / "repo" / ".venv" / "bin"
        bindir.mkdir(parents=True)
        python = bindir / "python"
        python.write_text("")
        return python

    def test_refuses_when_the_running_gateway_lacks_the_hook(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = self._setup(tmp_path)
        gateway = self._gateway_python(tmp_path)
        monkeypatch.setattr(
            _runtime_gate, "_default_gateway_discovery", lambda *, home: [GatewayRuntime(pid=4242, python=gateway)]
        )
        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=lambda *, home, runtime_python=None: (
                (True, "ok") if runtime_python is None else (False, "config-decrypt .pth hook not installed")
            ),
        )
        assert rc == 1
        assert (home / "config.yaml").read_bytes() == _CONFIG  # plaintext untouched
        assert _read_vault_config(root, backend, store) is None  # nothing enrolled
        assert not _marker_path(home).exists()  # marker never written
        err = capsys.readouterr().err
        assert "refusing to vault-seal config.yaml" in err
        assert f"{gateway} (pid 4242)" in err

    def test_proceeds_when_the_running_gateway_has_the_hook(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root, home, backend, store = self._setup(tmp_path)
        gateway = self._gateway_python(tmp_path)
        monkeypatch.setattr(
            _runtime_gate, "_default_gateway_discovery", lambda *, home: [GatewayRuntime(pid=9, python=gateway)]
        )
        rc = config_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=lambda *, home, runtime_python=None: (True, "ok"),
        )
        assert rc == 0
        assert _marker_path(home).exists()
        assert _read_vault_config(root, backend, store) == _CONFIG
