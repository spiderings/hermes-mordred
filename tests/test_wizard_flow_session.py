"""One passphrase, one vault unlock, one key policy per guided flow.

A guided flow (``hermes-mordred setup``, ``encryption enable all``, the
Telegram setup's memory step, the Desktop ``/memory/enable``) runs several
sub-commands in one process. They used to act as if each ran alone:

* ``setup`` made the operator choose and confirm a passphrase twice (keyvault
  Passphrase + vault recovery passphrase) -- four masked prompts;
* ``enable env`` and ``enable memory`` each unwrapped the vault master -- one
  Secure Enclave ECDH (one Touch ID / macOS password dialog) per step;
* the vault's device key ignored setup's "allow background services" answer.

These tests pin the fixed behaviour. Masked prompts are counted through the
production ``PromptToolkitIO`` with ``prompt_toolkit.prompt`` mocked (the
masked-input equivalent of mocking ``getpass``); unlocks are counted as
``enclave_ecdh`` calls on the software ``FakeBackend``. The cross-interpreter
runtime probes are stubbed (they shell out).
"""

from __future__ import annotations

import asyncio
import functools
import pickle
import sys
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _bip39, _identity, _runtime_probe, api, vault
from mordred_hermes.keyvault import digest as kvdigest
from mordred_hermes.keyvault import pow as kvpow
from mordred_hermes.keyvault.memory_crypto import is_sealed
from mordred_hermes.wizard import (
    _keyvault_init,
    config_decrypt_cli,
    configure,
    encryption_cli,
    env_decrypt_cli,
    memory_cli,
    setup_cli,
    status_cli,
    vault_cli,
)
from mordred_hermes.wizard._flow_session import FlowSession

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "one passphrase for the whole setup run"
_FIXED_SEED = _bip39.entropy_to_mnemonic(bytes(range(1, 33)))


class _RecordingBackend(FakeBackend):
    """FakeBackend that also records the unattended policy of each new key."""

    def __init__(self) -> None:
        super().__init__()
        self.unattended: dict[str, bool | None] = {}

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        public = super().generate_enclave_key(key_id, unattended=unattended)
        self.unattended[key_id] = unattended
        return public


def _unlocks(backend: FakeBackend) -> int:
    """Secure Enclave unwraps (one Touch ID / password dialog each on real hardware)."""
    return sum(1 for call in backend.calls if call[0] == "ecdh")


class _CountingPromptIO:
    """PromptIO double that records every masked prompt label and yes/no question."""

    def __init__(self, passphrase: str = _PASSPHRASE, *, allow_background: bool = False) -> None:
        self.passphrase = passphrase
        self.allow_background = allow_background
        self.password_labels: list[str] = []
        self.bool_labels: list[str] = []

    def ask_choice(self, label: str, choices: Any, default: str, **_: Any) -> str:
        return default

    def ask_text(self, label: str, default: str = "", **_: Any) -> str:
        # The keyvault ceremony's offline verification digest (visible prompt).
        return _expected_digest_hex(self.passphrase) if "digest" in label.lower() else default

    def ask_bool(self, label: str, default: bool, **_: Any) -> bool:
        self.bool_labels.append(label)
        return self.allow_background if "background services" in label else default

    def ask_multi(self, label: str, choices: Any, default: Any = ()) -> tuple[str, ...]:
        return tuple(default)

    def ask_password(self, label: str, default: str = "", **_: Any) -> str:
        self.password_labels.append(label)
        return self.passphrase


def _background_questions(prompt_io: _CountingPromptIO) -> int:
    return sum(1 for label in prompt_io.bool_labels if "background services" in label)


def _expected_digest_hex(passphrase: str) -> str:
    """The digest the operator would transcribe back from the offline device."""
    norm_seed = api._normalize_seed_phrase(_FIXED_SEED)
    pow_bytes = kvpow.compute_pow(norm_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    return kvdigest.compute_digest(norm_seed, api._normalize_passphrase(passphrase), pow_bytes).hex()


class _NoopSurface:
    def banner(self, message: str) -> None:
        return None

    def show(self, seed: str) -> None:
        return None

    def clear(self) -> None:
        return None


def _as_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    """These flows seal memory, which only exists on macOS; run them as macOS
    on every CI runner (the backends are fakes, so nothing native is touched)."""
    monkeypatch.setattr(sys, "platform", "darwin")


def _stub_runtime_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(env_decrypt_cli, "_runtime_gate", lambda **_kw: 0)
    monkeypatch.setattr(config_decrypt_cli, "_runtime_gate", lambda **_kw: 0)
    monkeypatch.setattr(memory_cli, "_runtime_gate", lambda **_kw: 0)
    monkeypatch.setattr(encryption_cli, "memory_runtime_available", lambda: (True, "seam A"))
    monkeypatch.setattr(_runtime_probe, "discover_running_gateway_runtimes", lambda **_kw: [])


def _plaintext_home(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / ".env").write_text("ANTHROPIC_API_KEY=sk-test\n", encoding="utf-8")
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    (home / "memories").mkdir(exist_ok=True)
    (home / "memories" / "MEMORY.md").write_text("remember me\n", encoding="utf-8")


def _existing_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    assert vault_cli.init(root=root, prompt_io=_CountingPromptIO(), backend=backend, store=store) == 0
    backend.calls.clear()


def _open(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> vault.OpenVault:
    key_id = _identity.vault_identity(root)
    return vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=key_id)


@pytest.fixture
def fresh_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    return make_fresh_host(tmp_path, monkeypatch)


def make_fresh_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A fresh macOS-like host: no keyvault, no vault, a plaintext .env + memory.

    The early setup steps (hermes / configure / network / hardware helper) are
    forced "done" -- they never ask for a passphrase and are covered elsewhere.
    The keyvault ceremony, vault creation, .env enrollment and memory sealing run
    for real against software fakes.
    """
    home, root = tmp_path / "home", tmp_path / "vault"
    _plaintext_home(home)

    for resolver in ("_resolve_step_hermes", "_resolve_step_configure", "_resolve_step_network"):
        name = resolver.removeprefix("_resolve_step_")
        monkeypatch.setattr(
            setup_cli, resolver, lambda _n=name, **_kw: setup_cli.StepResult(_n, "done", "forced for test")
        )
    monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: True)
    monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)

    # Keyvault ceremony: fast PoW, pinned seed, offline, stdout guard satisfied
    # by an injected surface, 60s display skipped.
    monkeypatch.setattr(kvpow, "POW_DIFFICULTY_BITS", 4)
    monkeypatch.setattr(_bip39, "generate_mnemonic", lambda: _FIXED_SEED)
    monkeypatch.setattr(setup_cli, "_keyvault_preflight", lambda **_kw: None)
    monkeypatch.setattr("mordred_hermes.keyvault.network_fallback.resolve_blackout_assert", lambda: lambda **_kw: None)
    kv_backend = _RecordingBackend()
    monkeypatch.setattr(
        _keyvault_init,
        "init_keyvault",
        functools.partial(
            _keyvault_init.init_keyvault,
            backend=kv_backend,
            surface=_NoopSurface(),
            display_fn=lambda _handle, _surface: None,
            audit_sink=lambda _entry: None,
        ),
    )

    # At-rest vault: software device key + in-memory anchor store.
    backend, store = _RecordingBackend(), FakeAnchorStore()
    monkeypatch.setattr(
        env_decrypt_cli, "enable", functools.partial(env_decrypt_cli.enable, backend=backend, store=store)
    )
    monkeypatch.setattr(memory_cli, "enable", functools.partial(memory_cli.enable, backend=backend, store=store))
    _stub_runtime_probes(monkeypatch)
    monkeypatch.setattr(status_cli, "status", lambda **_kw: 0)

    return {"home": home, "root": root, "tmp": tmp_path, "backend": backend, "store": store, "kv": kv_backend}


def _run_setup(host: dict[str, Any], prompt_io: Any, *, unattended_keys: bool | None = None) -> int:
    return setup_cli.run_setup(
        home=host["home"],
        root=host["root"],
        platform="darwin",
        workspace=encryption_cli.WorkspacePaths(
            image=host["tmp"] / "ws.sparsebundle", blob=host["tmp"] / "ws.wrapped", mount=host["tmp"] / "ws"
        ),
        prompt_io=prompt_io,
        policy_writer=None,  # type: ignore[arg-type]  # configure step is forced done
        setup_runner=None,  # type: ignore[arg-type]  # hermes step is forced done
        options=setup_cli.SetupOptions(unattended_keys=unattended_keys),
    )


def _vault_key_policy(host: dict[str, Any]) -> bool | None:
    policy: bool | None = host["backend"].unattended[_identity.vault_identity(host["root"])]
    return policy


# -----------------------------------------------------------------------------
# Passphrase prompts
# -----------------------------------------------------------------------------
class TestSetupPassphrase:
    def test_fresh_setup_asks_for_one_passphrase_through_the_real_prompt_layer(
        self, fresh_host: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Keyvault + vault + env + memory in one run: exactly one masked
        "choose" prompt and one confirmation, via the production PromptToolkitIO
        (before: four -- a second choose/confirm pair for the vault)."""
        masked: list[str] = []
        digest_hex = _expected_digest_hex(_PASSPHRASE)

        def fake_prompt(message: str, *, is_password: bool = False, **_: Any) -> str:
            if is_password:
                masked.append(message)
                return _PASSPHRASE
            if "background services" in message:
                return "n"
            assert "digest" in message.lower(), f"unexpected visible prompt: {message!r}"
            return digest_hex

        import prompt_toolkit

        monkeypatch.setattr(prompt_toolkit, "prompt", fake_prompt)
        monkeypatch.setattr(configure, "_require_tty", lambda _label: None)

        rc = _run_setup(fresh_host, configure.PromptToolkitIO())

        assert rc == 0
        assert masked == ["Choose a Passphrase: ", "Re-enter the Passphrase: "]
        # The reused passphrase really is the vault's recovery passphrase.
        vault.recover_vault(fresh_host["root"], _PASSPHRASE).close()
        assert is_sealed((fresh_host["home"] / "memories" / "MEMORY.md").read_bytes())

    def test_fresh_setup_counts_one_choose_and_one_confirm(self, fresh_host: dict[str, Any]) -> None:
        prompt_io = _CountingPromptIO()
        assert _run_setup(fresh_host, prompt_io) == 0
        assert prompt_io.password_labels == ["Choose a Passphrase", "Re-enter the Passphrase"]

    def test_flow_session_is_closed_when_the_run_ends(
        self, fresh_host: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[FlowSession] = []
        real_env_step = setup_cli._resolve_step_env_encryption

        def spy(**kwargs: Any) -> setup_cli.StepResult:
            flow = kwargs["flow_session"]
            seen.append(flow)
            assert flow.passphrase == _PASSPHRASE  # handed over from the keyvault step
            return real_env_step(**kwargs)

        monkeypatch.setattr(setup_cli, "_resolve_step_env_encryption", spy)
        assert _run_setup(fresh_host, _CountingPromptIO()) == 0
        assert len(seen) == 1
        assert seen[0].passphrase is None
        assert seen[0].lend_vault(fresh_host["root"]) is None  # handle closed, master zeroed

    def test_existing_keyvault_then_vault_creation_prompts_once_plus_confirm(
        self, fresh_host: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Resume case: keyvault already done, so the vault's creation is the
        only thing that needs a passphrase -- chosen and confirmed once."""
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **_kw: ("initialised", "1 key"))
        prompt_io = _CountingPromptIO()
        assert _run_setup(fresh_host, prompt_io) == 0
        assert prompt_io.password_labels == ["Choose a vault recovery passphrase", "Re-enter the passphrase"]

    def test_everything_already_set_up_never_prompts(self, fresh_host: dict[str, Any]) -> None:
        assert _run_setup(fresh_host, _CountingPromptIO()) == 0
        again = _CountingPromptIO()
        assert _run_setup(fresh_host, again) == 0
        assert again.password_labels == []


# -----------------------------------------------------------------------------
# Vault unlocks (Secure Enclave ECDH = Touch ID / password dialog)
# -----------------------------------------------------------------------------
class TestVaultUnlocks:
    def test_fresh_setup_never_unwraps_the_vault(self, fresh_host: dict[str, Any]) -> None:
        """The run creates the vault and keeps it open for env + memory: 0 unlocks
        (before: 2 -- one for the .env enroll, one for the memory key)."""
        assert _run_setup(fresh_host, _CountingPromptIO()) == 0
        assert _unlocks(fresh_host["backend"]) == 0

    def test_setup_with_an_existing_vault_unlocks_once(
        self, fresh_host: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **_kw: ("initialised", "1 key"))
        _existing_vault(fresh_host["root"], fresh_host["backend"], fresh_host["store"])
        assert _run_setup(fresh_host, _CountingPromptIO()) == 0
        assert _unlocks(fresh_host["backend"]) == 1  # before: 2

    def test_env_then_memory_share_one_unlock(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The Telegram-setup / Desktop pattern: env then memory in one flow."""
        _stub_runtime_probes(monkeypatch)
        home, root = tmp_path / "home", tmp_path / "v"
        _plaintext_home(home)
        backend, store = FakeBackend(), FakeAnchorStore()
        _existing_vault(root, backend, store)
        with FlowSession() as flow:
            assert (
                env_decrypt_cli.enable(
                    home=home, root=root, platform="darwin", backend=backend, store=store, flow_session=flow
                )
                == 0
            )
            assert (
                memory_cli.enable(
                    home=home, root=root, platform="darwin", backend=backend, store=store, flow_session=flow
                )
                == 0
            )
        assert _unlocks(backend) == 1  # before: 2

    def test_without_a_flow_each_command_still_unlocks_on_its_own(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Standalone `encryption enable env` / `enable memory` (separate commands)
        are unchanged: one unlock each."""
        _stub_runtime_probes(monkeypatch)
        home, root = tmp_path / "home", tmp_path / "v"
        _plaintext_home(home)
        backend, store = FakeBackend(), FakeAnchorStore()
        _existing_vault(root, backend, store)
        assert env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store) == 0
        assert memory_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store) == 0
        assert _unlocks(backend) == 2

    def test_enable_all_on_a_fresh_host_prompts_once_and_never_unlocks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`encryption enable all` creating the vault: 1 choose + 1 confirm and 0
        unlocks (before: 3 unlocks -- env, config, memory each opened it)."""
        _as_macos(monkeypatch)
        _stub_runtime_probes(monkeypatch)
        home = tmp_path / "home"
        _plaintext_home(home)
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)
        monkeypatch.setattr(encryption_cli, "resolve_root", lambda _r: tmp_path / "v")
        backend, store = FakeBackend(), FakeAnchorStore()
        prompt_io = _CountingPromptIO()
        for module in (env_decrypt_cli, config_decrypt_cli, memory_cli):
            monkeypatch.setattr(
                module,
                "enable",
                functools.partial(module.enable, backend=backend, store=store, prompt_io=prompt_io),
            )
        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: False)
        assert rc == 0
        assert prompt_io.password_labels == ["Choose a vault recovery passphrase", "Re-enter the passphrase"]
        assert _unlocks(backend) == 0

    def test_enable_all_with_an_existing_vault_unlocks_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _as_macos(monkeypatch)
        _stub_runtime_probes(monkeypatch)
        home = tmp_path / "home"
        _plaintext_home(home)
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)
        monkeypatch.setattr(encryption_cli, "resolve_root", lambda _r: tmp_path / "v")
        backend, store = FakeBackend(), FakeAnchorStore()
        _existing_vault(tmp_path / "v", backend, store)
        for module in (env_decrypt_cli, config_decrypt_cli, memory_cli):
            monkeypatch.setattr(module, "enable", functools.partial(module.enable, backend=backend, store=store))
        assert encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: False) == 0
        assert _unlocks(backend) == 1  # before: 3

    def test_desktop_memory_enable_is_one_flow(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Desktop `/memory/enable` on a fresh host: vault created and kept open,
        so 0 unlocks (before: 2), and the key follows setup's default policy."""
        pytest.importorskip("fastapi")
        from mordred_hermes.desktop import api as desktop_api

        _as_macos(monkeypatch)
        _stub_runtime_probes(monkeypatch)
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
        home, root = tmp_path / "home", tmp_path / "v"
        _plaintext_home(home)
        backend, store = _RecordingBackend(), FakeAnchorStore()
        monkeypatch.setattr(desktop_api, "_home", lambda: home)
        monkeypatch.setattr(vault_cli, "_resolve_root", lambda _r: root)
        state = {"calls": 0}

        def active(home: Any = None) -> bool:
            state["calls"] += 1
            return state["calls"] > 1

        monkeypatch.setattr("mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", active)
        monkeypatch.setattr(
            env_decrypt_cli, "enable", functools.partial(env_decrypt_cli.enable, backend=backend, store=store)
        )
        monkeypatch.setattr(memory_cli, "enable", functools.partial(memory_cli.enable, backend=backend, store=store))

        result = asyncio.run(desktop_api.memory_enable({}))

        assert result["ok"] is True and result["recovery_passphrase"]
        assert _unlocks(backend) == 0
        # Same default as setup: MORDRED_SEKEY_UNATTENDED, else attended (backend default).
        assert backend.unattended[_identity.vault_identity(root)] is None

    def test_desktop_memory_enable_honours_an_explicit_unattended_request(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("fastapi")
        from mordred_hermes.desktop import api as desktop_api

        _as_macos(monkeypatch)
        _stub_runtime_probes(monkeypatch)
        home, root = tmp_path / "home", tmp_path / "v"
        _plaintext_home(home)
        backend, store = _RecordingBackend(), FakeAnchorStore()
        monkeypatch.setattr(desktop_api, "_home", lambda: home)
        monkeypatch.setattr(vault_cli, "_resolve_root", lambda _r: root)
        answers = iter([False, True])
        monkeypatch.setattr(
            "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active",
            lambda home=None: next(answers),
        )
        monkeypatch.setattr(
            env_decrypt_cli, "enable", functools.partial(env_decrypt_cli.enable, backend=backend, store=store)
        )
        monkeypatch.setattr(memory_cli, "enable", functools.partial(memory_cli.enable, backend=backend, store=store))

        assert asyncio.run(desktop_api.memory_enable({"unattended": True}))["ok"] is True
        assert backend.unattended[_identity.vault_identity(root)] is True


# -----------------------------------------------------------------------------
# The vault device key's unattended policy
# -----------------------------------------------------------------------------
class TestVaultKeyPolicy:
    def test_setup_answer_yes_makes_the_vault_key_unattended(self, fresh_host: dict[str, Any]) -> None:
        prompt_io = _CountingPromptIO(allow_background=True)
        assert _run_setup(fresh_host, prompt_io) == 0
        assert _vault_key_policy(fresh_host) is True
        # The keyvault's main key got the same answer. (Its audit-log key is only
        # used to encrypt -- public key, no prompt -- so it keeps the default.)
        assert True in fresh_host["kv"].unattended.values()
        assert _background_questions(prompt_io) == 1

    def test_setup_answer_no_keeps_the_vault_key_attended(self, fresh_host: dict[str, Any]) -> None:
        assert _run_setup(fresh_host, _CountingPromptIO(allow_background=False)) == 0
        assert _vault_key_policy(fresh_host) is False

    def test_flag_wins_without_asking(self, fresh_host: dict[str, Any]) -> None:
        prompt_io = _CountingPromptIO(allow_background=False)
        assert _run_setup(fresh_host, prompt_io, unattended_keys=True) == 0
        assert _vault_key_policy(fresh_host) is True
        assert _background_questions(prompt_io) == 0

    def test_resume_asks_before_creating_the_vault_key(
        self, fresh_host: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Keyvault already done (question not asked there): it is asked once,
        right before the vault's device key is created."""
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **_kw: ("initialised", "1 key"))
        prompt_io = _CountingPromptIO(allow_background=True)
        assert _run_setup(fresh_host, prompt_io) == 0
        assert _vault_key_policy(fresh_host) is True
        assert _background_questions(prompt_io) == 1

    def test_standalone_vault_init_keeps_the_backend_default(self, tmp_path: Path) -> None:
        backend = _RecordingBackend()
        root = tmp_path / "v"
        assert vault_cli.init(root=root, prompt_io=_CountingPromptIO(), backend=backend, store=FakeAnchorStore()) == 0
        assert backend.unattended[_identity.vault_identity(root)] is None


# -----------------------------------------------------------------------------
# vault init with a flow + the FlowSession object itself
# -----------------------------------------------------------------------------
class TestVaultInitWithFlow:
    def test_reuses_a_flow_passphrase_without_prompting(self, tmp_path: Path) -> None:
        prompt_io = _CountingPromptIO(passphrase="must not be used")
        with FlowSession() as flow:
            flow.remember_passphrase(_PASSPHRASE)
            rc = vault_cli.init(
                root=tmp_path / "v",
                prompt_io=prompt_io,
                backend=FakeBackend(),
                store=FakeAnchorStore(),
                flow_session=flow,
            )
        assert rc == 0
        assert prompt_io.password_labels == []
        vault.recover_vault(tmp_path / "v", _PASSPHRASE).close()

    def test_remembers_a_new_passphrase_and_keeps_the_vault_open(self, tmp_path: Path) -> None:
        with FlowSession() as flow:
            rc = vault_cli.init(
                root=tmp_path / "v",
                prompt_io=_CountingPromptIO(),
                backend=FakeBackend(),
                store=FakeAnchorStore(),
                flow_session=flow,
            )
            assert rc == 0
            assert flow.passphrase == _PASSPHRASE
            lent = flow.lend_vault(tmp_path / "v")
            assert lent is not None
            with lent:  # a lent handle survives the borrower's `with`
                pass
            assert lent.list_files() == []

    def test_mismatch_is_not_remembered(self, tmp_path: Path) -> None:
        class _Mismatch(_CountingPromptIO):
            def ask_password(self, label: str, default: str = "", **_: Any) -> str:
                super().ask_password(label)
                return "first" if len(self.password_labels) == 1 else "second"

        with FlowSession() as flow:
            rc = vault_cli.init(
                root=tmp_path / "v",
                prompt_io=_Mismatch(),
                backend=FakeBackend(),
                store=FakeAnchorStore(),
                flow_session=flow,
            )
            assert rc == 1
            assert flow.passphrase is None


class TestFlowSession:
    def test_repr_never_contains_the_secret(self) -> None:
        flow = FlowSession()
        flow.remember_passphrase(_PASSPHRASE)
        assert _PASSPHRASE not in repr(flow)
        assert "<set>" in repr(flow)

    def test_cannot_be_pickled(self) -> None:
        flow = FlowSession()
        flow.remember_passphrase(_PASSPHRASE)
        with pytest.raises(TypeError):
            pickle.dumps(flow)

    def test_close_drops_the_passphrase_and_closes_the_vault(self, tmp_path: Path) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        _existing_vault(tmp_path / "v", backend, store)
        opened = _open(tmp_path / "v", backend, store)
        with FlowSession() as flow:
            flow.remember_passphrase(_PASSPHRASE)
            flow.keep_vault(tmp_path / "v", opened)
        assert flow.passphrase is None
        with pytest.raises(vault.VaultError):
            opened.list_files()  # the real handle is closed

    def test_lends_only_for_the_same_root(self, tmp_path: Path) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        _existing_vault(tmp_path / "v", backend, store)
        with FlowSession() as flow:
            flow.keep_vault(tmp_path / "v", _open(tmp_path / "v", backend, store))
            assert flow.lend_vault(tmp_path / "other") is None
            assert flow.lend_vault(tmp_path / "v") is not None

    def test_empty_passphrase_is_ignored(self) -> None:
        flow = FlowSession()
        flow.remember_passphrase("")
        assert flow.passphrase is None
