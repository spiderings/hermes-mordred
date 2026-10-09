"""How many macOS Keychain accesses (and password dialogs) each flow costs.

The at-rest vault pins its freshness anchor in a login-keychain generic-password
item. macOS shows "<binary> wants to use your confidential information stored in
... in your keychain" -- a dialog that asks for the login password -- whenever a
binary other than the one that created the item reads, updates or deletes it.
The Python interpreter changes identity easily (the repo's dev venv, Hermes's
managed Python, a Python upgrade), so an anchor written by one interpreter made
every later vault open in another interpreter ask again, several times per flow.

The anchor now lives in an item created and read by the Secure Enclave helper
(``mordred-hermes-sekey``) -- one stable binary for every Python process -- and
each flow touches it fewer times. These tests replay the flows against
:class:`tests._keychain_sim.SimKeychain` and pin both numbers.

Scenario "stale": the anchor item was created by another interpreter
(``python-dev``) and the flow runs in Hermes's interpreter (``python-hermes``);
the operator answers each dialog with "Allow" (not "Always Allow"). That is the
state found on the reporting machine.
"""

from __future__ import annotations

import asyncio
import functools
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _anchor_keychain, _identity, _runtime_env
from mordred_hermes.keyvault import _config_bootstrap as config_bootstrap
from mordred_hermes.wizard import config_decrypt_cli, env_decrypt_cli, memory_cli, vault_cli
from mordred_hermes.wizard._flow_session import FlowSession

from ._keychain_sim import SimHelperRunner, SimKeychain, SimPyobjcOps
from ._keyvault_fakes import FakeBackend
from .test_wizard_flow_session import (
    _CountingPromptIO,
    _plaintext_home,
    _run_setup,
    _stub_runtime_probes,
    make_fresh_host,
)

StoreFactory = Callable[[SimKeychain, str], Any]


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """``hermes-mordred setup``'s test host (see ``test_wizard_flow_session``)."""
    return make_fresh_host(tmp_path, monkeypatch)


def _legacy_store(kc: SimKeychain, binary: str) -> Any:
    """The pre-fix store: in-process Security.framework calls by ``binary``."""
    return _anchor_keychain.KeychainAnchorStore(ops=SimPyobjcOps(kc, binary))


def _helper_store(kc: SimKeychain, binary: str) -> Any:
    """The production store when the SE helper is installed."""
    return _anchor_keychain.HelperAnchorStore(
        _anchor_keychain._HelperAnchorOps("mordred-hermes-sekey", runner=SimHelperRunner(kc)),
        legacy=_anchor_keychain.KeychainAnchorStore(ops=SimPyobjcOps(kc, binary)),
    )


class _World:
    """A home + vault whose anchor was written by ``python-dev``."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, factory: StoreFactory) -> None:
        _stub_runtime_probes(monkeypatch)
        self.home, self.root = tmp_path / "home", tmp_path / "vault"
        _plaintext_home(self.home)
        self.kc = SimKeychain()
        self.backend = FakeBackend()
        self.factory = factory
        creator = factory(self.kc, "python-dev")
        assert vault_cli.init(root=self.root, prompt_io=_CountingPromptIO(), backend=self.backend, store=creator) == 0
        self.kc.reset_counts()

    def store(self) -> Any:
        """A fresh store instance as each process / entry point builds one."""
        return self.factory(self.kc, "python-hermes")

    def counts(self) -> tuple[int, int]:
        return self.kc.access_count, self.kc.dialog_count


def _enable_env_and_memory(world: _World, *, flow: FlowSession | None) -> None:
    kwargs: dict[str, Any] = {"home": world.home, "root": world.root, "platform": "darwin", "backend": world.backend}
    assert env_decrypt_cli.enable(store=world.store(), flow_session=flow, **kwargs) == 0
    assert memory_cli.enable(store=world.store(), flow_session=flow, **kwargs) == 0


def _flow_telegram_setup_memory_step(world: _World) -> None:
    """``hermes-mordred telegram setup`` -> memory step: env + memory in one FlowSession."""
    with FlowSession() as flow:
        _enable_env_and_memory(world, flow=flow)


def _flow_desktop_memory_enable(world: _World, monkeypatch: pytest.MonkeyPatch) -> None:
    """Desktop ``POST /memory/enable`` with the vault already present."""
    pytest.importorskip("fastapi")
    from mordred_hermes.desktop import api as desktop_api

    monkeypatch.setattr(sys, "platform", "darwin")  # memory sealing is macOS-only; backends are fakes

    monkeypatch.setattr(desktop_api, "_home", lambda: world.home)
    monkeypatch.setattr(vault_cli, "_resolve_root", lambda _r: world.root)
    answers = iter([False, True])
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", lambda home=None: next(answers)
    )
    for module in (env_decrypt_cli, memory_cli):
        monkeypatch.setattr(
            module,
            "enable",
            functools.partial(module.enable, backend=world.backend, store=world.store()),
        )
    assert asyncio.run(desktop_api.memory_enable({}))["ok"] is True


def _seal_env_and_config(world: _World) -> None:
    """Pre-state for the start-up flows: .env and config.yaml sealed in the vault."""
    kwargs: dict[str, Any] = {"home": world.home, "root": world.root, "platform": "darwin", "backend": world.backend}
    with FlowSession() as flow:
        assert env_decrypt_cli.enable(store=world.store(), flow_session=flow, **kwargs) == 0
        assert config_decrypt_cli.enable(store=world.store(), flow_session=flow, **kwargs) == 0
    world.kc.reset_counts()


def _flow_hermes_start(world: _World) -> None:
    """One Hermes process start: the .pth config.yaml decrypt + register()'s .env inject."""
    assert (
        config_bootstrap.materialize_config(
            root=world.root, home=world.home, backend=world.backend, store=world.store()
        )
        == 1
    )
    environ: dict[str, str] = {}
    assert (
        _runtime_env.inject_vault_env(root=world.root, environ=environ, backend=world.backend, store=world.store()) > 0
    )


def _flow_extension_serve_start(world: _World) -> None:
    """``python -m mordred_hermes.extension`` start: the .env inject only."""
    environ: dict[str, str] = {}
    assert (
        _runtime_env.inject_vault_env(root=world.root, environ=environ, backend=world.backend, store=world.store()) > 0
    )


# -----------------------------------------------------------------------------
# Measurements
# -----------------------------------------------------------------------------


def _measure_setup_existing(
    host: dict[str, Any], monkeypatch: pytest.MonkeyPatch, factory: StoreFactory
) -> tuple[int, int]:
    monkeypatch.setattr("mordred_hermes.wizard.setup_cli._probe_keyvault", lambda **_kw: ("initialised", "1 key"))
    kc = SimKeychain()
    backend = host["backend"]
    assert (
        vault_cli.init(
            root=host["root"], prompt_io=_CountingPromptIO(), backend=backend, store=factory(kc, "python-dev")
        )
        == 0
    )
    kc.reset_counts()
    for module in (env_decrypt_cli, memory_cli):
        monkeypatch.setattr(module, "enable", functools.partial(module.enable, store=factory(kc, "python-hermes")))
    assert _run_setup(host, _CountingPromptIO()) == 0
    return kc.access_count, kc.dialog_count


def _measure_setup_fresh(
    host: dict[str, Any], monkeypatch: pytest.MonkeyPatch, factory: StoreFactory
) -> tuple[int, int]:
    kc = SimKeychain()
    for module in (env_decrypt_cli, memory_cli):
        monkeypatch.setattr(module, "enable", functools.partial(module.enable, store=factory(kc, "python-hermes")))
    assert _run_setup(host, _CountingPromptIO()) == 0
    return kc.access_count, kc.dialog_count


# -----------------------------------------------------------------------------
# Per-flow numbers. BEFORE (in-process anchor store, two reads per open, a
# pre-check read before each start-up open, add-then-update on every commit):
#   setup, vault already present .......... 10 accesses, 8 dialogs
#   telegram setup (memory step) .......... 10 accesses, 8 dialogs
#   desktop POST /memory/enable ........... 10 accesses, 8 dialogs
#   Hermes start (.env + config sealed) ...  6 accesses, 6 dialogs
#   Hermes exit (config reseal, unchanged)   2 accesses, 2 dialogs
#   extension serve start .................  3 accesses, 3 dialogs
#   setup on a fresh host ................. 11 accesses, 0 dialogs (created in-flow)
# -----------------------------------------------------------------------------

_EXPECTED_HELPER = {
    "setup_existing": (6, 0),
    "telegram_setup": (6, 0),
    "desktop_memory_enable": (6, 0),
    "hermes_start": (2, 0),
    "hermes_exit": (1, 0),
    "extension_serve": (1, 0),
}

#: Without the helper (in-process store): still fewer accesses than before, but a
#: stale item still costs one dialog per access -- the reason for the helper store.
_EXPECTED_LEGACY = {
    "setup_existing": (8, 6),
    "telegram_setup": (8, 6),
    "desktop_memory_enable": (8, 6),
    "hermes_start": (2, 2),
    "hermes_exit": (1, 1),
    "extension_serve": (1, 1),
}


def _measure(flow: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, factory: StoreFactory) -> tuple[int, int]:
    world = _World(tmp_path / flow, monkeypatch, factory)
    if flow == "telegram_setup":
        _flow_telegram_setup_memory_step(world)
    elif flow == "desktop_memory_enable":
        _flow_desktop_memory_enable(world, monkeypatch)
    elif flow == "hermes_start":
        _seal_env_and_config(world)
        _flow_hermes_start(world)
    elif flow == "hermes_exit":
        _seal_env_and_config(world)
        _flow_hermes_start(world)
        world.kc.reset_counts()
        assert (
            config_bootstrap.reseal_config(root=world.root, home=world.home, backend=world.backend, store=world.store())
            == 1
        )
    elif flow == "extension_serve":
        _seal_env_and_config(world)
        _flow_extension_serve_start(world)
    else:  # pragma: no cover - table and branches are kept in sync
        raise AssertionError(flow)
    return world.counts()


_WORLD_FLOWS = [flow for flow in _EXPECTED_HELPER if flow != "setup_existing"]


@pytest.mark.parametrize("flow", _WORLD_FLOWS)
def test_helper_store_flows_never_raise_a_keychain_dialog(
    flow: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The helper created the item, the helper reads it: no dialog, whatever
    interpreter runs the flow."""
    assert _measure(flow, tmp_path, monkeypatch, _helper_store) == _EXPECTED_HELPER[flow]


@pytest.mark.parametrize("flow", _WORLD_FLOWS)
def test_in_process_store_flows_read_the_item_less(flow: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _measure(flow, tmp_path, monkeypatch, _legacy_store) == _EXPECTED_LEGACY[flow]


def test_setup_with_an_existing_vault(monkeypatch: pytest.MonkeyPatch, host: dict[str, Any]) -> None:
    assert _measure_setup_existing(host, monkeypatch, _helper_store) == _EXPECTED_HELPER["setup_existing"]


def test_setup_with_an_existing_vault_in_process(monkeypatch: pytest.MonkeyPatch, host: dict[str, Any]) -> None:
    assert _measure_setup_existing(host, monkeypatch, _legacy_store) == _EXPECTED_LEGACY["setup_existing"]


def test_fresh_setup_never_raises_a_dialog(monkeypatch: pytest.MonkeyPatch, host: dict[str, Any]) -> None:
    """Fresh host: only misses (no dialog) and the helper's own writes.

    Accesses: ensure (helper miss, legacy miss, helper re-check) + init_vault's
    locked check (same three) + the first pin (update miss, add) + two commits
    (read + update each) = 12. The misses cost no dialog; before, the vault was
    created in-process (11 accesses, 0 dialogs) and every later interpreter paid.
    """
    assert _measure_setup_fresh(host, monkeypatch, _helper_store) == (12, 0)


def test_fresh_setup_then_another_interpreter_starts_hermes(
    monkeypatch: pytest.MonkeyPatch, host: dict[str, Any]
) -> None:
    """Setup in one interpreter, Hermes started by another: 0 dialogs, because
    neither interpreter owns the item."""
    kc = SimKeychain()
    for module in (env_decrypt_cli, memory_cli):
        monkeypatch.setattr(module, "enable", functools.partial(module.enable, store=_helper_store(kc, "python-dev")))
    assert _run_setup(host, _CountingPromptIO()) == 0
    kc.reset_counts()
    environ: dict[str, str] = {}
    injected = _runtime_env.inject_vault_env(
        root=host["root"], environ=environ, backend=host["backend"], store=_helper_store(kc, "python-hermes")
    )
    assert injected > 0
    assert (kc.access_count, kc.dialog_count) == (1, 0)


# -----------------------------------------------------------------------------
# Migration of an anchor written in-process by an older version
# -----------------------------------------------------------------------------


def _legacy_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _World:
    """Vault + anchor made by the previous version: an item owned by ``python-dev``."""
    return _World(tmp_path, monkeypatch, _legacy_store)


def test_after_the_migration_no_flow_raises_a_dialog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _legacy_world(tmp_path, monkeypatch)
    world.factory = _helper_store  # the new version, run by Hermes's interpreter
    assert world.store().read(_identity.vault_identity(world.root)) is not None
    assert world.kc.dialog_count == 1  # the one-time legacy read (next test)
    world.kc.reset_counts()

    _flow_telegram_setup_memory_step(world)
    assert world.kc.dialog_count == 0
    _seal_env_and_config(world)
    _flow_hermes_start(world)
    _flow_extension_serve_start(world)
    assert world.kc.dialog_count == 0


def test_migration_read_is_the_only_dialog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _legacy_world(tmp_path, monkeypatch)
    label = _identity.vault_identity(world.root)
    store = _helper_store(world.kc, "python-hermes")
    value = store.read(label)
    assert value is not None
    # helper miss + legacy read (THE dialog) + helper add + silent legacy delete attempt
    assert world.kc.dialog_count == 1
    assert world.kc.dialogs[0] == ("python-hermes", "read", _anchor_keychain.DEFAULT_SERVICE)
    # python-hermes may not delete python-dev's item without asking, so it is left
    # in place -- harmless: the helper item is read first from now on.
    assert (_anchor_keychain.DEFAULT_SERVICE, label) in world.kc.items
    world.kc.reset_counts()
    assert _helper_store(world.kc, "python-hermes").read(label) == value
    assert (world.kc.access_count, world.kc.dialog_count) == (1, 0)


def test_migration_by_the_interpreter_that_wrote_the_item_is_silent_and_removes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _legacy_world(tmp_path, monkeypatch)
    label = _identity.vault_identity(world.root)
    assert _helper_store(world.kc, "python-dev").read(label) is not None
    assert world.kc.dialog_count == 0
    assert (_anchor_keychain.DEFAULT_SERVICE, label) not in world.kc.items
    assert (_anchor_keychain.HELPER_SERVICE, label) in world.kc.items


# -----------------------------------------------------------------------------
# Telegram / Desktop Telegram endpoints never touch the login keychain
# -----------------------------------------------------------------------------


def test_telegram_secret_store_never_touches_the_keychain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``/llm/venice``, ``/llm/local``, ``/telegram/login/*`` and ``/sync`` go through
    :class:`TeeSecretStore`: Secure Enclave ECDH via the helper, no keychain item."""
    from dataclasses import replace

    from .extension.test_telegram_tee import _tee_store, _value

    def tripwire(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("the Telegram secret store touched the Keychain anchor")

    monkeypatch.setattr(_anchor_keychain, "default_anchor_store", tripwire)
    monkeypatch.setattr(_anchor_keychain.KeychainAnchorStore, "__init__", tripwire)
    monkeypatch.setattr(_identity, "resolve_store", tripwire)

    store, _enclave = _tee_store(tmp_path)
    store.ensure_key()
    store.store(_value())
    store.update(lambda old: replace(old, venice_model="m"))
    assert store.load().venice_model == "m"
