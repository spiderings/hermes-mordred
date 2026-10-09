"""One Enclave unseal per Telegram operation.

Every unseal of ``credentials.sealed`` is a Secure Enclave ECDH -- one Touch ID
(or macOS password) dialog. Several commands used to unseal twice or three
times for one operation (a ``load()`` and then an ``update()`` that loads again,
or a load whose result was thrown away). These tests count ``enclave_ecdh``
calls on a fake Enclave per operation, and pin that a concurrent writer's change
is never lost by skipping the second unseal.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

from mordred_hermes.extension.telegram import secrets
from mordred_hermes.extension.telegram.login_flow import LoginFlows
from mordred_hermes.wizard import telegram_cli

from .test_telegram_api import _LoginClient
from .test_telegram_tee import _tee_store, _value


def _sealed_store(tmp_path: Any, value: secrets.TelegramSecrets | None) -> Any:
    store, enclave = _tee_store(tmp_path)
    store.ensure_key()
    if value is not None:
        store.store(value)  # sealing uses the public key only: no unseal
    enclave.ecdh_calls = 0
    return store, enclave


# -- TeeSecretStore snapshot -------------------------------------------------------------


def test_update_from_snapshot_does_not_unseal_again(tmp_path):
    store, enclave = _sealed_store(tmp_path, _value())
    snapshot = store.load_snapshot()
    store.update_from_snapshot(snapshot, lambda old: replace(old, venice_model="m"))
    assert enclave.ecdh_calls == 1
    assert store.load().venice_model == "m"


def test_update_from_snapshot_falls_back_when_another_writer_changed_the_file(tmp_path):
    store, enclave = _sealed_store(tmp_path, _value())
    snapshot = store.load_snapshot()
    store.store(_value(venice_model="written-meanwhile"))  # a concurrent writer
    store.update_from_snapshot(snapshot, lambda old: replace(old, session=None))
    after = store.load()
    assert after.venice_model == "written-meanwhile"  # the other write is kept
    assert after.session is None
    assert enclave.ecdh_calls == 3  # snapshot + fallback update + the check above


def test_update_from_snapshot_of_an_absent_file_writes_without_unsealing(tmp_path):
    store, enclave = _sealed_store(tmp_path, None)
    snapshot = store.load_snapshot()
    assert snapshot == (None, None)
    store.update_from_snapshot(snapshot, lambda _old: _value())
    assert enclave.ecdh_calls == 0


# -- CLI commands --------------------------------------------------------------------


def test_cli_venice_unseals_once(tmp_path):
    """Before: a load() to check for a stored key, then update() loaded again (2)."""
    store, enclave = _sealed_store(tmp_path, _value(venice_api_key=None))
    assert telegram_cli.telegram_venice(model="qwen3-6-27b", secret_fn=lambda _p: "NEWKEY", store=store) == 0
    assert enclave.ecdh_calls == 1
    assert store.load().venice_api_key == "NEWKEY"


def test_cli_venice_keeps_the_stored_key_on_empty_input_with_one_unseal(tmp_path):
    store, enclave = _sealed_store(tmp_path, _value())
    assert telegram_cli.telegram_venice(model="m2", secret_fn=lambda _p: "", store=store) == 0
    assert enclave.ecdh_calls == 1
    assert (store.load().venice_api_key, store.load().venice_model) == ("VENICE-SECRET", "m2")


def test_cli_venice_without_any_key_refuses_and_writes_nothing(tmp_path):
    store, enclave = _sealed_store(tmp_path, _value(venice_api_key=None))
    before = store.sealed_path.read_bytes()
    assert telegram_cli.telegram_venice(model=None, secret_fn=lambda _p: "", store=store) == 1
    assert store.sealed_path.read_bytes() == before
    assert enclave.ecdh_calls == 1


def test_cli_logout_unseals_once(tmp_path):
    """Before: load() for the session to revoke, then update() loaded again (2)."""
    store, enclave = _sealed_store(tmp_path, _value())
    fake = _LoginClient(needs_password=False)
    assert telegram_cli.telegram_logout(store=store, client_factory=lambda *_a, **_k: fake) == 0
    assert fake.logged_out
    assert enclave.ecdh_calls == 1
    assert store.load().session is None


def test_cli_logout_forget_unseals_once(tmp_path):
    store, enclave = _sealed_store(tmp_path, _value())
    fake = _LoginClient(needs_password=False)
    assert telegram_cli.telegram_logout(forget=True, store=store, client_factory=lambda *_a, **_k: fake) == 0
    assert enclave.ecdh_calls == 1
    assert not store.sealed_path.exists()


def test_cli_login_with_stored_api_credentials_unseals_once(tmp_path, monkeypatch):
    """Re-login after a logout (API credentials kept). Before: load() + update() (2)."""
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.save_session", lambda c: c.session)
    store, enclave = _sealed_store(tmp_path, _value(session=None))
    fake = _LoginClient(needs_password=False)
    answers = iter(["+810000", "11111"])
    rc = telegram_cli.telegram_login(
        input_fn=lambda _p: next(answers),
        secret_fn=lambda _p: "",
        store=store,
        client_factory=lambda *_a, **_k: fake,
    )
    assert rc == 0
    assert enclave.ecdh_calls == 1
    assert store.load().session == "SESSION"


# -- Hermes Desktop login flow -------------------------------------------------------


def test_desktop_login_with_stored_api_credentials_unseals_once(tmp_path):
    """Before: start() load, then _finish() load + update() load (3)."""
    store, enclave = _sealed_store(tmp_path, _value(session=None, venice_model="kept"))
    fake = _LoginClient(needs_password=False)
    flows = LoginFlows(store, client_factory=lambda *_a, **_k: fake, save_session=lambda c: c.session)

    async def run() -> str:
        flow = await flows.start(api_id=None, api_hash=None, phone="+810000")
        return await flows.submit_code(flow.flow_id, "11111")

    assert asyncio.run(run()) == "done"
    assert enclave.ecdh_calls == 1
    after = store.load()
    assert (after.session, after.venice_model) == ("SESSION", "kept")
