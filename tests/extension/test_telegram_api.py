"""Service, WebSocket-handler and CLI tests for the Telegram importer."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension import pairing
from mordred_hermes.extension.crypto import decrypt_message, encrypt_message_v2, hkdf_subkey, key_id
from mordred_hermes.extension.egress import EgressRoute
from mordred_hermes.extension.telegram import secrets, service, store, venice
from mordred_hermes.extension.telegram.ask import AskRequest
from mordred_hermes.wizard import telegram_cli

_AES = b"\x01" * 32
_EK = hkdf_subkey(_AES, "mordred-extchat-v1", "extchat")


class _MemorySecrets:
    def __init__(self, value: secrets.TelegramSecrets | None):
        self.value = value

    def load(self, *, fresh: bool = False) -> secrets.TelegramSecrets | None:
        return self.value

    def update(self, mutate: Any) -> Any:
        self.value = mutate(self.value)
        return self.value

    def flags(self) -> dict[str, Any] | None:
        if self.value is None:
            return None
        return {
            "logged_in": self.value.session is not None,
            "llm_backend": self.value.llm_backend(),
            "llm_model": self.value.llm_model(),
        }


def _value(**overrides: Any) -> secrets.TelegramSecrets:
    base: dict[str, Any] = {
        "api_id": 1,
        "api_hash": "ab" * 16,
        "store_key": b"\x05" * 32,
        "session": "S",
        "venice_api_key": "VK",
        "venice_model": "m1",
    }
    base.update(overrides)
    return secrets.TelegramSecrets(**base)


def _seed_archive(root, key: bytes = b"\x05" * 32) -> None:
    archive = store.ArchiveStore(key, root)
    archive.append_messages(
        -5,
        [
            store.StoredMessage(id=1, date=1_790_000_000, sender="Carol", text="Budget review moved to Monday"),
            store.StoredMessage(id=2, date=1_790_000_100, sender="Me", text="thanks", out=True),
        ],
    )
    archive.save_index(
        store.ArchiveIndex(
            account_label="Me",
            last_sync=1_790_000_200,
            dialogs={
                -5: store.DialogInfo(-5, "group", "Finance team", last_message_id=2, message_count=2, last_date=1)
            },
        )
    )


class _VeniceSession:
    def __init__(self, privacy: str = "private") -> None:
        self.privacy = privacy
        self.bodies: list[dict[str, Any]] = []
        self.closed = False

    def get(self, url: str, **_kwargs: Any) -> Any:
        payload = {"data": [{"id": "m1", "model_spec": {"privacy": self.privacy, "availableContextTokens": 32000}}]}
        return _Resp(payload=payload)

    def post(self, url: str, **kwargs: Any) -> Any:
        self.bodies.append(kwargs["json"])
        return _Resp(
            chunks=[
                b'data: {"choices":[{"delta":{"content":"\\u27e6P1\\u27e7 moved it to Monday in "}}]}\n',
                b'data: {"choices":[{"delta":{"content":"\\u27e6C1\\u27e7."}}]}\n',
                b"data: [DONE]\n",
            ]
        )

    async def close(self) -> None:
        self.closed = True


class _Resp:
    def __init__(self, payload: Any = None, chunks: list[bytes] | None = None) -> None:
        self.status = 200
        self._payload = payload
        self._chunks = chunks or []

        class _Content:
            async def iter_any(inner) -> Any:
                for c in self._chunks:
                    yield c

        self.content = _Content()

    async def json(self) -> Any:
        return self._payload

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None


@pytest.fixture(autouse=True)
def _clear_cache():
    venice._catalog_cache.clear()


def _service(tmp_path, value=None, *, privacy="private", policy=None, installed=True) -> tuple[Any, _VeniceSession]:
    session = _VeniceSession(privacy)
    svc = service.TelegramService(
        secret_store=_MemorySecrets(value),
        archive_root=tmp_path / "tg",
        http_session_factory=lambda _route, _t: session,
        route_resolver=lambda _h: EgressRoute(None, None),
        policy_check=policy or (lambda _backend, _url: None),
        installed=lambda: installed,
    )
    return svc, session


# -- service ---------------------------------------------------------------------------


def test_status_unconfigured(tmp_path):
    svc, _ = _service(tmp_path, None)
    status = asyncio.run(svc.status())
    assert status["configured"] is False and status["logged_in"] is False


def test_status_counts(tmp_path):
    _seed_archive(tmp_path / "tg")
    svc, _ = _service(tmp_path, _value())

    async def scenario() -> dict[str, Any]:
        await svc.dialogs()  # counts are remembered after an Enclave-backed read
        return await svc.status()

    status = asyncio.run(scenario())
    assert (status["dialog_count"], status["message_count"], status["account_label"]) == (1, 2, "Me")
    assert (status["llm_backend"], status["llm_model"]) == ("venice", "m1")


def test_start_sync_preconditions(tmp_path):
    svc, _ = _service(tmp_path, None)
    with pytest.raises(service.TelegramServiceError, match="telegram_not_configured"):
        asyncio.run(svc.start_sync())
    svc, _ = _service(tmp_path, _value(session=None))
    with pytest.raises(service.TelegramServiceError, match="telegram_not_logged_in"):
        asyncio.run(svc.start_sync())
    svc, _ = _service(tmp_path, _value(), installed=False)
    with pytest.raises(service.TelegramServiceError, match="telegram_not_installed"):
        asyncio.run(svc.start_sync())


def test_sync_runs_in_background_and_records_errors(tmp_path):
    class _Client:
        async def connect(self) -> None:
            return None

        async def is_user_authorized(self) -> bool:
            return False

        async def disconnect(self) -> None:
            return None

    svc, _ = _service(tmp_path, _value())
    svc._client_factory = lambda *_a, **_k: _Client()

    async def scenario() -> dict[str, Any]:
        await svc.start_sync()
        await svc.wait_for_sync()
        return await svc.status()

    status = asyncio.run(scenario())
    assert status["last_error"] == "telegram_session_revoked"
    assert status["syncing"] is False


def _collect_ask(svc, request) -> tuple[list[str], list[Any]]:
    meta: list[Any] = []

    async def run() -> list[str]:
        return [c async for c in svc.ask(request, meta.append)]

    return asyncio.run(run()), meta


def test_ask_pseudonymizes_outbound_and_restores_inbound(tmp_path):
    _seed_archive(tmp_path / "tg")
    svc, session = _service(tmp_path, _value())
    chunks, meta = _collect_ask(svc, AskRequest(question="When is the budget review?"))
    assert "".join(chunks) == "Carol moved it to Monday in Finance team."
    assert meta[0].message_count >= 1
    sent = json.dumps(session.bodies[0], ensure_ascii=False)
    assert "Carol" not in sent and "Finance team" not in sent
    assert "tools" not in session.bodies[0]
    assert session.closed


def test_ask_refuses_anonymized_models(tmp_path):
    _seed_archive(tmp_path / "tg")
    svc, session = _service(tmp_path, _value(), privacy="anonymized")
    with pytest.raises(venice.VeniceError, match="venice_model_not_private"):
        _collect_ask(svc, AskRequest(question="budget"))
    assert session.bodies == []  # nothing about the archive was sent


def test_ask_respects_llm_policy(tmp_path):
    _seed_archive(tmp_path / "tg")

    def refuse(_backend: str, _url: str) -> None:
        raise service.TelegramServiceError("llm_policy_refused")

    svc, session = _service(tmp_path, _value(), policy=refuse)
    with pytest.raises(service.TelegramServiceError, match="llm_policy_refused"):
        _collect_ask(svc, AskRequest(question="budget"))
    assert session.bodies == []


def test_ask_requires_venice_key(tmp_path):
    svc, _ = _service(tmp_path, _value(venice_api_key=None))
    with pytest.raises(Exception, match="llm_not_configured"):
        _collect_ask(svc, AskRequest(question="budget"))


def test_strict_policy_refuses_unlisted_venice(tmp_path, monkeypatch):
    policy = tmp_path / "mordred" / "policy.json"
    policy.parent.mkdir(parents=True)
    policy.write_text(json.dumps({"policy": "strict", "allow_cloud_llm": True, "cloud_provider_allowlist": []}))
    with pytest.raises(service.TelegramServiceError, match="llm_policy_refused"):
        service.check_llm_policy("venice", venice.DEFAULT_BASE_URL)
    policy.write_text(json.dumps({"policy": "strict", "allow_cloud_llm": True, "cloud_provider_allowlist": ["venice"]}))
    service.check_llm_policy("venice", venice.DEFAULT_BASE_URL)
    with pytest.raises(service.TelegramServiceError, match="llm_policy_refused"):
        service.check_llm_policy("venice", "https://evil.example/api/v1")


def test_error_code_mapping():
    flood = type("FloodWaitError", (Exception,), {})
    assert service.error_code(flood(), "x") == "telegram_rate_limited"
    assert service.error_code(ConnectionError(), "x") == "telegram_unavailable"
    assert service.error_code(ValueError("secret text"), "fallback") == "fallback"


# -- WebSocket handlers ------------------------------------------------------------------


class _FakeWS:
    def __init__(self) -> None:
        self.closed = False
        self.sent: list[dict[str, Any]] = []

    async def send_str(self, data: str) -> None:
        self.sent.append(json.loads(data))


async def _no_chat(_content: str, _context: dict[str, Any]) -> Any:
    if False:
        yield ""


@pytest.fixture(autouse=True)
def _no_api_env(monkeypatch):
    monkeypatch.delenv(telegram_cli.API_ID_ENV, raising=False)
    monkeypatch.delenv(telegram_cli.API_HASH_ENV, raising=False)


def test_cli_login_reads_api_credentials_from_env(monkeypatch):
    monkeypatch.setenv(telegram_cli.API_ID_ENV, "777")
    monkeypatch.setenv(telegram_cli.API_HASH_ENV, "ef" * 16)
    assert telegram_cli._read_api_credentials(lambda _p: "unused", lambda _p: "unused") == (777, "ef" * 16)


def _conn(svc: Any, *, page: bool = False) -> Any:
    token = "telegram-test-token"
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=_AES,
            ext_token=token,
            ext_pubkey_b64="ext",
            hermes_pubkey_b64="hermes",
            paired_at=1.0,
        )
    )
    conn = extension_api._Connection(_FakeWS(), _no_chat, telegram_service=svc, page_token="p" if page else None)
    conn.authed = True
    if page:
        conn._page_authenticated = True
    else:
        conn._authentication_generation = pairing.authentication_generation_fingerprint(token)
    return conn


def _dispatch(conn: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    async def run() -> None:
        await conn.dispatch(json.dumps(payload))
        # Questions run as background tasks; let them finish.
        await asyncio.gather(*list(conn._telegram_asks.values()), return_exceptions=True)

    asyncio.run(run())
    return conn.ws.sent


def test_ws_status_seals_account_label(tmp_path):
    _seed_archive(tmp_path / "tg")
    svc, _ = _service(tmp_path, _value())
    conn = _conn(svc)
    _dispatch(conn, {"id": "d", "type": "telegram_dialogs"})
    conn.ws.sent.clear()
    [frame] = _dispatch(conn, {"id": "s", "type": "telegram_status"})
    assert frame["type"] == "telegram_status_result" and frame["ok"] is True
    label = frame["status"]["account_label"]
    assert label != "Me" and decrypt_message(_EK, label) == "Me"


def test_ws_dialogs_seal_titles(tmp_path):
    _seed_archive(tmp_path / "tg")
    svc, _ = _service(tmp_path, _value())
    [frame] = _dispatch(_conn(svc), {"id": "d", "type": "telegram_dialogs"})
    [dialog] = frame["dialogs"]
    assert dialog["id"] == "-5" and "Finance" not in json.dumps(frame)
    assert decrypt_message(_EK, dialog["title"]) == "Finance team"


def test_ws_ask_streams_sealed_chunks(tmp_path):
    _seed_archive(tmp_path / "tg")
    svc, _ = _service(tmp_path, _value())
    question = encrypt_message_v2(_EK, "budget review?", key_id(_EK))
    frames = _dispatch(_conn(svc), {"id": "a", "type": "telegram_ask", "question": question, "dialog_ids": ["-5"]})
    types = [f["type"] for f in frames]
    assert types[0] == "telegram_ask_meta" and types[-1] == "telegram_ask_end"
    text = "".join(decrypt_message(_EK, f["content"]) for f in frames if f["type"] == "telegram_ask_chunk")
    assert text == "Carol moved it to Monday in Finance team."
    assert all("Carol" not in json.dumps(f) for f in frames)


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ({"question": "plaintext question"}, "invalid_request"),
        ({"question": "🔒ENC:v2:AAAAAAAA:AAAAAAAAAAAAAAAA:AAAA"}, "undecryptable"),
        ({"question": None}, "invalid_request"),
        ({"dialog_ids": [5]}, "invalid_request"),
        ({"dialog_ids": ["1; drop"]}, "invalid_request"),
        ({"since": -1}, "invalid_request"),
    ],
)
def test_ws_ask_rejects_bad_requests(tmp_path, payload, reason):
    svc, session = _service(tmp_path, _value())
    body = {"id": "a", "type": "telegram_ask", "question": encrypt_message_v2(_EK, "q", key_id(_EK))}
    body.update(payload)
    [frame] = _dispatch(_conn(svc), body)
    assert frame == {"id": "a", "type": "telegram_ask_error", "reason": reason}
    assert session.bodies == []


def test_ws_ask_runs_in_background_and_can_be_cancelled(tmp_path):
    svc, _ = _service(tmp_path, _value())

    async def slow_ask(_request: Any, _on_meta: Any) -> Any:
        await asyncio.sleep(3600)
        yield "never"

    svc.ask = slow_ask
    conn = _conn(svc)
    question = encrypt_message_v2(_EK, "q", key_id(_EK))

    async def run() -> None:
        await conn.dispatch(json.dumps({"id": "a", "type": "telegram_ask", "question": question}))
        assert "a" in conn._telegram_asks  # dispatch returned while the ask runs
        # Other frames are not blocked behind it.
        await conn.dispatch(json.dumps({"id": "s", "type": "telegram_sync"}))
        await conn.dispatch(json.dumps({"id": "a", "type": "telegram_ask_cancel"}))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert conn._telegram_asks == {}

    asyncio.run(run())
    assert [f["type"] for f in conn.ws.sent] == ["telegram_sync_result"]


def test_start_sync_reports_a_held_lock(tmp_path):
    svc, _ = _service(tmp_path, _value())
    held = store.ArchiveStore(b"\x05" * 32, tmp_path / "tg")
    with held.locked(), pytest.raises(store.StoreError, match="sync_in_progress"):
        asyncio.run(svc.start_sync())
    assert svc.syncing is False


def test_ws_ask_error_is_a_code(tmp_path):
    svc, _ = _service(tmp_path, _value(venice_api_key=None))
    question = encrypt_message_v2(_EK, "q", key_id(_EK))
    [frame] = _dispatch(_conn(svc), {"id": "a", "type": "telegram_ask", "question": question})
    assert frame == {"id": "a", "type": "telegram_ask_error", "reason": "llm_not_configured"}


@pytest.mark.parametrize("mtype", ["telegram_status", "telegram_sync", "telegram_dialogs", "telegram_ask"])
def test_ws_page_sessions_cannot_reach_telegram(tmp_path, mtype):
    svc, _ = _service(tmp_path, _value())
    [frame] = _dispatch(_conn(svc, page=True), {"id": "x", "type": mtype})
    assert frame == {"id": "x", "type": "error", "reason": "page_session_forbidden"}


def test_ws_sync_validates_options(tmp_path):
    svc, _ = _service(tmp_path, None)
    [frame] = _dispatch(_conn(svc), {"id": "y", "type": "telegram_sync", "options": {"limit_per_dialog": 0}})
    assert frame["error"] == "invalid_request"
    conn = _conn(svc)
    [frame] = _dispatch(conn, {"id": "y", "type": "telegram_sync"})
    assert frame == {"id": "y", "type": "telegram_sync_result", "ok": False, "error": "telegram_not_configured"}


# -- CLI --------------------------------------------------------------------------------------


class _LoginClient:
    def __init__(self, *, needs_password: bool) -> None:
        self.needs_password = needs_password
        self.sign_ins: list[dict[str, Any]] = []
        self.session = "SESSION"
        self.logged_out = False

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None

    async def send_code_request(self, phone: str) -> None:
        assert phone == "+810000"

    async def sign_in(self, **kwargs: Any) -> Any:
        self.sign_ins.append(kwargs)
        if "code" in kwargs and self.needs_password:
            raise type("SessionPasswordNeededError", (Exception,), {})()
        return object()

    async def is_user_authorized(self) -> bool:
        return True

    async def log_out(self) -> None:
        self.logged_out = True


def test_cli_login_stores_session_in_vault_only(tmp_path, monkeypatch):
    monkeypatch.setattr(telegram_cli, "_secret_store", lambda: None)
    monkeypatch.setattr("mordred_hermes.extension.telegram.client.save_session", lambda c: c.session)
    fake = _LoginClient(needs_password=True)
    policies: list[Any] = []

    def factory(api_id: int, api_hash: str, session: Any, *, policy: Any) -> Any:
        policies.append(policy)
        return fake

    answers = iter(["12345", "+810000", "11111"])
    hidden = iter(["cd" * 16, "2fa-password"])
    mem = _MemorySecrets(None)
    rc = telegram_cli.telegram_login(
        input_fn=lambda _p: next(answers), secret_fn=lambda _p: next(hidden), store=mem, client_factory=factory
    )
    assert rc == 0
    assert mem.value is not None and mem.value.session == "SESSION" and mem.value.api_id == 12345
    assert fake.sign_ins[-1] == {"password": "2fa-password"}
    assert policies[0].login is True
    assert "2fa-password" not in secrets.encode(mem.value).decode()


def test_cli_login_refuses_when_already_logged_in():
    mem = _MemorySecrets(_value())
    rc = telegram_cli.telegram_login(
        input_fn=lambda _p: "", secret_fn=lambda _p: "", store=mem, client_factory=lambda *_a, **_k: None
    )
    assert rc == 1 and mem.value.session == "S"


def test_cli_login_revokes_when_saving_the_session_fails(monkeypatch):
    fake = _LoginClient(needs_password=False)
    fake._authorized = True

    def broken_save(_client: Any) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr("mordred_hermes.extension.telegram.client.save_session", broken_save)
    answers = iter(["12345", "+810000", "11111"])
    mem = _MemorySecrets(None)
    rc = telegram_cli.telegram_login(
        input_fn=lambda _p: next(answers),
        secret_fn=lambda _p: "cd" * 16,
        store=mem,
        client_factory=lambda *_a, **_k: fake,
    )
    assert rc == 1 and fake.logged_out and mem.value is None


def test_cli_login_rejects_bad_api_hash(tmp_path):
    answers = iter(["12345"])
    rc = telegram_cli.telegram_login(
        input_fn=lambda _p: next(answers),
        secret_fn=lambda _p: "nothex",
        store=_MemorySecrets(None),
        client_factory=lambda *_a, **_k: None,
    )
    assert rc == 1


def test_cli_logout_revokes_and_forgets(tmp_path, monkeypatch):
    _seed_archive(tmp_path / "mordred" / "telegram")
    fake = _LoginClient(needs_password=False)
    mem = _MemorySecrets(_value())
    rc = telegram_cli.telegram_logout(forget=True, store=mem, client_factory=lambda *_a, **_k: fake)
    assert rc == 0 and fake.logged_out and mem.value is None
    assert not list((tmp_path / "mordred" / "telegram").rglob("*.enc"))


def test_cli_logout_keeps_archive_by_default(tmp_path):
    mem = _MemorySecrets(_value())
    fake = _LoginClient(needs_password=False)
    assert telegram_cli.telegram_logout(store=mem, client_factory=lambda *_a, **_k: fake) == 0
    assert mem.value is not None and mem.value.session is None and mem.value.store_key == b"\x05" * 32


def test_cli_venice_stores_key_and_model():
    mem = _MemorySecrets(_value(venice_api_key=None, venice_model=None))
    assert telegram_cli.telegram_venice(model="qwen3-6-27b", secret_fn=lambda _p: "NEWKEY", store=mem) == 0
    assert (mem.value.venice_api_key, mem.value.venice_model) == ("NEWKEY", "qwen3-6-27b")
    assert telegram_cli.telegram_venice(model=None, secret_fn=lambda _p: "", store=_MemorySecrets(None)) == 1
