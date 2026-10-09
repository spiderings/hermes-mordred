"""Enclave-sealed credentials, the Venice/local-only LLM rule, and migration."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.extension.egress import EgressRoute
from mordred_hermes.extension.telegram import llm, secrets, service, store, tee, venice
from mordred_hermes.extension.telegram.ask import AskRequest
from mordred_hermes.keyvault._exceptions import WrapKeyAlreadyExists, WrapKeyNotFound
from mordred_hermes.wizard import telegram_cli


class _FakeEnclave:
    """NativeBackend stand-in: the private key stays inside this object."""

    def __init__(self) -> None:
        self.keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        self.ecdh_calls = 0
        self.unattended: dict[str, bool | None] = {}

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        if key_id in self.keys:
            raise WrapKeyAlreadyExists(key_id)
        self.keys[key_id] = ec.generate_private_key(ec.SECP256R1())
        self.unattended[key_id] = unattended
        return self.get_enclave_public_key(key_id)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        if key_id not in self.keys:
            raise WrapKeyNotFound(key_id)
        return self.keys[key_id].public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def delete_enclave_key(self, key_id: str) -> None:
        self.keys.pop(key_id, None)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        if key_id not in self.keys:
            raise WrapKeyNotFound(key_id)
        self.ecdh_calls += 1
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self.keys[key_id].exchange(ec.ECDH(), peer)


def _value(**overrides: Any) -> secrets.TelegramSecrets:
    base: dict[str, Any] = {
        "api_id": 1,
        "api_hash": "ab" * 16,
        "store_key": b"\x05" * 32,
        "session": "SESSION-SECRET",
        "venice_api_key": "VENICE-SECRET",
    }
    base.update(overrides)
    return secrets.TelegramSecrets(**base)


def _tee_store(tmp_path, enclave: _FakeEnclave | None = None) -> tuple[tee.TeeSecretStore, _FakeEnclave]:
    fake = enclave or _FakeEnclave()
    return tee.TeeSecretStore(tmp_path / "tg", backend_factory=lambda: fake, audit_sink=lambda _e: None), fake


# -- Enclave seal ---------------------------------------------------------------------


def test_sealed_file_holds_no_plaintext_and_needs_the_enclave(tmp_path):
    vault, _enclave = _tee_store(tmp_path)
    vault.ensure_key()
    vault.store(_value())
    raw = vault.sealed_path.read_bytes()
    assert raw.startswith(b"MTC1")
    for secret in (b"SESSION-SECRET", b"VENICE-SECRET", b"abab"):
        assert secret not in raw
    assert vault.load() == _value()

    # Another device (a different Enclave key) cannot open it.
    other, _ = _tee_store(tmp_path, _FakeEnclave())
    other._backend_factory().generate_enclave_key(tee.KEY_ID)
    with pytest.raises(secrets.TelegramSecretsError):
        other.load()


def test_every_load_is_a_fresh_enclave_unwrap_and_status_uses_none(tmp_path):
    vault, enclave = _tee_store(tmp_path)
    vault.ensure_key()
    vault.store(_value())
    before = enclave.ecdh_calls
    vault.load()
    vault.load()
    assert enclave.ecdh_calls == before + 2  # nothing cached
    flags = vault.flags()
    assert enclave.ecdh_calls == before + 2  # status never unseals
    assert flags == {
        "version": 1,
        "logged_in": True,
        "api_configured": True,
        "llm_backend": "venice",
        "llm_model": venice.DEFAULT_MODEL,
    }
    assert "SESSION" not in json.dumps(flags)


def test_key_requires_presence_by_default(tmp_path):
    vault, enclave = _tee_store(tmp_path)
    vault.ensure_key()
    assert enclave.unattended[tee.KEY_ID] is False
    vault2, enclave2 = _tee_store(tmp_path / "b")
    vault2.ensure_key(require_presence=False)
    assert enclave2.unattended[tee.KEY_ID] is True


def test_tampered_seal_is_refused(tmp_path):
    vault, _ = _tee_store(tmp_path)
    vault.ensure_key()
    vault.store(_value())
    raw = bytearray(vault.sealed_path.read_bytes())
    raw[-1] ^= 1
    vault.sealed_path.write_bytes(bytes(raw))
    with pytest.raises(secrets.TelegramSecretsError, match="secrets_corrupt"):
        vault.load()


def test_no_helper_means_no_seal(monkeypatch):
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: None)
    monkeypatch.setattr(_seckey_helper, "find_tpmkey_helper", lambda: None)
    with pytest.raises(secrets.TelegramSecretsError, match="tee_unavailable"):
        tee.hardware_backend()


def test_hardware_backend_has_no_software_fallback(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _seckey_helper

    monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: "/nonexistent/helper")
    monkeypatch.setattr(_seckey_helper, "find_tpmkey_helper", lambda: "/nonexistent/helper")
    backend = tee.hardware_backend(tmp_path)
    assert backend._sw_ops is None and backend._legacy_ops is None


# -- LLM destinations --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:11434/v1", "http://127.0.0.1:11434/v1"),
        ("http://localhost:8080/v1/", "http://127.0.0.1:8080/v1"),
        ("https://[::1]:8443/api", "https://[::1]:8443/api"),
    ],
)
def test_local_endpoint_accepts_only_loopback(url, expected):
    assert llm.normalize_local_endpoint(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.10:11434/v1",
        "http://example.com:80/v1",
        "http://127.0.0.1/v1",  # no explicit port
        "http://user:pw@127.0.0.1:1/v1",
        "http://127.0.0.1:1/v1?x=1",
        "ftp://127.0.0.1:21/",
        "http://127.0.0.1.nip.io:80/",
    ],
)
def test_local_endpoint_rejects_everything_else(url):
    with pytest.raises(llm.LlmConfigError, match="local_endpoint_invalid"):
        llm.normalize_local_endpoint(url)


def test_venice_url_is_not_configurable():
    target = llm.resolve_target("venice", venice_api_key="k", venice_model="m", local_endpoint=None, local_model=None)
    assert target.base_url == "https://api.venice.ai/api/v1"
    with pytest.raises(llm.LlmConfigError, match="llm_not_configured"):
        llm.resolve_target("custom", venice_api_key="k", venice_model="m", local_endpoint=None, local_model=None)


class _Resp:
    def __init__(self, status: int, chunks: list[bytes]):
        self.status = status
        self._chunks = chunks

        class _Content:
            async def iter_any(inner) -> Any:
                for c in self._chunks:
                    yield c

        self.content = _Content()

    async def json(self) -> Any:
        return {}

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None


class _LocalSession:
    def __init__(self, status: int = 200) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.status = status

    def get(self, url: str, **kwargs: Any) -> Any:
        raise AssertionError("a local model needs no catalog lookup")

    def post(self, url: str, **kwargs: Any) -> Any:
        self.calls.append((url, kwargs))
        return _Resp(self.status, [b'data: {"choices":[{"delta":{"content":"ok"}}]}\n'])

    async def close(self) -> None:
        return None


class _Mem:
    def __init__(self, value: secrets.TelegramSecrets) -> None:
        self.value = value

    def load(self, *, fresh: bool = True) -> secrets.TelegramSecrets:
        return self.value

    def flags(self) -> dict[str, Any]:
        return {"logged_in": True, "llm_backend": self.value.llm_backend(), "llm_model": self.value.llm_model()}


def _seed(root) -> None:
    archive = store.ArchiveStore(b"\x05" * 32, root)
    archive.append_messages(-5, [store.StoredMessage(id=1, date=1, sender="Carol", text="budget moved")])
    archive.save_index(store.ArchiveIndex(dialogs={-5: store.DialogInfo(-5, "group", "Finance", message_count=1)}))


def test_local_backend_goes_direct_to_loopback_without_proxy_or_venice_params(tmp_path):
    _seed(tmp_path / "tg")
    session = _LocalSession()
    routes: list[EgressRoute] = []
    value = _value(backend="local", local_endpoint="http://127.0.0.1:11434/v1", local_model="qwen", venice_api_key=None)

    def resolver(_host: str) -> EgressRoute:
        raise AssertionError("a loopback model must not consult the proxy route")

    svc = service.TelegramService(
        secret_store=_Mem(value),
        archive_root=tmp_path / "tg",
        http_session_factory=lambda route, _t: routes.append(route) or session,
        route_resolver=resolver,
        policy_check=lambda _b, _u: None,
    )

    async def run() -> str:
        return "".join([c async for c in svc.ask(AskRequest(question="budget"), lambda _m: None)])

    assert asyncio.run(run()) == "ok"
    [(url, kwargs)] = session.calls
    assert url == "http://127.0.0.1:11434/v1/chat/completions"
    assert kwargs["allow_redirects"] is False
    assert "Authorization" not in kwargs["headers"]
    assert "venice_parameters" not in kwargs["json"] and "tools" not in kwargs["json"]
    assert routes == [EgressRoute(None, None)]


def test_redirects_are_errors_not_followed():
    session = _LocalSession(status=307)
    cfg = venice.VeniceConfig(api_key="", model="m", base_url="http://127.0.0.1:1/v1")

    async def run() -> None:
        async for _ in venice.stream_chat(session, cfg, [], backend="local"):
            pass

    with pytest.raises(venice.VeniceError, match="local_llm_unavailable"):
        asyncio.run(run())


# -- CLI -----------------------------------------------------------------------------------


def test_cli_local_llm_validates_and_stores(tmp_path):
    vault, _ = _tee_store(tmp_path)
    vault.ensure_key()
    vault.store(_value())
    assert telegram_cli.telegram_local_llm(endpoint="http://10.0.0.2:1/v1", model="m", store=vault) == 1
    assert telegram_cli.telegram_local_llm(endpoint="http://localhost:11434/v1", model="qwen", store=vault) == 0
    loaded = vault.load()
    assert (loaded.backend, loaded.local_endpoint, loaded.local_model) == ("local", "http://127.0.0.1:11434/v1", "qwen")
    assert vault.flags()["llm_backend"] == "local"


def test_cli_migrate_moves_vault_credentials_into_the_enclave_seal(tmp_path):
    class _Legacy:
        def __init__(self) -> None:
            self.value: secrets.TelegramSecrets | None = _value()

        def load(self, *, fresh: bool = False) -> secrets.TelegramSecrets | None:
            return self.value

        def update(self, mutate: Any) -> None:
            self.value = mutate(self.value)

    legacy = _Legacy()
    vault, enclave = _tee_store(tmp_path)
    assert telegram_cli.telegram_migrate_tee(store=vault, legacy=legacy) == 0
    assert legacy.value is None
    assert vault.load() == _value()
    assert enclave.unattended[tee.KEY_ID] is False
    assert telegram_cli.telegram_migrate_tee(store=vault, legacy=legacy) == 1  # nothing left to move
