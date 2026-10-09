"""End-to-end WebSocket server test: drives ExtensionAPIServer over a real
socket through the full protocol (pair → auth → crypto → chat → sign), plus the
Origin guard. Uses asyncio.run to avoid a pytest-asyncio dependency."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.metadata
import json
import os
import socket
import stat
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes.extension import extension_api
from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


def test_reported_package_version_prefers_canonical_distribution(monkeypatch):
    calls: list[str] = []

    def fake_version(name: str) -> str:
        calls.append(name)
        return {"hermes-mordred": "0.1.0a16", "mordred-hermes": "0.1.0a15"}[name]

    monkeypatch.setattr(importlib.metadata, "version", fake_version)

    assert extension_api._hermes_version() == "0.1.0a16"
    assert calls == ["hermes-mordred"]


def test_reported_package_version_falls_back_to_legacy_distribution(monkeypatch):
    calls: list[str] = []

    def fake_version(name: str) -> str:
        calls.append(name)
        if name == "hermes-mordred":
            raise importlib.metadata.PackageNotFoundError(name)
        return "0.1.0a15"

    monkeypatch.setattr(importlib.metadata, "version", fake_version)

    assert extension_api._hermes_version() == "0.1.0a15"
    assert calls == ["hermes-mordred", "mordred-hermes"]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _ec_public_key_b64(curve: ec.EllipticCurve) -> str:
    public_key = ec.generate_private_key(curve).public_key()
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return xc.b64u_encode(spki)


def _p256_public_key_b64() -> str:
    return _ec_public_key_b64(ec.SECP256R1())


async def _chat_handler(content, _context):
    for piece in ("こんにちは、", f"受け取りました: {content}"):
        yield piece


async def _recv(ws):
    """Receive one frame, never block the suite forever on a missing reply."""
    return json.loads((await asyncio.wait_for(ws.receive(), timeout=5)).data)


async def _pair_and_auth(ws) -> bytes:
    """Drive pair_init + auth as the extension would; returns the shared AES key."""
    await _recv(ws)  # auth_challenge
    code, _ = pairing.generate_code()
    ext_priv = X25519PrivateKey.generate()
    await ws.send_str(
        json.dumps(
            {
                "id": "p1",
                "type": "pair_init",
                "code": code,
                "ext_pubkey": xc.b64u_encode(xc.x25519_public_raw(ext_priv)),
                "challenge": xc.b64u_encode(b"\x07" * 32),
            }
        )
    )
    complete = await _recv(ws)
    await ws.send_str(json.dumps({"type": "auth", "ext_token": complete["ext_token"]}))
    await _recv(ws)  # auth_ok
    return xc.derive_shared_key(ext_priv, complete["hermes_pubkey"], code)


async def _page_auth(ws, server) -> None:
    """Authenticate as the keyless localhost page (per-process page token)."""
    await _recv(ws)  # auth_challenge
    await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
    await _recv(ws)  # auth_ok


async def _run_flow(port: int) -> dict:
    results: dict = {}
    server = extension_api.ExtensionAPIServer(port=port, chat_handler=_chat_handler)
    await server.start()
    try:
        async with aiohttp.ClientSession() as session:
            # Origin guard: a web page origin is rejected.
            try:
                await session.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": "https://evil.example"})
                results["origin_rejected"] = False
            except aiohttp.WSServerHandshakeError as e:
                results["origin_rejected"] = e.status == 403

            async with session.ws_connect(
                f"http://127.0.0.1:{port}/ext", headers={"Origin": "chrome-extension://abc"}
            ) as ws:
                # Server greets with an auth_challenge (§3.5).
                chal = json.loads((await ws.receive()).data)
                results["challenge_type"] = chal["type"]
                results["webauthn_required"] = chal["webauthn_required"]

                # --- pairing ---
                code, _ = pairing.generate_code()
                ext_priv = X25519PrivateKey.generate()
                ext_pub_b64 = xc.b64u_encode(xc.x25519_public_raw(ext_priv))
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "p1",
                            "type": "pair_init",
                            "code": code,
                            "ext_pubkey": ext_pub_b64,
                            "challenge": xc.b64u_encode(b"\x07" * 32),
                        }
                    )
                )
                complete = json.loads((await ws.receive()).data)
                results["pair_type"] = complete["type"]
                ext_key = xc.derive_shared_key(ext_priv, complete["hermes_pubkey"], code)

                # --- auth ---
                await ws.send_str(json.dumps({"type": "auth", "ext_token": complete["ext_token"]}))
                auth = json.loads((await ws.receive()).data)
                results["auth_type"] = auth["type"]
                results["auth_capabilities"] = auth.get("capabilities")

                # --- encrypt then decrypt round-trip via the server ---
                await ws.send_str(json.dumps({"id": "e1", "type": "encrypt", "plaintext": "秘密"}))
                enc = json.loads((await ws.receive()).data)
                results["enc_type"] = enc["type"]
                # The extension would also be able to decrypt locally:
                results["client_decrypt"] = xc.decrypt_message(ext_key, enc["ciphertext"])

                await ws.send_str(json.dumps({"id": "d1", "type": "decrypt", "ciphertext": enc["ciphertext"]}))
                dec = json.loads((await ws.receive()).data)
                results["dec_plaintext"] = dec.get("plaintext")

                # --- chat streaming ---
                await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": "状態"}))
                chat_chunks = []
                while True:
                    m = json.loads((await ws.receive()).data)
                    if m["type"] == "chat_chunk":
                        chat_chunks.append(m["content"])
                    elif m["type"] == "chat_end":
                        break
                results["chat"] = "".join(chat_chunks)

                # --- sign flow (stub the keyvault signer) ---
                import mordred_hermes.extension.api as api_mod
                from mordred_hermes.keyvault import extension_sign

                original_do_sign = api_mod._do_sign
                original_get_address = extension_sign.get_address
                signer = "0x" + "ab" * 20
                try:
                    api_mod._do_sign = lambda method, params, *a: "0xstubbedsig"  # type: ignore[assignment]
                    extension_sign.get_address = lambda: signer
                    await ws.send_str(
                        json.dumps(
                            {
                                "id": "s1",
                                "type": "sign_request",
                                "request_id": "r1",
                                "method": "personal_sign",
                                "params": ["0xdeadbeef", signer.upper()],
                                "origin": "https://app.uniswap.org",
                            }
                        )
                    )
                    prompt = json.loads((await ws.receive()).data)
                    results["sign_prompt_type"] = prompt["type"]
                    results["sign_risk"] = prompt["analysis"]["risk"]
                    results["signer"] = prompt["decoded"]["signer"]
                    await ws.send_str(
                        json.dumps({"id": "s2", "type": "sign_approve", "request_id": "r1", "approved": True})
                    )
                    sresult = json.loads((await ws.receive()).data)
                    results["signature"] = sresult.get("signature")
                finally:
                    api_mod._do_sign = original_do_sign
                    extension_sign.get_address = original_get_address
    finally:
        await server.stop()
    return results


def test_full_server_flow():
    r = asyncio.run(_run_flow(_free_port()))
    assert r["origin_rejected"] is True
    assert r["challenge_type"] == "auth_challenge"
    assert r["webauthn_required"] is False
    assert r["pair_type"] == "pair_complete"
    assert r["auth_type"] == "auth_ok"
    assert r["auth_capabilities"] == ["discord_channel_resolve_v1", "telegram_import_v1"]
    assert r["enc_type"] == "encrypt_result"
    assert r["client_decrypt"] == "秘密"
    assert r["dec_plaintext"] == "秘密"
    assert r["chat"] == "こんにちは、受け取りました: 状態"
    assert r["sign_prompt_type"] == "sign_prompt"
    # "0xdeadbeef" is opaque bytes, not a readable message: medium, not low.
    assert r["sign_risk"] == "medium"
    assert r["signer"] == "0x" + "ab" * 20
    assert r["signature"] == "0xstubbedsig"


def test_page_response_is_never_cached():
    """The anonymous HTML shell never discloses the page bearer token."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as session, session.get(f"http://127.0.0.1:{port}/") as response:
                return response.status, response.headers, await response.text(), server._page_token
        finally:
            await server.stop()

    status, headers, html, token = asyncio.run(_flow(_free_port()))
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert token not in html
    assert "%%MORDRED_PAGE_TOKEN%%" not in html
    assert "window.location.hash" in html
    bootstrap = html.split("</script>", 1)[0]
    assert bootstrap.index("sessionStorage.setItem(pageTokenStorageKey, pageToken)") < bootstrap.index(
        "history.replaceState"
    )
    assert "sessionStorage.getItem(pageTokenStorageKey)" in bootstrap
    assert "sessionStorage.removeItem(pageTokenStorageKey)" in bootstrap
    assert "window.__MORDRED_HANDLE_AUTH_FAILURE__" in bootstrap
    assert "Mordred authentication expired" in bootstrap


def test_page_launch_url_keeps_token_out_of_http_url():
    server = extension_api.ExtensionAPIServer(port=7788)
    assert server.page_url.startswith("http://127.0.0.1:7788/#token=")
    assert server._page_token in server.page_url
    assert "?" not in server.page_url


def test_noncanonical_loopback_bind_origin_is_a_page_principal():
    """Every validated loopback bind address can authenticate its own page."""
    server = extension_api.ExtensionAPIServer(host="127.0.0.2", port=7788)
    origin = "http://127.0.0.2:7788"
    assert server.page_url.startswith(f"{origin}/#token=")
    assert server._origin_allowed(origin) is True
    assert origin in server._local_origins


def test_server_constructor_rejects_non_loopback_bind():
    with pytest.raises(ValueError, match="loopback-only"):
        extension_api.ExtensionAPIServer(host="0.0.0.0")


@pytest.mark.parametrize(
    ("remote", "host", "allowed"),
    [
        ("127.0.0.1", "127.0.0.1:7788", True),
        ("::1", "[::1]:7788", True),
        ("127.0.0.1", "evil.example:7788", False),
        ("10.0.0.8", "127.0.0.1:7788", False),
    ],
)
def test_request_loopback_gate_checks_peer_and_host(remote, host, allowed):
    request = SimpleNamespace(remote=remote, host=host)
    assert extension_api._request_is_loopback(request) is allowed


@pytest.mark.parametrize(
    "origin",
    [
        "chrome-extension://good-id/path",
        "chrome-extension://good-id@evil.example",
        "moz-extension://good-id?redirect=evil",
    ],
)
def test_extension_origin_parser_rejects_lookalikes(origin):
    assert extension_api._is_extension_origin(origin) is False


def test_page_token_auth_and_history():
    """The localhost page authenticates with the per-process page token (only
    from a local origin) and can read/clear the encrypted history."""

    async def _flow(port):
        # Seed some history under the test home.

        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_chat_handler)
        await server.start()
        try:
            # Local origin → page token accepted.
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                json.loads((await ws.receive()).data)  # auth_challenge
                await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
                auth = json.loads((await ws.receive()).data)
                await ws.send_str(json.dumps({"id": "h", "type": "history_get"}))
                hist = json.loads((await ws.receive()).data)
                await ws.send_str(json.dumps({"id": "hc", "type": "history_clear"}))
                cleared = json.loads((await ws.receive()).data)
                return auth, hist["type"], cleared["type"]
        finally:
            await server.stop()

    auth, hist_type, cleared_type = asyncio.run(_flow(_free_port()))
    assert auth["type"] == "auth_ok"
    assert "capabilities" not in auth
    assert hist_type == "history_result"
    assert cleared_type == "history_cleared"


def test_accounts_failure_is_a_correlated_rpc_error(monkeypatch):
    def _fail_account_snapshot():
        # The message is attacker/environment-shaped (paths, backend detail).
        raise RuntimeError("vault unavailable: /Users/operator/.hermes/extension/wallet.json")

    monkeypatch.setattr(extension_api, "_get_account_snapshot", _fail_account_snapshot)

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.ws_connect(
                    f"http://127.0.0.1:{port}/ext",
                    headers={"Origin": f"http://127.0.0.1:{port}"},
                ) as ws,
            ):
                await _page_auth(ws, server)
                await ws.send_str(json.dumps({"id": "a1", "type": "accounts_request"}))
                return await _recv(ws)
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port())) == {
        "id": "a1",
        "type": "error",
        "reason": "wallet_unavailable",
    }


def test_auth_required_before_commands():
    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s, s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                json.loads((await ws.receive()).data)  # drain auth_challenge
                await ws.send_str(json.dumps({"id": "x", "type": "encrypt", "plaintext": "hi"}))
                return json.loads((await ws.receive()).data)
        finally:
            await server.stop()

    msg = asyncio.run(_flow(_free_port()))
    assert msg["type"] == "auth_fail"
    assert msg["reason"] == "not_authenticated"


def test_keepalive_ping_pushed_to_idle_client():
    """An idle connection must receive app-level pings (MV3 service-worker
    keepalive) without sending anything itself."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port, keepalive_interval=0.05)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s, s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                json.loads((await ws.receive()).data)  # auth_challenge
                return json.loads((await asyncio.wait_for(ws.receive(), timeout=2)).data)
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port())) == {"type": "ping"}


def test_reconnect_reauths_with_persisted_token():
    """A reconnecting client (e.g. after an MV3 service-worker kill) redoes
    only the auth handshake with its stored ext_token — no re-pairing."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                    json.loads((await ws.receive()).data)  # auth_challenge
                    code, _ = pairing.generate_code()
                    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
                    await ws.send_str(
                        json.dumps(
                            {
                                "id": "p1",
                                "type": "pair_init",
                                "code": code,
                                "ext_pubkey": ext_pub,
                                "challenge": xc.b64u_encode(b"\x07" * 32),
                            }
                        )
                    )
                    token = json.loads((await ws.receive()).data)["ext_token"]
                # First socket is closed here — reconnect with the token only.
                async with s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws2:
                    json.loads((await ws2.receive()).data)  # fresh auth_challenge
                    await ws2.send_str(json.dumps({"type": "auth", "ext_token": token}))
                    return json.loads((await ws2.receive()).data)
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port()))["type"] == "auth_ok"


@pytest.mark.parametrize("state_change", ["replace", "clear"])
def test_open_extension_socket_is_revoked_when_pairing_changes(state_change):
    """A live socket must never inherit replacement pairing keys or privileges."""
    old_token = "old-extension-token"
    old_key = b"\x11" * 32
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=old_key,
            ext_token=old_token,
            ext_pubkey_b64="old-extension",
            hermes_pubkey_b64="old-hermes",
            paired_at=1.0,
        )
    )
    conn = extension_api._Connection(_FakeWS(), _chat_handler)
    asyncio.run(conn._on_auth({"type": "auth", "ext_token": old_token}))
    assert conn.ws.sent[-1]["type"] == "auth_ok"
    conn._pending_sign["approved-under-old-pairing"] = {"method": "personal_sign"}

    if state_change == "replace":
        pairing._save_pairing(
            pairing.Pairing(
                aes_key=b"\x22" * 32,
                ext_token="replacement-extension-token",
                ext_pubkey_b64="new-extension",
                hermes_pubkey_b64="new-hermes",
                paired_at=2.0,
            )
        )
    else:
        pairing.clear_pairing()

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "e1",
                    "type": "encrypt",
                    "plaintext": "must not cross pairing generations",
                }
            )
        )
    )

    assert conn.ws.sent[-1] == {"type": "auth_fail", "reason": "pairing_changed"}
    assert conn.authed is False
    assert conn._pending_sign == {}
    assert not any(frame.get("type") == "encrypt_result" for frame in conn.ws.sent)


def test_socket_authenticated_before_webauthn_enable_cannot_unregister_it():
    """Credential generation changes revoke token-only sessions immediately."""
    token = "extension-token"
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x11" * 32,
            ext_token=token,
            ext_pubkey_b64="extension",
            hermes_pubkey_b64="hermes",
            paired_at=1.0,
        )
    )
    conn = extension_api._Connection(
        _FakeWS(),
        _chat_handler,
        client_origin="chrome-extension://abcdefghijklmnopabcdefghijklmnop",
    )
    asyncio.run(conn._on_auth({"type": "auth", "ext_token": token}))
    assert conn.ws.sent[-1]["type"] == "auth_ok"

    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential(
        "cred-1",
        xc.b64u_encode(spki),
        origin="chrome-extension://abcdefghijklmnopabcdefghijklmnop",
    )
    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "w1",
                    "type": "webauthn_register",
                    # Empty credential fields request unregister.
                }
            )
        )
    )

    assert conn.ws.sent[-1] == {"type": "auth_fail", "reason": "pairing_changed"}
    assert conn.authed is False
    assert pairing.has_webauthn_credential() is True


def test_malformed_frames_get_error_and_connection_survives():
    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s, s.ws_connect(f"http://127.0.0.1:{port}/ext") as ws:
                json.loads((await ws.receive()).data)  # auth_challenge
                await ws.send_str("this is {not json")
                bad_json = json.loads((await ws.receive()).data)
                await ws.send_str(json.dumps(["a", "json", "array"]))
                non_dict = json.loads((await ws.receive()).data)
                # The connection must still dispatch normally afterwards.
                await ws.send_str(json.dumps({"type": "auth", "ext_token": "nope"}))
                after = json.loads((await ws.receive()).data)
                return bad_json, non_dict, after
        finally:
            await server.stop()

    bad_json, non_dict, after = asyncio.run(_flow(_free_port()))
    assert bad_json == {"type": "error", "reason": "bad_json"}
    assert non_dict == {"type": "error", "reason": "bad_json"}
    assert after["type"] == "auth_fail"


def test_crashed_handler_replies_error(monkeypatch):
    """A handler exception must produce an id-keyed error frame instead of
    leaving the client to await a reply forever."""
    from mordred_hermes.extension import extension_history

    def _boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(extension_history, "projected_history", _boom)

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                json.loads((await ws.receive()).data)  # auth_challenge
                await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
                json.loads((await ws.receive()).data)  # auth_ok
                await ws.send_str(json.dumps({"id": "h1", "type": "history_get"}))
                return json.loads((await asyncio.wait_for(ws.receive(), timeout=5)).data)
        finally:
            await server.stop()

    msg = asyncio.run(_flow(_free_port()))
    assert msg == {"id": "h1", "type": "error", "reason": "internal_error"}


def test_page_session_cannot_touch_credentials(tmp_path):
    """The launch-fragment page principal is exempt from WebAuthn, so its
    allowlist must not reach credential/key-writing handlers or clear the
    extension's registered second factor."""
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="page-test-extension-token",
            ext_pubkey_b64="test-extension",
            hermes_pubkey_b64="test-hermes",
            paired_at=1.0,
        )
    )
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pairing.save_webauthn_credential("cred-1", xc.b64u_encode(spki))

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)
                out = {}
                # Empty fields = "unregister" — the attacker's cheapest move.
                await ws.send_str(json.dumps({"id": "w1", "type": "webauthn_register"}))
                out["webauthn"] = await _recv(ws)
                await ws.send_str(
                    json.dumps({"id": "s1", "type": "slack_setup", "bot_token": "xoxb-a", "app_token": "xapp-b"})
                )
                out["slack"] = await _recv(ws)
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "k1",
                            "type": "channel_key_set",
                            "channel_id": "C1",
                            "key_ct": xc.b64u_encode(b"\x01" * 32),
                        }
                    )
                )
                out["channel"] = await _recv(ws)
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "dc1",
                            "type": "discord_channel_resolve",
                            "guild_id": "123",
                            "channel_id": "456",
                        }
                    )
                )
                out["discord"] = await _recv(ws)
                return out
        finally:
            await server.stop()

    out = asyncio.run(_flow(_free_port()))
    assert out["webauthn"] == {
        "id": "w1",
        "type": "error",
        "reason": "page_session_forbidden",
    }
    assert out["slack"] == {"id": "s1", "type": "error", "reason": "page_session_forbidden"}
    assert out["channel"] == {"id": "k1", "type": "error", "reason": "page_session_forbidden"}
    assert out["discord"] == {"id": "dc1", "type": "error", "reason": "page_session_forbidden"}
    assert pairing.has_webauthn_credential() is True  # second factor survived
    assert not (tmp_path / ".env").exists()  # no Slack tokens written
    assert pairing.load_channel_keys() == {}


def test_page_session_allowlist_blocks_crypto_and_wallet_but_allows_chat_and_accounts(monkeypatch):
    """Flip side of ``test_page_session_cannot_touch_credentials``: the
    allowlist (``_PAGE_ALLOWED``) must ALSO refuse the K_master crypto oracle
    (``encrypt``/``decrypt``) and the keyvault wallet signer
    (``sign_request``/``sign_approve``) for a page session -- above all a
    denylist would have silently exposed exactly the fund-moving operations
    the WebAuthn hardening exists to protect. And it must still PERMIT the
    two handlers the bundled localhost web app actually uses (``chat``,
    ``accounts_request``), proving the allowlist blocks and permits
    correctly rather than over-blocking."""
    monkeypatch.setattr(extension_api, "_get_account_snapshot", lambda: ("0xabc", "0x1"))

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_chat_handler)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)
                out = {}

                await ws.send_str(json.dumps({"id": "e1", "type": "encrypt", "plaintext": "x"}))
                out["encrypt"] = await _recv(ws)

                await ws.send_str(json.dumps({"id": "d1", "type": "decrypt", "ciphertext": "irrelevant"}))
                out["decrypt"] = await _recv(ws)

                await ws.send_str(
                    json.dumps(
                        {
                            "id": "sr1",
                            "type": "sign_request",
                            "request_id": "r1",
                            "method": "personal_sign",
                            "params": ["0x1"],
                        }
                    )
                )
                out["sign_request"] = await _recv(ws)

                await ws.send_str(
                    json.dumps({"id": "sa1", "type": "sign_approve", "request_id": "r1", "approved": True})
                )
                out["sign_approve"] = await _recv(ws)

                # Positive: allowlisted handlers still work for a page session.
                await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": "hi"}))
                chunks = []
                while True:
                    m = await _recv(ws)
                    if m["type"] == "chat_chunk":
                        chunks.append(m["content"])
                    elif m["type"] == "chat_end":
                        break
                out["chat"] = "".join(chunks)

                await ws.send_str(json.dumps({"id": "a1", "type": "accounts_request"}))
                out["accounts"] = await _recv(ws)

                return out
        finally:
            await server.stop()

    out = asyncio.run(_flow(_free_port()))
    assert out["encrypt"] == {"id": "e1", "type": "error", "reason": "page_session_forbidden"}
    assert out["decrypt"] == {"id": "d1", "type": "error", "reason": "page_session_forbidden"}
    assert out["sign_request"] == {"id": "sr1", "type": "error", "reason": "page_session_forbidden"}
    assert out["sign_approve"] == {"id": "sa1", "type": "error", "reason": "page_session_forbidden"}
    # Never reached the wallet signer -- no pending sign entry was even created.
    assert out["chat"] == "こんにちは、受け取りました: hi"
    assert out["accounts"]["type"] == "accounts_result"
    assert out["accounts"]["accounts"] == ["0xabc"]
    assert out["accounts"]["chainId"] == "0x1"


def test_slack_setup_rejects_newline_bearing_token(tmp_path):
    """``.strip()`` + ``startswith`` let an *internal* newline through, and the
    token is written as a raw ``KEY=value`` line — so "xoxb-x\\nEVIL=..." would
    inject an extra dotenv entry that Hermes loads on its next restart."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": "chrome-extension://abc"}) as ws,
            ):
                await _pair_and_auth(ws)
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "s1",
                            "type": "slack_setup",
                            "bot_token": "xoxb-x\nEVIL=pwned",
                            "app_token": "xapp-1-A",
                        }
                    )
                )
                bad = await _recv(ws)
                # A well-formed pair must still be accepted (no over-blocking).
                await ws.send_str(
                    json.dumps(
                        {
                            "id": "s2",
                            "type": "slack_setup",
                            "bot_token": "xoxb-123456-abcDEF",
                            "app_token": "xapp-1-A01-9zz",
                        }
                    )
                )
                good = await _recv(ws)
                return bad, good
        finally:
            await server.stop()

    bad, good = asyncio.run(_flow(_free_port()))
    assert bad["ok"] is False
    assert bad["error"] == "bad_token_format"
    assert good["ok"] is True
    env = (tmp_path / ".env").read_text()
    assert "EVIL=pwned" not in env  # nothing injected
    assert "SLACK_BOT_TOKEN=xoxb-123456-abcDEF" in env


def test_upsert_env_vars_rejects_newlines(tmp_path):
    """Last line of defence: the writer itself refuses CR/LF in a key or value."""
    env = tmp_path / ".env"
    with pytest.raises(ValueError):
        extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-x\nEVIL=pwned"})
    with pytest.raises(ValueError):
        extension_api._upsert_env_vars(env, {"SLACK\rBOT": "x"})
    assert not env.exists()


def test_upsert_env_vars_new_file_is_0600(tmp_path):
    """This file holds Slack bot/app tokens, so a plain ``write_text`` would
    leave a freshly-created ``.env`` at the umask default (typically 0o644,
    world-readable) rather than the atomic writer's tmp-file mode."""
    env = tmp_path / ".env"
    extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-a"})
    assert oct(stat.S_IMODE(os.stat(env).st_mode)) == "0o600"


def test_upsert_env_vars_tightens_a_loosely_permissioned_existing_file(tmp_path):
    """A host-managed ``.env`` may legitimately pre-exist at 0o644 (unlike
    ``keyvault._storage.atomic_write``, which refuses that case outright) --
    ``os.replace`` gives the result the tmp file's 0o600 mode, tightening the
    permissions rather than preserving the leak."""
    env = tmp_path / ".env"
    env.write_text("EXISTING=1\n", encoding="utf-8")
    os.chmod(env, 0o644)

    extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-a"})

    assert oct(stat.S_IMODE(os.stat(env).st_mode)) == "0o600"


def test_upsert_env_vars_preserves_unrelated_existing_vars(tmp_path):
    """The atomic upsert (mkstemp + os.replace) must not clobber vars already
    in the file that the update did not touch."""
    env = tmp_path / ".env"
    env.write_text("KEEP_ME=untouched\nSLACK_BOT_TOKEN=old\n", encoding="utf-8")

    extension_api._upsert_env_vars(env, {"SLACK_BOT_TOKEN": "xoxb-new"})

    text = env.read_text(encoding="utf-8")
    assert "KEEP_ME=untouched" in text
    assert "SLACK_BOT_TOKEN=xoxb-new" in text
    assert "SLACK_BOT_TOKEN=old" not in text


def test_upsert_env_vars_replaces_export_assignments_without_leaving_old_tokens(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "export SLACK_BOT_TOKEN=xoxb-old\nexport SLACK_APP_TOKEN=xapp-old\nKEEP_ME=untouched\n",
        encoding="utf-8",
    )

    extension_api._upsert_env_vars(
        env,
        {
            "SLACK_BOT_TOKEN": "xoxb-new",
            "SLACK_APP_TOKEN": "xapp-new",
        },
    )

    text = env.read_text(encoding="utf-8")
    assert "xoxb-old" not in text
    assert "xapp-old" not in text
    assert text.count("SLACK_BOT_TOKEN=") == 1
    assert text.count("SLACK_APP_TOKEN=") == 1
    assert "export SLACK_BOT_TOKEN=xoxb-new" in text
    assert "export SLACK_APP_TOKEN=xapp-new" in text
    assert "KEEP_ME=untouched" in text


def test_slack_setup_requires_explicit_overwrite_for_existing_tokens(tmp_path):
    env = tmp_path / ".env"
    original = "KEEP_ME=untouched\nSLACK_BOT_TOKEN=xoxb-old\nSLACK_APP_TOKEN=xapp-old\n"
    env.write_text(original, encoding="utf-8")
    conn = _authed_conn()

    asyncio.run(
        conn._on_slack_setup(
            {
                "id": "s1",
                "type": "slack_setup",
                "bot_token": "xoxb-new",
                "app_token": "xapp-new",
            }
        )
    )

    assert conn.ws.sent[-1]["error"] == "slack_already_configured"
    assert env.read_text(encoding="utf-8") == original

    asyncio.run(
        conn._on_slack_setup(
            {
                "id": "s2",
                "type": "slack_setup",
                "bot_token": "xoxb-new",
                "app_token": "xapp-new",
                "overwrite": True,
            }
        )
    )

    assert conn.ws.sent[-1]["ok"] is True
    updated = env.read_text(encoding="utf-8")
    assert "KEEP_ME=untouched" in updated
    assert "SLACK_BOT_TOKEN=xoxb-new" in updated
    assert "SLACK_APP_TOKEN=xapp-new" in updated


def test_page_encrypt_without_pairing_is_forbidden_with_generic_error():
    """A page session hitting ``encrypt`` is now refused BEFORE ``_on_encrypt``
    even runs: the page allowlist (``_PAGE_ALLOWED``) added later blocks
    ``encrypt`` for page sessions outright, so the reply is a correlated generic
    ``error`` rather than a malformed operation-specific result. Direct unit
    coverage below still verifies the handler's own ``encrypt_fail`` response."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)  # authed but keyless: no pairing exists
                await ws.send_str(json.dumps({"id": "e1", "type": "encrypt", "plaintext": "x"}))
                return await _recv(ws)
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port())) == {
        "id": "e1",
        "type": "error",
        "reason": "page_session_forbidden",
    }


def test_chat_undecryptable_ciphertext_is_not_forwarded_to_the_agent():
    """A stale K_extchat (e.g. the client re-paired) must yield a ``chat_error``
    — forwarding the still-encrypted blob would hand the agent ciphertext as the
    user's message."""
    seen: list[str] = []

    async def _recording_handler(content, _context):
        seen.append(content)
        yield "ok"

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_recording_handler)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": "chrome-extension://abc"}) as ws,
            ):
                aes = await _pair_and_auth(ws)
                stale = xc.encrypt_message(b"\x09" * 32, "hello")  # not our K_extchat
                await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": stale}))
                err = await _recv(ws)
                # A correctly-keyed encrypted message must still get through.
                ek = xc.hkdf_subkey(aes, extension_api._EXTCHAT_SALT, extension_api._EXTCHAT_INFO)
                await ws.send_str(json.dumps({"id": "c2", "type": "chat", "content": xc.encrypt_message(ek, "hi")}))
                ok = await _recv(ws)
                return err, ok
        finally:
            await server.stop()

    err, ok = asyncio.run(_flow(_free_port()))
    assert err == {"id": "c1", "type": "chat_error", "reason": "undecryptable"}
    assert ok["type"] == "chat_chunk"
    assert seen == ["hi"]  # the agent never saw the undecryptable blob


@pytest.mark.parametrize("pairing_failure", ["missing", "unreadable"])
def test_encrypted_chat_without_a_derived_key_fails_closed(monkeypatch, pairing_failure):
    """Pairing loss/corruption must never downgrade ciphertext to agent input."""
    seen: list[str] = []

    async def _recording_handler(content, _context):
        seen.append(content)
        yield "must not run"

    conn = extension_api._Connection(_FakeWS(), _recording_handler)
    if pairing_failure == "missing":
        monkeypatch.setattr(conn, "_extchat_key", lambda: None)
    else:

        def _unreadable():
            raise OSError("pairing file unreadable")

        monkeypatch.setattr(conn, "_extchat_key", _unreadable)

    ciphertext = xc.encrypt_message(b"\x03" * 32, "never forward me")
    asyncio.run(conn._on_chat({"id": "c1", "type": "chat", "content": ciphertext}))

    assert seen == []
    assert conn.ws.sent == [
        {
            "id": "c1",
            "type": "chat_error",
            "reason": "encryption_key_unavailable",
        }
    ]


class _FakeWS:
    """Minimal stand-in for ``web.WebSocketResponse`` — ``_Connection`` only ever
    touches ``closed`` and ``send_str``."""

    def __init__(self):
        self.closed = False
        self.sent: list[dict] = []

    async def send_str(self, data: str) -> None:
        self.sent.append(json.loads(data))


def _authed_conn() -> extension_api._Connection:
    token = "direct-test-extension-token"
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token=token,
            ext_pubkey_b64="test-extension",
            hermes_pubkey_b64="test-hermes",
            paired_at=1.0,
        )
    )
    conn = extension_api._Connection(_FakeWS(), _chat_handler)
    conn.authed = True
    conn._authentication_generation = pairing.authentication_generation_fingerprint(token)
    assert conn._authentication_generation is not None
    return conn


def test_authed_extension_resolves_discord_channel_metadata():
    from mordred_hermes.extension.discord_context import DiscordChannelContext

    async def resolver(guild_id: str, channel_id: str) -> DiscordChannelContext:
        assert (guild_id, channel_id) == ("123", "999")
        return DiscordChannelContext(
            guild_id="123",
            channel_id="999",
            channel_type=11,
            channel_name="release thread",
            parent_channel_id="456",
            parent_channel_name="secure-ops",
        )

    conn = _authed_conn()
    conn.discord_resolver = resolver
    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "dc1",
                    "type": "discord_channel_resolve",
                    "guild_id": "123",
                    "channel_id": "999",
                }
            )
        )
    )
    assert conn.ws.sent == [
        {
            "id": "dc1",
            "type": "discord_channel_resolve_result",
            "ok": True,
            "guild_id": "123",
            "channel_id": "999",
            "channel_type": 11,
            "channel_name": "release thread",
            "parent_channel_id": "456",
            "parent_channel_name": "secure-ops",
        }
    ]


def test_webauthn_registration_binds_chromium_origin_as_rp_id(tmp_path):
    origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="registration-test-token",
            ext_pubkey_b64="test-extension",
            hermes_pubkey_b64="test-hermes",
            paired_at=1.0,
        )
    )
    conn = extension_api._Connection(_FakeWS(), _chat_handler, client_origin=origin)
    conn.authed = True

    asyncio.run(
        conn._on_webauthn_register(
            {
                "id": "w1",
                "credential_id": "cred-1",
                "public_key": _p256_public_key_b64(),
            }
        )
    )

    stored = json.loads((tmp_path / "extension" / "webauthn.json").read_text("utf-8"))
    assert stored["origin"] == origin
    assert stored["rp_id"] == origin
    assert conn.ws.sent == [{"id": "w1", "type": "webauthn_registered", "ok": True}]


@pytest.mark.parametrize(
    "invalid_public_key",
    [
        pytest.param(xc.b64u_encode(b"not a DER public key"), id="malformed"),
        pytest.param(_ec_public_key_b64(ec.SECP384R1()), id="p384"),
    ],
)
def test_webauthn_registration_rejects_invalid_public_key_without_replacing_credential(
    tmp_path,
    invalid_public_key,
):
    origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="registration-test-token",
            ext_pubkey_b64="test-extension",
            hermes_pubkey_b64="test-hermes",
            paired_at=1.0,
        )
    )
    pairing.save_webauthn_credential("existing-credential", _p256_public_key_b64(), origin=origin)
    stored_path = tmp_path / "extension" / "webauthn.json"
    original = stored_path.read_bytes()
    conn = extension_api._Connection(_FakeWS(), _chat_handler, client_origin=origin)
    conn.authed = True

    asyncio.run(
        conn._on_webauthn_register(
            {
                "id": "w-invalid",
                "credential_id": "replacement-credential",
                "public_key": invalid_public_key,
            }
        )
    )

    assert conn.ws.sent == [
        {
            "id": "w-invalid",
            "type": "webauthn_registered",
            "ok": False,
            "error": "invalid_public_key",
        }
    ]
    assert stored_path.read_bytes() == original
    assert json.loads(original)["credential_id"] == "existing-credential"


def test_webauthn_registration_rejects_firefox_until_binding_is_in_protocol(tmp_path):
    conn = extension_api._Connection(
        _FakeWS(),
        _chat_handler,
        client_origin="moz-extension://random-document-uuid",
    )
    conn.authed = True

    asyncio.run(
        conn._on_webauthn_register(
            {
                "id": "w1",
                "credential_id": "cred-1",
                "public_key": _p256_public_key_b64(),
            }
        )
    )

    assert conn.ws.sent == [
        {
            "id": "w1",
            "type": "webauthn_registered",
            "ok": False,
            "error": "webauthn_browser_unsupported",
        }
    ]
    assert not (tmp_path / "extension" / "webauthn.json").exists()


def test_on_encrypt_not_paired_replies_encrypt_fail(monkeypatch):
    """Direct unit coverage for the ``_on_encrypt`` reply-type-rename fix: the
    not-paired branch used to answer with ``decrypt_fail`` (copy-paste from
    ``_on_decrypt``), which no client keys a reply on. A page session can no
    longer reach this branch at all (the allowlist refuses ``encrypt`` for
    page sessions before ``_on_encrypt`` runs — see
    ``test_encrypt_without_pairing_replies_encrypt_fail`` above), so exercise
    ``_on_encrypt`` directly on an authed, non-page connection with no pairing
    on disk."""
    monkeypatch.setattr(pairing, "load_pairing", lambda: None)
    conn = extension_api._Connection(_FakeWS(), _chat_handler, page_token=None)
    conn.authed = True
    asyncio.run(conn._on_encrypt({"id": "e1", "type": "encrypt", "plaintext": "x"}))
    assert conn.ws.sent == [{"id": "e1", "type": "encrypt_fail", "reason": "not_paired"}]


def test_sign_request_without_request_id_is_rejected():
    """An empty request_id collapsed every id-less request onto "" — a second
    one silently overwrote the first's frozen params."""
    conn = _authed_conn()
    asyncio.run(
        conn.dispatch(json.dumps({"id": "s1", "type": "sign_request", "method": "personal_sign", "params": ["0x1"]}))
    )
    assert conn.ws.sent == [{"id": "s1", "type": "sign_result", "request_id": "", "error": "missing_request_id"}]
    assert conn._pending_sign == {}


@pytest.mark.parametrize("approved", ["false", 1, {}, [True], None])
def test_sign_approve_accepts_only_boolean_true(approved, monkeypatch):
    conn = _authed_conn()
    conn._pending_sign["r1"] = {
        "method": "personal_sign",
        "params": ["0x1"],
        "chain_id": None,
        "rpc_url": None,
        "expected_signer": None,
    }
    monkeypatch.setattr(extension_api, "_do_sign", lambda *_args: pytest.fail("unapproved request was signed"))

    asyncio.run(
        conn._on_sign_approve(
            {
                "id": "s1",
                "type": "sign_approve",
                "request_id": "r1",
                "approved": approved,
            }
        )
    )

    assert conn.ws.sent[-1] == {
        "id": "s1",
        "type": "sign_result",
        "request_id": "r1",
        "error": "user_rejected",
    }


def test_sign_request_duplicate_request_id_is_rejected(monkeypatch):
    """Wallet "approve A, sign B" defense: re-using a ``request_id`` that is
    still pending must be refused outright, not silently overwrite the frozen
    params of the prompt already shown to the user — otherwise a dapp could
    display a benign tx, then swap in a draining tx under the same id before
    the user clicks approve."""
    from mordred_hermes.keyvault import extension_sign

    signer = "0x" + "aa" * 20
    monkeypatch.setattr(extension_sign, "get_address", lambda: signer)
    conn = _authed_conn()
    first_params = ["0xfirst", signer]
    second_params = ["0xsecond", signer]

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": "dup",
                    "method": "personal_sign",
                    "params": first_params,
                }
            )
        )
    )
    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s2",
                    "type": "sign_request",
                    "request_id": "dup",
                    "method": "personal_sign",
                    "params": second_params,
                }
            )
        )
    )

    assert conn.ws.sent[-1] == {"id": "s2", "type": "sign_result", "request_id": "dup", "error": "duplicate_request_id"}
    # The first request's frozen params must survive untouched.
    assert conn._pending_sign["dup"]["params"] == first_params


def test_transaction_sign_request_rejects_unsafe_rpc_before_prompt():
    conn = _authed_conn()

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": "tx1",
                    "method": "eth_sendTransaction",
                    "params": [{"to": "0x" + "11" * 20}],
                    "rpc_url": "http://169.254.169.254/latest/meta-data",
                }
            )
        )
    )

    assert conn.ws.sent == [
        {
            "id": "s1",
            "type": "sign_result",
            "request_id": "tx1",
            # The rejection reason stays a stable code; the human-readable
            # detail ("RPC endpoints must use HTTPS") is logged, not returned.
            "error": "transaction_prepare_failed: invalid_rpc_url",
        }
    ]
    assert conn._pending_sign == {}


def test_transaction_sign_prompt_freezes_rpc_fields_and_signs_exact_snapshot(monkeypatch):
    from mordred_hermes.extension import extension_rpc
    from mordred_hermes.keyvault import extension_sign

    monkeypatch.setattr(extension_sign, "chain_id_int", lambda: 1)
    monkeypatch.setattr(extension_sign, "get_address", lambda: "0x" + "aa" * 20)
    rpc_url = "https://rpc.example.com:8443/v1/secret-api-key?token=hidden"
    monkeypatch.setattr(extension_sign, "rpc_url_for", lambda _chain_id: rpc_url)

    def fill_transaction(_rpc_url, tx, _from_address, _chain_id):
        return {
            **tx,
            "nonce": "0x7",
            "gas": "0x5208",
            "maxPriorityFeePerGas": "0x3b9aca00",
            "maxFeePerGas": "0x77359400",
        }

    monkeypatch.setattr(extension_rpc, "fill_transaction", fill_transaction)
    signed = {}

    def do_sign(method, params, chain_id, rpc_url, expected_signer):
        signed.update(
            method=method,
            params=params,
            chain_id=chain_id,
            rpc_url=rpc_url,
            expected_signer=expected_signer,
        )
        return "0xfrozen"

    monkeypatch.setattr(extension_api, "_do_sign", do_sign)
    conn = _authed_conn()

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": "tx1",
                    "method": "eth_sendTransaction",
                    "params": [{"to": "0x" + "11" * 20}],
                    "rpc_url": rpc_url,
                }
            )
        )
    )

    prompt = conn.ws.sent[-1]
    assert prompt["type"] == "sign_prompt"
    assert prompt["decoded"]["rpc_endpoint"] == "https://rpc.example.com:8443"
    assert prompt["decoded"]["chain_id"] == "0x1"
    assert prompt["decoded"]["transaction"]["nonce"] == "0x7"
    assert prompt["decoded"]["transaction"]["gas"] == "0x5208"
    assert prompt["decoded"]["transaction"]["maxFeePerGas"] == "0x77359400"
    assert prompt["decoded"]["transaction"]["from"] == "0x" + "aa" * 20
    assert prompt["decoded"]["signer"] == "0x" + "aa" * 20
    assert prompt["params"] == [prompt["decoded"]["transaction"]]
    assert "RPC 接続先: https://rpc.example.com:8443" in prompt["analysis"]["warnings"]
    assert "secret-api-key" not in json.dumps(prompt)
    assert "token=hidden" not in json.dumps(prompt)
    assert conn._pending_sign["tx1"]["rpc_url"] == rpc_url
    assert conn._pending_sign["tx1"]["expected_signer"] == "0x" + "aa" * 20

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s2",
                    "type": "sign_approve",
                    "request_id": "tx1",
                    "approved": True,
                }
            )
        )
    )

    assert conn.ws.sent[-1]["signature"] == "0xfrozen"
    assert signed == {
        "method": "eth_sendTransaction",
        "params": prompt["params"],
        "chain_id": "0x1",
        "rpc_url": rpc_url,
        "expected_signer": "0x" + "aa" * 20,
    }


@pytest.mark.parametrize(
    ("method", "account_index"),
    [
        ("personal_sign", 1),
        ("eth_signTypedData_v4", 0),
    ],
)
def test_message_approval_rejects_wallet_switch_before_signing(monkeypatch, method, account_index):
    from mordred_hermes.extension.wallet import _do_sign as wallet_do_sign
    from mordred_hermes.keyvault import extension_sign

    approved_signer = "0x" + "aa" * 20
    replacement_signer = "0x" + "bb" * 20
    addresses = iter((approved_signer, replacement_signer))
    params = (
        ["0xdeadbeef", approved_signer.upper()]
        if method == "personal_sign"
        else [approved_signer.upper(), {"types": {}, "primaryType": "Test", "domain": {}, "message": {}}]
    )
    monkeypatch.setattr(extension_api, "_do_sign", wallet_do_sign)
    monkeypatch.setattr(extension_sign, "get_address", lambda: next(addresses))
    monkeypatch.setattr(
        extension_sign,
        "personal_sign",
        lambda *_args, **_kwargs: pytest.fail("changed wallet must be rejected before personal_sign"),
    )
    monkeypatch.setattr(
        extension_sign,
        "sign_typed_data_v4",
        lambda *_args, **_kwargs: pytest.fail("changed wallet must be rejected before typed-data signing"),
    )
    conn = _authed_conn()

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": f"{method}-switch",
                    "method": method,
                    "params": params,
                }
            )
        )
    )

    prompt = conn.ws.sent[-1]
    assert prompt["type"] == "sign_prompt"
    assert prompt["decoded"]["signer"] == approved_signer
    assert prompt["params"][account_index] == approved_signer
    assert conn._pending_sign[f"{method}-switch"]["expected_signer"] == approved_signer

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s2",
                    "type": "sign_approve",
                    "request_id": f"{method}-switch",
                    "approved": True,
                }
            )
        )
    )

    assert conn.ws.sent[-1] == {
        "id": "s2",
        "type": "sign_result",
        "request_id": f"{method}-switch",
        "error": "wallet_signer_changed",
    }
    assert conn._pending_sign == {}


def test_transaction_approval_rejects_wallet_switch_before_signing(monkeypatch):
    from mordred_hermes.extension import extension_rpc
    from mordred_hermes.extension.wallet import _do_sign as wallet_do_sign
    from mordred_hermes.keyvault import extension_sign

    approved_signer = "0x" + "aa" * 20
    replacement_signer = "0x" + "bb" * 20
    addresses = iter((approved_signer, replacement_signer))
    # ``test_full_server_flow`` stubs the imported API symbol for its real
    # socket flow; restore the wallet implementation so this test exercises the
    # approval-time signer recheck rather than that test-only stub.
    monkeypatch.setattr(extension_api, "_do_sign", wallet_do_sign)
    monkeypatch.setattr(extension_sign, "chain_id_int", lambda: 1)
    monkeypatch.setattr(extension_sign, "get_address", lambda: next(addresses))
    monkeypatch.setattr(extension_sign, "rpc_url_for", lambda _chain_id: "https://rpc.example.com")
    monkeypatch.setattr(
        extension_sign,
        "sign_transaction",
        lambda *_args, **_kwargs: pytest.fail("changed wallet must be rejected before signing"),
    )
    monkeypatch.setattr(
        extension_rpc,
        "fill_transaction",
        lambda _rpc_url, tx, _from_address, _chain_id: dict(tx),
    )
    conn = _authed_conn()

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": "tx-switch",
                    "method": "eth_sendTransaction",
                    "params": [
                        {
                            "to": "0x" + "11" * 20,
                            "nonce": "0x1",
                            "gas": "0x5208",
                            "gasPrice": "0x3b9aca00",
                        }
                    ],
                    "chain_id": "0x1",
                }
            )
        )
    )

    prompt = conn.ws.sent[-1]
    assert prompt["type"] == "sign_prompt"
    assert prompt["decoded"]["signer"] == approved_signer
    assert prompt["decoded"]["transaction"]["from"] == approved_signer

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s2",
                    "type": "sign_approve",
                    "request_id": "tx-switch",
                    "approved": True,
                }
            )
        )
    )

    assert conn.ws.sent[-1] == {
        "id": "s2",
        "type": "sign_result",
        "request_id": "tx-switch",
        "error": "wallet_signer_changed",
    }
    assert conn._pending_sign == {}


def test_transaction_sign_request_rejects_unconfigured_public_rpc(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    monkeypatch.setattr(extension_sign, "chain_id_int", lambda: 1)
    monkeypatch.setattr(extension_sign, "rpc_url_for", lambda _chain_id: "https://trusted.example/rpc")
    monkeypatch.setattr(
        extension_sign,
        "get_address",
        lambda: pytest.fail("unapproved endpoint must be rejected before wallet address lookup"),
    )
    conn = _authed_conn()

    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": "tx1",
                    "method": "eth_sendTransaction",
                    "params": [{"to": "0x" + "11" * 20}],
                    "chain_id": "0x1",
                    "rpc_url": "https://attacker.example/rpc",
                }
            )
        )
    )

    assert conn.ws.sent == [
        {
            "id": "s1",
            "type": "sign_result",
            "request_id": "tx1",
            "error": "transaction_prepare_failed: rpc_endpoint_not_allowed",
        }
    ]
    assert conn._pending_sign == {}


def test_pending_sign_table_is_bounded(monkeypatch):
    """Entries only leave ``_pending_sign`` on approve/reject, so an authed socket
    that never approves must not grow it without bound."""
    from mordred_hermes.keyvault import extension_sign

    signer = "0x" + "aa" * 20
    monkeypatch.setattr(extension_sign, "get_address", lambda: signer)
    conn = _authed_conn()
    n = extension_api._MAX_PENDING_SIGN + 10

    async def _fire():
        for i in range(n):
            await conn.dispatch(
                json.dumps(
                    {
                        "id": f"s{i}",
                        "type": "sign_request",
                        "request_id": f"r{i}",
                        "method": "personal_sign",
                        "params": ["0x1", signer],
                    }
                )
            )

    asyncio.run(_fire())
    assert len(conn._pending_sign) == extension_api._MAX_PENDING_SIGN
    assert "r0" not in conn._pending_sign  # oldest evicted
    assert f"r{n - 1}" in conn._pending_sign  # newest kept


def test_ws_chat_client_disconnect_closes_generator():
    """When the client vanishes mid-stream the server must stop consuming the
    chat generator (closing it) instead of streaming into the void."""

    async def _flow(port):
        closed = asyncio.Event()

        async def endless_handler(_content, _context):
            try:
                for i in range(200):
                    yield f"c{i}"
                    await asyncio.sleep(0.05)
            finally:
                closed.set()

        server = extension_api.ExtensionAPIServer(port=port, chat_handler=endless_handler)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.ws_connect(
                    f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}
                ) as ws:
                    json.loads((await ws.receive()).data)  # auth_challenge
                    await ws.send_str(json.dumps({"type": "auth", "ext_token": server._page_token}))
                    json.loads((await ws.receive()).data)  # auth_ok
                    await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": "x"}))
                    for _ in range(2):  # prove streaming started, then vanish
                        assert json.loads((await ws.receive()).data)["type"] == "chat_chunk"
                await asyncio.wait_for(closed.wait(), timeout=10)
                return True
        finally:
            await server.stop()

    assert asyncio.run(_flow(_free_port())) is True


def test_authed_dispatch_does_not_reparse_state_per_frame(monkeypatch):
    """Every authed frame re-checks the pairing generation via
    ``_authentication_is_current`` (extension_api.py), and encrypt/decrypt also
    re-derive the AES key from the pairing; across many frames on one
    connection this must not re-parse the (possibly multi-MB) state.json each
    time (review 2026-08-02, PR #88 follow-up)."""
    conn = _authed_conn()

    counter = [0]
    real_read_json = pairing._read_json

    def counting_read_json(path):
        if path == pairing._state_path():
            counter[0] += 1
        return real_read_json(path)

    monkeypatch.setattr(pairing, "_read_json", counting_read_json)

    for i in range(10):
        asyncio.run(conn.dispatch(json.dumps({"id": f"e{i}", "type": "encrypt", "plaintext": f"msg-{i}"})))

    assert len(conn.ws.sent) == 10
    assert all(frame["type"] == "encrypt_result" for frame in conn.ws.sent)
    assert counter[0] == 0


def test_accounts_request_burst_costs_one_keyvault_resolution():
    """A page principal must not be able to drive one Secure-Enclave unwrap
    (and one Touch ID prompt, and one audit row) per frame it sends. The
    snapshot is public data — addresses the page is already entitled to — so
    the bound is a short-lived cache rather than a refusal."""
    from mordred_hermes.extension import wallet as extension_wallet
    from mordred_hermes.keyvault import extension_sign

    calls: list[int] = []

    def _snapshot():
        calls.append(1)
        return "0x" + "ab" * 20, 1

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.ws_connect(
                    f"http://127.0.0.1:{port}/ext",
                    headers={"Origin": f"http://127.0.0.1:{port}"},
                ) as ws,
            ):
                await _page_auth(ws, server)
                for i in range(4):
                    await ws.send_str(json.dumps({"id": f"a{i}", "type": "accounts_request"}))
                replies = [await _recv(ws) for _ in range(4)]
            # Deliberate: the snapshot is NOT keyed by principal. Both the page
            # and the paired extension are entitled to the same public address,
            # so a shared entry leaks nothing — and keying it per principal
            # would let a second principal re-arm the prompts the bound exists
            # to prevent.
            async with (
                aiohttp.ClientSession() as ext_session,
                ext_session.ws_connect(
                    f"http://127.0.0.1:{port}/ext",
                    headers={"Origin": "chrome-extension://abc"},
                ) as ext_ws,
            ):
                await _pair_and_auth(ext_ws)
                await ext_ws.send_str(json.dumps({"id": "x", "type": "accounts_request"}))
                replies.append(await _recv(ext_ws))
            return replies
        finally:
            await server.stop()

    extension_wallet.reset_account_snapshot_cache()
    original = extension_sign.account_snapshot
    extension_sign.account_snapshot = _snapshot
    try:
        replies = asyncio.run(_flow(_free_port()))
    finally:
        extension_sign.account_snapshot = original
        extension_wallet.reset_account_snapshot_cache()

    assert len(calls) == 1
    assert [r["type"] for r in replies] == ["accounts_result"] * 5
    assert all(r["accounts"] == ["0x" + "ab" * 20] and r["chainId"] == "0x1" for r in replies)


def test_page_response_carries_a_hash_based_csp():
    """The page holds a bearer token in its fragment: deny framing, deny
    referrers, and pin the document's executable content by hash."""
    from mordred_hermes.extension import page_headers

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as session, session.get(f"http://127.0.0.1:{port}/") as response:
                return response.headers, await response.text(), port
        finally:
            await server.stop()

    headers, html, port = asyncio.run(_flow(_free_port()))
    policy = headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in policy
    assert "base-uri 'none'" in policy
    assert "form-action 'none'" in policy
    assert "'unsafe-inline'" not in policy
    # The page's own WebSocket endpoint must stay reachable.
    assert f"ws://127.0.0.1:{port}" in policy
    # Everything the served bytes actually execute or style is covered.
    scripts, styles = page_headers._inline_sources(html)
    assert scripts, "the served page has no inline script — check the bundle"
    for source in (*scripts, *styles):
        digest = base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")
        assert f"'sha256-{digest}'" in policy
    assert "style=" not in html.split("<body", 1)[-1]


def test_history_result_flags_undecryptable_history(tmp_path):
    """The page must be able to tell "no history yet" from "the stored history
    no longer decrypts" — both used to arrive as an empty turn list."""

    from mordred_hermes.extension import extension_history

    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)
                await ws.send_str(json.dumps({"id": "h0", "type": "history_get"}))
                empty = await _recv(ws)
                extension_history.save_messages([{"role": "user", "content": "hello"}])
                await ws.send_str(json.dumps({"id": "h1", "type": "history_get"}))
                readable = await _recv(ws)
                # Re-pairing leaves a blob sealed under a key that is now gone.
                (tmp_path / "extension" / "history.enc").write_text(
                    "\U0001f512ENC:v1:not-a-real-envelope", encoding="utf-8"
                )
                await ws.send_str(json.dumps({"id": "h2", "type": "history_get"}))
                return empty, readable, await _recv(ws)
        finally:
            await server.stop()

    empty, readable, broken = asyncio.run(_flow(_free_port()))
    assert empty["turns"] == [] and empty["status"] == "empty"
    assert readable["turns"] == [{"role": "user", "content": "hello"}]
    assert readable["status"] == "ok"
    assert broken["turns"] == [] and broken["status"] == "undecryptable"
    assert broken["type"] == "history_result"


def test_page_allowlist_entries_are_all_used_by_the_shipped_page():
    """``_PAGE_ALLOWED`` is a page-scoped action list, not a read-only one:
    ``history_clear`` mutates. It stays allowed only because the bundled page
    triggers it from an explicit, confirmed user action — if a bundle refresh
    ever drops that call, the entry must be dropped with it."""
    from mordred_hermes.extension import page_headers

    bundle = Path(page_headers.__file__).parent / "web" / "index.html"
    if not bundle.exists():  # pragma: no cover - only when the app isn't built
        pytest.skip("the localhost web app bundle is not built in this checkout")
    html = bundle.read_text("utf-8")
    for action in extension_api._PAGE_ALLOWED:
        assert f'"{action}"' in html or f"'{action}'" in html, action


@pytest.mark.parametrize(
    ("raised", "expected_reason"),
    [
        (RuntimeError("boom at /Users/operator/.hermes/secret-detail"), "agent_error"),
        (RuntimeError("agent_unavailable: refused connecting to 10.0.0.5:11434"), "agent_unavailable"),
    ],
)
def test_chat_handler_exception_text_never_reaches_the_client(raised, expected_reason):
    async def _boom(_content, _context):
        raise raised
        yield ""  # pragma: no cover - unreachable, keeps this an async generator

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_boom)
        await server.start()
        try:
            async with (
                aiohttp.ClientSession() as s,
                s.ws_connect(f"http://127.0.0.1:{port}/ext", headers={"Origin": f"http://127.0.0.1:{port}"}) as ws,
            ):
                await _page_auth(ws, server)
                await ws.send_str(json.dumps({"id": "c1", "type": "chat", "content": "hi"}))
                return await _recv(ws)
        finally:
            await server.stop()

    reply = asyncio.run(_flow(_free_port()))
    assert reply == {"id": "c1", "type": "chat_error", "reason": expected_reason}
    assert "10.0.0.5" not in json.dumps(reply)
    assert "/Users/operator" not in json.dumps(reply)


def test_sign_failure_text_never_reaches_the_client(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    signer = "0x" + "ab" * 20
    monkeypatch.setattr(extension_sign, "get_address", lambda: signer)
    conn = _authed_conn()

    def _boom(*_args):
        raise RuntimeError("keyvault unwrap failed: /Users/operator/.hermes/keyvault/wmk")

    monkeypatch.setattr(extension_api, "_do_sign", _boom)
    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "sign_request",
                    "request_id": "r1",
                    "method": "personal_sign",
                    "params": ["0x1", signer],
                }
            )
        )
    )
    asyncio.run(conn.dispatch(json.dumps({"id": "s2", "type": "sign_approve", "request_id": "r1", "approved": True})))

    result = conn.ws.sent[-1]
    assert result == {"id": "s2", "type": "sign_result", "request_id": "r1", "error": "sign_failed"}
    assert "/Users/operator" not in json.dumps(conn.ws.sent)


def test_slack_setup_failure_text_never_reaches_the_client(monkeypatch):
    def _boom(*_args):
        raise OSError("[Errno 13] Permission denied: '/Users/operator/.hermes/.env'")

    monkeypatch.setattr(extension_api, "_update_slack_env", _boom)
    conn = _authed_conn()
    asyncio.run(
        conn.dispatch(
            json.dumps(
                {
                    "id": "s1",
                    "type": "slack_setup",
                    "bot_token": "xoxb-" + "a" * 20,
                    "app_token": "xapp-" + "b" * 20,
                }
            )
        )
    )

    assert conn.ws.sent == [
        {"id": "s1", "type": "slack_setup_result", "ok": False, "note": "", "error": "slack_setup_failed"}
    ]


def test_page_route_error_replies_still_carry_security_headers(tmp_path, monkeypatch):
    """The 403 and 503 branches answer from the same origin as the page, so
    the route's protection must not depend on which branch replied."""

    async def _flow(port):
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                # Rebinding attempt: loopback peer, non-loopback Host header.
                async with session.get(
                    f"http://127.0.0.1:{port}/",
                    headers={"Host": "evil.example"},
                ) as rebind:
                    forbidden = rebind.status, dict(rebind.headers)
                monkeypatch.setattr(extension_api, "_WEB_DIR", tmp_path / "missing")
                async with session.get(f"http://127.0.0.1:{port}/") as unbuilt:
                    return forbidden, (unbuilt.status, dict(unbuilt.headers))
        finally:
            await server.stop()

    (forbidden_status, forbidden_headers), (unbuilt_status, unbuilt_headers) = asyncio.run(_flow(_free_port()))
    assert forbidden_status == 403
    assert unbuilt_status == 503
    for headers in (forbidden_headers, unbuilt_headers):
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
