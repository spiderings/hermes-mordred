"""Context binding and replay guarantees for the gateway-only E2E v3 wire."""

from __future__ import annotations

import json
import secrets
from types import SimpleNamespace

import pytest

from mordred_hermes.extension import crypto, e2e, gateway_plugin, pairing


@pytest.fixture
def channel_key() -> bytes:
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=secrets.token_bytes(32),
            ext_token="active-pairing",
            ext_pubkey_b64="",
            hermes_pubkey_b64="",
            paired_at=0.0,
        )
    )
    raw_key = secrets.token_bytes(32)
    pairing.save_channel_key("C-v3", raw_key)
    return raw_key


def _command(
    raw_key: bytes,
    plaintext: str = "authenticated command",
    *,
    platform: str = "slack",
    chat_id: str = "C-v3",
    thread_root: str | None = None,
    message_id: str | None = None,
    nonce: bytes | None = None,
) -> str:
    return crypto.encrypt_message_v3(
        raw_key,
        plaintext,
        crypto.key_id(raw_key),
        direction="command",
        platform=platform,
        chat_id=chat_id,
        thread_root=thread_root,
        message_id=message_id,
        nonce=nonce,
    )


@pytest.mark.parametrize("wire_prefix", ["🔒", "", ":lock:"])
def test_gateway_accepts_only_canonical_v3_prefix_variants(channel_key: bytes, wire_prefix: str) -> None:
    token = _command(channel_key)
    wire = wire_prefix + token.removeprefix("🔒")

    plaintext, kid, replay = e2e.decrypt_gateway_envelope(
        wire,
        "slack",
        chat_id="C-v3",
        thread_root=None,
    )

    assert plaintext == "authenticated command"
    assert kid == crypto.key_id(channel_key)
    assert replay is not None


@pytest.mark.parametrize(
    ("platform", "chat_id", "thread_root"),
    [
        ("discord", "C-v3", None),
        ("slack", "C-other", None),
        ("slack", "C-v3", "wrong-thread"),
    ],
)
def test_v3_aad_rejects_cross_context_replay(
    channel_key: bytes,
    platform: str,
    chat_id: str,
    thread_root: str | None,
) -> None:
    token = _command(channel_key)
    with pytest.raises(e2e.InvalidEncryptedEnvelope):
        e2e.decrypt_gateway_envelope(
            token,
            platform,
            chat_id=chat_id,
            thread_root=thread_root,
        )


def test_v3_key_must_be_registered_for_event_channel(channel_key: bytes) -> None:
    # The AAD itself is valid for this destination, but its key is registered
    # only under C-v3. A global kid→key lookup would wrongly accept it.
    token = _command(channel_key, chat_id="C-other")
    with pytest.raises(e2e.InvalidEncryptedEnvelope, match="key_not_bound_to_channel"):
        e2e.decrypt_gateway_envelope(
            token,
            "slack",
            chat_id="C-other",
            thread_root=None,
        )


def test_v3_resolves_a_key_stored_under_the_extension_composite_id() -> None:
    # The browser extension pushes channel_key_set keyed by its own composite
    # id, which save_channel_key stores verbatim, while an event only carries
    # the platform's native chat id. Requiring an exact string match resolved
    # no real install's keys at all — every v3 command failed as unbound.
    raw_key = secrets.token_bytes(32)
    pairing.save_channel_key("slack:T0TEAM:C0BCX916V6Z", raw_key)
    token = _command(raw_key, chat_id="C0BCX916V6Z")

    plaintext, _kid, replay = e2e.decrypt_gateway_envelope(
        token,
        "slack",
        chat_id="C0BCX916V6Z",
        thread_root=None,
    )
    assert plaintext == "authenticated command"
    assert replay is not None


def test_v3_composite_key_binding_still_requires_the_event_platform() -> None:
    # Suffix matching must not become a bare "ends with the channel id" rule:
    # a key stored for another platform never unlocks this one, even when the
    # channel ids collide.
    raw_key = secrets.token_bytes(32)
    pairing.save_channel_key("discord:G0GUILD:C0BCX916V6Z", raw_key)
    token = _command(raw_key, chat_id="C0BCX916V6Z")

    with pytest.raises(e2e.InvalidEncryptedEnvelope, match="key_not_bound_to_channel"):
        e2e.decrypt_gateway_envelope(
            token,
            "slack",
            chat_id="C0BCX916V6Z",
            thread_root=None,
        )


def test_v3_composite_key_binding_rejects_a_partial_channel_id_match() -> None:
    # The channel id must be the WHOLE last segment, never a suffix of it.
    raw_key = secrets.token_bytes(32)
    pairing.save_channel_key("slack:T0TEAM:XC0BCX916V6Z", raw_key)
    token = _command(raw_key, chat_id="C0BCX916V6Z")

    with pytest.raises(e2e.InvalidEncryptedEnvelope, match="key_not_bound_to_channel"):
        e2e.decrypt_gateway_envelope(
            token,
            "slack",
            chat_id="C0BCX916V6Z",
            thread_root=None,
        )


def test_discord_thread_can_resolve_key_from_authenticated_parent(channel_key: bytes) -> None:
    token = _command(
        channel_key,
        platform="discord",
        chat_id="T-v3",
        thread_root="T-v3",
    )
    plaintext, _kid, replay = e2e.decrypt_gateway_envelope(
        token,
        "discord",
        chat_id="T-v3",
        thread_root="T-v3",
        parent_chat_id="C-v3",
    )
    assert plaintext == "authenticated command"
    assert replay is not None


def test_gateway_rejects_legacy_commands_but_legacy_helper_remains(channel_key: bytes) -> None:
    legacy = crypto.encrypt_message_v2(channel_key, "legacy", crypto.key_id(channel_key))
    with pytest.raises(e2e.InvalidEncryptedEnvelope):
        e2e.decrypt_gateway_envelope(
            legacy,
            "slack",
            chat_id="C-v3",
            thread_root=None,
        )
    assert e2e.decrypt_inbound_keyed(legacy)[0] == "legacy"


def test_gateway_rejects_multi_token_splicing(channel_key: bytes) -> None:
    first = _command(channel_key, "first")
    second = _command(channel_key, "second")
    with pytest.raises(e2e.InvalidEncryptedEnvelope, match="mixed_or_multiple_content"):
        e2e.decrypt_gateway_envelope(
            f"{first} {second}",
            "slack",
            chat_id="C-v3",
            thread_root=None,
        )


def test_reply_token_cannot_be_reflected_as_a_command(channel_key: bytes) -> None:
    reply = crypto.encrypt_message_v3(
        channel_key,
        "agent reply",
        crypto.key_id(channel_key),
        direction="reply",
        platform="slack",
        chat_id="C-v3",
        thread_root=None,
    )
    with pytest.raises(e2e.InvalidEncryptedEnvelope, match="authentication_failed"):
        e2e.decrypt_gateway_envelope(
            reply,
            "slack",
            chat_id="C-v3",
            thread_root=None,
        )
    assert (
        crypto.decrypt_message_v3(
            channel_key,
            reply,
            direction="reply",
            platform="slack",
            chat_id="C-v3",
            thread_root=None,
        )
        == "agent reply"
    )


def test_replay_claim_survives_gateway_restart_state(channel_key: bytes, tmp_path) -> None:
    token = _command(channel_key)
    _plaintext, _kid, first_claim = e2e.decrypt_gateway_envelope(
        token,
        "slack",
        chat_id="C-v3",
        thread_root=None,
    )
    assert first_claim is not None
    assert e2e.claim_gateway_replay(first_claim) is True

    # Authentication is deliberately separate from the release-time commit.
    # A restarted process can authenticate the capture again, but the private
    # persisted claim still rejects it before plaintext is released.
    _plaintext, _kid, replayed_claim = e2e.decrypt_gateway_envelope(
        token,
        "slack",
        chat_id="C-v3",
        thread_root=None,
    )
    assert replayed_claim is not None
    assert e2e.claim_gateway_replay(replayed_claim) is False

    state_text = (tmp_path / "extension" / "state.json").read_text(encoding="utf-8")
    _kid, message_id, _sequence, _total, nonce, _ciphertext = crypto.parse_token_v3(token)
    assert message_id not in state_text
    assert crypto.b64u_encode(nonce) not in state_text
    assert isinstance(json.loads(state_text)["e2e_replay_v3"], list)


def test_corrupt_persisted_replay_state_fails_closed(channel_key: bytes, tmp_path) -> None:
    token = _command(channel_key)
    _plaintext, _kid, claim = e2e.decrypt_gateway_envelope(
        token,
        "slack",
        chat_id="C-v3",
        thread_root=None,
    )
    assert claim is not None
    state_path = tmp_path / "extension" / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["e2e_replay_v3"] = {"malformed": True}
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(RuntimeError, match="invalid E2E replay state"):
        e2e.claim_gateway_replay(claim)


@pytest.mark.parametrize("payload", [b"{not-json", b"[]"])
def test_corrupt_pairing_store_is_not_replaced_by_replay_claim(
    channel_key: bytes,
    tmp_path,
    payload: bytes,
) -> None:
    state_path = tmp_path / "extension" / "state.json"
    state_path.write_bytes(payload)

    with pytest.raises(RuntimeError, match="E2E replay state store is missing, unreadable, or corrupt"):
        pairing.claim_e2e_replay_identities(("a" * 64,))

    assert state_path.read_bytes() == payload


def test_missing_pairing_store_rejects_replay_claim(channel_key: bytes, tmp_path) -> None:
    state_path = tmp_path / "extension" / "state.json"
    state_path.unlink()

    with pytest.raises(RuntimeError, match="E2E replay state store is missing, unreadable, or corrupt"):
        pairing.claim_e2e_replay_identities(("b" * 64,))

    assert not state_path.exists()


def test_replay_capacity_fails_closed_without_evicting_unexpired_evidence(channel_key: bytes, tmp_path) -> None:
    state_path = tmp_path / "extension" / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    accepted_at = 1_000_000.0
    capacity = 32_768
    state["e2e_replay_v3"] = [{"id": f"{index:064x}", "accepted_at": accepted_at} for index in range(capacity)]
    state_path.write_text(json.dumps(state), encoding="utf-8")
    fresh = (f"{capacity:064x}", f"{capacity + 1:064x}")

    with pytest.raises(RuntimeError, match="capacity exhausted"):
        pairing.claim_e2e_replay_identities(fresh, now=accepted_at + 1.0)
    assert pairing.claim_e2e_replay_identities((f"{0:064x}",), now=accepted_at + 2.0) is False

    persisted = json.loads(state_path.read_text(encoding="utf-8"))["e2e_replay_v3"]
    assert len(persisted) == capacity
    assert {entry["id"] for entry in persisted}.isdisjoint(fresh)

    after_ttl = accepted_at + pairing._E2E_REPLAY_TTL_SECONDS + 1.0
    assert pairing.claim_e2e_replay_identities(fresh, now=after_ttl) is True
    persisted = json.loads(state_path.read_text(encoding="utf-8"))["e2e_replay_v3"]
    assert [entry["id"] for entry in persisted] == list(fresh)


def test_gateway_commits_replay_only_after_outbound_path_is_ready(channel_key: bytes) -> None:
    token = _command(channel_key, "release exactly once")
    event = SimpleNamespace(
        text=token,
        source=SimpleNamespace(
            platform="slack",
            chat_id="C-v3",
            thread_id=None,
            profile=None,
        ),
    )

    class FrozenAdapterMeta(type):
        def __setattr__(cls, name, value):
            if name == "send":
                raise TypeError("adapter cannot be wrapped")
            return super().__setattr__(name, value)

    class FrozenAdapter(metaclass=FrozenAdapterMeta):
        async def send(self, *_args, **_kwargs):
            raise AssertionError("plaintext must never be sent")

    assert gateway_plugin.pre_gateway_dispatch(
        event=event,
        gateway=SimpleNamespace(adapters={"slack": FrozenAdapter()}),
    ) == {
        "action": "skip",
        "reason": "mordred-outbound-encryption-unavailable",
    }

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("not called by inbound verification")

    protected_gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=protected_gateway) == {
        "action": "rewrite",
        "text": "release exactly once",
    }
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=protected_gateway) == {
        "action": "skip",
        "reason": "mordred-replayed-encrypted-envelope",
    }


def test_slack_synthetic_thread_root_authenticates_as_top_level(channel_key: bytes) -> None:
    """A live top-level Slack command must decrypt under the top-level context.

    The Slack adapter's default ``reply_in_thread`` session keying stamps
    ``thread_id`` with a synthetic root equal to the top-level message's OWN
    ``ts`` (``thread_ts == ts``). Slack assigns that ts only after the send,
    so the extension provably encrypted with ``thread_root=None`` — deriving
    the AAD from the routed synthetic root instead refuses every genuine
    top-level command as ``authentication_failed`` (live 2026-08-01).
    """
    ts = "1785544512.573099"
    token = _command(channel_key)
    event = SimpleNamespace(
        text=token,
        message_id=ts,
        source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id=ts, profile=None),
    )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("not called by inbound verification")

    gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "rewrite",
        "text": "authenticated command",
    }
    # Reply routing must keep the routed synthetic thread: the agent's answer
    # lands in the thread Slack rooted at the mention, re-encrypted in kind.
    assert e2e.thread_key_id("slack", "C-v3", ts) == crypto.key_id(channel_key)


def test_slack_genuine_thread_reply_keeps_its_real_root(channel_key: bytes) -> None:
    root, reply_ts = "1785000000.000100", "1785000000.000200"
    token = _command(channel_key, thread_root=root)
    event = SimpleNamespace(
        text=token,
        message_id=reply_ts,
        source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id=root, profile=None),
    )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("not called by inbound verification")

    gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "rewrite",
        "text": "authenticated command",
    }


def test_slack_top_level_token_is_refused_inside_a_real_thread(channel_key: bytes) -> None:
    # A captured top-level token pasted into a genuine thread must not
    # authenticate: canonicalization applies only when the routed root IS the
    # command's own message id, so the thread binding stays intact.
    root, reply_ts = "1785000000.000100", "1785000000.000200"
    token = _command(channel_key)
    event = SimpleNamespace(
        text=token,
        message_id=reply_ts,
        source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id=root, profile=None),
    )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("plaintext must never be released")

    gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "skip",
        "reason": "mordred-invalid-encrypted-envelope",
    }


def test_slack_thread_token_is_refused_at_top_level(channel_key: bytes) -> None:
    # The converse lift: a token bound to a genuine thread must not
    # authenticate on a top-level (synthetic-root) event. Guards against a
    # future "fix" that canonicalizes unconditionally or tries both roots.
    ts = "1785546061.254429"
    token = _command(channel_key, thread_root="1785000000.000100")
    event = SimpleNamespace(
        text=token,
        message_id=ts,
        source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id=ts, profile=None),
    )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("plaintext must never be released")

    gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "skip",
        "reason": "mordred-invalid-encrypted-envelope",
    }


def test_synthetic_root_shape_does_not_canonicalize_off_slack(channel_key: bytes) -> None:
    # Pins the platform gate: a discord event shaped thread_id == message_id
    # must keep its routed root, so a top-level-bound token stays refused.
    pairing.save_channel_key("D-v3", secrets.token_bytes(32))
    raw_key = secrets.token_bytes(32)
    pairing.save_channel_key("discord:G0GUILD:D-v3", raw_key)
    token = _command(raw_key, platform="discord", chat_id="D-v3", thread_root=None)
    event = SimpleNamespace(
        text=token,
        message_id="999888777",
        source=SimpleNamespace(platform="discord", chat_id="D-v3", thread_id="999888777", profile=None),
    )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("plaintext must never be released")

    gateway = SimpleNamespace(adapters={"discord": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "skip",
        "reason": "mordred-invalid-encrypted-envelope",
    }


@pytest.mark.parametrize("bad_message_id", [None, "", 0])
def test_slack_degenerate_message_id_fails_closed(channel_key: bytes, bad_message_id) -> None:
    # Without a usable message id the synthetic root cannot be proven, so the
    # stricter routed root stands and the top-level token is refused.
    token = _command(channel_key)
    event = SimpleNamespace(
        text=token,
        message_id=bad_message_id,
        source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id="1785000000.000300", profile=None),
    )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("plaintext must never be released")

    gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "skip",
        "reason": "mordred-invalid-encrypted-envelope",
    }


def test_slack_top_level_replay_is_refused_through_the_hook(channel_key: bytes) -> None:
    # The replay store is the SOLE defense for the context this fix newly
    # makes reachable (same channel, top level) — exercise it end to end
    # through the hook, not just at the claim_gateway_replay level.
    token = _command(channel_key, "release exactly once, live shape")

    def live_event(ts: str) -> SimpleNamespace:
        return SimpleNamespace(
            text=token,
            message_id=ts,
            source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id=ts, profile=None),
        )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("not called by inbound verification")

    gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=live_event("1785000000.000400"), gateway=gateway) == {
        "action": "rewrite",
        "text": "release exactly once, live shape",
    }
    assert gateway_plugin.pre_gateway_dispatch(event=live_event("1785000000.000500"), gateway=gateway) == {
        "action": "skip",
        "reason": "mordred-replayed-encrypted-envelope",
    }


def test_slack_flat_reply_mode_top_level_authenticates_identically(channel_key: bytes) -> None:
    # reply_in_thread=false delivers top-level messages with no thread at all;
    # both Slack config modes must accept the same top-level-bound token.
    token = _command(channel_key, "flat mode")
    event = SimpleNamespace(
        text=token,
        message_id="1785000000.000600",
        source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id=None, profile=None),
    )

    class WrappableAdapter:
        async def send(self, *_args, **_kwargs):
            raise AssertionError("not called by inbound verification")

    gateway = SimpleNamespace(adapters={"slack": WrappableAdapter()})
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "rewrite",
        "text": "flat mode",
    }


@pytest.mark.parametrize(
    "text",
    ["", None],
    ids=["image-or-voice-attachment", "no-text-field"],
)
def test_empty_text_is_refused_on_mandatory_e2e_platforms(text: object) -> None:
    """An empty ``text`` must not bypass the mandatory-encryption gate.

    The shipped Slack adapter strips the bot mention and carries attachments in
    ``media_urls``, so `@Hermes` + image / voice clip / a bare mention all reach
    the hook with ``text == ""``. Returning ``None`` (normal dispatch) would let
    such an event reach the agent with no encryption check at all, and the
    answer would leave through the cleartext send path — the leak SLACK_E2E.md
    §5 forbids. A v3 token cannot accompany an empty text, so the only correct
    verdict is "unencrypted inbound".
    """

    class NoticeAdapter:
        async def send(self, *_args, **_kwargs):
            return None

    event = SimpleNamespace(
        text=text,
        media_urls=["https://files.slack.com/secret-screenshot.png"],
        source=SimpleNamespace(platform="slack", chat_id="C-v3", thread_id=None, profile=None),
    )
    gateway = SimpleNamespace(adapters={"slack": NoticeAdapter()})

    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=gateway) == {
        "action": "skip",
        "reason": "mordred-encryption-required",
    }


def test_empty_text_still_dispatches_normally_off_mandatory_platforms() -> None:
    """The refusal is scoped to the mandatory-E2E platforms only.

    Telegram and friends have no encryption requirement, so an empty text there
    remains "nothing for this hook to do" — returning a skip would silently drop
    legitimate media messages on every other platform.
    """
    event = SimpleNamespace(
        text="",
        source=SimpleNamespace(platform="telegram", chat_id="123", thread_id=None, profile=None),
    )
    assert gateway_plugin.pre_gateway_dispatch(event=event, gateway=None) is None


@pytest.mark.parametrize("reuse", ["message_id", "nonce"])
def test_replay_cache_rejects_authenticated_identity_reuse(channel_key: bytes, reuse: str) -> None:
    message_id = crypto.b64u_encode(secrets.token_bytes(16))
    nonce = secrets.token_bytes(12)
    first = _command(channel_key, "first", message_id=message_id, nonce=nonce)
    second = _command(
        channel_key,
        "second",
        message_id=message_id if reuse == "message_id" else None,
        nonce=secrets.token_bytes(12) if reuse == "message_id" else nonce,
    )

    for index, token in enumerate((first, second)):
        _plaintext, _kid, claim = e2e.decrypt_gateway_envelope(
            token,
            "slack",
            chat_id="C-v3",
            thread_root=None,
        )
        assert claim is not None
        assert e2e.claim_gateway_replay(claim) is (index == 0)


# --------------------------------------------------------------------------- #
# Composite channel-key binding: the {team}/{guild} segment
#
# #83 made the composite id resolvable by matching only its first (platform)
# and last (channel) segments, because a gateway event was not known to carry
# the workspace id. ``SessionSource.scope_id`` does carry it on Slack, so the
# middle segment is now enforced wherever the caller actually knows it — and
# only there, since resurrecting a global "must match" would recreate the #83
# outage on every event shape that omits the field.
# --------------------------------------------------------------------------- #


def _bind_key(stored_id: str) -> bytes:
    """Store a channel key under ``stored_id`` on an actively paired install.

    The pairing is what the replay store requires before it will claim an
    authenticated envelope, so a hook-level test needs it to reach a verdict
    other than a replay failure.
    """
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=secrets.token_bytes(32),
            ext_token="active-pairing",
            ext_pubkey_b64="",
            hermes_pubkey_b64="",
            paired_at=0.0,
        )
    )
    raw_key = secrets.token_bytes(32)
    pairing.save_channel_key(stored_id, raw_key)
    return raw_key


def test_v3_composite_binding_requires_a_known_scope_to_match() -> None:
    raw_key = _bind_key("slack:T0TEAM:C0BCX916V6Z")
    token = _command(raw_key, chat_id="C0BCX916V6Z")

    with pytest.raises(e2e.InvalidEncryptedEnvelope, match="key_not_bound_to_channel"):
        e2e.decrypt_gateway_envelope(
            token,
            "slack",
            chat_id="C0BCX916V6Z",
            thread_root=None,
            scope_id="T0OTHERTEAM",
        )


def test_v3_composite_binding_accepts_the_matching_scope() -> None:
    raw_key = _bind_key("slack:T0TEAM:C0BCX916V6Z")
    token = _command(raw_key, chat_id="C0BCX916V6Z")

    plaintext, _kid, replay = e2e.decrypt_gateway_envelope(
        token,
        "slack",
        chat_id="C0BCX916V6Z",
        thread_root=None,
        scope_id="T0TEAM",
    )
    assert plaintext == "authenticated command"
    assert replay is not None


@pytest.mark.parametrize("scope_id", [None, ""])
def test_v3_composite_binding_stays_lenient_when_the_scope_is_unknown(scope_id: str | None) -> None:
    """The #83 shape: no event field to compare against, so do not refuse."""
    raw_key = _bind_key("slack:T0TEAM:C0BCX916V6Z")
    token = _command(raw_key, chat_id="C0BCX916V6Z")

    plaintext, _kid, _replay = e2e.decrypt_gateway_envelope(
        token,
        "slack",
        chat_id="C0BCX916V6Z",
        thread_root=None,
        scope_id=scope_id,
    )
    assert plaintext == "authenticated command"


def test_v3_bare_channel_id_binding_ignores_a_known_scope() -> None:
    """A key stored under the native chat id carries no scope to check."""
    raw_key = _bind_key("C0BCX916V6Z")
    token = _command(raw_key, chat_id="C0BCX916V6Z")

    plaintext, _kid, _replay = e2e.decrypt_gateway_envelope(
        token,
        "slack",
        chat_id="C0BCX916V6Z",
        thread_root=None,
        scope_id="T0TEAM",
    )
    assert plaintext == "authenticated command"


class _WrappableAdapter:
    async def send(self, *_args, **_kwargs):
        raise AssertionError("not called by inbound verification")


class _SlackConnectWrappableAdapter(_WrappableAdapter):
    def __init__(self, *installed_team_ids: str) -> None:
        self._team_clients = {team_id: object() for team_id in installed_team_ids}


def _scoped_slack_event(
    token: str,
    chat_id: str,
    scope_id: str | None,
    *,
    raw_team_id: str | None = None,
):
    return SimpleNamespace(
        text=token,
        source=SimpleNamespace(
            platform="slack",
            chat_id=chat_id,
            thread_id=None,
            profile=None,
            scope_id=scope_id,
        ),
        raw_message=({"type": "message", "channel": chat_id, "team": raw_team_id} if raw_team_id is not None else None),
    )


def test_gateway_hook_binds_a_slack_command_to_its_workspace() -> None:
    """The hook feeds ``source.scope_id`` into key resolution.

    A mismatch is refused as an invalid envelope; the matching workspace gets
    past decryption (and only then stops on this test's unwrapped gateway), so
    the two verdicts distinguish "wrong workspace" from "no reply path".
    """
    raw_key = _bind_key("slack:T0TEAM:C0BCX916V6Z")
    gateway = SimpleNamespace(adapters={"slack": _WrappableAdapter()})

    assert gateway_plugin.pre_gateway_dispatch(
        event=_scoped_slack_event(_command(raw_key, chat_id="C0BCX916V6Z"), "C0BCX916V6Z", "T0OTHERTEAM"),
        gateway=gateway,
    ) == {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}

    assert gateway_plugin.pre_gateway_dispatch(
        event=_scoped_slack_event(_command(raw_key, chat_id="C0BCX916V6Z"), "C0BCX916V6Z", "T0TEAM"),
        gateway=gateway,
    ) == {"action": "rewrite", "text": "authenticated command"}


def test_gateway_hook_accepts_external_slack_connect_scope_for_an_installed_host() -> None:
    raw_key = _bind_key("slack:T0HOSTTEAM:C0BCX916V6Z")
    gateway = SimpleNamespace(adapters={"slack": _SlackConnectWrappableAdapter("T0HOSTTEAM")})

    assert gateway_plugin.pre_gateway_dispatch(
        event=_scoped_slack_event(
            _command(raw_key, chat_id="C0BCX916V6Z"),
            "C0BCX916V6Z",
            "T0EXTERNALTEAM",
            raw_team_id="T0EXTERNALTEAM",
        ),
        gateway=gateway,
    ) == {"action": "rewrite", "text": "authenticated command"}


def test_gateway_hook_never_relaxes_slack_connect_to_an_uninstalled_key_scope() -> None:
    raw_key = _bind_key("slack:T0STALETEAM:C0BCX916V6Z")
    gateway = SimpleNamespace(adapters={"slack": _SlackConnectWrappableAdapter("T0HOSTTEAM")})

    assert gateway_plugin.pre_gateway_dispatch(
        event=_scoped_slack_event(
            _command(raw_key, chat_id="C0BCX916V6Z"),
            "C0BCX916V6Z",
            "T0EXTERNALTEAM",
            raw_team_id="T0EXTERNALTEAM",
        ),
        gateway=gateway,
    ) == {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}


def test_gateway_hook_requires_the_raw_slack_team_to_prove_the_external_scope() -> None:
    raw_key = _bind_key("slack:T0HOSTTEAM:C0BCX916V6Z")
    gateway = SimpleNamespace(adapters={"slack": _SlackConnectWrappableAdapter("T0HOSTTEAM")})

    assert gateway_plugin.pre_gateway_dispatch(
        event=_scoped_slack_event(
            _command(raw_key, chat_id="C0BCX916V6Z"),
            "C0BCX916V6Z",
            "T0EXTERNALTEAM",
            raw_team_id="T0DIFFERENTTEAM",
        ),
        gateway=gateway,
    ) == {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}


@pytest.mark.parametrize("scope_id", [None, "", 12345, object()])
def test_gateway_hook_treats_an_absent_or_hostile_scope_as_unknown(scope_id: object) -> None:
    """An unusable scope field must not refuse a legitimate command."""
    raw_key = _bind_key("slack:T0TEAM:C0BCX916V6Z")
    gateway = SimpleNamespace(adapters={"slack": _WrappableAdapter()})

    assert gateway_plugin.pre_gateway_dispatch(
        event=_scoped_slack_event(_command(raw_key, chat_id="C0BCX916V6Z"), "C0BCX916V6Z", scope_id),
        gateway=gateway,
    ) == {"action": "rewrite", "text": "authenticated command"}
