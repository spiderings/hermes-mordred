"""Mordred E2E transport as a pure hermes-agent plugin (no core fork).

The vendored fork wired Slack/Discord/Teams E2E by editing each platform
adapter (inbound decrypt) and ``gateway/run.py`` (start the extension server).
This module replaces the *inbound* half with a single ``pre_gateway_dispatch``
hook so the exact same behaviour runs on a stock ``hermes-agent`` install via
``pip install hermes-mordred`` — no upstream edits, no fork.

``pre_gateway_dispatch`` fires once per incoming ``MessageEvent`` after the
internal-event guard but BEFORE auth/pairing and agent dispatch, and may return:
  * ``{"action": "skip",    "reason": ...}`` — drop the message (no reply)
  * ``{"action": "rewrite", "text": ...}``  — replace ``event.text``, continue

which is exactly what the E2E transport needs:
  * ``🔑REQ/GRANT`` key-exchange control messages (peer-to-peer between
    extensions, SPEC-v2 §5) → skip, so the agent never reacts to them;
  * one complete, context-bound ``🔒ENC:v3`` command → authenticate it, then
    rewrite with decrypted plaintext, so the agent reads cleartext while the
    wire stays encrypted. Legacy versions and arbitrary surrounding plaintext
    are rejected on this gateway boundary;
  * before releasing plaintext, verify and record a live fail-closed outbound
    reply path for the same platform/channel/thread.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from . import e2e

logger = logging.getLogger(__name__)

# Platforms where end-to-end encryption is mandatory across ALL channels:
# an inbound message the plugin cannot decrypt (plaintext, or ciphertext whose
# key we do not hold) is never handed to the agent in cleartext. Instead the
# sender is told to set up / obtain an encryption key (see _notify_needs_key).
# Shared with the send path (e2e.outbound_must_encrypt): the two directions must
# agree on which platforms are ciphertext-only, so the set has one definition.
_ENFORCE_ENCRYPTION_PLATFORMS = e2e.MANDATORY_ENCRYPTION_PLATFORMS

_NEEDS_KEY_NOTICE = (
    "🔒 暗号化されていないメッセージには応答できません。"
    "拡張機能で暗号化キーを設定または取得のうえ、暗号化して再送してください。"
)

# One needs-key notice per conversation per window. The notice is sent BEFORE
# the host authorizes the sender, so on a mandatory-E2E platform every member of
# a channel can otherwise amplify each message of their own into a bot post.
# Same shape as ``gateway.pairing.PairingStore._is_rate_limited``: last-send
# timestamp compared against a fixed window. Kept in memory (unlike the pairing
# store's file) because a notice dropped across a restart costs nothing — the
# message itself is refused either way.
_NEEDS_KEY_RATE_LIMIT_SECONDS = 60
_NEEDS_KEY_NOTICE_TIMES: dict[tuple[str, str | None, str], float] = {}

# Strong refs to fire-and-forget notice sends: without this the event loop only
# holds a weak reference and may garbage-collect the task mid-flight (RUF006).
_bg_tasks: set[Any] = set()
_INVALID_PROFILE = "\x00mordred-invalid-profile"
_MISSING = object()


def _platform_name(event: Any) -> str:
    """Normalized lowercase platform id ("slack"/"discord"/...) from an event.

    ``source.platform`` may be a ``Platform`` enum or a bare string; ``.value``
    unwraps the enum, ``str`` covers the string case.
    """
    src = getattr(event, "source", None)
    raw = getattr(src, "platform", None) or getattr(event, "platform", None)
    return str(getattr(raw, "value", raw) or "").lower()


def _profile_name(event: Any) -> str | None:
    """Return the multiplex profile stamped on ``event.source``.

    Hermes versions before multiplexing simply omit the field. A malformed or
    hostile profile value gets an impossible sentinel so adapter lookup fails
    closed instead of falling back to the active/default bot.
    """
    try:
        src = getattr(event, "source", None)
        raw = getattr(src, "profile", None)
        if raw is None:
            return None
        if not isinstance(raw, str):
            return _INVALID_PROFILE
        return raw.strip() or None
    except BaseException:
        return _INVALID_PROFILE


async def _safe_send(adapter: Any, chat_id: str, content: str, metadata: dict[str, Any] | None) -> None:
    """Deliver a Mordred control notice through the (wrapped) live adapter.

    Marked as a control notice so the send path's channel-binding rule does not
    encrypt it: the notice exists to tell a sender who could not encrypt how to
    obtain a key, so ciphertext would make it unreadable by its only audience.
    It carries no agent or user content. Reply-in-kind is unaffected — a
    conversation already marked encrypted still gets an encrypted notice.
    """
    try:
        with e2e.control_notice_send():
            await adapter.send(chat_id, content, reply_to=None, metadata=metadata)
    except Exception as exc:
        logger.warning("mordred_e2e: needs-key notice send failed: %s", exc)


def _notice_rate_limited(platform: str, profile: str | None, chat_id: str) -> bool:
    """Has this conversation already been sent a needs-key notice recently?

    Mirrors ``gateway.pairing.PairingStore._is_rate_limited``. Expired entries
    are dropped on the way through: the key space is attacker-influenced (one
    entry per channel they can post in), so it must not grow unbounded.
    """
    now = time.time()
    for key, sent_at in list(_NEEDS_KEY_NOTICE_TIMES.items()):
        if (now - sent_at) >= _NEEDS_KEY_RATE_LIMIT_SECONDS:
            del _NEEDS_KEY_NOTICE_TIMES[key]
    last_sent = _NEEDS_KEY_NOTICE_TIMES.get((platform, profile, chat_id), 0.0)
    return (now - last_sent) < _NEEDS_KEY_RATE_LIMIT_SECONDS


def _notify_needs_key(gateway: Any, event: Any, outbound: Any, profile: str | None) -> bool:
    """Reply to the originating channel/thread asking the sender to set up or
    obtain an encryption key. Best-effort; returns True if a send was scheduled.

    Rate-limited per (platform, profile, channel): suppressing a notice only
    costs the sender an explanation, while sending one per inbound message hands
    any channel member a flood amplifier. The caller's ``skip`` verdict — the
    encryption gate itself — is unaffected either way.

    The send is scheduled on the running loop (the hook itself is sync and is
    invoked from the gateway's async dispatch path) so returning ``skip`` stays
    non-blocking.
    """
    import asyncio

    src = getattr(event, "source", None)
    chat_id = getattr(src, "chat_id", None) or getattr(event, "chat_id", None)
    platform = _platform_name(event)
    if not chat_id or _notice_rate_limited(platform, profile, str(chat_id)):
        return False
    adapter = (
        outbound.live_adapter_for(gateway, platform, profile) if gateway is not None and outbound is not None else None
    )
    if adapter is None:
        return False

    thread = getattr(src, "thread_id", None) or getattr(event, "thread_id", None)
    metadata: dict[str, Any] | None = None
    if thread:
        # Slack threads reply via thread_ts; Discord via thread_id.
        metadata = {"thread_ts": thread} if platform == "slack" else {"thread_id": thread}

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # no running loop (e.g. unit test calling the hook directly)
        return False
    task = loop.create_task(_safe_send(adapter, str(chat_id), _NEEDS_KEY_NOTICE, metadata))
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    # Only a scheduled send opens the cooldown; a notice we could not even
    # attempt must not silence the next message.
    _NEEDS_KEY_NOTICE_TIMES[(platform, profile, str(chat_id))] = time.time()
    return True


def _scope_id(event: Any) -> str | None:
    """The workspace/guild this event arrived from, when the host stamps one.

    ``SessionSource.scope_id`` is Hermes' platform-neutral scope discriminator
    (Slack team id / Discord guild id); ``guild_id`` is its deprecated alias,
    read as a fallback for older events. The extension's composite channel-key
    id embeds the same value, so a known scope tightens key binding
    (:func:`e2e._channel_key_matches`).

    Returns ``None`` — meaning "unknown, stay lenient" — whenever the field is
    absent, blank, or not a string. Today the shipped Slack adapter stamps it
    from the event's ``team_id`` while the Discord adapter never sets it, so
    Discord binding is unchanged. Anything hostile-shaped is treated as unknown
    rather than as a mismatch: a wrong value here would refuse a legitimate
    command, and the lenient path is exactly the #83-verified behaviour.
    """
    try:
        src = getattr(event, "source", None)
        raw = getattr(src, "scope_id", None) or getattr(src, "guild_id", None)
        if not isinstance(raw, str):
            return None
        return raw.strip() or None
    except BaseException:
        return None


def _slack_connect_host_scope_ids(
    event: Any,
    gateway: Any,
    outbound: Any,
    profile: str | None,
    *,
    platform: str,
    chat_id: str,
    scope_id: str | None,
) -> frozenset[str]:
    """Trusted installing-team alternatives for an external Slack event.

    Slack Connect's generic ``message`` event stamps the posting member's team
    on ``SessionSource.scope_id``. The channel key, however, is normally stored
    under the bot's installing team. Do not solve that by dropping scope checks:
    prove that the source scope came from this raw Slack event, prove that it is
    not one of this live adapter's authenticated installations, and then allow
    only the adapter's ``auth_test``-backed ``_team_clients`` keys as alternate
    composite scopes. A normal workspace event, slash command, DM, malformed
    event, or adapter drift gets no relaxation and continues to fail closed.
    """
    if platform != "slack" or not scope_id or not chat_id.startswith(("C", "G")):
        return frozenset()
    try:
        raw = getattr(event, "raw_message", None)
        if not isinstance(raw, dict) or str(raw.get("channel") or "") != chat_id:
            return frozenset()
        raw_team: Any = raw.get("team_id") or raw.get("team")
        if isinstance(raw_team, dict):
            raw_team = raw_team.get("id")
        if not isinstance(raw_team, str) or raw_team.strip() != scope_id:
            return frozenset()

        adapter = outbound.live_adapter_for(gateway, "slack", profile)
        team_clients = getattr(adapter, "_team_clients", None)
        if not isinstance(team_clients, dict):
            return frozenset()
        installed = frozenset(team.strip() for team in team_clients if isinstance(team, str) and team.strip())
        if not installed or scope_id in installed:
            return frozenset()
        return installed
    except BaseException:
        return frozenset()


def _thread_ctx(event: Any) -> tuple[str, str, str | None, str | None]:
    """Best-effort platform/channel/thread/parent context from a MessageEvent.

    The platform MUST come from :func:`_platform_name` (which unwraps the
    ``Platform`` enum via ``.value``). ``str(Platform.SLACK)`` is
    ``"Platform.SLACK"``, not ``"slack"`` — marking a thread under that repr
    while the outbound wrappers look it up by the literal ``"slack"`` silently
    disables reply-in-kind, sending the agent's answer in CLEARTEXT into an
    encrypted channel.
    """
    src = getattr(event, "source", None)
    chat_id = getattr(src, "chat_id", None) or getattr(event, "chat_id", "") or ""
    thread = getattr(src, "thread_id", None)
    if thread is None:
        thread = getattr(event, "thread_id", None)
    parent = getattr(src, "parent_chat_id", None)
    if parent is None:
        parent = getattr(event, "parent_chat_id", None)
    thread_root = str(thread) if thread not in (None, "") else None
    parent_chat_id = str(parent) if parent not in (None, "") else None
    return _platform_name(event), str(chat_id), thread_root, parent_chat_id


def _slack_command_thread_root(event: Any, thread_root: str | None) -> str | None:
    """The thread root a Slack command's sender could actually have bound.

    The Slack adapter's default ``reply_in_thread`` session keying stamps
    ``thread_id`` with a synthetic root equal to a top-level command's OWN
    ``ts`` (``thread_ts == ts``). Slack assigns that ts only after the send,
    so the extension provably encrypted with the top-level context
    (``thread_root=None``) — authenticate under it. A genuine thread reply
    arrives with ``thread_ts != ts`` and keeps its real root, so a captured
    top-level token still cannot be replayed into a thread.

    Canonicalizing requires two adapter-stamped markers to agree: the routed
    root equals the command's own ``message_id`` AND no
    ``reply_to_message_id`` was recorded (the adapter stamps that field for
    every genuine reply). A missing or contradicting marker keeps the
    stricter routed root, so authentication fails closed.

    Note on that pairing: in the *shipped* Slack adapter both markers derive
    from the same ``(ts, thread_ts)`` pair in the same function, so they are
    one predicate (``ts == thread_ts``) rather than two independent signals —
    do not rely on this as defence-in-depth. It is a shape check against an
    adapter that stops stamping either field, not against a wrong value in
    both. A genuinely independent marker would be
    ``event.metadata["slack_thread_ts"]``.
    """
    message_id = getattr(event, "message_id", None)
    if (
        thread_root is not None
        and isinstance(message_id, str)
        and message_id
        and message_id == thread_root
        and getattr(event, "reply_to_message_id", None) in (None, "")
    ):
        return None
    return thread_root


def _command_aad_ctx(
    event: Any,
    routed_context: tuple[str, str, str | None, str | None],
) -> tuple[str, str, str | None]:
    """Derive the context the sender knew before Discord auto-threading.

    Discord creates a reply thread before ``pre_gateway_dispatch``. The routed
    ``SessionSource`` then points at the new thread even though the extension
    encrypted the command while posting in its parent channel. Both supported
    Hermes generations retain the original Discord message in
    ``event.raw_message``; 0.19 additionally stamps ``auto_thread_created``.

    Reply routing must keep using ``routed_context`` (the new thread), while
    command authentication uses the original parent channel with no thread.
    Ambiguous floor-version thread events without the original raw channel fail
    closed instead of guessing a context.

    Slack has the mirror problem, canonicalized by
    :func:`_slack_command_thread_root`.
    """
    platform, chat_id, thread_root, _parent_chat_id = routed_context
    if platform == "slack":
        return platform, chat_id, _slack_command_thread_root(event, thread_root)
    if platform != "discord":
        return platform, chat_id, thread_root
    return _discord_command_ctx(event, routed_context)


def _discord_command_ctx(
    event: Any,
    routed_context: tuple[str, str, str | None, str | None],
) -> tuple[str, str, str | None]:
    """Resolve the pre-auto-threading context (rules in :func:`_command_aad_ctx`)."""
    platform, chat_id, thread_root, parent_chat_id = routed_context
    src = getattr(event, "source", None)
    explicit_auto = getattr(src, "auto_thread_created", _MISSING)
    if explicit_auto is not _MISSING and not isinstance(explicit_auto, bool):
        raise ValueError("invalid Discord auto-thread marker")

    raw_message = getattr(event, "raw_message", None)
    raw_channel = getattr(raw_message, "channel", None)
    raw_channel_value = getattr(raw_channel, "id", None)
    raw_channel_id = str(raw_channel_value) if raw_channel_value not in (None, "") else None

    parent = parent_chat_id or ""
    routed_thread = bool(parent and thread_root and chat_id == thread_root)
    inferred_auto = bool(routed_thread and raw_channel_id == parent and raw_channel_id != chat_id)

    if explicit_auto is True:
        if not inferred_auto:
            raise ValueError("inconsistent Discord auto-thread context")
        return platform, parent, None
    if explicit_auto is False and inferred_auto:
        raise ValueError("inconsistent Discord auto-thread marker")
    if inferred_auto:
        return platform, parent, None

    if routed_thread and explicit_auto is _MISSING:
        if raw_channel_id is None:
            raise ValueError("ambiguous Discord thread context")
        if raw_channel_id != chat_id:
            raise ValueError("inconsistent Discord thread context")

    return platform, chat_id, thread_root


def _rewrite_encrypted(
    context: tuple[str, str, str | None, str | None],
    gateway: Any,
    outbound: Any,
    decrypted: str,
    kid: str | None,
    replay: e2e.ReplayClaim | None,
    profile: str | None,
) -> dict[str, Any]:
    """Authorize outbound encryption before releasing decrypted text."""
    try:
        platform, chat_id, thread, _parent_chat_id = context
        if not platform or not chat_id or not kid:
            logger.error("mordred_e2e: refusing encrypted message because reply context is incomplete")
            return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}
        if gateway is None or outbound is None or not outbound.live_adapter_is_wrapped(gateway, platform, profile):
            logger.error(
                "mordred_e2e: refusing encrypted %s message because its live outbound adapter is not wrapped",
                platform,
            )
            return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}

        # Remember this conversation is encrypted so the reply re-encrypts
        # (§4). A context/registry failure must also stop before plaintext
        # reaches the agent.
        if not e2e.mark_encrypted_thread(platform, chat_id, thread, kid):
            logger.error("mordred_e2e: refusing encrypted message because reply context was not recorded")
            return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}
    except BaseException:
        logger.error("mordred_e2e: encrypted outbound verification failed")
        return {"action": "skip", "reason": "mordred-outbound-encryption-unavailable"}

    # Replay state is committed only after the reply path and conversation
    # registry are ready. A transient unwrappable adapter must not consume a
    # legitimate command that was never released to the agent.
    try:
        if replay is None:
            raise ValueError("missing replay claim")
        if not e2e.claim_gateway_replay(replay):
            logger.warning("mordred_e2e: refusing replayed encrypted envelope")
            return {"action": "skip", "reason": "mordred-replayed-encrypted-envelope"}
    except BaseException:
        logger.error("mordred_e2e: encrypted replay-state verification failed")
        return {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}
    return {"action": "rewrite", "text": decrypted}


def pre_gateway_dispatch(
    event: Any = None,
    gateway: Any = None,
    session_store: Any = None,
    **_kw: Any,
) -> dict[str, Any] | None:
    """Decrypt inbound ciphertext / drop key-exchange, before the agent."""
    # The concrete platform adapters are directory-based plugins that only exist
    # once the gateway is up, so register() cannot reach them by import path.
    # Wrap the LIVE adapter classes here (idempotent) — otherwise the reply goes
    # out through the real, unwrapped send in cleartext.
    outbound = None
    profile = _profile_name(event)
    if gateway is not None:
        try:
            from . import outbound as outbound_module

            outbound_module.wrap_live_adapters(gateway, profile)
            outbound = outbound_module
        except BaseException:
            logger.warning("mordred_e2e: live adapter wrap failed")

    text = getattr(event, "text", None)
    if not isinstance(text, str) or not text:
        # An absent/empty text is NOT "nothing to do" on a mandatory-E2E
        # platform. The shipped Slack adapter strips the bot mention
        # (``text.replace(f"<@{bot_uid}>", "").strip()``) and carries
        # attachments in ``media_urls``, so `@Hermes` + image / voice clip /
        # a bare mention all arrive here with ``text == ""``. Returning None
        # means "normal dispatch" to the host, so such an event would reach
        # the agent without ever passing the encryption check below, and the
        # agent's answer would leave through the cleartext send path — the
        # exact leak the mandatory gate exists to prevent (SLACK_E2E.md §5).
        # A v3 token can never accompany an empty text, so the only correct
        # verdict here is "unencrypted inbound": refuse it like any other.
        if _platform_name(event) in _ENFORCE_ENCRYPTION_PLATFORMS:
            _notify_needs_key(gateway, event, outbound, profile)
            return {"action": "skip", "reason": "mordred-encryption-required"}
        return None

    # 🔑REQ/GRANT are peer-to-peer between extensions — the agent must not see them.
    if e2e.is_key_exchange(text):
        return {"action": "skip", "reason": "mordred-key-exchange"}

    # Treat the whole wire value as one authenticated envelope. Only a
    # platform-valid leading mention prefix, one fully authenticated v3 token,
    # and trailing whitespace are accepted. In particular, never decrypt a
    # valid token embedded beside attacker-controlled plaintext.
    try:
        context = _thread_ctx(event)
        platform, chat_id, thread_root = _command_aad_ctx(event, context)
        parent_chat_id = context[3]
        scope_id = _scope_id(event)
        decrypted, kid, replay = e2e.decrypt_gateway_envelope(
            text,
            platform,
            chat_id=chat_id,
            thread_root=thread_root,
            parent_chat_id=parent_chat_id,
            scope_id=scope_id,
            slack_connect_host_scope_ids=_slack_connect_host_scope_ids(
                event,
                gateway,
                outbound,
                profile,
                platform=platform,
                chat_id=chat_id,
                scope_id=scope_id,
            ),
        )
    except e2e.InvalidEncryptedEnvelope as exc:
        # The reason is a fixed identifier (never message text, keys or
        # plaintext), and without it an operator cannot tell a wrong channel
        # key from a mangled wire or a thread-context mismatch — all of which
        # look identical in the log and need completely different fixes.
        logger.warning("mordred_e2e: refusing encrypted envelope: %s", exc)
        return {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}
    except BaseException:
        logger.error("mordred_e2e: encrypted envelope verification failed")
        return {"action": "skip", "reason": "mordred-invalid-encrypted-envelope"}

    if decrypted is not None:
        # Decrypting commits the agent to producing a reply for an encrypted
        # channel. Check/record the outbound path before plaintext is released.
        return _rewrite_encrypted(context, gateway, outbound, decrypted, kid, replay, profile)

    # Nothing decrypted → the agent would otherwise read this as cleartext.
    # On platforms with mandatory E2E (Slack/Discord, all channels), refuse to
    # answer in cleartext: tell the sender to set up / obtain an encryption key
    # and skip, so the agent never processes the plaintext.
    if _platform_name(event) in _ENFORCE_ENCRYPTION_PLATFORMS:
        _notify_needs_key(gateway, event, outbound, profile)
        return {"action": "skip", "reason": "mordred-encryption-required"}

    return None


def register(ctx: Any) -> None:
    """Plugin entry point (``hermes_agent.plugins`` group).

    Wires the full E2E transport with no core fork:
      * inbound decrypt / key-exchange drop  → ``pre_gateway_dispatch`` hook
      * outbound reply re-encryption         → platform ``send`` wrappers
    The browser-extension WebSocket server ships as the standalone
    ``hermes-mordred extension serve`` command (``extension.api``); it does not
    need the gateway process.
    """
    from ..privacy_check.hooks import check_plugin_integrity

    ctx.register_hook("on_session_start", check_plugin_integrity)
    ctx.register_hook("pre_gateway_dispatch", pre_gateway_dispatch)
    logger.debug("mordred_e2e: registered pre_gateway_dispatch hook")

    # Read-only Telegram tools; offered only to a Venice/loopback Hermes model.
    try:
        from .telegram.hermes_tools import register_tools

        register_tools(ctx)
    except Exception as e:
        logger.warning("mordred_e2e: Telegram tools not registered: %s", type(e).__name__)

    # Outbound: wrap each installed platform adapter's send (best-effort).
    try:
        from . import outbound

        installed = outbound.install_outbound_patches()
        if installed:
            logger.debug("mordred_e2e: outbound E2E wrapped for %s", ", ".join(installed))
    except Exception as e:
        logger.warning("mordred_e2e: outbound patch install failed: %s", e)
