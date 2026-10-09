"""Context-bound v3 outbound reply encryption, as a plugin.

No hermes-agent hook carries channel/thread context on the *send* path
(``transform_llm_output`` only sees ``response_text``/``session_id``/``platform``),
so the reply-in-kind encryption is applied by wrapping each concrete platform
adapter's ``send`` at plugin load. The wrapper diverts ONLY encrypted-thread
replies to an encrypted send; every other message goes to the original,
unmodified ``send``.

Fail-closed: once a conversation must be encrypted, the wrapper never falls back
to plaintext — a missing key returns a failure (Slack also posts a locked
notice), exactly like the vendored fork's adapter edits.

"Must be encrypted" is :func:`e2e.outbound_must_encrypt`: a conversation that
recently carried ciphertext, OR any channel with a bound ``K_chan`` on a
mandatory-E2E platform. The second rule covers every send that has no inbound
thread context to inherit — cron output, proactive notifications, agent-initiated
messages — which otherwise left in cleartext into a ciphertext-only channel.
Mordred's own needs-key notice is the sole exception (``e2e.control_notice_send``).
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from . import e2e

logger = logging.getLogger(__name__)

# Adapter class names we've already wrapped (idempotent install).
_patched: set[str] = set()

_LOCKED_NOTICE = "🔒 (暗号化できないため本文を送信できませんでした)"
_CONTEXT_UNAVAILABLE = "mordred_encrypt_context_unavailable"


def _SendResult() -> Any:
    from gateway.platforms.base import SendResult  # lazy: only inside a gateway

    return SendResult


# --- Slack -----------------------------------------------------------------


async def _slack_encrypted_send(self: Any, chat_id: str, content: str, thread_ts: str | None) -> Any:
    SendResult = _SendResult()
    client = self._get_client(chat_id)
    kid = e2e.outbound_key_id("slack", chat_id, thread_ts)
    key = e2e.reply_key(kid)
    if key is None:
        kw = {"channel": chat_id, "text": _LOCKED_NOTICE, "mrkdwn": False}
        if thread_ts:
            kw["thread_ts"] = thread_ts
        try:
            await client.chat_postMessage(**kw)
        except Exception as exc:
            # Best-effort notice, but never silent: if it fails the user sees no
            # reply at all, and the operator needs the reason (mirrors the
            # warning gateway_plugin._safe_send emits for the needs-key notice).
            logger.warning("mordred_e2e: locked-notice send failed: %s", exc)
        return SendResult(success=False, error="mordred_encrypt_unavailable")

    chunks = e2e.encrypt_reply(
        key,
        content,
        self.MAX_MESSAGE_LENGTH,
        e2e.SLACK_MENTION_PREFIX_RE,
        platform="slack",
        chat_id=str(chat_id),
        thread_root=thread_ts,
    )
    last = None
    for chunk in chunks:
        kw = {"channel": chat_id, "text": chunk, "mrkdwn": False}  # ciphertext: never mrkdwn
        if thread_ts:
            kw["thread_ts"] = thread_ts
        last = await client.chat_postMessage(**kw)

    if thread_ts:
        with contextlib.suppress(Exception):
            await self.stop_typing(chat_id)
    sent_ts = last.get("ts") if last else None
    if sent_ts:
        try:
            self._bot_message_ts.add(sent_ts)
            if thread_ts:
                self._bot_message_ts.add(thread_ts)
        except Exception as exc:
            # Bookkeeping only — the ciphertext is already posted, so failing the
            # send here would be wrong. But it is how the adapter recognizes its
            # own messages, so a silent failure degrades that invariant with no
            # trace if the attribute ever changes shape upstream.
            logger.warning("mordred_e2e: bot-message bookkeeping failed: %s", exc)
    return SendResult(success=True, message_id=sent_ts, raw_response={"ts": sent_ts})


def _wrap_slack(cls: Any) -> None:
    orig_send = cls.send

    async def send(self, chat_id, content, reply_to=None, metadata=None):  # type: ignore[no-untyped-def]
        # NOTE: a falsy ``_app`` falls through to the plaintext sender. That is
        # load-bearing — the needs-key notice is itself a plaintext send through
        # this wrapper, and adapters that expose no ``_app`` must still deliver
        # it. Tightening this into a fail-closed refusal needs a way to tell
        # "not an initialized adapter" from "real adapter, transient reconnect";
        # see the follow-up recorded in the 2026-08-02 extension review.
        if getattr(self, "_app", None):
            try:
                thread_ts = self._resolve_thread_ts(reply_to, metadata)
                encrypted = e2e.outbound_must_encrypt("slack", chat_id, thread_ts)
            except Exception as exc:
                # Context resolution is part of the confidentiality boundary.
                # Adapter API drift or a registry failure must not turn a
                # possibly encrypted reply into a call to the plaintext sender.
                logger.warning("mordred_e2e: Slack encryption-context lookup failed: %s", exc)
                SendResult = _SendResult()
                return SendResult(success=False, error=_CONTEXT_UNAVAILABLE)
            if encrypted:  # fail-closed: never delegate to the plaintext path
                return await _slack_encrypted_send(self, chat_id, content, thread_ts)
        return await orig_send(self, chat_id, content, reply_to, metadata)

    send.__mordred_wrapped__ = True  # type: ignore[attr-defined]
    cls.send = send


# --- Discord ---------------------------------------------------------------


async def _discord_encrypted_send(self: Any, chat_id: str, content: str, thread_id: str | None, ids: list[str]) -> Any:
    SendResult = _SendResult()
    tid = thread_id or chat_id
    channel = self._client.get_channel(int(tid))
    if not channel:
        channel = await self._client.fetch_channel(int(tid))
    if not channel:
        return SendResult(success=False, error=f"Channel {tid} not found")

    # Include the parent channel id in the key lookup (threads inherit the key).
    parent = None
    try:
        _p = getattr(channel, "parent_id", None) or getattr(getattr(channel, "parent", None), "id", None)
        if _p:
            parent = str(_p)
    except Exception:
        parent = None
    lookup = [x for x in {*ids, parent or ""} if x]

    kid = None
    for cid in lookup:
        kid = e2e.outbound_key_id("discord", cid, thread_id)
        if kid:
            break
    key = e2e.reply_key(kid)
    if key is None:
        return SendResult(success=False, error="mordred_encrypt_unavailable")

    mids: list[str] = []
    for chunk in e2e.encrypt_reply(
        key,
        content,
        self.MAX_MESSAGE_LENGTH,
        e2e.DISCORD_MENTION_PREFIX_RE,
        platform="discord",
        chat_id=str(tid),
        thread_root=thread_id,
    ):
        msg = await channel.send(chunk)
        mids.append(str(msg.id))
    return SendResult(success=True, message_id=mids[0] if mids else None, raw_response={"message_ids": mids})


def _wrap_discord(cls: Any) -> None:
    orig_send = cls.send

    async def send(self, chat_id, content, reply_to=None, metadata=None):  # type: ignore[no-untyped-def]
        # See the matching note in _wrap_slack: the falsy-client fallthrough is
        # deliberate for now (plaintext notices must still reach the user).
        if getattr(self, "_client", None):
            try:
                raw_thread_id = (metadata or {}).get("thread_id")
                thread_id = str(raw_thread_id) if raw_thread_id not in (None, "") else None
                # Only the ids this call carries. A Discord thread inherits its
                # parent's key, but the parent is resolved from the live client
                # inside _discord_encrypted_send, so a proactive send addressed
                # to a bare thread id can still miss the channel-binding rule.
                ids = [x for x in {str(chat_id), str(thread_id or "")} if x]
                encrypted = any(e2e.outbound_must_encrypt("discord", x, thread_id) for x in ids)
            except Exception as exc:
                # As with Slack, an indeterminate encryption context is a send
                # failure. Falling through would expose the reply via orig_send.
                logger.warning("mordred_e2e: Discord encryption-context lookup failed: %s", exc)
                SendResult = _SendResult()
                return SendResult(success=False, error=_CONTEXT_UNAVAILABLE)
            if encrypted:  # fail-closed
                return await _discord_encrypted_send(self, chat_id, content, thread_id, ids)
        return await orig_send(self, chat_id, content, reply_to, metadata)

    send.__mordred_wrapped__ = True  # type: ignore[attr-defined]
    cls.send = send


# --- install ---------------------------------------------------------------

_TARGETS = [
    ("slack", "gateway.platforms.slack.adapter", "SlackAdapter", _wrap_slack),
    ("discord", "gateway.platforms.discord.adapter", "DiscordAdapter", _wrap_discord),
    # Some builds ship platform adapters under plugins/platforms/*.
    ("slack", "plugins.platforms.slack.adapter", "SlackAdapter", _wrap_slack),
    ("discord", "plugins.platforms.discord.adapter", "DiscordAdapter", _wrap_discord),
]


_WRAPPERS = {"slack": _wrap_slack, "discord": _wrap_discord}


def _live_adapter_items(gateway: Any, profile: str | None = None) -> list[tuple[Any, Any]]:
    """Return the adapter registry selected by an inbound event's profile.

    Hermes 0.19+ stores secondary multiplex-profile adapters under
    ``gateway._profile_adapters[profile]`` while the active/default profile
    continues to use ``gateway.adapters``. Older supported Hermes releases
    only expose ``gateway.adapters``. A stamped secondary profile must never
    fall back to the default registry: that could verify one bot's wrapped
    adapter while the reply is actually routed through another bot.

    Gateway/plugin objects are outside Mordred's trust boundary. Attribute,
    mapping and iterator failures therefore resolve to an empty registry so
    callers fail closed.
    """
    try:
        profile_name = profile.strip() if isinstance(profile, str) else None
        if profile_name and profile_name != "default":
            profile_adapters = getattr(gateway, "_profile_adapters", None)
            if profile_adapters is None:
                return []
            adapters = profile_adapters.get(profile_name)
        else:
            adapters = getattr(gateway, "adapters", None)
        if adapters is None:
            return []
        return list(adapters.items())
    except BaseException:
        return []


def live_adapter_for(gateway: Any, platform: str, profile: str | None = None) -> Any | None:
    """Resolve the exact live adapter for ``platform`` and ``profile``.

    This shares the same fail-closed profile selection as wrapping and
    verification, and is also used for the mandatory-E2E setup notice.
    """
    try:
        wanted = str(platform or "").lower()
        for raw_platform, adapter in _live_adapter_items(gateway, profile):
            name = str(getattr(raw_platform, "value", raw_platform) or "").lower()
            if name == wanted:
                return adapter
    except BaseException:
        return None
    return None


def wrap_live_adapters(gateway: Any, profile: str | None = None) -> list[str]:
    """Wrap the ``send`` of the adapter classes the gateway ACTUALLY built.

    This is the reliable path. Guessing import paths does not work: the concrete
    Slack/Discord adapters are directory-based plugins loaded into a synthetic
    package (``hermes_plugins.slack_platform.adapter``) that only resolves inside
    a live gateway process, and the path differs between hermes builds. Patching
    a same-named class from some other importable module silently wraps a class
    nobody instantiates, so replies go out through the real, unwrapped adapter —
    in cleartext.

    ``GatewayRunner.adapters`` is ``Dict[Platform, BasePlatformAdapter]`` of the
    active profile's live instances; newer multiplex builds additionally use
    ``GatewayRunner._profile_adapters[profile]`` for secondary profiles.
    ``type(adapter)`` is exactly the class that will send. Idempotent and cheap:
    safe to call on every inbound event.
    """
    installed: list[str] = []
    for plat, adapter in _live_adapter_items(gateway, profile):
        try:
            name = str(getattr(plat, "value", plat) or "").lower()
            wrap = _WRAPPERS.get(name)
            if wrap is None or adapter is None:
                continue
            cls = type(adapter)
            send = getattr(cls, "send", None)
            if send is None or getattr(send, "__mordred_wrapped__", False):
                _patched.add(name)
                continue
            wrap(cls)
            _patched.add(name)
            installed.append(name)
            logger.info("mordred_e2e: wrapped %s.%s.send for outbound E2E", cls.__module__, cls.__name__)
        except BaseException:
            # Adapter objects and classes come from third-party plugins. Treat
            # even hostile descriptors/metaclasses as an unwrappable adapter;
            # the inbound gate will then fail closed.
            logger.debug("mordred_e2e: could not wrap a live adapter")
    return installed


def live_adapter_is_wrapped(gateway: Any, platform: str, profile: str | None = None) -> bool:
    """Return whether the live adapter has fail-closed send.

    This is a total security predicate: plugin-owned mappings, iterators,
    descriptors, enum values and metaclasses are all untrusted. Any failure is
    conservatively ``False`` and never escapes into the gateway dispatch path.
    """
    try:
        adapter = live_adapter_for(gateway, platform, profile)
        if adapter is None:
            return False
        send = getattr(type(adapter), "send", None)
        return bool(send is not None and getattr(send, "__mordred_wrapped__", False))
    except BaseException:
        return False


def install_outbound_patches() -> list[str]:
    """Best-effort wrap of statically importable adapters (pre-gateway fallback).

    Kept for builds that DO expose the adapters as ordinary modules. The
    authoritative path is :func:`wrap_live_adapters`, driven from the live
    gateway once its adapters exist.
    """
    import importlib

    installed = []
    for platform, module_path, cls_name, wrap in _TARGETS:
        if platform in _patched:
            continue
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, cls_name, None)
            if cls is None:
                continue
            if getattr(cls.send, "__mordred_wrapped__", False):
                continue
            wrap(cls)
            installed.append(platform)
            logger.debug("mordred_e2e: wrapped %s.%s.send for outbound E2E", module_path, cls_name)
        except Exception as e:
            logger.debug("mordred_e2e: outbound wrap skipped for %s (%s): %s", platform, module_path, e)
    return installed
