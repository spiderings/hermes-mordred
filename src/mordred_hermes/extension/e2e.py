"""Shared Mordred E2E transport hooks for chat platform adapters.

Slack / Discord / Teams adapters call into this module so each platform acts
as a pure encrypted transport for the Mordred browser extension:

  * inbound gateway commands must use context-bound ``🔒ENC:v3``;
  * replies into a conversation that received an encrypted message are
    re-encrypted with the channel key (reply-in-kind, §4);
  * ``🔑REQ/GRANT`` key-exchange control messages (§5) are peer-to-peer
    between extensions and must be dropped before the agent reacts to them.

The legacy v1/v2 token-replacement helpers remain fail-open for stored history
and non-gateway callers.
The gateway uses :func:`decrypt_gateway_envelope`, which authenticates the
entire wire grammar before releasing any plaintext and fails closed.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Platforms where E2E is mandatory across ALL channels: inbound cleartext is
# refused (gateway_plugin._ENFORCE_ENCRYPTION_PLATFORMS is this same set), so an
# outbound cleartext message into a channel whose key the extension already
# holds is never right either — see :func:`outbound_must_encrypt`.
MANDATORY_ENCRYPTION_PLATFORMS = frozenset({"slack", "discord"})

# A `🔒ENC:v1/v2:…` token anywhere in the text. Extensions keep a leading
# @mention plaintext, so the ciphertext is NOT necessarily at the start; the
# 🔒 may also be dropped by the platform's renderer. v2 first — it's longer.
ENC_TOKEN_RE = re.compile(
    r"🔒?ENC:v2:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+"
    r"|🔒?ENC:v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+"
)

# A claim that a wire message is encrypted, including unsupported/truncated
# forms. The lock emoji can survive the platform render or be stripped. Once a
# message makes this claim, the gateway must parse it as a complete authenticated
# envelope; it must never fall back to treating an invalid claim as plaintext.
ENC_CLAIM_RE = re.compile(r"🔒\ufe0f?ENC|(?<![A-Za-z0-9_])ENC:")

_CANONICAL_V1_TOKEN_RE = re.compile(r"🔒?ENC:v1:(?P<nonce>[A-Za-z0-9_-]+):(?P<ciphertext>[A-Za-z0-9_-]+)")
_CANONICAL_V2_TOKEN_RE = re.compile(
    r"🔒?ENC:v2:(?P<key_id>[A-Za-z0-9_-]{8}):"
    r"(?P<nonce>[A-Za-z0-9_-]+):(?P<ciphertext>[A-Za-z0-9_-]+)"
)
_CANONICAL_V3_TOKEN_RE = re.compile(
    r"(?:(?:🔒|:lock:))?ENC:v3:(?P<key_id>[A-Za-z0-9_-]{8}):"
    r"(?P<message_id>[A-Za-z0-9_-]{22}):(?P<sequence>0|[1-9][0-9]{0,4}):"
    r"(?P<total>[1-9][0-9]{0,4}):(?P<nonce>[A-Za-z0-9_-]+):"
    r"(?P<ciphertext>[A-Za-z0-9_-]+)"
)
_NON_WHITESPACE_RE = re.compile(r"\S+")
_WHITESPACE_RE = re.compile(r"\s+")

# Key-exchange control tokens (SPEC-v2 §5). v1 = X25519-only (legacy),
# v2 = hybrid X25519+ML-KEM-768 (post-quantum).
KEYEXCH_RE = re.compile(r"🔑?(?:REQ|GRANT):v[12]:\S+")

# Leading mention/control tokens kept PLAINTEXT so pings still work, per
# platform wire format:
#   Slack:   <@U123>, <!here>, <!subteam^S1|…>, <#C1|…>
#   Discord: <@123>, <@!123> (nick), <@&456> (role), @everyone/@here
#   Teams:   <at>Name</at> (Graph/Bot Framework mention markup)
SLACK_MENTION_PREFIX_RE = re.compile(
    r"^((?:<@[A-Z0-9]+>|<!(?:here|channel|everyone)>"
    r"|<!subteam\^[A-Z0-9]+(?:\|[^>]*)?>|<#[A-Z0-9]+(?:\|[^>]*)?>|\s)+)"
)
DISCORD_MENTION_PREFIX_RE = re.compile(r"^((?:<@[!&]?\d+>|<#\d+>|@everyone|@here|\s)+)")
TEAMS_MENTION_PREFIX_RE = re.compile(r"^((?:<at>[^<]*</at>|\s)+)", re.IGNORECASE)
_SLACK_FREE_TEXT_LABEL_RE = re.compile(r"(<!(?:subteam)\^[A-Z0-9]+|<#[A-Z0-9]+)\|[^>]*(>)")
_TEAMS_FREE_TEXT_MENTION_RE = re.compile(r"<at>[^<]*</at>", re.IGNORECASE)

_MENTION_PREFIXES = {
    "slack": SLACK_MENTION_PREFIX_RE,
    "discord": DISCORD_MENTION_PREFIX_RE,
    "teams": TEAMS_MENTION_PREFIX_RE,
}


class InvalidEncryptedEnvelope(ValueError):
    """The inbound wire claimed E2E encryption but was not wholly authentic."""


@dataclass(frozen=True, slots=True)
class ReplayClaim:
    """Opaque, authenticated identities committed immediately before release."""

    identities: tuple[str, str]


def is_key_exchange(text: str) -> bool:
    """True when `text` carries a 🔑REQ/GRANT token — drop it before the agent."""
    return bool(text) and KEYEXCH_RE.search(text) is not None


def key_index() -> dict[str, bytes]:
    """keyId → raw key for every key Hermes holds (per-channel + master/v1)."""
    from mordred_hermes.extension.crypto import key_id
    from mordred_hermes.extension.pairing import load_channel_keys, load_pairing

    idx: dict[str, bytes] = {}
    for raw in load_channel_keys().values():
        idx[key_id(raw)] = raw
    p = load_pairing()
    if p is not None:
        idx.setdefault(key_id(p.aes_key), p.aes_key)  # master (v1 legacy)
    return idx


def decrypt_inbound(text: str) -> str | None:
    """Replace EVERY `🔒ENC:v1/v2:` token in `text` with its plaintext,
    selecting the key per token (v2: by keyId from the channel keyring;
    v1: master). Returns None when there is nothing to decrypt. Fail-open;
    a per-token failure leaves that token as-is.
    """
    return decrypt_inbound_keyed(text)[0]


def decrypt_inbound_keyed(text: str) -> tuple[str | None, str | None]:
    """Like :func:`decrypt_inbound`, but also returns the keyId of the key that
    decrypted (the first successful token). Callers store that keyId on the
    conversation so the reply can be re-encrypted with the SAME key regardless
    of how the platform/extension formats channel ids (SPEC-v2)."""
    try:
        if not text or not ENC_TOKEN_RE.search(text):
            return None, None
        from mordred_hermes.extension.crypto import (
            DecryptError,
            decrypt_message,
            key_id,
            parse_token,
        )
        from mordred_hermes.extension.pairing import load_pairing

        pairing = load_pairing()
        if pairing is None:
            return None, None
        by_id = key_index()
        used: dict[str, str | None] = {"kid": None}

        def _sub(m: re.Match[str]) -> str:
            token = m.group(0)
            core = token[1:] if token.startswith("🔒") else token
            full = "🔒" + core
            try:
                ver, kid, _n, _c = parse_token(full)
                key = (by_id.get(kid) if kid is not None else None) if ver == 2 else pairing.aes_key
                if key is None:
                    return token  # missing channel key — leave locked
                out = decrypt_message(key, full)
                if used["kid"] is None:
                    used["kid"] = kid if ver == 2 else key_id(key)
                return out
            except (DecryptError, Exception):
                return token

        return ENC_TOKEN_RE.sub(_sub, text), used["kid"]
    except Exception:
        return None, None


def _gateway_prefix_end(text: str, platform: str) -> int:
    """Return the end of the only plaintext prefix allowed on this platform."""
    prefix_re = _MENTION_PREFIXES.get(platform)
    if prefix_re is not None:
        match = prefix_re.match(text)
        if match is not None:
            return match.end()
    # Unknown platforms may still surround a ciphertext token with whitespace,
    # but do not get to smuggle another platform's mention syntax through.
    match = _WHITESPACE_RE.match(text)
    return match.end() if match is not None else 0


def _normalize_v3_token(token: str) -> str:
    if token.startswith(":lock:"):
        return "🔒" + token[len(":lock:") :]
    return token if token.startswith("🔒") else "🔒" + token


def _canonical_v3_parts(token: str) -> tuple[str, str, int, int, bytes, bytes, str, ReplayClaim]:
    """Parse one exact v3 token, accepting Slack's canonical ``:lock:`` alias."""
    import hashlib

    from mordred_hermes.extension.crypto import b64u_encode, parse_token_v3

    match = _CANONICAL_V3_TOKEN_RE.fullmatch(token)
    if match is None:
        raise InvalidEncryptedEnvelope("legacy_or_malformed_token")
    normalized = _normalize_v3_token(token)
    try:
        kid, message_id, sequence, total, nonce, ciphertext = parse_token_v3(normalized)
    except Exception as exc:
        raise InvalidEncryptedEnvelope("malformed_token") from exc
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise InvalidEncryptedEnvelope("malformed_token")
    if (
        b64u_encode(nonce) != match.group("nonce")
        or b64u_encode(ciphertext) != match.group("ciphertext")
        or kid != match.group("key_id")
        or message_id != match.group("message_id")
        or str(sequence) != match.group("sequence")
        or str(total) != match.group("total")
    ):
        raise InvalidEncryptedEnvelope("noncanonical_token")
    # One platform message is one authenticated command. Keeping sequence and
    # total in v3 makes a future assembly protocol explicit without accepting
    # today's spliceable multi-token grammar.
    if sequence != 0 or total != 1:
        raise InvalidEncryptedEnvelope("multi_token_not_supported")
    message_identity = hashlib.sha256(
        b"mordred-e2e-v3-message\0" + kid.encode("ascii") + b"\0" + message_id.encode("ascii")
    ).hexdigest()
    nonce_identity = hashlib.sha256(b"mordred-e2e-v3-nonce\0" + kid.encode("ascii") + b"\0" + nonce).hexdigest()
    return (
        kid,
        message_id,
        sequence,
        total,
        nonce,
        ciphertext,
        normalized,
        ReplayClaim((message_identity, nonce_identity)),
    )


def _channel_key_matches(
    stored_id: str,
    *,
    platform: str,
    chat_id: str,
    scope_id: str | None = None,
    slack_connect_host_scope_ids: frozenset[str] | None = None,
) -> bool:
    """Does a stored channel-key id name exactly ``chat_id`` on ``platform``?

    The extension pushes ``channel_key_set`` keyed by its own composite id
    (``slack:{team}:{cid}`` / ``discord:{guild}:{cid}``), which
    :func:`pairing.save_channel_key` stores verbatim, while a gateway event
    only ever carries the platform's native ``chat_id``. Matching the exact
    string alone therefore never resolves a real install's keys, and every v3
    command fails ``key_not_bound_to_channel``.

    The composite is accepted only when its LAST segment is the channel id and
    its FIRST segment is this event's platform, so the binding stays as tight
    as an exact match: a key stored for another platform that happens to share
    a channel id cannot unlock this one, and no bare suffix match is allowed.

    ``scope_id`` is the workspace/guild the event actually arrived from
    (``SessionSource.scope_id``: the Slack team id, the Discord guild id). When
    the caller knows it, the composite's MIDDLE segment must equal it, so a key
    bound in one workspace cannot unlock a same-id channel in another. The
    middle segment is only *ignored* when the caller cannot know the scope:
    the shipped Discord adapter never stamps ``scope_id``/``guild_id`` on the
    source, some Slack event shapes carry no team id, and the outbound send
    wrapper has no event at all. Refusing those would resurrect the #83 outage
    (every v3 command failing ``key_not_bound_to_channel``), so an unknown
    scope keeps the lenient first/last-segment match.

    A Slack Connect event from an external member carries that member's team
    as ``scope_id`` even though the extension key is normally stored under the
    bot's installing team. ``slack_connect_host_scope_ids`` is the gateway's
    independently authenticated set of installing Slack teams for that exact
    external event. Only those scopes are accepted as alternates; callers may
    not use it to disable scope binding generally, and it has no effect on
    non-Slack platforms.
    """
    if stored_id == chat_id:
        return True
    segments = stored_id.split(":")
    if len(segments) < 2 or segments[0].lower() != platform or segments[-1] != chat_id:
        return False
    if scope_id and len(segments) > 2:
        stored_scope = ":".join(segments[1:-1])
        return stored_scope == scope_id or (
            platform == "slack"
            and slack_connect_host_scope_ids is not None
            and stored_scope in slack_connect_host_scope_ids
        )
    return True


def _context_channel_key(
    kid: str,
    *,
    platform: str,
    chat_id: str,
    parent_chat_id: str | None,
    scope_id: str | None = None,
    slack_connect_host_scope_ids: frozenset[str] | None = None,
) -> bytes:
    """Resolve a key only from the authenticated event's channel context."""
    from mordred_hermes.extension.crypto import key_id
    from mordred_hermes.extension.pairing import load_channel_keys

    channel_keys = load_channel_keys()
    candidates = [chat_id]
    if parent_chat_id and parent_chat_id not in candidates:
        candidates.append(parent_chat_id)
    for channel_id in candidates:
        for stored_id, raw_key in channel_keys.items():
            if not _channel_key_matches(
                stored_id,
                platform=platform,
                chat_id=channel_id,
                scope_id=scope_id,
                slack_connect_host_scope_ids=slack_connect_host_scope_ids,
            ):
                continue
            if key_id(raw_key) == kid:
                return raw_key
    raise InvalidEncryptedEnvelope("key_not_bound_to_channel")


def _decrypt_gateway_claim(
    text: str,
    platform: str,
    *,
    chat_id: str,
    thread_root: str | None,
    parent_chat_id: str | None,
    scope_id: str | None = None,
    slack_connect_host_scope_ids: frozenset[str] | None = None,
) -> tuple[str, str, ReplayClaim]:
    """Parse and authenticate one context-bound v3 platform message."""
    from mordred_hermes.extension.crypto import DecryptError, decrypt_message_v3

    prefix_end = _gateway_prefix_end(text, platform)
    # Mentions are unauthenticated transport routing metadata. In particular,
    # Slack channel/subteam labels and Teams display names contain free text;
    # accepting their syntax must not release that text into the agent prompt.
    position = prefix_end
    whitespace = _WHITESPACE_RE.match(text, position)
    if whitespace is not None:
        position = whitespace.end()
    token_match = _NON_WHITESPACE_RE.match(text, position)
    if token_match is None:
        raise InvalidEncryptedEnvelope("missing_token")
    token = token_match.group(0)
    position = token_match.end()
    if text[position:].strip():
        raise InvalidEncryptedEnvelope("mixed_or_multiple_content")

    kid, _message_id, _sequence, _total, _nonce, _ciphertext, normalized, replay = _canonical_v3_parts(token)
    raw_key = _context_channel_key(
        kid,
        platform=platform,
        chat_id=chat_id,
        parent_chat_id=parent_chat_id,
        scope_id=scope_id,
        slack_connect_host_scope_ids=slack_connect_host_scope_ids,
    )
    try:
        plaintext = decrypt_message_v3(
            raw_key,
            normalized,
            direction="command",
            platform=platform,
            chat_id=chat_id,
            thread_root=thread_root,
        )
    except (DecryptError, UnicodeError, ValueError) as exc:
        raise InvalidEncryptedEnvelope("authentication_failed") from exc
    return plaintext, kid, replay


def decrypt_gateway_envelope(
    text: str,
    platform: str,
    *,
    chat_id: str,
    thread_root: str | None,
    parent_chat_id: str | None = None,
    scope_id: str | None = None,
    slack_connect_host_scope_ids: frozenset[str] | None = None,
) -> tuple[str | None, str | None, ReplayClaim | None]:
    """Authenticate and decrypt a complete gateway wire envelope.

    The accepted grammar is::

        [platform mention prefix] one context-bound ENC:v3 token [whitespace]

    The prefix may contain only the existing Slack/Discord/Teams mention
    syntax for ``platform`` and whitespace. It is accepted as transport routing
    metadata but discarded rather than released into the agent prompt.
    Legacy v1/v2 gateway commands are rejected; their helpers remain available
    only for stored/history compatibility. The returned replay claim must be
    committed after outbound reply-path verification and immediately before
    plaintext release. ``(None, None, None)`` means no encrypted claim.

    ``scope_id`` is the event's workspace/guild id when the caller knows it;
    it tightens composite channel-key binding (see :func:`_channel_key_matches`).
    ``slack_connect_host_scope_ids`` permits only authenticated installing-team
    alternatives for a proven external Slack Connect event.
    """
    if not text or ENC_CLAIM_RE.search(text) is None:
        return None, None, None

    try:
        if not platform or not chat_id:
            raise InvalidEncryptedEnvelope("missing_context")
        return _decrypt_gateway_claim(
            text,
            platform.lower(),
            chat_id=chat_id,
            thread_root=thread_root,
            parent_chat_id=parent_chat_id,
            scope_id=scope_id,
            slack_connect_host_scope_ids=slack_connect_host_scope_ids,
        )
    except InvalidEncryptedEnvelope:
        raise
    except Exception as exc:
        # Pairing/keyring I/O and parser drift are security failures here, not
        # invitations to hand the claimed ciphertext wire to the agent.
        raise InvalidEncryptedEnvelope("internal_error") from exc


def claim_gateway_replay(replay: ReplayClaim) -> bool:
    """Persist an authenticated replay claim atomically across restarts."""
    from mordred_hermes.extension.pairing import claim_e2e_replay_identities

    return claim_e2e_replay_identities(replay.identities)


# Conversations that received an encrypted message → reply-in-kind. Value is
# (expiry, key_id) so replies re-encrypt with exactly the inbound key. Keyed by
# (platform, channel_id, thread_root) so ids never collide across platforms.
#
# NOT keyed by multiplex profile, deliberately. The mark is written from the
# inbound hook (which knows ``event.source.profile``) but read from the adapter
# ``send`` wrapper, which receives only ``(self, chat_id, content, …)`` — the
# shipped adapters expose no profile attribute, and the profile is resolved
# per-source at ``build_source`` time, so a profile-keyed registry would miss on
# every reply and fail closed into a locked notice. The residual risk is two
# profiles whose workspaces reuse one channel id: Slack channel ids and Discord
# snowflakes are platform-wide identifiers, so a collision needs the same id in
# two workspaces. Its failure mode is fail-secure anyway — the reply encrypts
# under the other profile's kid, which ``reply_key`` cannot resolve against the
# active profile's ``HERMES_HOME`` keyring, so it degrades to a locked notice
# rather than plaintext. The channel-binding rule below has no such gap: it
# reads the key store of whatever ``HERMES_HOME`` the gateway has scoped in for
# this profile's turn.
_ENC_THREADS: dict[tuple[str, str, str | None], tuple[float, str | None]] = {}
_ENC_TTL = 24 * 3600  # seconds

# Set while Mordred itself sends a control notice (the needs-key setup guidance)
# through a wrapped adapter. See :func:`control_notice_send`.
_CONTROL_NOTICE: contextvars.ContextVar[bool] = contextvars.ContextVar("mordred_e2e_control_notice", default=False)


@contextlib.contextmanager
def control_notice_send() -> Iterator[None]:
    """Mark the enclosed adapter ``send`` as a Mordred control notice.

    The needs-key notice is Mordred's own fixed setup guidance, carries no
    agent or user content, and is addressed to exactly the person who could not
    encrypt — so it is the one message that must still reach a key-bound
    channel in cleartext. Everything else routed into such a channel is agent
    output and must be ciphertext (:func:`outbound_must_encrypt`).

    Scoped through a ``ContextVar`` rather than a ``send`` argument because the
    wrapper has to stay signature-compatible with the host's adapter API; a
    task-local flag also cannot leak into a concurrent send.

    One leak vector to know about: ``asyncio`` copies the current context when
    a task is CREATED, so a task spawned *inside* this block inherits the
    bypass for its whole lifetime. Not reachable today — the shipped adapters
    ``await`` their send inline, and Mordred enters the marker inside
    ``gateway_plugin._safe_send`` itself — but an adapter that hands the notice
    to a background task would carry the bypass into whatever else that task
    sends. Keep the marker around the single ``await`` that delivers the
    notice, never around adapter setup or fan-out.
    """
    token = _CONTROL_NOTICE.set(True)
    try:
        yield
    finally:
        _CONTROL_NOTICE.reset(token)


def in_control_notice() -> bool:
    """Is the current task inside a :func:`control_notice_send` block?"""
    return _CONTROL_NOTICE.get()


def mark_encrypted_thread(
    platform: str,
    channel_id: str,
    thread_root: str | None,
    key_id: str | None = None,
) -> bool:
    """Record reply-in-kind context, returning whether it was stored."""
    if not channel_id:
        return False
    _ENC_THREADS[(platform, channel_id, thread_root)] = (time.time() + _ENC_TTL, key_id)
    return True


def _prune(now: float) -> None:
    for k, (exp, _kid) in list(_ENC_THREADS.items()):
        if exp < now:
            _ENC_THREADS.pop(k, None)


def is_encrypted_thread(platform: str, channel_id: str, thread_root: str | None) -> bool:
    """Is this conversation known-encrypted? Falls back to the channel-level mark.

    The fallback must apply even when ``thread_root`` is set: a user who
    @-mentions the agent at channel top level is recorded under
    ``thread_root=None`` (the inbound event has no thread), but the agent
    answers *in a thread* rooted at that mention, so the outbound lookup carries
    a thread_ts. Without the fallback the reply is judged unencrypted and goes
    out in CLEARTEXT. Mirrors :func:`thread_key_id`, which already scans
    ``(thread_root, None)`` — the two must agree or the reply path leaks.

    On Slack that ``(channel, None)`` bucket is nearly always empty: the shipped
    adapter's ``reply_in_thread`` session keying stamps a synthetic per-message
    ``thread_ts == ts`` on top-level messages, so the inbound mark lands under a
    thread root even for a channel-level mention. This predicate therefore only
    covers conversations Mordred has actually *seen* ciphertext in, within the
    24h TTL; it is not the outbound policy. Send-path callers must use
    :func:`outbound_must_encrypt`.
    """
    now = time.time()
    _prune(now)
    return any(_ENC_THREADS.get((platform, channel_id, tr), (0, None))[0] > now for tr in (thread_root, None))


def thread_key_id(platform: str, channel_id: str, thread_root: str | None) -> str | None:
    """The keyId last seen encrypting this conversation, if still fresh."""
    now = time.time()
    _prune(now)
    for tr in (thread_root, None):
        exp, kid = _ENC_THREADS.get((platform, channel_id, tr), (0, None))
        if exp > now and kid:
            return kid
    return None


def bound_channel_key_ids(platform: str, channel_id: str) -> list[str]:
    """Every DISTINCT keyId bound to this channel, in key-store order.

    Answers "can the people in this channel decrypt?" from the persisted
    keyring alone, so it survives a gateway restart, the 24h reply TTL, and
    Slack's synthetic thread roots — unlike the in-memory thread bookkeeping.

    More than one entry can name one channel. ``pairing.save_channel_key``
    keys the store by the extension's full composite id and never evicts, so a
    re-pairing or a workspace change leaves both ``slack:{old}:{cid}`` and
    ``slack:{new}:{cid}`` bound to ``cid``. Deduplicating by keyId means the
    same key pushed under two ids is *not* ambiguity; two different keys are.

    Store failures propagate. An unreadable keyring already fails every inbound
    command closed (``internal_error``); resolving it to "no key bound" here
    would instead let the same failure re-open the cleartext send path.
    """
    from mordred_hermes.extension.crypto import key_id
    from mordred_hermes.extension.pairing import load_channel_keys

    if not platform or not channel_id:
        return []
    found: list[str] = []
    for stored_id, raw_key in load_channel_keys().items():
        # No scope id is available on the send path (no event, no adapter
        # profile), so this is the lenient platform+channel match documented in
        # _channel_key_matches.
        if not _channel_key_matches(stored_id, platform=platform, chat_id=str(channel_id)):
            continue
        kid = key_id(raw_key)
        if kid not in found:
            found.append(kid)
    return found


def bound_channel_key_id(platform: str, channel_id: str) -> str | None:
    """The one keyId to encrypt a channel-bound message with, or ``None``.

    ``None`` means "do not guess", NOT "not encrypted" — the caller has already
    decided the message must be encrypted (:func:`outbound_must_encrypt` asks
    :func:`bound_channel_key_ids` whether *any* key is bound), so ``None``
    lands on the visible locked-notice path rather than on cleartext.

    Ambiguity fails closed because the store carries no recency signal to break
    the tie. ``save_channel_key`` writes a plain ``{id: key}`` mapping with no
    bound-at timestamp, and it updates an existing id *in place*, so JSON
    insertion order records when an id was FIRST bound, not when it was last
    refreshed — "first match" would therefore reliably pick the STALE key after
    a re-pairing. Encrypting under a key nobody holds is the failure
    :func:`reply_key` calls strictly worse than refusing: ``reply_key`` still
    resolves it, so the send reports success while the channel sees
    permanently unreadable ciphertext. A locked notice instead tells the
    operator to clear the stale binding.

    Live conversations are unaffected: :func:`outbound_key_id` prefers the
    keyId actually observed inbound, so only a channel-bound send with no
    reply-in-kind context can reach the ambiguous case. A caller that knows the
    event's workspace can disambiguate before this point by filtering with
    ``_channel_key_matches(..., scope_id=...)``; no send-path caller does.
    """
    kids = bound_channel_key_ids(platform, channel_id)
    if len(kids) != 1:
        if kids:
            logger.warning(
                "mordred_e2e: %s channel has %d different bound keys; refusing to guess which is current",
                platform,
                len(kids),
            )
        return None
    return kids[0]


def outbound_must_encrypt(platform: str, channel_id: str, thread_root: str | None) -> bool:
    """Must an outbound message into this conversation be encrypted?

    Two independent reasons, checked cheapest first:

    1. Mordred saw ciphertext in this conversation within the reply TTL
       (:func:`is_encrypted_thread`) — reply-in-kind, §4.
    2. The channel has a bound ``K_chan`` on a platform where E2E is mandatory.

    Rule 2 is what makes agent-initiated traffic safe. A cron result, a
    proactive notification or any other send that carries no inbound thread
    context has no reply-in-kind mark to find, so before this rule it left in
    CLEARTEXT into a channel the operator had configured as a ciphertext-only
    transport. A bound key means the recipients can decrypt, and inbound
    cleartext is already refused there, so cleartext outbound is never right.

    The single exception is Mordred's own needs-key notice
    (:func:`control_notice_send`), which must stay readable by the sender who
    could not encrypt. It is a fixed string with no agent or user content.

    Rule 2 asks whether ANY key is bound, deliberately not which one: a channel
    with two conflicting bindings is still a ciphertext-only channel, and it is
    :func:`bound_channel_key_id` that then refuses to guess between them, so the
    ambiguity surfaces as a locked notice instead of as cleartext.
    """
    if is_encrypted_thread(platform, channel_id, thread_root):
        return True
    if platform not in MANDATORY_ENCRYPTION_PLATFORMS or in_control_notice():
        return False
    return bool(bound_channel_key_ids(platform, channel_id))


def outbound_key_id(platform: str, channel_id: str, thread_root: str | None) -> str | None:
    """keyId to encrypt an outbound message with: the remembered inbound key
    first (reply-in-kind uses exactly the key the sender used), else the key
    bound to the channel.

    Unlike :func:`outbound_must_encrypt` this swallows keyring failures: the
    caller has already decided the message must be encrypted, and "no usable
    key" is the designed, visible outcome (a locked notice) rather than a
    crashing send. Conflicting channel bindings resolve to ``None`` the same
    way (:func:`bound_channel_key_id`), but only when the conversation has no
    remembered inbound keyId to prefer.
    """
    kid = thread_key_id(platform, channel_id, thread_root)
    if kid:
        return kid
    try:
        return bound_channel_key_id(platform, channel_id)
    except Exception:
        return None


def reply_key(key_id_hint: str | None) -> bytes | None:
    """Raw key to encrypt a reply with: the remembered inbound key, by keyId.
    Id-format-agnostic — no channel-id matching needed.

    Fail-closed: when the hint is missing or unknown this returns ``None``
    instead of falling back to the master/pairing key. The master is NOT a
    channel key any extension holds, so encrypting a reply with it emits
    ciphertext nobody in the channel can read — strictly worse than refusing,
    because the failure is silent (it looks encrypted). Callers turn ``None``
    into a visible "could not encrypt" notice.

    v1/legacy conversations are unaffected: their remembered keyId IS the
    master's, and ``key_index()`` contains the master, so the lookup still hits.
    """
    try:
        if not key_id_hint:
            return None
        return key_index().get(key_id_hint)
    except Exception:
        return None


def channel_key(channel_id: str) -> bytes | None:
    """The K_chan for a channel (SPEC-v2), falling back to the master key for
    channels that only have a v1/legacy key. Retained for callers that key by a
    native channel id; the reply path prefers reply_key(keyId)."""
    try:
        from mordred_hermes.extension.pairing import load_channel_keys, load_pairing

        ck = load_channel_keys().get(channel_id)
        if ck is not None:
            return ck
        p = load_pairing()
        return p.aes_key if p is not None else None
    except Exception:
        return None


def _unpadded_b64_length(raw_length: int) -> int:
    """Return the exact unpadded base64url length for ``raw_length`` bytes."""
    return (4 * raw_length + 2) // 3


def _v3_plaintext_budget(max_len: int, prefix: str = "") -> int:
    """Maximum UTF-8 plaintext bytes whose complete v3 wire fits ``max_len``."""
    from mordred_hermes.extension.crypto import ENC_PREFIX_V3

    # Key id (8), message id (22), sequence/total (one digit each), nonce
    # (12 bytes -> 16 base64url chars), their separators, and an optional
    # plaintext routing prefix. AES-GCM adds a 16-byte tag to the plaintext.
    fixed = len(prefix) + (1 if prefix else 0) + len(ENC_PREFIX_V3) + 8 + 1 + 22 + 1 + 1 + 1 + 1 + 1 + 16 + 1
    if fixed + _unpadded_b64_length(16) > max_len:
        return -1

    low, high = 0, max_len
    while low < high:
        candidate = (low + high + 1) // 2
        wire_length = fixed + _unpadded_b64_length(candidate + 16)
        if wire_length <= max_len:
            low = candidate
        else:
            high = candidate - 1
    return low


def _split_utf8(body: str, first_budget: int, later_budget: int) -> list[str]:
    """Split at Unicode boundaries without exceeding per-chunk byte budgets."""
    if first_budget < 0 or later_budget < 0:
        raise ValueError("platform message limit is too small for an encrypted reply")
    if not body:
        return [""]

    pieces: list[str] = []
    current: list[str] = []
    used = 0
    budget = first_budget
    for character in body:
        size = len(character.encode("utf-8"))
        if used + size > budget:
            # A long plaintext mention prefix can leave no room for the first
            # body character. Emit an authenticated empty first message, then
            # continue with the normal no-prefix budget.
            pieces.append("".join(current))
            current = []
            used = 0
            budget = later_budget
        if size > budget:
            raise ValueError("platform message limit cannot fit one encrypted character")
        current.append(character)
        used += size
    if current:
        pieces.append("".join(current))
    return pieces


def encrypt_reply(
    raw_key: bytes,
    content: str,
    max_len: int,
    mention_prefix_re: re.Pattern[str] | None = None,
    *,
    platform: str,
    chat_id: str,
    thread_root: str | None,
) -> list[str]:
    """Encrypt reply platform messages as context-bound v3 tokens.

    Slack channel/subteam display labels and Teams mention display names are
    free text, not authenticated routing identifiers, so they are normalized
    away. Even an empty/all-mention reply carries an authenticated empty token;
    a known-encrypted send never degrades to a wholly plaintext chunk.
    """
    from mordred_hermes.extension.crypto import encrypt_message_v3, key_id

    kid = key_id(raw_key)
    m = mention_prefix_re.match(content) if mention_prefix_re else None
    prefix = m.group(1).strip() if m else ""
    prefix = _SLACK_FREE_TEXT_LABEL_RE.sub(r"\1\2", prefix)
    prefix = _TEAMS_FREE_TEXT_MENTION_RE.sub("", prefix).strip()
    body = content[m.end() :] if m else content
    first_budget = _v3_plaintext_budget(max_len, prefix)
    later_budget = _v3_plaintext_budget(max_len)
    pieces = _split_utf8(body, first_budget, later_budget)
    out: list[str] = []
    for i, piece in enumerate(pieces):
        enc = encrypt_message_v3(
            raw_key,
            piece,
            kid,
            direction="reply",
            platform=platform,
            chat_id=chat_id,
            thread_root=thread_root,
        )
        wire = f"{prefix} {enc}" if (i == 0 and prefix) else enc
        if len(wire) > max_len:  # Defensive assertion against wire-format drift.
            raise ValueError("encrypted reply exceeds the platform message limit")
        out.append(wire)
    return out
