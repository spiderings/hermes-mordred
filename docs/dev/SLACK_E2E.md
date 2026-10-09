<a id="hermes--gateway-e2e-&#x6697;&#x53f7;&#x5316;"></a>

# Hermes ⇄ gateway E2E encryption

This document defines how Hermes receives and replies to agent commands when
the Mordred browser extension uses Slack or Discord only as a ciphertext
transport. Gateway agent commands accept `ENC:v3` only. The WebSocket API,
history, and the v1/v2 `K_extchat` helpers are separate protocols and remain
available for compatibility.

> **Migration note:** v3 is an intentional breaking wire change. Deploying this
> gateway before the external Mordred extension implements the v3 AAD and
> direction fields disables both gateway commands and replies for v1/v2
> clients. Update Hermes and the extension together. There is no implicit
> downgrade path for older commands.

## 1. v3 wire

A platform post contains only an allowed leading mention, one v3 token, and
trailing whitespace:

```text
[mention-prefix] 🔒ENC:v3:{kid}:{message_id}:{seq}:{total}:{nonce}:{ciphertext}
```

- `kid`: `base64url(SHA-256(K_chan)[0:6])` (8 characters)
- `message_id`: a random 128-bit value generated before posting (22-character
  base64url), not the platform message ID assigned later by Slack or Discord
- The current profile always uses `seq=0,total=1`.
- `nonce`: a 96-bit AES-GCM nonce
- `ciphertext`: AES-256-GCM ciphertext for the UTF-8 body plus its 16-byte tag
- All base64url values use canonical, unpadded encoding.

When Slack normalizes the Unicode lock emoji to `:lock:`,
`:lock:ENC:v3:…` is accepted as the same canonical alias. A token without the
lock is also accepted for compatibility with existing renderers. An unknown
version, multiple tokens, a plaintext prefix or suffix, non-canonical
encoding, or tampering rejects the entire post.

<a id="2-aad&#x3068;&#x5b9b;&#x5148;&#x675f;&#x7e1b;"></a>

## 2. AAD and destination binding

AES-GCM AAD joins the following fields in order. Each string is encoded as
UTF-8 and framed as `uint32_be(length) || bytes`; the final fields are encoded
as `uint16_be(seq) || uint16_be(total)`.

```text
"mordred-e2e-v3"
direction          # "command" or "reply"
platform.lower()   # "slack" / "discord"
chat_id
thread_root        # None is the empty string
message_id
seq
total
```

Hermes fixes inbound messages to `direction="command"` and replies to
`direction="reply"`, so a reply ciphertext cannot be reflected into an agent
command. Cross-channel and cross-thread replays also fail authentication when
`platform`, `chat_id`, or `thread_root` changes.

For a Discord auto-thread, the new thread ID does not exist when the extension
encrypts the command. Its command AAD therefore uses the canonical
`(parent_chat_id, thread_root=None)` destination. Hermes performs this
conversion only after correlating the Hermes 0.19 `auto_thread_created` marker
with the `raw_message.channel.id` retained by Hermes 0.13 and 0.19. The reply
registry and reply AAD use `(thread_id, thread_id)` after creation. Hermes
rejects the message instead of guessing if the marker, parent, and raw channel
conflict, or if an older event cannot distinguish an auto-thread from an
existing thread.

Slack top-level channel messages have a mirrored issue. For session keying,
the default Slack adapter (`reply_in_thread`) synthesizes the message's own
`ts` as `thread_id` (`thread_ts == ts`). The extension cannot know this
server-assigned value while encrypting, so command AAD uses
`thread_root=None` only when the routed thread root equals the command's own
message ID. A real thread reply arrives with `thread_ts != ts` and is
authenticated against the real root, so replaying a top-level token into an
existing thread still fails. Reply routing continues to use the synthesized
thread.

Keys are never selected from a global `kid` index. Hermes considers only the
`K_chan` registered for the event's `chat_id`, or for an authenticated Discord
thread's `parent_chat_id`, and decrypts only when that key's fingerprint
matches `kid`.

The extension registers a key under its own composite id
(`slack:{team}:{cid}` / `discord:{guild}:{cid}`) while an event carries the
platform's native channel id, so the composite matches when its first segment
is the event's platform and its last segment is exactly the channel id. The
middle `{team}`/`{guild}` segment is additionally required to equal the event's
`SessionSource.scope_id` (`guild_id` is read as the deprecated alias) **when the
event carries one**: a key bound in one workspace then cannot unlock a
same-id channel in another. An absent, blank, or non-string scope keeps the
lenient first-and-last match, because refusing there would recreate the failure
in which no v3 command authenticates at all. Today the shipped Slack adapter
stamps `scope_id` from the event's team id, the shipped Discord adapter stamps
nothing, and the outbound send path has no event, so only Slack inbound is
tightened.

<a id="3-replay&#x9632;&#x6b62;&#x3068;plaintext-release"></a>

## 3. Replay protection and plaintext release

After authentication, domain-separated SHA-256 produces two identities:

- `(kid, message_id)`
- `(kid, nonce)`

Raw IDs and nonces are not stored. The identities are saved atomically in the
private `~/.hermes/extension/state.json` file with a 30-day TTL and a fixed
capacity. Restarting the gateway therefore does not make a command fresh.
Hermes rejects both message-ID reuse and AES-GCM nonce reuse.

The commit order is:

1. Authenticate the wire grammar and AES-GCM payload.
2. Confirm that the target profile's live outbound adapter has a fail-closed
   wrapper.
3. Record `(platform, chat_id, thread_root, kid)` in the reply-in-kind
   registry.
4. Atomically check and store the replay identities.
5. Release plaintext to the agent for the first time.

A valid post that fails step 2 or 3, such as during an adapter outage, does not
consume its replay entry. Replay-store read or write failures are fail-closed.

<a id="4-&#x8fd4;&#x4fe1;"></a>

## 4. Replies

A conversation that supplies an encrypted command is recorded in an in-memory
registry for 24 hours. Reply bodies are encrypted with the same channel key as
v3 tokens using `direction="reply"`. Long replies are split by platform post;
each post is an independent `seq=0,total=1` message with a fresh message ID and
nonce.

Slack and Discord routing mentions may remain as a plaintext prefix, but Slack
channel or subteam display labels and Teams display names are not added to the
agent prompt, and free-form text is removed. If encryption classification,
thread resolution, key lookup, or encryption fails, the wrapper never delegates
to the original plaintext sender. Slack may emit a minimal locked notice, but
never the reply body.

In a multiplexed Hermes gateway, the wrapper, verification, and notice path use
`gateway._profile_adapters[profile]` selected by `event.source.profile`. A
wrapped default-profile adapter is never substituted for an unprotected
secondary-profile adapter on the same platform. The legacy
`gateway.adapters` path remains supported for older Hermes versions.

The 24-hour registry is keyed by `(platform, chat_id, thread_root)` and not by
profile. The send wrapper receives only the adapter instance and the send
arguments, and neither the shipped adapters nor Hermes expose the profile there
— the profile is resolved per source in `build_source` — so a profile-keyed
registry would miss on every reply and fail closed into a locked notice. Two
profiles therefore share a registry entry when their workspaces reuse one
channel id. That case still fails secure: the reply encrypts under the other
profile's `kid`, which the active profile's keyring cannot resolve, so the send
degrades to a locked notice instead of plaintext. The channel-binding rule in
section 5 has no such gap because it reads the key store of whichever
`HERMES_HOME` the gateway scoped in for this profile's turn.

## 5. Mandatory E2E

Hermes never sends an unencrypted Slack or Discord message to the agent. It
attempts to send setup guidance and skips dispatch. Other platforms such as
Teams may still accept plaintext, but any payload claiming the `ENC` wire
format fails closed unless it passes the same v3 validation.

The needs-key notice is rate-limited per conversation (platform × profile ×
channel, 60-second window). The notice is emitted before host authorization;
without a cooldown, any channel member could amplify a message flood into an
equal flood of bot posts. Suppression affects only the notice: every refused
message still receives the `skip` verdict.

### Outbound: channel-key binding

Mandatory E2E is symmetric. **A Slack or Discord channel with a bound `K_chan`
never receives cleartext from Hermes**, whether or not the reply-in-kind
registry holds an entry for the conversation. The send wrapper encrypts when
either condition holds:

1. the conversation carried ciphertext within the 24-hour reply TTL
   (section 4), or
2. the channel has a bound `K_chan` and the platform is in the mandatory set.

Rule 2 exists because rule 1 cannot see agent-initiated traffic. A cron result,
a proactive notification, or any other send with no inbound thread context has
no registry entry to inherit, and on Slack the adapter's synthetic per-message
`thread_ts == ts` also keeps ordinary mentions out of the channel-level
`(channel, None)` bucket, so that fallback is inert in the default
`reply_in_thread` mode. Before rule 2 those sends left in cleartext into a
channel the operator had configured as a ciphertext-only transport. A bound key
means the channel's members can decrypt, and inbound cleartext is already
refused there, so cleartext outbound is never the right answer.

Consequences to know:

- The binding is read from the key store on every classification that rule 1
  does not already satisfy, so a key bound or removed in the extension takes
  effect on the next send with no restart. An unreadable key store fails the
  send closed rather than falling back to plaintext.
- Rule 2 outlasts the 24-hour TTL. Expiry no longer reopens a cleartext path,
  and the reply key is recovered from the binding once the remembered `kid` is
  pruned.
- Rule 2 does not apply to channels with no bound key: those are unchanged.
- Two *different* keys bound to one channel — the store keys entries by the
  extension's full composite id and never evicts, so a re-pairing or workspace
  change leaves the old binding beside the new one — keep rule 2 active but
  refuse to pick a key: the store carries no bound-at timestamp, and an id is
  updated in place, so insertion order records first binding rather than
  recency. The send emits the locked notice and logs the conflict instead of
  encrypting under a possibly stale key that nobody can read. The same key
  pushed under several ids is one binding, not a conflict. Replies are
  unaffected because they use the keyId observed inbound.
- A Discord thread inherits its parent channel's key, but the parent is
  resolved from the live client inside the encrypted send, so a proactive send
  addressed to a bare thread id can still miss rule 2. Replies are unaffected.
- Messages the host itself originates through the adapter (authorization
  notices and similar) are encrypted too when they target a bound channel.

**The needs-key notice is the one exception.** It is Mordred's own fixed setup
guidance, carries no agent or user content, and is addressed to exactly the
person who could not encrypt, so ciphertext would make it unreadable by its only
audience. It is marked as a control notice for the duration of that one send and
bypasses rule 2 only; a conversation already marked encrypted under rule 1 still
receives an encrypted notice, as before. The Slack locked notice is sent by the
encrypted-send path directly and never passes through the wrapper.

> **Live verification required before release.** Rule 2 changes what leaves the
> gateway on a live workspace and the live-gated suites have no CI automation.
> Re-run the Slack round-trip (encrypted command in a bound channel, encrypted
> reply, an agent-initiated send into the same channel decrypting in the
> extension, and a plaintext post still receiving a readable needs-key notice)
> and record the result in `docs/dev/CI.md` §Manual live-device validation log.
>
> **Also verify Slack Connect (externally shared) channels, including a
> `/hermes` slash command.** The two inbound paths derive the team id
> differently: `_event_team_id` reads the inner event's `team_id`/`team` first
> — in a shared channel that is the **posting user's** workspace — while slash
> commands take the installing workspace from the command payload. The gateway
> keeps exact scope binding for normal events and slash commands. It accepts an
> installing-team alternative only for a proven external Slack channel event:
> the raw event's channel and team must match the `SessionSource`, the source
> team must not be an installed team, and the alternative must be one of the
> live adapter's `auth_test`-backed installations. DMs, malformed events,
> uninstalled or stale key scopes, and every non-Slack platform remain
> fail-closed. Record both the external-member round-trip and the installing-
> workspace slash result in `docs/dev/CI.md` §Manual live-device validation log.

**An empty `text` value is also rejected as unencrypted input.** The Slack
adapter strips bot mentions (`text.replace(f"<@{bot_uid}>", "").strip()`) and
stores attachments in `media_urls`, so `@Hermes` plus an image, audio clip, or
mention alone reaches the hook with `text == ""`. An empty value cannot contain
a v3 token. Mandatory platforms therefore skip it and send setup guidance just
like any other plaintext input. Other platforms continue normal dispatch. A
2026-08-02 security review found that this path could otherwise bypass the gate
and leak an agent reply in plaintext.

<a id="6-&#x30c6;&#x30b9;&#x30c8;&#x8981;&#x4ef6;"></a>

## 6. Test requirements

- Canonical v3 with the Unicode lock, no lock, and Slack's `:lock:` alias
- AAD failure after independently changing platform, chat, thread, or direction
- Rejection when a matching key exists only in a different channel
- Rejection of v1/v2 gateway commands, multiple tokens, mixed plaintext, and
  tampering
- Rejection of replayed messages, reused message IDs, and reused nonces across
  simulated restarts with persistent state
- Replay commit occurring only after outbound protection is confirmed
- No confusion between default- and secondary-profile adapters
- No plaintext `orig_send` call when encryption classification raises
- Rejection of empty or missing `text` on mandatory platforms for image/audio
  attachments and mention-only posts, while other platforms still dispatch
  normally
- Encryption of an agent-initiated send with no thread context into a channel
  with a bound key, no change for a channel without one, and encryption that
  survives reply-TTL expiry
- A needs-key notice into a bound channel still delivered in cleartext, with
  the control-notice marker scoped to that send alone: a concurrent task does
  not observe it, a task created inside it does inherit it, and it resets after
  an exception
- Two different keys bound to one channel yielding a locked notice rather than
  a guess, while one key stored under several ids stays unambiguous
- Refusal of a composite key whose scope segment contradicts a known
  `scope_id`, and acceptance when the scope is unknown or the key is stored
  under a bare channel id

## 7. Known gaps

**v3 replay evidence expires after 30 days.** The replay store keeps the
`(kid, message_id)` and `(kid, nonce)` identities of accepted commands for
`pairing._E2E_REPLAY_TTL_SECONDS` (30 days) with a fixed capacity, and the AAD
carries no timestamp or other freshness field. A captured v3 frame therefore
becomes acceptable again once its identities age out, provided its channel key
is still bound and its `(platform, chat_id, thread_root)` destination is
unchanged. The TTL is not arbitrary: unbounded evidence would make the store
grow without limit, and exhausting the capacity refuses every authenticated
command, so the window trades a long replay horizon against availability.

Mitigation today is key lifecycle rather than protocol: rotating the channel key
or re-pairing invalidates every captured frame immediately, because `kid` no
longer resolves and the AAD no longer authenticates. Operators holding a
long-lived channel key should rotate it on the same cadence as any other shared
secret. The planned fix is a freshness field in the v4 AAD (a sender timestamp
bound into the authenticated data and rejected outside a short skew window),
which would let the replay store shrink its TTL to that window instead of
carrying month-old evidence.

**Composite key ids stay lenient without a scope.** See section 2: a Discord
event and every outbound send classify without a workspace id, so their key
binding is platform-and-channel only.

**A chat turn overwrites an undecryptable history blob.** Extension chat
history is stored as one encrypted blob. When the key that wrote it is gone —
after a re-pairing, for example — `history.load_messages()` reports status
`undecryptable` and returns no messages, and the next turn's persistence step
(`chat.py`, `_persist_and_final`) compares that empty list against the turn's
starting history and then calls `save_messages`, replacing the unreadable
ciphertext with the new turn's transcript. The old blob is not recoverable
afterwards.

This is current behaviour and a deliberate product decision: refusing to
persist would wedge the chat for every user whose history is already
unreadable, and the blob is unreadable to Hermes too, so it cannot be merged.
The operational consequence is the part to remember — **restoring a key backup
recovers the old history only if it happens before the next chat turn in that
conversation.** Operators who re-pair and want the previous transcript should
restore the key (or copy the blob aside) first.
