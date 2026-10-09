# Mordred — Policy Schema Reference

This document owns policy input, decision matrices, and the human-readable
audit vocabulary. Typed implementation remains authoritative:

- policy/network closed sets: `src/mordred_hermes/_policy_types.py`;
- audit reasons: `privacy_check/_audit_reasons.py::ReasonCode`;
- install/tool decisions: `privacy_check/policy.py`;
- LLM decisions: `llm_guard/enforce.py`; and
- consumed Hermes fields: `tools/hook_payload_contract.json`.

## Audit log `reason` enum (frozen)

`ReasonCode` is a closed `Literal` with 31 stable values. “Reserved” means the
string remains valid for compatibility but current code deliberately has no
emit site. A reserved value is not evidence that the feature exists.

| # | Code | Status | Current meaning |
|---:|---|---|---|
| 1 | `policy.strict.clearnet` | live | Strict install/runtime policy refused a clearnet requirement or blocked tool on clearnet. |
| 2 | `policy.strict.unknown_metadata` | live | Strict install policy rejected missing network metadata. |
| 3 | `policy.strict.unconditional_override` | live, legacy name | Active provider was unresolved under strict policy. Current action is block/refuse; no provider is overridden. |
| 4 | `policy.strict.cloud_not_allowlisted` | live | Classification emitted before strict cloud refusal. |
| 5 | `policy.strict.cloud_allowlisted` | live | Strict local or cloud provider passed the applicable identity/endpoint checks. |
| 6 | `policy.strict.cloud_endpoint_mismatch` | live | Runtime cloud endpoint is absent, unsafe, or not owned/pinned for the provider. |
| 7 | `policy.strict.cloud_prompted_allow` | live | Interactive `prompt-once` granted the provider for this process. |
| 8 | `policy.strict.cloud_prompted_deny` | live | Operator denied, or no interactive terminal was available. |
| 9 | `policy.lenient.unknown_metadata_warning` | live | Missing skill metadata warned but install continued. |
| 10 | `mordred.degraded.disable_unprotected` | live | One or more required Mordred sibling plugins are disabled. |
| 11 | `mordred.degraded.no_origin_skill` | live | Hermes supplies no trusted skill origin to `pre_tool_call`. |
| 12 | `mordred.degraded.no_resolved_provider` | live | Disk/session provider identity could not be resolved. |
| 13 | `policy.strict.local_stream_interrupted` | reserved | No plugin-side streaming seam exists; current code cannot emit this reliably. |
| 14 | `policy.strict.session_refused` | live | Action record for a strict LLM/session refusal. |
| 15 | `policy.strict.provider_override_at_session_start` | reserved | Automatic provider replacement is not implemented. |
| 16 | `network.use` | live | Initial/unfrozen route activation succeeded. |
| 17 | `network.use_failed` | live | Route activation raised a Mordred network error. |
| 18 | `network.bringup_failed` | live | Route bring-up failed; strict raises, non-strict may record clearnet fallback. |
| 19 | `network.path_dropped` | live | Repeated health failures marked the active route dropped. |
| 20 | `network.transport_incompatible` | live | Provider/transport evidence cannot honor the selected protected route. |
| 21 | `keyvault.recovery_digest_mismatch` | live | Backup verification failed before secret decryption. |
| 22 | `keyvault.seed_display_aborted_screenshot` | live | Seed display aborted after the macOS capture detector fired. |
| 23 | `keyvault.unwrap_authorized` | live | Native private-key unwrap completed after its authorization policy. |
| 24 | `keyvault.unwrap_denied` | live | Native private-key authorization was denied/cancelled. |
| 25 | `keyvault.init_started` | live | Durable key initialization began before mutation. |
| 26 | `keyvault.init_completed` | live | Key initialization and digest commitment completed. |
| 27 | `keyvault.init_denied` | live | Initialization digest confirmation failed before mutation. |
| 28 | `keyvault.backup_exported` | live API/CLI event | `keyvault.api.export_backup()` returned a blob, including when invoked by `keyvault export`. |
| 29 | `policy.strict.keyvault_uninitialized` | live | Strict install rejected a skill requiring an initialized keyvault. |
| 30 | `policy.lenient.keyvault_uninitialized_warning` | live | Same condition warned under lenient policy. |
| 31 | `mordred.degraded.audit_encryption_unavailable` | live | Encrypted audit was expected but writer creation fell back to plaintext. |
| 32 | `policy.egress.tool_blocked` | live | The tool-egress level blocked a tool call that could reach the internet; the entry's `rule` field names the rule (e.g. `egress.url_fetch`, `egress.tainted_session`). |

Existing reason strings are not renamed. Adding one requires the typed Literal,
an emit site or explicit reserved rationale, focused tests, and this table in
the same change.

Strict LLM behavior is refusal-based. The primary request is checked at
`pre_api_request` using the resolved provider and actual `base_url`; auxiliary
Hermes clients are guarded at their separate construction seams. Mordred does
not redirect a resolved cloud client through `pre_llm_call`.

For `mordred-local`, strict mode permits only HTTP(S) endpoints at exact
`127.0.0.1`, `::1`, or `localhost` whose current DNS answers are all loopback.
Userinfo, query, fragment, non-loopback hosts, and a runtime URL differing from
the policy pin are refused before probing or egress.

For cloud providers, an allowlist entry is necessary but not sufficient. The
runtime endpoint must be HTTPS, contain no userinfo/query/fragment, and match
the provider-owned or explicitly supported endpoint shape. Audit output keeps
only a bounded origin; it never echoes arbitrary URL paths or credentials.

### Phase 3 step-0 freeze (added 2026-05-13, PR1)

Historical anchor. The live Phase 3 reasons are `network.use`,
`network.use_failed`, `network.bringup_failed`, `network.path_dropped`, and the
later `network.transport_incompatible`. Dotted names are canonical.

### Phase 4 step-0 freeze (added 2026-05-14, PR2)

Historical anchor. Recovery-digest mismatch is emitted before decryption, and
seed-display capture abort is emitted before initialization continues.

### Phase 4 PR3 step-0 freeze (added 2026-05-14, PR3)

Historical anchor. Public-key wrapping does not cross a user-authorization
boundary; native private-key unwrap emits the authorized/denied pair.

### Phase 4 PR4 step-0 freeze (added 2026-05-15, PR4)

Historical anchor. Initialization emits started/completed/denied, and the
internal backup API emits `keyvault.backup_exported` after materializing the
blob in memory. At that phase file persistence was the caller's responsibility.
The current wizard publishes the returned bytes through `keyvault export`; it
does not add a second audit reason or expose recovery material in audit fields.

### Phase 4 §4.1 freeze (added 2026-05-16)

The install wrapper enforces `requires_keyvault: true` using a backend-free
metadata probe: strict blocks, lenient warns, off allows.

### PR #39 review follow-up freeze (added 2026-05-17)

`mordred.degraded.audit_encryption_unavailable` marks the expected-encrypted →
plaintext downgrade. A profile that never initialized a keyvault is the
plaintext baseline and does not emit this downgrade.

### prompt-once freeze (added 2026-06-24)

`prompt-once` asks at most once per normalized provider/route in an interactive
process. An explicit allow or deny is cached. Lack of a TTY fails closed and is
not cached, so a later interactive request may still prompt.

### Network transport-gate freeze (added 2026-07-27)

The route is selected and frozen before provider-client construction.
Incompatible or unresolved transport evidence is blocking under strict
protected routes and diagnostic under non-strict policy. A refusal does not
tear down the shared Tor/VPN route and expose another session to clearnet.

### Strict cloud endpoint-binding freeze (added 2026-07-30)

Provider identity is bound to the actual request endpoint before
`prompt-once`; a prompt cannot approve an arbitrary `base_url` override.

### Audit entry shape

Synthetic example:

```json
{"ts":"2026-04-29T12:34:56.789Z","event":"pre_install","decision":"block","reason":"policy.strict.clearnet","skill_id":"clearnet-skill"}
```

| Field | Contract |
|---|---|
| `ts` | ISO-8601 UTC with millisecond precision and `Z`. Added by the writer when absent. |
| `event` | Hook or lifecycle identifier. |
| `decision` | Current writers use `allow`, `block`, `override`, `warn`, `raise`, or `fallback`. |
| `reason` | A `ReasonCode`, or `null` for decisions that have no reason. |
| event fields | Bounded identifiers/status only; never secret values or raw untrusted content. |

## SKILL.md `metadata.mordred.*` extension

Mordred reads:

| Field | Type | Default/current use |
|---|---|---|
| `metadata.mordred.network_requirements` | `tor | vpn | clearnet | local-only` | absent/unknown; enforced at install |
| `metadata.mordred.requires_keyvault` | boolean | `false`; enforced at install |
| `metadata.mordred.outbound_endpoints` | list of strings | empty; parsed but not an enforcement grant |

Only `hermes-mordred install` applies these fields before Hermes installs the
skill. Hermes's ordinary installer does not pass through this wrapper, and the
runtime hook has no `origin_skill` provenance.

### agentskills.io deviation

Mordred uses a nested vendor object and non-string values, while the portable
agentskills.io metadata model is flatter and more restrictive. Pure spec
consumers may treat the block as opaque or reject it. This is accepted only for
the Mordred wrapper; do not imply universal registry compatibility.

## `plugins.mordred_privacy_check` config schema

The canonical editable input is `<home>/config.yaml`:

| Key | Type | Default | Notes |
|---|---|---|---|
| `policy` | `strict | lenient | off` | `lenient` | Invalid persisted values are treated conservatively by each boundary. |
| `allow_cloud_llm` | boolean | `false` | Under strict, still requires an allowlisted provider and valid endpoint. |
| `cloud_provider_allowlist` | list of strings | `[]` | Provider identities, not arbitrary URLs. |
| `audit_log_path` | string | `<home>/mordred/audit.log` | Must resolve within the active Hermes home. |

`plugins.mordred_llm_guard.harness_primary` holds the declared harness. The
wizard also emits the cross-plugin `policy.json` fields documented in
[`PATHS.md`](./PATHS.md) §Schema sketch (Phase 1).

## Decision matrix (Phase 1)

### Install-time (`hermes-mordred install <skill>`)

Network decision first:

| Mode | `network_requirements` | Result | Reason |
|---|---|---|---|
| off | any | allow | `null` |
| strict | absent | block | `policy.strict.unknown_metadata` |
| strict | clearnet | block | `policy.strict.clearnet` |
| strict | tor/vpn/local-only | allow | `null` |
| lenient | absent | warn and continue | `policy.lenient.unknown_metadata_warning` |
| lenient | declared | allow | `null` |

If that did not already block and the skill declares `requires_keyvault: true`
while no key is initialized: strict blocks with
`policy.strict.keyvault_uninitialized`, lenient warns with
`policy.lenient.keyvault_uninitialized_warning`, and off allows.

### Runtime (`pre_tool_call`)

Hermes provides only `tool_name`. Under strict, an absent route is treated as
clearnet and the default `{web_fetch, web_search}` blocklist is refused on
clearnet. Tor/VPN allows it; lenient/off allow it. This generic tool guard is
not per-skill containment and cannot stop direct sockets from skill code.

## `policy.json` Phase 3 fields (Task #2 / #7)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `disable_ipv6` | boolean | strict `true`, otherwise `false` | Renders Tor `ClientUseIPv6 0`; it does not disable host IPv6 or direct sockets. |
| `provider_overrides` | object | `{}` | Additive facts for internal provider transports; bundled baseline IDs cannot be replaced. |

Override fields are `transport`, `respects_proxy`, `respects_socks5h`,
`respects_ipv6_proxy`, `localhost_only`, `dns_quirk`, `unverified_baseline`,
and `transport_class` (`http`, `tcp`, `udp`, `quic`, `grpc`, or `websocket`).
Missing safety facts default conservatively. Unknown fields, invalid types, or
attempts to replace a baseline provider are rejected by the strict Tor gate.

The startup check uses persisted provider state; `pre_api_request` repeats the
gate against the resolved request provider so one-shot and environment
overrides cannot bypass it.

## SOCKS5h library compatibility allowlist (Task #4)

The executable source is
`network.proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS`:

| Library | Minimum | Verified behavior |
|---|---:|---|
| `httpx` | 0.27.0 | SOCKS transport defers DNS to the proxy. |
| `urllib3` | 2.0.0 | `SOCKSProxyManager` honors `socks5h://` remote DNS. |
| `requests` | 2.32.0 | Requires compatible urllib3 + PySocks for remote DNS. |
| `aiohttp` | 3.10.0 | `aiohttp-socks` requires translating to `socks5://` with explicit `rdns=True`; passing `socks5h://` directly is invalid. |

Version membership alone is evidence, not an OS sandbox. Provider-specific
transport classification still applies.

## Mullvad credential indirection (Task #6)

The account value lives only in `<home>/.env` as
`MORDRED_MULLVAD_ACCOUNT=...`. `credentials/network.json` and policy/config
store the environment-variable name plus non-secret relay/killswitch settings.
Empty interactive input keeps the current value; `network init
--clear-mullvad` removes it. The secret is never accepted as a CLI flag.

When `.env` is enrolled in the macOS vault lifecycle, the plaintext is removed
after verified enrollment and injected into the process at startup. Outside
macOS the current transparent startup shim is inactive and the plaintext file
remains the runtime source.

## Tor ControlPort optional extra (Task #5)

`hermes-mordred[tor-control]` installs `stem>=1.8,<2`. With it, Mordred performs
cookie-authenticated `GETINFO circuit-status` health checks. Missing stem or a
not-yet-created cookie uses the shallow child-process check; authentication,
ControlPort, malformed-response, and known terminal-state failures are
unhealthy. The optional dependency bounds the risk of the old, lightly
maintained Stem package.
