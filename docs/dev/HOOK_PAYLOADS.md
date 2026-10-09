# Mordred — Hermes Hook Payload Verification Reference

> **Status**: current consumed contract. The machine-readable source of truth is
> `tools/hook_payload_contract.json`; `tests/test_hook_payload_drift.py` and
> `.github/workflows/upstream-check.yml` verify it against the installed Hermes
> release and upstream `main`. The original Hermes 0.11.0 survey is historical
> context, not the active compatibility floor.

## Why this doc exists

Hermes can add hooks or fields without breaking Mordred, but removing a hook or
a field that Mordred reads can weaken enforcement. This document records the
small contract Mordred actually consumes and the behavior chosen where Hermes
does not expose enough context.

Current contract:

| Hook | Fields Mordred reads | Consumers |
|---|---|---|
| `on_session_start` | `session_id` | Network activation and shared startup integrity |
| `on_session_end` | none | Network cleanup and keyvault resealing |
| `pre_tool_call` | `tool_name` | Privacy and network generic tool guards |
| `pre_api_request` | `provider`, `base_url` | LLM and network egress policy |
| `pre_gateway_dispatch` | `event`, `gateway` | Mandatory gateway E2E |

Callbacks may accept additional keyword arguments for compatibility, but policy
must not silently start depending on a new field until the JSON contract and
tests are updated in the same change.

## 1. `VALID_HOOKS` set and hook ordering guarantee

Mordred verifies that every literal `register_hook` name exists in Hermes's
`VALID_HOOKS`. Callback order is registration order; Hermes exposes no priority
argument that Mordred can rely on.

Mordred is one plugin, `mordred` (`mordred_hermes.plugin`). Its `register()`
registers the integrity callback first, then the components in a fixed order
(keyvault, llm_guard, network, privacy_check, e2e, wizard), so component
callbacks run in that order within each hook. A callback registered by more
than one component (the shared `check_plugin_integrity`) is registered once.
The `.pth` runtime bootstrap additionally keeps a mandatory integrity bridge at
the front of `on_session_start`. Network startup still uses explicit readiness
and process-freeze behavior rather than assuming another component ran first.

## 2. Plugin disable detection (`hermes plugins list --disabled` equivalent API)

At session start, the shared integrity code resolves the enabled/disabled state
of the `mordred` plugin from Hermes configuration and, with the plugin manager
in hand, checks that it loaded, holds the union of its components' required
hooks, and that no component failed (a failed component is reported as
`mordred/<component>`).

- `strict`: audit, poison the process, and raise
  `MordredIntegrityRefused(BaseException)` so Hermes cannot continue without
  every component.
- `lenient` / `off`: audit and warn, then continue.

When `mordred` is missing but `config.yaml` still lists the pre-0.2.0a0
per-component names (`mordred_network`, ...), the message points at
`hermes-mordred plugins migrate`. Those names are no longer a unit of
enablement: the components cannot be disabled one by one.

## 3. Dynamic plugin disable in running session (TODO §0.8 L105)

The heading is retained as a stable anchor; the old TODO line reference is
historical. Current ownership is [`SPEC.md`](./SPEC.md)
§Plugin-disable protection.

Hermes does not re-register hooks when configuration is edited during an active
process. A disable/enable change therefore takes effect at the next process
start. Mordred documents and audits this startup boundary; it does not claim to
intercept the configuration edit itself.

## 4. `pre_tool_call` payload

Mordred reads only `tool_name`. Hermes does not provide `origin_skill`, so the
runtime guard cannot apply per-skill metadata.

- The privacy_check component applies a generic strict-mode tool blocklist and
  returns an `action: block` response when required.
- The network component blocks calls when a strict route has dropped or the process
  is poisoned.
- Per-skill `metadata.mordred.*` decisions happen at install time through
  `hermes-mordred install`.

Adding `origin_skill` to Hermes would be an additive future capability. Mordred
must keep treating it as unavailable until the machine contract and enforcement
tests explicitly adopt it.

## 5. `pre_llm_call` payload and override return shape

Mordred does not register `pre_llm_call`. Its return channel is unsuitable for
rewriting the resolved provider, so policy is split across boundaries that
observe the real client/request:

1. Session-start checks catch invalid disk configuration and prohibited agent
   harnesses early.
2. `pre_api_request` validates the resolved provider and `base_url` immediately
   before the primary request.
3. Auxiliary-client guards validate Hermes call sites that do not pass through
   the primary request hook.

### 🔴 Phase 2 design implication (MAJOR)

Strict mode is refuse-only at these boundaries; it does not promise to replace
a cloud provider with `mordred-local` automatically. Any future auto-swap needs
a pre-client-construction integration point or an optional vendored layer.

## 6. `pre_gateway_dispatch` payload and return action shape

The e2e component reads `event` and `gateway` to authenticate `ENC:v3`, bind channel
keys to the routed destination, install reply-in-kind protection, and skip
plaintext or invalid mandatory-platform events before agent dispatch.

The callback returns the Hermes-supported allow/rewrite/skip action. Failure to
resolve the adapter, channel key, authenticated context, replay store, or
outbound protection is fail-closed for encrypted or mandatory-E2E traffic.

See [`SLACK_E2E.md`](./SLACK_E2E.md) for the wire contract.

## 7. `pre_approval_request` / `post_approval_response` payload

Mordred does not consume these hooks. Extension wallet approval is implemented
inside the local WebSocket protocol, where the prompt freezes signer, chain,
transaction fields, fees, and RPC origin before approval. Do not infer an
extension security guarantee from unused Hermes approval hooks.

## 8. Subprocess spawn API and proxy env passing (TODO §0.8 L101-103)

The heading is retained as a stable anchor. [`PLAN.md`](./PLAN.md) §Boundary
discipline and [`ROADMAP.md`](./ROADMAP.md) §v2-OS1 own the current and future
execution boundaries.

Mordred controls subprocess networking only where the selected Hermes/plugin
boundary accepts an explicit environment. It never assumes that setting a
process-global proxy retroactively changes already-constructed provider clients.

### 8.1 Two distinct env-filter regimes (CRITICAL distinction)

1. Provider clients capture proxy configuration when they are constructed.
2. Child processes receive a filtered environment at spawn time.

The network plugin activates one route before provider construction and freezes
that choice for the process. Child-process code uses the approved proxy
environment instead of copying arbitrary caller variables.

### 🔴 Phase 3 design implication (MAJOR — flagged by Codex review on PR #9)

The historical heading remains for inbound anchors; the rule below is the
current contract, independent of the review that first identified it.

Switching the saved route while Hermes is running does not rebuild existing
clients. Operators must restart Hermes. A conflicting live activation is
refused rather than partially switching traffic.

### 8.2 Implications for M3 (transitive proxy-env failure mode)

Libraries or subprocesses that ignore the selected proxy are classified by the
provider transport gate. Strict mode blocks known incompatible egress; it does
not silently retry on clearnet.

### 8.3 Spawn-site classes (out of 285 total subprocess sites)

The historical survey counted upstream spawn sites, but the count is not a
stable contract. Review only the concrete spawn paths touched by a change and
verify their explicit `env`, timeout, and cleanup behavior against the current
Hermes source.

## Cross-cutting findings → SPEC.md updates

- No `origin_skill`: install-time per-skill policy plus generic runtime guard.
- No provider rewrite: resolved-request refusal plus auxiliary guards.
- No hook priority: local callback ordering plus readiness checks.
- No service boot hook: `extension serve` has an explicit operator lifecycle.
- Payload drift is checked by field, not only by hook name.

## Out of scope (deferred to a follow-up "live verify" task)

Real provider DNS behavior, live cloud SDK proxy behavior, Secure Enclave user
presence, and live VPN state cannot be proven by static hook inspection. Their
gated tests and last validation dates are tracked in [`CI.md`](./CI.md).

## Maintenance

1. Update `tools/hook_payload_contract.json` whenever a callback begins or
   stops reading a field.
2. Run `tests/test_hook_payload_drift.py` and the scanner against installed
   Hermes.
3. Let the weekly workflow compare both PyPI and upstream `main`.
4. Update SPEC/PLAN and the affected canonical policy/path document in the same
   behavior change.
5. Never describe an old Hermes snapshot as the current source of truth.
