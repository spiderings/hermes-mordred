# Mordred Roadmap (post-v1, Hermes-base)

> **Status**: deferred work only. Current behavior belongs in
> [`SPEC.md`](./SPEC.md), implementation shape in [`PLAN.md`](./PLAN.md), and
> actionable current work in [`TODO.md`](./TODO.md). Inclusion here is not a
> commitment or authorization to modify Hermes upstream.

## Legend

- **H** — address early when its dependency exists.
- **M** — decide from user feedback and threat-model need.
- **L** — long-term exploration.
- **Blocked** — requires an interface or platform capability not currently
  available to the plugin package.

## Security-critical release gates

The first critical expansion is an enforceable execution boundary for
untrusted skills (`v2-OS1`). Proxy environment variables, metadata checks, and
Hermes hooks remain useful policy layers, but they are not a security boundary:
skill code can otherwise open a direct socket, read same-user files, or spawn an
unrestricted child process.

The following are release gates, not interchangeable hardening ideas:

1. Do not claim protection from malicious or compromised skills until every
   skill-controlled process is contained by `v2-OS1` and the acceptance checks
   below pass on the supported platform.
2. Do not ship payment skills until both `v2-OS1` and the isolated signing and
   per-use authorization boundary in `v3-P1` are complete.
3. Audit-log integrity, skill signatures, additional encryption, and GUI
   controls are defense in depth. None substitutes for the two runtime
   boundaries above.

The current v1 threat model remains unchanged until those gates ship. Moving a
gate into implementation requires a separate SPEC/PLAN change before code.

## Remaining browser-extension gateway integration

Pairing, localhost serving, encrypted chat, history, wallet/RPC, and the real
Hermes chat bridge ship in `mordred_hermes.extension`. The remaining question is
service lifecycle: keep explicit `extension serve`, document launchd/systemd,
or integrate only if Hermes exposes a safe plugin service-boot hook.

- Preserve coexistence with a legacy/custom gateway or standalone Extension
  service already listening on port 7788.
- Keep explicit startup as the default until ownership and shutdown semantics
  are unambiguous.
- **Priority**: M.

## v2 candidates: Hermes hook extensions (PR candidates)

The historical heading is retained, but the zero-PR commitment remains in
force. These describe capabilities a future optional vendored layer could
provide; Mordred does not submit them to Hermes upstream.

### v2-H1: Skill install hook

Provide one policy gate for both `hermes skills install` and
`hermes-mordred install`. Until then, only Mordred's wrapper can enforce
`metadata.mordred.*` before installation.

- **Priority**: H.
- **Blocked by**: a pre-install boundary before Hermes writes skill files.

### v2-H2: Add `origin_skill` to the `pre_tool_call` payload

Associate tool calls with the originating skill so runtime policy can apply the
skill's declared network and keyvault requirements. Calls without a skill must
remain explicitly unattributed.

- **Priority**: M.
- **Blocked by**: end-to-end provenance through Hermes tool dispatch.

### v2-H3: Add `provider_id` / `model_id` to the `pre_llm_call` payload

No longer required for primary-request refusal: Mordred enforces resolved
provider and endpoint at `pre_api_request`. Revisit only if a pre-construction
provider replacement capability is designed.

- **Priority**: L.

### v2-H4: Plugin loader hook priority control

Could replace local readiness/polling coordination with declared callback
priority. Current behavior must remain correct without it.

- **Priority**: M.

## v2 candidates: OS integration (largest defense expansion)

### v2-OS1: Local malware / co-resident process mitigations

Build a mandatory skill runner plus a Mordred-owned network broker. Run every
skill-controlled process inside an OS sandbox; do not rely on
`HTTP(S)_PROXY`, skill metadata, or cooperative client libraries as the final
egress control.

Minimum acceptance criteria:

- Default-deny direct IPv4/IPv6 TCP, UDP, QUIC, raw-socket, and DNS egress from
  the skill process. The only egress path is an authenticated, least-privilege
  IPC channel to the broker, which applies destination policy and owns the
  selected Tor/VPN/policy-controlled clearnet/localhost transport. Direct
  egress remains denied in every policy mode: lenient/off may broaden brokered
  clearnet grants, while strict retains the clearnet refusal in `POLICY.md`.
- Deny direct reads of `~/.hermes`, Mordred keyvault state, credentials, agent
  memory, and unrelated workspace files. Grant only an explicit per-skill
  filesystem view.
- Construct every skill environment from a clean baseline rather than
  inheriting the Hermes process environment. Pass only allowlisted non-secret
  runtime variables. Any secret requires an explicit, auditable,
  least-privilege grant scoped to the skill and invocation; prefer
  broker-mediated credential use whenever the raw value need not enter the
  skill process.
- Ensure every descendant inherits the restrictions; deny escape through
  process spawning, shell execution, `ptrace`, signals, inherited file
  descriptors, or alternate interpreters.
- In strict mode, refuse the skill before execution when the required sandbox,
  broker, or kernel capability is unavailable or degraded. Lenient mode must
  show and audit the downgrade; it must never label the run as isolated.
- Add adversarial integration tests that attempt direct network connections,
  local DNS resolution, protected-file reads, reads of an ungranted sentinel
  secret through environment APIs and OS process-environment views, inherited
  descriptor access, child-process escape, and broker policy bypass. Test both
  successful denials and explicitly allowed brokered traffic, including
  clearnet grants under lenient/off and clearnet refusal under strict.

Implementation sequence:

- Start with a Linux runner using Landlock/seccomp plus an appropriate network
  enforcement mechanism; probe the available kernel ABI at runtime and fail
  closed under strict policy.
- Add a signed macOS runner using supported sandbox facilities and a narrowly
  scoped broker service. Endpoint Security is an escalation path if the runner
  cannot provide complete mediation without it.
- Require a mandatory Hermes execution/spawn boundary. If the public plugin API
  cannot cover every path, implement it only through Mordred's separately
  approved, version-pinned vendored layer; never send an upstream PR.

This first stage contains malicious skill code. It does **not** constrain an
arbitrary same-UID process that was already running outside the runner. Extending
the threat model to hostile co-resident malware additionally requires a
dedicated OS account or VM/container boundary and an authenticated key service
that does not trust same-UID callers merely because they can reach it.

- **Risk**: incomplete process mediation creates a false security claim;
  platform entitlements and restrictive profiles can also break legitimate
  skills.
- **Priority**: Critical / H. Required before claiming untrusted-skill
  containment and before any payment-skill release.
- **Blocked by**: a mandatory dispatch/spawn boundary covering all
  skill-originated execution paths.

### v2-OS2: Remaining keyvault platforms and authorization tiers

Current custody is Secure Enclave/Keychain on macOS and TPM 2.0 on Linux.
Candidates are Windows DPAPI/CNG TPM, external PKCS#11/FIDO2 hardware, and a
stronger Linux PIN/PCR presence policy.

- **Priority**: M.
- **Constraint**: no new backend may weaken the existing platform floors or
  introduce a silent software fallback on Linux.

## v2 candidates: feature expansion

### v2-F1: Per-skill independent network paths

Construct independent transports instead of changing process-global proxy
state. Requires `origin_skill`, per-request/provider-client routing, and
explicit child-process environment injection.

- **Priority**: M.

### v2-F2: Skill metadata signing / integrity verification

Verify publisher signatures over canonical skill metadata and content at
install time. Proceed only with an ecosystem signing chain and a plugin-owned
verification boundary.

- **Priority**: M.

### v2-F3: GUI controls

Offer status, policy, network, and audit controls through a thin client over
stable internal APIs. Do not duplicate security decisions in the UI.

- **Priority**: L.

### v2-F4: Tamper-resistant audit logs

Encrypted logs protect content at rest but do not provide append-only integrity.
Evaluate a hash chain or externally anchored checkpoints while retaining the
current degraded audit trail.

- **Priority**: M.

### v2-F5: Multi-user / multi-tenant

Add user-isolated configuration, credentials, key custody, and audit ownership.

- **Priority**: L; the current target remains one local operator.

### v2-F6: Trace-minimization layer (binary / folder / file-name encryption)

Explore a plugin-owned encrypted overlay for skill artifacts and filenames.
Avoid loader patches unless the optional vendored strategy is separately
approved.

- **Priority**: M only for a concrete forensic-resistance use case.
- **Risk**: decrypted mount lifecycle and OS-specific filesystem facilities.

### v2-F7: Seed-display PC↔phone pairing UI

Move recovery-passphrase input or digest confirmation to a single-use phone
session, bound by QR and a short expiry.

- **Priority**: M.
- **Risk**: local-network MITM and self-signed TLS usability.

### v2-F8: `config.yaml` at-rest transparent decryption

Complete; the current opt-in contract and plaintext working-file limitation
live in [`SPEC.md`](./SPEC.md) and [`PATHS.md`](./PATHS.md).

### v2-F9: agent-memory at-rest encryption

Complete; the shipped runtime contract lives in [`SPEC.md`](./SPEC.md), and its
live Apple Silicon result is recorded in [`CI.md`](./CI.md).

## v3+ candidates: Payment layer

### v3-P1: Payment skills

Add policy-aware payment skills only after wallet signing is moved behind a
dedicated signer boundary. A hardware-backed non-exportable key is insufficient
when untrusted code can freely request signatures.

Release requirements:

- Depend on a completed `v2-OS1`; sandboxed skills receive no raw private key,
  seed, keyvault master, or unrestricted signing handle.
- Canonicalize and decode the exact transaction or message before approval.
  Build an approval envelope containing the complete canonical signing payload
  plus its origin and request context, and bind approval to a cryptographic
  digest of that entire envelope rather than a selected field list. For a
  transaction, the envelope includes the transaction type and every applicable
  signing-affecting field, including account, chain, destination, value,
  calldata, nonce, gas limit, fee fields, access list, authorization fields,
  and blob fields. For a message, it includes the signing method and the exact
  message bytes or complete typed-data domain, types, primary type, and
  message. Context includes the caller skill identity, session/tool-call
  identity, RPC context, origin, approval expiry, and a single-use request
  identifier. The isolated signer recomputes the entire envelope digest from
  the exact payload and trusted request context immediately before signing and
  rejects any mismatch.
- Require explicit per-use operator authorization for value-moving or
  permission-granting operations. A general tool approval, chat instruction,
  or previous transaction approval never authorizes a later signature.
- Enforce independent signer-side limits and destination/contract policy; do
  not trust validation performed only inside the requesting skill.
- For every applicable state-changing transaction, simulate the exact approved
  payload and fail closed when simulation is unavailable, fails, is stale, or
  was produced for a payload other than the one committed by the
  approval-envelope digest. Reject transaction forms the product cannot
  completely decode, simulate when applicable, and evaluate.
  Transaction simulation does not apply to `personal_sign` or EIP-712 message
  requests; those requests still require complete decoding and display, policy
  evaluation, per-use authorization, user-presence verification, audit
  recording, and signer isolation.
- Fail closed when any check required for the request type is unavailable.
- Test replay, approval substitution, omitted-field mutation (including gas,
  fees, access-list, authorization, and blob fields), origin confusion, chain
  switching, hidden calldata, simulation/payload mismatch, valid message
  requests without transaction simulation, concurrent requests, and a
  compromised skill attempting to sign outside the displayed authorization.

- **Priority**: Critical / H within a future payment milestone, not the current
  product.
- **Blocked by**: `v2-OS1` and a separately specified isolated signer and
  approval protocol.

### v3-P2: x402 / agent payment protocol integration

Evaluate protocol support with explicit spend limits, destination policy, and
human approval. Never infer payment authorization from a general tool approval.

- **Priority**: M.

## v2+ candidates: miscellaneous

### v2-X1: Mordred-branded mobile apps

Consider only when a concrete workflow, such as seed confirmation, requires a
native companion.

- **Priority**: L.

### v2-X2: Mordred-specific telemetry / crash reporting

Default remains no telemetry. Any future diagnostics must be opt-in, locally
inspectable, aggressively redacted, and documented in the threat model first.

- **Priority**: L; discussion before implementation.

### v2-X3: Documentation reorganization — DONE (2026-06-25, ahead of GA)

Complete. User, developer, and upstream-snapshot documents are separated by
directory and indexed. Keep the structure rather than scheduling another
migration.

### v2-X4: Canonical Hermes subcommand

Make `hermes mordred ...` the canonical user-facing CLI spelling. Keep
`hermes-mordred` as a bootstrap and recovery entry point until the host
subcommand is available immediately after installation and remains usable when
plugin configuration is missing or damaged.

Transition only after:

- the minimum supported Hermes version is 0.19.0 or newer;
- first-time configuration works through `hermes mordred configure`;
- a reliable recovery path exists for disabled or invalid plugin configuration.

Until those conditions are met, user documentation continues to use
`hermes-mordred ...` as the dependable command form.

- **Priority**: H after the Hermes version floor can move to 0.19.0.

## Forever out of scope

- Submitting Mordred changes to Hermes upstream.
- Silent clearnet fallback from a selected privacy route.
- Linux software-key fallback presented as hardware protection.
- Recovery that bypasses the documented seed/passphrase/backup guarantees.
- Plaintext fallback for mandatory Slack/Discord E2E commands or replies.
- Telemetry enabled by default.

## Update rules for this document

1. Add only work that is outside the current release.
2. Move actionable work to `TODO.md` when dependencies and acceptance criteria
   are decided.
3. Move shipped behavior to SPEC/PLAN and reduce the roadmap item to one
   completion sentence.
4. Do not preserve PR-by-PR history here; Git and release notes already do so.
