# Mordred — Implementation Plan (Hermes-base)

> **Status**: current implementation map. Completed PR-by-PR history lives in
> Git and PR descriptions; this document describes the architecture to maintain
> now. [`SPEC.md`](./SPEC.md) defines behavior and [`TODO.md`](./TODO.md) lists
> open work.

Mordred is a standalone Python distribution loaded through
`hermes_agent.plugins`. It does not fork Hermes and does not submit changes to
Hermes upstream.

## Current architecture

| Entry point | Implementation | Responsibility |
|---|---|---|
| `mordred_privacy_check` | `privacy_check/` | Skill policy, runtime tool guard, audit log |
| `mordred_wizard` | `wizard/` | Standalone and host CLI surfaces |
| `mordred_llm_guard` | `llm_guard/` | Provider, endpoint, and harness enforcement |
| `mordred_network` | `network/` | Process-wide Tor/VPN/clearnet route |
| `mordred_keyvault` | `keyvault/` | Vault, hardware key, backup, and signing |
| `mordred_e2e` | `extension/gateway_plugin.py` | Slack/Discord E2E gateway hook |

Shared policy, path, audit, YAML, provider, and terminal boundaries live at the
package root. The extension package also contains the standalone localhost
WebSocket server.

## Phase 0 — Operational Setup (one-time, blocking everything else)

Phase 0 is complete. Its rules remain the baseline for every change.

### 0.1 Repo & venv Check

- Run development work from the repository `.venv` created by
  `uv sync --all-extras`.
- Confirm `mordred_hermes.__file__` points into `src/` before testing local code.
- Isolate mutating CLI tests with `HERMES_HOME`; read-only status commands may
  use the normal profile.
- Treat `~/.hermes/hermes-agent/venv` as the released production environment.

### 0.2 Hermes Upstream Tracking Strategy (optional)

- No rebase or fork synchronization is required.
- The optional `hermes-upstream` remote is for source inspection only.
- `.github/workflows/upstream-check.yml` checks both the latest PyPI release and
  upstream `main` for hook-name and consumed-payload drift.

### 0.3 Mordred-owned paths (kept in sync with PATHS.md)

Persistent state is resolved from the active Hermes profile. Most private
state is beneath `<hermes-home>/mordred/`; extension state lives under
`<hermes-home>/extension/`, and the encryption facade deliberately manages
selected Hermes-owned `.env`, config, memory, and workspace targets.
[`PATHS.md`](./PATHS.md) owns the complete paths, permissions, writers, and
readers.

### 0.4 Plugin scaffolding pattern

- Manifest-backed plugins provide `plugin.yaml` and a module-level
  `register(ctx)`.
- Entry points name modules, not `module:register`; Hermes loads the module and
  calls `register` itself.
- `mordred_e2e` is intentionally registered from
  `extension.gateway_plugin` and has no separate manifest.
- Plugin boundaries expose narrow Protocols under `TYPE_CHECKING` rather than
  importing optional Hermes internals at runtime.

### 0.5 `mordred-hermes` Package Scaffold

- Python floor: 3.11; Hermes floor: 0.13.0.
- Version source: `src/mordred_hermes/__about__.py`, read by Hatch.
- Human marker, plugin manifests, the development-setup pin, and compatibility
  shim pins are synchronized by `python tools/bump_version.py <version>`; the
  top-level README remains version-agnostic and relies on its PyPI badge.
- Base install stays small. Platform and feature dependencies remain in the
  `keyvault`, `macos`, `extension`, `ethereum`, `messaging`, `tor-control`, and
  integration extras.
- `hermes-mordred` is the canonical user-facing CLI across the full Hermes
  support range. Hermes 0.19.0+ can expose the same handlers through an
  additional host-CLI compatibility surface after the plugins are enabled.
  Command examples use the canonical form; README mentions the host form only
  as a compatibility note.
- The public distribution rename completed 2026-08-12: `hermes-mordred` was
  reserved independently, published as the real distribution, and
  `mordred-hermes` now publishes only as a metadata-only compatibility shim.
  The import tree, entry-point IDs, persistent state, and native helper
  identifiers did not change. [`CI.md`](./CI.md) §Normal release owns the
  ordering and compatibility contract for future releases.

### 0.6 CI workflow

CI owns lint, formatting, strict typing, unit tests, the supported Python/OS
matrix, optional-feature coverage, package smoke tests, the Hermes floor,
hermetic Tor/TPM coverage, and native helper builds. Details and release policy
live in [`CI.md`](./CI.md).

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

No upstream PR is created. Strict mode detects a disabled Mordred sibling at
session start and aborts through the shared integrity callback. A future
vendored `hard-lock` extra remains only a roadmap option.

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

### 1.1 Plugin: `mordred_privacy_check`

- Parse `metadata.mordred.*` at skill-install time and evaluate network and
  keyvault requirements before delegation to Hermes.
- Enforce the generic strict-mode tool blocklist at `pre_tool_call`; Hermes does
  not supply `origin_skill`, so per-skill runtime enforcement is unavailable.
- Write typed audit events through the shared writer factory. Continue auditing
  with an explicit degraded marker if encrypted logging cannot be opened.
- Run sibling-plugin integrity checks at session start and poison later tool
  calls after a strict refusal.

### 1.2 Skill metadata namespace

The supported extension remains under `metadata.mordred`, with validation and
defaults defined by [`POLICY.md`](./POLICY.md). Unknown metadata is blocking in
strict mode and warning-only in lenient mode.

### 1.3 Plugin: `mordred_wizard`

The wizard owns configuration, status, policy inspection, skill-install
dispatch, network and keyvault ceremonies, encryption lifecycle, audit
inspection, plugin discovery, migration, and extension launcher commands.
Interactive flows fail safely without a TTY and destructive actions require
explicit confirmation or `--yes`.

### 1.4 Tests

Keep policy decisions pure and table-tested. Cover audit serialization,
degraded behavior, CLI parsing, non-interactive refusal, YAML preservation, and
isolated `HERMES_HOME` state.

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

### 2.1 Plugin: `mordred_llm_guard` (landed)

- Register the synthetic `mordred-local` provider from policy.
- Refuse known external agent harnesses under strict policy.
- `pre_llm_call` cannot rewrite the provider, so `pre_api_request` and the
  auxiliary-client guards are the only live enforcement boundaries.
- Enforce the resolved primary request in `pre_api_request` using both provider
  identity and the actual `base_url`.
- Guard Hermes auxiliary LLM client construction separately because those
  calls can bypass the primary request hook.
- Permit cloud traffic only when policy, provider identity, and a
  provider-owned HTTPS endpoint all agree.

### 2.2 Wizard additions (landed)

`configure` owns policy mode, cloud allowance, provider allowlist, local model
endpoint/model ID, prompt-once behavior, and harness selection. Non-interactive
updates preserve unspecified existing values.

### 2.3 Tests (landed)

Cover provider aliases, endpoint ownership, loopback validation, harness
refusal, local endpoint health, prompt-once state, and auxiliary-client guards
without making live provider calls.

## Phase 3 — Network Paths (`mordred_network`)

### 3.1 Plugin: `mordred_network`

- Select one process-wide route before provider clients are constructed.
- Build Tor/VPN/clearnet settings without mutating an already-active conflicting
  route; changing routes requires a Hermes restart.
- Inject proxy variables only through the guarded environment boundary and
  reject known incompatible transports under strict policy.
- Monitor route health and fail closed after a strict route drops.

### 3.2 Wizard additions

`network init`, `network use`, and `network status` own operator interaction.
Secrets are written to `.env`; policy and credentials files contain references,
not copied credentials.

### 3.3 Tests

Unit tests cover route state, environment filtering, provider compatibility,
timeouts, and liveness. Docker supplies hermetic Tor/SOCKS coverage; Mullvad is
an explicitly gated live-device test.

## Phase 4 — Key Management (`mordred_keyvault`)

### 4.1 Plugin: `mordred_keyvault`

- Use Secure Enclave with login-Keychain fallback on macOS and the packaged TPM
  2.0 helper on Linux; Linux has no software fallback.
- Store encrypted envelopes and metadata under the profile-owned keyvault root
  with atomic writes, process locks, permission checks, and purpose-bound AAD.
- Provide recovery seed/digest, portable backup export/import in both the
  Python API and operator CLI, passphrase recovery, audit encryption, Ethereum
  keys, extension signing, and the macOS-only config/env materialize-and-inject
  shims plus the agent-memory at-rest encryption runtime (a wrapper around the
  memory tool seam, fail-closed).
- Keep native imports lazy so unsupported platforms can still import the
  package and report capabilities.

### 4.2 Wizard additions

The CLI owns `keyvault init/list/verify-digest/export/recover/reset`, native
helper installation, Ethereum subcommands, the lower-level vault interface,
and the `encryption` facade. Export collects recovery material through masked
prompts and publishes a new mode-`0600` MRKV snapshot without replacement.
The facade's `memory` target drives key provisioning, the marker, eager
migration, and the `setup` step for agent-memory at-rest encryption.

### 4.3 Tests

Pure-Python tests cover formats, normalization, storage, backup rollback,
recovery ordering, and fake native backends. CI builds both helpers and runs a
software TPM. Real Secure Enclave validation remains manually gated. A CI
canary test runs the memory-encryption hook against the installed upstream
memory tool, so an upstream seam refactor fails the build instead of
regressing silently.

## Cross-cutting concerns

### Documentation

Use [`README.md`](./README.md) as the only developer index. Keep current contracts in
SPEC/POLICY/PATHS/HOOK_PAYLOADS, operational policy in CI/setup, and future work
in TODO/ROADMAP. Git and PR descriptions hold change history; package-local
plugin READMEs are not separate documentation authorities.

### Testing posture

The default suite is hermetic: the root `tests/conftest.py` defaults
`HERMES_HOME` to a fresh temporary directory (cleaned up at process exit)
before anything imports `mordred_hermes`, unless the caller already set
`HERMES_HOME` — an explicit value always wins untouched. Live tests require
their documented environment gate and never run accidentally. A test that
needs its own isolated or per-test `HERMES_HOME` still sets/unsets it
explicitly (e.g. via `monkeypatch`) rather than relying on ambient state.

### Type/build/lint posture

Run pytest, Ruff lint/format check, and
`mypy --strict src tools scripts/keyvault_offline_digest.py` through uv.
Optional imports stay behind lazy or `TYPE_CHECKING` boundaries so CI's reduced
extras remain valid.

### Boundary discipline

- No upstream Hermes modifications.
- No implicit writes outside the active Hermes home.
- No plaintext secret values in policy, credentials references, logs, or error
  messages.
- No network fallback that bypasses the selected route.
- Fail closed for key custody and mandatory E2E; audit fail-open only where the
  explicit degraded marker preserves observability.

### Versioning & SDK compatibility

The package and all plugin manifests share one version. The machine contract in
`tools/hook_payload_contract.json`, its static scanner, and compatibility tests
detect Hermes drift. The 0.13.0 floor and latest release are tested separately.

### Hook payload realities (Phase 0.8 verify complete — 2026-05-10)

Mordred consumes only the fields listed in
[`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md). The current contract is verified
against installed Hermes and upstream `main`; the original 0.11.0 survey is
historical context, not the source of truth. 2026-05-10 is when the contract
was first frozen; it is now continuously enforced by the weekly
`.github/workflows/upstream-check.yml` run and `tests/test_hook_payload_drift.py`.

## Risks and unresolved decisions

- Automatic lifecycle integration for `extension serve` is undecided.
- Hermes still provides no `origin_skill` for per-skill runtime enforcement.
- Process-wide provider/proxy construction prevents independent concurrent
  per-skill routes.
- Co-resident malware and OS-level traffic bypass remain outside the plugin
  threat boundary.
- Secure Enclave and live LLM paths require periodic on-device validation.
  Live VPN validation is manual-only, including its explicitly dispatched
  GitHub Actions workflow.

## Recommended execution order

1. Pick an unchecked item from [`TODO.md`](./TODO.md) and confirm it belongs to
   the current release rather than the roadmap.
2. Update SPEC/PLAN first when behavior or cross-plugin contracts change.
3. Implement one plugin per PR and update its canonical SPEC/PLAN/PATHS/POLICY
   sections in the same PR.
4. Run the reduced-extras compatibility checks when touching optional
   dependency code.
5. Record one-line Changes/Fixes entries in the PR description; do not create a
   `CHANGELOG.md`.

No cross-plugin work is currently in flight; open items live in
[`TODO.md`](./TODO.md).
