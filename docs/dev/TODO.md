# Mordred — TODO (Hermes-base)

> **Status**: actionable current-release work only. Completed work is in Git
> history and merged PR descriptions; deferred product work is in
> [`ROADMAP.md`](./ROADMAP.md). [`PLAN.md`](./PLAN.md) describes the
> implementation that exists today.

Every item here must have a known owner boundary and a testable completion
condition. Preserve the zero-upstream-PR commitment and one-plugin-one-PR rule.

## Standalone-repo repair backlog (2026-07-01)

The repair backlog is complete. The only remaining item is the `extension
serve` lifecycle decision; its canonical description — including the
port-7788 coexistence and restart-after-upgrade constraints — is
[`ROADMAP.md` — lifecycle integration](./ROADMAP.md#remaining-browser-extension-gateway-integration).

- [ ] Decide and document the supported long-running lifecycle for
  `extension serve` per that section.

## Phase 0 — Operational Setup (blocks all later phases)

No open setup work. Keep the gates in [`CI.md`](./CI.md) green.

### Open decisions

None for the current release.

### 0.1 Confirm repo & venv

No open work. Use the repository `.venv` and isolate mutating CLI validation
with `HERMES_HOME`.

### 0.2 Hermes upstream tracking strategy (optional, rebase not recommended)

No open work. Compatibility checks are read-only and no upstream PRs are sent.

### 0.3 Reserve Mordred-owned filesystem paths (kept in sync with PATHS.md)

No open work. Any new path must update [`PATHS.md`](./PATHS.md) in the same
change.

### 0.4 Plugin scaffolding (five plugins)

No open work. The heading is retained as a stable historical anchor; the
current package exposes five manifest-backed plugins plus `mordred_e2e`.

### 0.5 `mordred-hermes` package scaffold

No open work. Release mechanics belong to [`CI.md`](./CI.md) §Normal release.

### 0.6 CI workflow

No open work. Workflow YAML and [`CI.md`](./CI.md) own the current gates.

### 0.7 ~~HSeam-1 PR~~ → Zero-PR commitment (deferred to v2 vendored fork)

No current-release work. A mandatory vendored enforcement layer, if approved,
must move from [`ROADMAP.md`](./ROADMAP.md) through SPEC/PLAN before code.

### 0.8 Verify Hermes hook payloads against real code

No open work. Maintain `tools/hook_payload_contract.json` whenever a consumed
field changes.

### Acceptance gate (Phase 0)

The package must discover all six entry points and pass the documented checks
from a clean supported environment.

## Phase 1 — Privacy Primitives (`mordred_privacy_check` + metadata + wizard)

No open Phase 1 implementation work.

### Open decisions

None for the current release. Per-skill runtime provenance is deferred.

### 1.1 `mordred_privacy_check` plugin

No open work.

### 1.2 Skill metadata namespace

No open work.

### 1.3 `mordred_wizard` plugin

No open Phase 1 work. The backup-export operator surface is tracked under
Phase 4 because it depends on keyvault semantics.

### 1.4 Tests (Phase 1)

No open work beyond tests required by a concrete behavior change.

### 1.5 Docs and bookkeeping (Phase 1)

No separate backlog. Documentation changes accompany the behavior they
describe, and PR descriptions carry `### Changes` / `### Fixes` entries.

### Acceptance gate (Phase 1)

Strict, lenient, and off decisions remain deterministic and auditable.

## Phase 2 — LLM Enforcement (`mordred_llm_guard` + `mordred-local` provider)

No open implementation work for the current enforcement model.

### Open decisions

Automatic provider replacement requires a pre-client-construction boundary and
remains in the roadmap; current strict behavior is refusal, not redirection.

### 2.1 `mordred_llm_guard` plugin

No open work.

### 2.2 Wizard additions (Phase 2)

No open work.

### 2.3 Tests (Phase 2)

No open hermetic work. Live-provider checks are listed under Phase 3 because
they validate transport classification.

### Acceptance gate (Phase 2)

Strict policy refuses a non-allowlisted, unresolved, or endpoint-mismatched
provider before egress.

## Phase 3 — Network Paths (`mordred_network`)

The implementation is complete; two conservative provider classifications
still need real-account evidence before they can be relaxed.

### Open decisions (resolved 2026-05-09 / 2026-05-13)

The classification decision itself is resolved: both providers keep the
conservative `unverified_baseline=True` stance until real-account evidence
justifies changing it. Verification is still open:

- [ ] Live-verify Bedrock DNS and proxy behavior with a real AWS account.
  Record the environment, SDK version, selected route, and result without
  recording credentials. Change the conservative classification only in a
  separate `mordred_network` change with a regression test.
- [ ] Live-verify Vertex proxy behavior with the real Google Cloud SDK under
  the same evidence and test requirements.

Per-session/per-skill routing remains deferred until Hermes supplies trusted
origin provenance and independently constructed transports.

### 3.1 `mordred_network` plugin

No open implementation work.

### 3.2 Wizard additions (Phase 3)

No open work.

### 3.3 Tests (Phase 3)

Complete the two live-provider checks above; ordinary unit, Tor, and
manual-Mullvad coverage remain governed by [`CI.md`](./CI.md).

### Acceptance gate (Phase 3)

Strict mode must never retry a selected protected route over clearnet.

## Phase 4 — Key Management (`mordred_keyvault`)

Portable backup export and import are available through both the crypto/storage
API and the operator CLI.

### Open decisions

None for the current release.

### 4.1 `mordred_keyvault` plugin

No open format/API work for export: `keyvault.api.export_backup()` already
returns an MRKV blob. Keep its wire compatibility unchanged while adding the
operator surface.

### 4.2 Wizard additions (Phase 4)

No open work. `keyvault export --output` and `keyvault recover --blob` are
shipped; see [`SPEC.md`](./SPEC.md) §export_backup / import_backup for the
current CLI and wire contract.

### 4.3 Tests (Phase 4)

No open work.

### 4.4 Agent-memory at-rest encryption (cross-plugin: keyvault + wizard)

No open work. The shipped contract lives in [`SPEC.md`](./SPEC.md)
§Agent-memory at-rest encryption, and the 2026-08-20 Apple Silicon
live-verification result is recorded in [`CI.md`](./CI.md) §Manual
live-device validation log.

### Acceptance gate (Phase 4)

A CLI-produced blob recovers successfully into an isolated fresh profile while
the source remains usable, and failure paths leave no partial destination.

## Cross-cutting (ongoing through the operational phase)

- Keep maintained documentation indexed, English-only, free of stale local
  links and brittle line-number references.
- Keep SPEC, PLAN, PATHS, POLICY, HOOK_PAYLOADS, and machine contracts aligned
  with code in the same change.
- Run the relevant manual/live validation after touching its gated path and
  record the result in [`CI.md`](./CI.md).
- Keep each implementation PR scoped to one plugin; land cross-plugin contract
  documentation first.
