# Mordred — CI Policy (Hermes-base)

> **Status**: current operational policy for this standalone repository. Workflow
> YAML is authoritative for mechanics; this document owns intent, release order,
> branching, and manual validation requirements.

## Why it got simpler

Mordred is a plugin package, not a Hermes fork. CI is responsible for Mordred's
source, package, native helpers, compatibility floor, and declared integration
boundaries. Hermes tests and releases remain upstream responsibilities.

## Standalone-repo adaptations (2026-07-01)

The standalone repository resolves `hermes-agent` from PyPI, ships its own five
workflows, and has no inherited upstream workflows. The initial repository-split
repair — the follow-up work from the 2026-07 move into this standalone
repository — is complete; historical restoration details remain in Git.

## Active workflows

| Workflow | Purpose | Trigger |
|---|---|---|
| `ci.yml` | Test matrix, extras, wheel smoke, Tor/TPM, native helper builds | PR and pushes to `dev`/`main` |
| `upstream-check.yml` | Hermes hook-name and consumed-payload drift | Weekly and manual |
| `labeler.yml` | Path-based PR labels | `pull_request_target` |
| `integration-vpn.yml` | Live Mullvad validation | Manual only |
| `release.yml` | TestPyPI/PyPI build and publish | Manual only |

## `ci.yml` details

The workflow has eight jobs:

1. **`test`** — Python/OS matrix; Ruff, shellcheck (one Linux cell), strict
   mypy, pytest, coverage, and the SKILL.md drift guard (mordred-status).
2. **`feature-extras`** — installs `ethereum`, `messaging`, and `tor-control`
   and runs their focused tests so optional coverage cannot disappear behind
   import skips.
3. **`package-smoke`** — builds sdist then wheel, installs outside the checkout,
   loads six plugin entry points plus the console script, and checks shipped
   native/offline/web/bootstrap assets.
4. **`hermes-floor`** — pins `hermes-agent==0.13.0`, verifies the resolver kept
   the pin, and runs the compatible default suite.
5. **`integration-tor`** — Docker-based Tor, SOCKS5h, and provider-transport
   integration tests. Tor bootstrap runs against the live Tor network; the
   harness waits up to 240s per attempt and recreates the container once
   before failing (`tests/integration/_docker.py`). A `BootstrapTimeout`
   that survives both attempts is a network flake — re-run the job rather
   than bypassing the CI gate.
6. **`sekey-helper`** — compiles the Secure Enclave Swift helper on macOS.
7. **`tpmkey-helper`** — checks the Rust crate, locked dependencies, MSRV, and
   `tss-esapi` build.
8. **`tpmkey-helper-tpm`** — runs the TPM backend against `swtpm` on Linux.

Key policy:

- The test matrix covers Ubuntu and macOS with Python 3.11–3.13.
- CI installs `.[dev,keyvault,extension]`; macOS adds `macos`. Do not assume
  `ethereum` or `tor-control` imports are available in the main typing job.
- Run `mypy --strict src tools scripts/keyvault_offline_digest.py`; a narrower
  CLI target silently stops checking `tools/` or the shipped digest script.
- GitHub Actions use immutable commit SHAs. Cargo commands use `--locked`.
- The default pytest configuration excludes `integration` tests.
- `pytest --cov` enforces an 80% coverage floor (`fail_under` in `pyproject.toml`).
- Required branch checks are the Ubuntu and macOS Python 3.12 `test` cells;
  helper and integration jobs remain additional signals.
- Live LLM and Secure Enclave tests have no automated workflow. VPN is the only
  live-gated suite with a manual workflow.

## `integration-vpn.yml` details

This workflow requires the `MORDRED_MULLVAD_ACCOUNT` repository secret and a
manual `mullvad_version` input. It installs the official daemon, runs
`tests/integration/test_vpn.py` with `MORDRED_LIVE_VPN_TEST=1`, then always
disconnects and logs out in teardown. It never runs automatically because it
uses a paid account and mutates runner network state.

## Manual live-device validation log

- **2026-05-25 — passed on real devices**:
  - `MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py -v`
  - `MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=... pytest -m integration tests/integration/test_vpn.py -v`
- **2026-08-21 — Slack E2E outbound channel-key binding passed on live Slack.**
  In an externally shared channel with a bound `K_chan`, an encrypted command
  reached the gateway, was released as `/version`, and received an encrypted
  reply that the browser extension rendered as the Hermes version with no
  decrypt failure. An agent-initiated top-level send also arrived as `ENC:v3`
  and decrypted, a plaintext post received the readable needs-key notice, and
  an unbound channel remained unchanged. The same end-user round-trip passed
  when the sender was an external Slack Connect member. The successful
  `app_mention` was stamped with the installing workspace; an earlier generic
  message supplied the external workspace scope and reproduced
  `key_not_bound_to_channel`. The captured generic-event shape now has strict
  regression coverage for the authenticated installing-team fallback,
  including stale-scope and forged-raw-team rejection.
- **2026-08-21 — isolated Slack `/hermes` slash-command dispatch passed on live
  Slack.** The app-level token was rotated to stop the competing Socket Mode
  client, and a fresh foreground gateway then received a Slack hello reporting
  one connection. In the installing workspace, `/hermes` carried a bare
  `ENC:v3` argument: the plaintext `/version`, Unicode lock, and Slack `:lock:`
  alias were absent from the wire value. The foreground gateway authenticated
  and released `/version`, and the bot posted a top-level encrypted reply. A
  Web API read confirmed that the reply was from the bot, decrypted under the
  bound channel key to `Hermes Agent v0.19.0`, and did not expose the version in
  plaintext. The gateway recorded no invalid-envelope, replay, encrypted-send,
  or Slack-send failure for the round trip.
- **2026-08-20 — agent-memory encryption passed on Apple Silicon with a running
  gateway.** Enabling memory encryption sealed the existing memory file and
  emitted the restart warning. After restarting the gateway, the Hermes memory
  seam read both existing entries, added and reloaded a temporary fact, and
  removed it again while the on-disk file remained mode `0600` with the
  `HERMES-MEMORY-ENC-v1` header; `encryption status` reported `memory [on]`.
  Disabling memory encryption restored the whole file to plaintext, the same
  two entries remained readable through Hermes, and the temporary fact was
  absent. The pre-test gateway and encryption states were restored afterward.

After changing a live-gated path, rerun the relevant command and append a dated
result here. Do not replace the previous result without recording the new date.
Tor and TPM use hermetic CI coverage and do not belong in this manual log.

## `upstream-check.yml` details

- Runs Monday at 03:00 UTC and by manual dispatch.
- Checks both the latest PyPI `hermes-agent` and a shallow clone of upstream
  `main`.
- `tools/check_hook_payload_drift.py` statically verifies `VALID_HOOKS` and the
  fields in literal `invoke_hook(...)` dispatches against
  `tools/hook_payload_contract.json`.
- A mismatch opens or updates an `actionable` + `upstream-drift` issue. It never
  patches Hermes or opens an upstream PR.
- `tests/test_hook_payload_drift.py` runs the same contract against the locally
  installed package and ensures contract keys match Mordred registrations.

## `labeler.yml` details

`.github/labeler.yml` maps repository paths to labels; the workflow applies
them with `contents: read` and `pull-requests: write`. Because it uses
`pull_request_target`, it must never check out or execute the PR head.

Required labels:

- `plugins/mordred-network`
- `plugins/mordred-privacy-check`
- `plugins/mordred-llm-guard`
- `plugins/mordred-keyvault`
- `plugins/mordred-wizard`
- `plugins/mordred-extension`
- `actionable`, `upstream-drift`, `docs`, and `ci`

## `dependabot.yml` details

`.github/dependabot.yml` keeps the SHA-pinned GitHub Actions current: weekly,
with all action bumps grouped into one `ci`-labelled PR against `dev`. Scope is
deliberately actions-only — Python dependencies are governed by
`pyproject.toml` floors plus `uv.lock` and the `hermes-floor` job, so pip/uv
update PRs would add review noise without a matching safety gain. It is not a
workflow, so the expected-path list in [Auditing](#auditing) is unchanged.

## `release.yml` details

Publishing is `workflow_dispatch` only and uses PyPI Trusted Publishing (OIDC),
not stored API tokens.

- `target`: `testpypi` or `pypi`.
- `mode=reserve`: the already-published permanent `mordred-hermes==0.0.0.dev0`
  name-reservation stub.
- `mode=reserve-rename`: the separate permanent
  `hermes-mordred==0.0.0.dev0` reservation required before the distribution
  rename.
- `mode=release`: the real package.
- `mode=compat`: the metadata-only legacy-name shim. The workflow refuses this
  mode unless the matching `hermes-mordred` version already exists on the
  selected index.
- `expected-version`: exact PEP 440 version required in source, wheel metadata,
  and sdist metadata.
- Production publishing accepts only `main` and never permits a CI-gate bypass.
- The build must produce exactly one wheel and one sdist with matching name and
  version.

### Initial setup (one-time, manual by the operator)

Completed 2026-07-07: TestPyPI/PyPI trusted publishers, GitHub environments,
and the `0.0.0.dev0` reservation are in place. Required reviewers on the
`pypi` environment are not yet configured: the setting was unavailable under
the former private-repository plan and has not been enabled since the
repository became public. Manual dispatch plus the production branch/CI gates
remain the compensating controls until a required reviewer is configured.

Completed 2026-08-12 for the `hermes-mordred` rename: pending publishers were
created on both indexes with owner `InternetMaximalism`, repository
`mordred-hermes`, workflow `release.yml`, and environments `testpypi` / `pypi`.
`reserve-rename` published `0.0.0.dev0` from main SHA `504e1b7ab` after exact-SHA
CI succeeded. Fresh installs from both indexes confirmed a dependency-free,
entry-point-free reservation with no `mordred_hermes` runtime package. The
historical `reserve` mode remains immutable and must not be dispatched again.

On 2026-08-12, after both `0.1.0a16` projects passed TestPyPI and production
verification, the repository was renamed to `mordredagent/hermes-mordred`.
All four publisher claims (two projects on both indexes) were replaced
add-first with the new repository claim while preserving `release.yml` and the
`testpypi` / `pypi` environments.

### Normal release (runbook)

1. Run `python tools/bump_version.py <version>`; never reuse a published PyPI
   version or edit version surfaces separately.
2. Run the full local checks and merge the version bump to `dev` through a PR.
3. Open the release PR from `dev` to `main`, aggregate the included PRs'
   Changes/Fixes entries, confirm CI, and merge.
4. Dispatch TestPyPI from `main` with `mode=release` and the exact expected
   version.
5. In a fresh venv, install `hermes-mordred` from TestPyPI (using PyPI as the
   dependency index) and verify six-entry-point discovery plus
   `hermes-mordred --version`.
6. Dispatch TestPyPI with `mode=compat`; install `mordred-hermes` in another
   fresh venv, verify that it resolves the matching canonical package, then
   uninstall only the shim and confirm the runtime package and CLI remain.
7. Repeat steps 4–6 against production PyPI, preserving the same canonical-first
   order.
8. Add annotated tag `v<version>` on the release merge and create the GitHub
   Release; mark pre-releases accordingly.

## Changelog convention

There is no `CHANGELOG.md`. Every PR description carries one entry per line
under `### Changes` and/or `### Fixes`; external contributions append
`Thanks @<author>`. A release PR aggregates those lines into its description,
tag annotation, and GitHub Release notes.

There is currently no PR template, so authors add the headings manually.

## Branching model (dev / main, introduced 2026-07-07)

- `dev` is the default integration branch. Feature PRs target `dev`.
- `main` is release-only and changes through `dev` → `main` PRs.
- CI runs for PRs and post-merge pushes to both branches.
- Scheduled workflows use the definition on the default `dev` branch.
- Release dispatches use the `main` ref.

## Branch protection (one-time setup)

Branch protection is not yet configured for `dev` or `main`: it was
unavailable under the former private-repository plan and has not been set up
since the repository became public. Protect both `dev` and `main`, require the
Ubuntu and macOS Python 3.12 test cells, require branches to be current, and
keep direct pushes to `main` disabled. Until that is done, the branching
convention above is the operational control.

## Auditing

List active workflows with:

```sh
gh api -X GET /repos/mordredagent/hermes-mordred/actions/workflows \
  --paginate --jq '.workflows[] | select(.state=="active") | .path' | sort
```

Expected paths are the five workflows in [Active workflows](#active-workflows).
Any additional workflow requires an explicit policy update and review.

## Future expansion

Add a documentation publishing workflow only when the project has a hosted docs
site. Add broader E2E automation only when it can run without production
credentials or state. Until then, keep the current workflows small and
purpose-specific.
