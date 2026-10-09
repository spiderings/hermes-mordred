# Mordred — Upstream Tracking (Hermes-base)

> **Status**: current repository relationship and compatibility procedure.
> This file owns the zero-upstream-PR rule. Historical migration alternatives
> remain available in Git history and are not implementation instructions.

## Repository position

`hermes-mordred` is a standalone plugin distribution for
[`NousResearch/hermes-agent`](https://github.com/NousResearch/hermes-agent).
It is not a fork and has no shared Git history with Hermes.

- Mordred code lives under `src/mordred_hermes/` and is published as the
  `hermes-mordred` PyPI distribution. The old `mordred-hermes` name is a
  metadata-only compatibility shim.
- Hermes is a normal runtime dependency resolved from PyPI.
- Compatibility work inspects an installed Hermes package, a read-only
  upstream checkout, or official upstream documentation.
- Normal development never merges or rebases Hermes history into this repo.

The single `hermes_agent.plugins` entry point in `pyproject.toml`, `mordred`, is
the public integration boundary. A future optional vendored layer would be separately
version-pinned and would not turn this repository into an upstream fork.

## Zero-PR commitment

**Mordred does not submit changes or pull requests to Hermes upstream.**

Use public plugin hooks and standalone wrappers where they provide an honest
boundary. If a security requirement cannot be enforced there, keep the
limitation explicit and move a version-pinned vendored-layer proposal through
ROADMAP → SPEC/PLAN before implementation. Do not describe a desired upstream
hook as if Mordred controls or has requested it.

Issues created by the upstream-drift workflow are local Mordred issues. They
track compatibility; they do not authorize an upstream patch.

## Optional remote

Add a remote only for read-only source inspection:

```sh
git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git
git fetch hermes-upstream
git log --oneline hermes-upstream/main -5
```

Never merge, rebase, or check out `hermes-upstream/main` onto a Mordred branch.
Use `git show hermes-upstream/main:<path>` or a separate temporary clone.

## Hook signature drift detection (informational only)

`tools/hook_payload_contract.json` lists the hook names and payload fields
Mordred actually consumes. The local test checks the installed supported
Hermes release; `.github/workflows/upstream-check.yml` also compares current
PyPI and upstream `main` weekly.

- Released-Hermes incompatibility can fail normal CI.
- Upstream-`main` drift opens or updates a local informational issue.
- A drift report never patches Hermes or opens an upstream PR.
- New upstream fields are not a Mordred contract until code, the machine
  contract, tests, and [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) adopt them
  together.

## Privacy-lock guard (replacement for the old HSeam-1)

Hermes can disable plugins through its normal configuration. Mordred cannot
prevent that edit from a plugin-only package, so v1 detects an incomplete
Mordred set at session start. [`SPEC.md`](./SPEC.md) §Plugin-disable protection
owns the behavior contract.

### Tier A: Plugin-side guard (v1 default, zero core change)

- Mordred is one plugin, `mordred`; its components cannot be disabled one by
  one. `privacy_check._runtime.SIBLING_PLUGINS` is `("mordred",)`, and a
  component that failed to register is reported as `mordred/<component>`.
- The plugin registers the shared `on_session_start` integrity callback before
  its components, and the `.pth` runtime bootstrap keeps a mandatory copy at
  the front of `on_session_start`, so disabling or not enabling `mordred` is
  still detected.
- Under `strict`, a disabled or incomplete plugin is audited and raises
  `MordredIntegrityRefused`, a direct `BaseException` subclass that escapes
  Hermes's ordinary `except Exception` hook wrapper.
- Under `lenient` or `off`, the condition is audited and warned, then execution
  continues.

The check occurs at the next session start; it does not intercept an edit made
inside an already-running process. If every runtime Mordred plugin is disabled,
no plugin callback can run. Those are explicit Tier A limits.

### Tier B: Vendored fork extra (v2, deferred)

No `hard-lock` extra or vendored Hermes module ships today. A future Tier B
could enforce a mandatory boundary before plugin disablement or skill process
launch, but only after:

1. its exact security property and supported Hermes version are specified;
2. a package/update/recovery strategy is designed;
3. the ordinary plugin-only install remains independent; and
4. [`ROADMAP.md`](./ROADMAP.md) security gates have been satisfied.

Tier B remains Mordred-owned distribution code. The zero-PR commitment still
applies.

## Conflict resolution (if a conflict occurs in the vendored fork)

There is no vendored tree today, so normal Mordred changes cannot conflict with
Hermes Git history. If Tier B is introduced, never merge a new upstream release
into an old vendored directory. Add a new versioned directory, reapply the
minimal reviewed patch, and run the complete compatibility/security suite.
Plugin code under `src/mordred_hermes/` remains Mordred-owned.

## Future migration

Revisit the relationship only when a concrete requirement cannot be met by the
public plugin package and the cost of maintaining a narrowly pinned vendored
layer is understood. A broader fork would require a new project decision; it
must not emerge incrementally from compatibility fixes.

Record an approved change in SPEC, PLAN, ROADMAP, CI, and packaging metadata.
Do not resurrect historical option tables as current guidance.

## Quick reference

- Hermes upstream URL: `https://github.com/NousResearch/hermes-agent`
- Mordred repository: `mordredagent/hermes-mordred`
- Distribution: `hermes-mordred` (PyPI; v1 is plugin-only)
- Legacy distribution alias: `mordred-hermes` (metadata-only compatibility shim)
- v2 candidate extra: `hermes-mordred[hard-lock]` (vendored fork, Tier B)
- Current integration: one pip entry-point plugin (`mordred`) plus `hermes-mordred`
- Upstream PRs: never submitted
- Vendored/hard-lock extra: not implemented; deferred
