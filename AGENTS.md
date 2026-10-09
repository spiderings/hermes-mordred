# AGENTS.md

Guidance for AI coding agents working in this repository. Everything here is a
condensed pointer — the documents under `docs/dev/` are the source of truth.

## What this repo is

Standalone package repository for **hermes-mordred**, a plugin suite for
[hermes-agent](https://pypi.org/project/hermes-agent/). It ships ONE entry-point
plugin, `mordred` (`src/mordred_hermes/plugin.py`), whose `register()` wires the
components in `src/mordred_hermes/` in a fixed order: `keyvault`, `llm_guard`,
`network`, `privacy_check`, `e2e` (`extension/gateway_plugin.py`), `wizard`.
The pre-0.2.0a0 per-component plugin names (`mordred_network`, ...) survive
only as `plugins.mordred_*` config section names and are migrated out of
`plugins.enabled` / `plugins.disabled` (`_plugin_identity.py`). It is **not** a fork of Hermes upstream — never send
PRs upstream (zero-PR commitment, `docs/dev/UPSTREAM.md`).

## Setup and everyday commands

```sh
uv sync --all-extras                      # one-time: .venv with hermes-agent + editable install
uv run pytest -q                          # unit suite (integration marker excluded by default)
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run mypy --strict src tools scripts/keyvault_offline_digest.py
shellcheck scripts/*.sh native/*/build.sh # blocking in CI; brew/apt install shellcheck
uv run pytest --cov=src/mordred_hermes    # coverage; CI floor is 80%
```

Full guide: `docs/dev/setup.md`. Always go through `uv run` / `.venv/bin/…`;
bare `pytest` or `hermes-mordred` may hit a different environment via PATH.

## Critical gotchas

- **Two venvs coexist.** The repo `.venv/` is an editable install (runs
  `src/` directly); `~/.hermes/hermes-agent/venv` runs the released PyPI wheel.
  Version strings cannot tell them apart — check `mordred_hermes.__file__`.
  See `docs/dev/setup.md` §"Two venvs".
- **CI type-checks with fewer extras.** CI installs `.[dev,keyvault,extension]`
  (+ `macos` on macOS runners) — not `--all-extras`. Type errors involving
  `eth_hash` / `eth_account` / `stem` (the `ethereum` / `tor-control` extras)
  pass locally but fail CI. If you touch that code, reproduce in a venv with
  only those extras before pushing. See `docs/dev/CI.md`.
- **Destructive CLI ceremonies read/write production state.** `configure`,
  `keyvault init`, `network init`, and `setup` (which drives all three) touch
  the real `~/.hermes/` unless isolated:
  `env HERMES_HOME=/tmp/mordred-test-home .venv/bin/hermes-mordred configure`
  (fish needs the `env` prefix). Read-only commands (`status`, `audit tail`)
  are safe.
- **Port 7788 belongs to the production extension gateway.** For local runs use
  `.venv/bin/hermes-mordred extension serve --port 7799`; check holders with
  `lsof -nP -iTCP:7788 -sTCP:LISTEN`.
- **Live-gated tests require explicit execution.** Secure Enclave and live-LLM
  suites have no CI automation. The Mullvad suite has a manual-only GitHub
  Actions workflow (`integration-vpn.yml`); it never runs on pushes or PRs.
  Run the relevant gated path after changing it and record the result in
  `docs/dev/CI.md` §Manual live-device validation log.

## Git and PR conventions

- **`dev` is the default branch.** Feature PRs target `dev`; `main` is updated
  only via dev→main release PRs (`docs/dev/CI.md` §Branching model).
- **One plugin, one PR.** Don't touch two plugins in the same change; if a
  cross-plugin change is needed, PR the SPEC/PLAN side first.
- **Parallel agent sessions need separate git worktrees.** Branch refs and the
  index are repo-global, so concurrent sessions sharing one checkout stomp each
  other — create one with `git worktree add ../hermes-mordred-<topic> -b <branch>`.
- **No CHANGELOG.md.** Record changes as one-line entries under `### Changes` /
  `### Fixes` headings in each PR description (`docs/dev/CI.md` §Changelog
  convention).
- **Releases:** bump with `python tools/bump_version.py <version>` (updates all
  pinned surfaces at once; `tests/test_packaging_versions.py` enforces
  agreement), then follow the runbook in `docs/dev/CI.md` §Normal release.

## Documentation rules

- All documentation is written in **English**, including `docs/dev/`.
- Don't rename existing headings — other docs and code comments cite them
  by name.
- Source-of-truth map: `SPEC.md` (what to build), `PLAN.md` (how), `TODO.md`
  (task order), `CI.md` (CI policy), `PATHS.md` (filesystem paths),
  `UPSTREAM.md` (relationship with Hermes upstream) — all under `docs/dev/`.
