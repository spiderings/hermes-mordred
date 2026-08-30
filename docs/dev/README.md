# Developer documentation

Start with [`setup.md`](./setup.md) for the editable environment and safe local
validation. This index lists every maintained developer document; superseded
design notes and historical upstream-fork snapshots are still available
through Git history (`git log -- docs/dev/`) but are no longer maintained.

## Current sources of truth

| Document | Owns |
|---|---|
| [`SPEC.md`](./SPEC.md) | Supported behavior, threat model, and product boundaries |
| [`PLAN.md`](./PLAN.md) | Current implementation shape and maintenance approach |
| [`TODO.md`](./TODO.md) | Actionable work for the current release |
| [`ROADMAP.md`](./ROADMAP.md) | Deferred work and its prerequisites |
| [`CI.md`](./CI.md) | CI, branching, release, and changelog policy |
| [`PATHS.md`](./PATHS.md) | Every filesystem path Mordred reads or manages |
| [`POLICY.md`](./POLICY.md) | Policy schema, decisions, and audit reason codes |
| [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) | Consumed Hermes hook fields and drift validation |
| [`SLACK_E2E.md`](./SLACK_E2E.md) | Gateway `ENC:v3` wire and mandatory-E2E behavior |
| [`UPSTREAM.md`](./UPSTREAM.md) | Hermes compatibility and the zero-PR commitment |

## Operational and design references

| Document | Purpose |
|---|---|
| [`setup.md`](./setup.md) | Development setup, the two venvs, and isolated validation |

When prose and code disagree, the typed implementation, tests, CLI parser, and
machine contracts named by the relevant document take precedence. Correct the
prose in the same change; do not preserve superseded guidance in the working
tree solely as history.

## Maintenance rules

- Keep all documentation in English.
- Do not rename existing headings; other documents and code comments cite them.
- Use repo-relative links between local documents. README links intended to
  render on PyPI may use absolute GitHub `main` URLs.
- Keep current behavior in the source-of-truth document and change history in
  Git and PR descriptions. This repository has no `CHANGELOG.md` or docs
  archive directory.
- Update package versions only with `python tools/bump_version.py <version>`.
- After editing these files, run `uv run pytest tests/test_docs_links.py`
  plus `uv run ruff check src tests scripts`,
  `uv run ruff format --check src tests scripts`,
  `uv run mypy --strict src tools scripts/keyvault_offline_digest.py`, and
  the full `uv run pytest -q`.
