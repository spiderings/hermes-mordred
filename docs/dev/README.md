# Developer documentation

Start with [`setup.md`](./setup.md) for the editable environment and safe local
validation. This index lists every maintained developer document; completed
design diaries and upstream snapshots remain available through Git history.

## Current sources of truth

| Document | Owns |
|---|---|
| [`SPEC.md`](./SPEC.md) | Supported behavior, threat model, and product boundaries |
| [`PLAN.md`](./PLAN.md) | Current implementation shape and maintenance approach |
| [`WINDOWS_FEASIBILITY.md`](./WINDOWS_FEASIBILITY.md) | Windows feasibility, actual-device findings, and proposed delivery sequence |
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
| [`WINDOWS_CONFIG_IO.md`](./WINDOWS_CONFIG_IO.md) | Canonical Windows configuration API, ownership and verification |
| [`WINDOWS_AUDIT_IO.md`](./WINDOWS_AUDIT_IO.md) | Opt-in checked audit sessions, bounded rotation, and validation |

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
- Run the documentation link test and the standard repository checks after
  editing these files.
