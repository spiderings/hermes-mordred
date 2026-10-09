# mordred-hermes — name reservation stub

This directory builds an **intentionally empty `0.0.0.dev0` package**.

It is **not** the real Mordred privacy plugin bundle. Its only purpose is
to claim the `mordred-hermes` name on TestPyPI and PyPI *before* the
public documentation launch, so a third party cannot squat the name and
ship a malicious package before the real distribution was released.

The old project shipped the real bundle through `0.1.0a15`. From `0.1.0a16`,
it is continued by the metadata-only compatibility package in
[`packaging/mordred-hermes-compat/`](../mordred-hermes-compat/), while the real
bundle is published as `hermes-mordred`.

## Build & publish

The publish path is `.github/workflows/release.yml`:

- `mode=reserve` — historical route that built **this stub**. Both uploads are
  complete; do not dispatch it again.
- `mode=compat` — builds and uploads the metadata-only continuation of this
  legacy project after the matching canonical release.

See `docs/dev/CI.md` § `release.yml` for the operator runbook
(PyPI Trusted Publishing / pending-publisher setup).
