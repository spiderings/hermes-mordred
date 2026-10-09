# Single source of truth for the hermes-mordred package version.
#
# Hatchling reads ``__version__`` from this file at build time
# (``[tool.hatch.version] path`` in pyproject.toml), so the version is NOT
# hardcoded in pyproject. This file lives INSIDE the importable package —
# not in the docs tree (docs/dev/VERSION) — because the sdist only includes
# /src, /tests, /README.md, /pyproject.toml, /native, /packaging/pth
# (see [tool.hatch.build.targets.sdist] in pyproject.toml); docs/ is excluded,
# so a wheel built from that sdist can't see the docs-tree VERSION marker
# Keeping the canonical value here is the
# build-isolation-safe resolution of that follow-up.
#
# Bump with `python tools/bump_version.py <new-version>`, which rewrites this
# file, the docs VERSION marker, and every plugin.yaml in lockstep. The
# consistency is pinned by tests/test_packaging_versions.py.
__version__ = "0.2.0a1"
