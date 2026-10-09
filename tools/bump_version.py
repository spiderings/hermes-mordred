#!/usr/bin/env python3
"""Bump the hermes-mordred version everywhere it is hardcoded, in lockstep.

The build's single source of truth is ``src/mordred_hermes/__about__.py`` —
Hatch reads ``__version__`` from it (``[tool.hatch.version] path``). But a
release version also appears in surfaces that are not auto-derived from it:

  - src/mordred_hermes/__about__.py    (__version__ — the canonical source)
  - docs/dev/VERSION                 (docs-tree marker; a human mirror)
  - docs/dev/setup.md                (the ``--reinstall`` install pin)
  - packaging/mordred-hermes-compat/pyproject.toml
                                      (shim version + exact forwarded deps)

This rewrites every mirrored surface in one command, including the shim's
version and exact forwarded dependencies. ``tests/test_packaging_versions.py``
pins that they agree, so CI catches any surface a hand-edit forgets. The
name-reservation stub (``packaging/name-reservation/pyproject.toml``) is
intentionally NOT touched — it stays permanently at ``0.0.0.dev0`` (M7).

Usage:
    python tools/bump_version.py 0.1.0a1
    python tools/bump_version.py 0.1.0 --dry-run
    python tools/bump_version.py 0.1.0a0 --allow-non-increasing   # re-sync only
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable
from pathlib import Path

from packaging.version import InvalidVersion, Version

_PKG_ROOT = Path(__file__).resolve().parent.parent
_ABOUT = _PKG_ROOT / "src" / "mordred_hermes" / "__about__.py"
_DOC_VERSION = _PKG_ROOT / "docs" / "dev" / "VERSION"
_SETUP_MD = _PKG_ROOT / "docs" / "dev" / "setup.md"
_COMPAT_PYPROJECT = _PKG_ROOT / "packaging" / "mordred-hermes-compat" / "pyproject.toml"

_ABOUT_VALUE_RE = re.compile(r"""(?m)^__version__\s*=\s*["']([^"']+)["']\s*$""")
_ABOUT_LINE_RE = re.compile(r"""(?m)^__version__\s*=\s*["'][^"']+["'][^\n]*$""")
#: `hermes-mordred[extra1,extra2]==<version>` copy-paste install pins.
_INSTALL_PIN_RE = re.compile(r"(hermes-mordred\[[^\]]*\]==)[0-9][^\s\"']*")
_COMPAT_VERSION_RE = re.compile(r"""(?m)^version\s*=\s*["'][^"']+["']\s*$""")
_COMPAT_REQUIREMENT_RE = re.compile(r"(hermes-mordred(?:\[[^\]]+\])?==)[0-9][^\s\"']*")


def _current_version() -> str:
    match = _ABOUT_VALUE_RE.search(_ABOUT.read_text(encoding="utf-8"))
    if match is None:
        sys.exit(f"error: no __version__ assignment found in {_ABOUT}")
    return match.group(1)


def _rewrite(
    path: Path,
    pattern: re.Pattern[str],
    replacement: str | Callable[[re.Match[str]], str],
    *,
    count: int = 1,
    dry_run: bool,
) -> bool:
    """Replace ``pattern`` matches in ``path`` with ``replacement``.

    ``count`` follows ``re.subn`` semantics: 1 (the default) replaces only the
    first match, 0 replaces every match. Returns True if the file changed.

    A plain string ``replacement`` is passed through a lambda so backslashes
    in a version string can't be misread as regex group refs; pass a callable
    directly when the replacement must reuse captured groups (e.g. to keep
    surrounding text a pattern matched but shouldn't overwrite).
    """
    text = path.read_text(encoding="utf-8")
    replace_fn = replacement if callable(replacement) else (lambda _m: replacement)
    new_text, n = pattern.subn(replace_fn, text, count=count)
    if n == 0:
        sys.exit(f"error: pattern {pattern.pattern!r} not found in {path}")
    if new_text == text:
        return False
    if not dry_run:
        path.write_text(new_text, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bump hermes-mordred version in lockstep.")
    parser.add_argument("version", help="new PEP 440 version, e.g. 0.1.0a1 / 0.1.0b0 / 0.1.0")
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing")
    parser.add_argument(
        "--allow-non-increasing",
        action="store_true",
        help="permit a version <= the current one (e.g. to re-sync drifted files)",
    )
    args = parser.parse_args(argv)

    try:
        new = Version(args.version)
    except InvalidVersion:
        sys.exit(f"error: {args.version!r} is not a valid PEP 440 version")

    current = Version(_current_version())
    if new <= current and not args.allow_non_increasing:
        sys.exit(
            f"error: new version {new} is not greater than current {current}. "
            "Pass --allow-non-increasing to override (e.g. re-syncing drifted files)."
        )

    # Version() may canonicalize (e.g. 0.1.0-alpha0 -> 0.1.0a0); write that form.
    new_str = str(new)
    targets: list[tuple[Path, re.Pattern[str], str | Callable[[re.Match[str]], str], int]] = [
        (_ABOUT, _ABOUT_LINE_RE, f'__version__ = "{new_str}"', 1),
    ]
    if _DOC_VERSION.exists():
        targets.append((_DOC_VERSION, re.compile(r"(?s).*"), f"{new_str}\n", 1))
    else:
        print(f"warning: docs marker {_DOC_VERSION} absent — skipping", file=sys.stderr)
    if _SETUP_MD.exists():
        targets.append((_SETUP_MD, _INSTALL_PIN_RE, lambda m: f"{m.group(1)}{new_str}", 0))
    else:
        print(f"warning: dev-setup doc {_SETUP_MD} absent — skipping", file=sys.stderr)
    targets.append((_COMPAT_PYPROJECT, _COMPAT_VERSION_RE, f'version = "{new_str}"', 1))
    targets.append(
        (
            _COMPAT_PYPROJECT,
            _COMPAT_REQUIREMENT_RE,
            lambda m: f"{m.group(1)}{new_str}",
            0,
        )
    )

    label = "would update" if args.dry_run else "updated"
    changed = 0
    for path, pattern, replacement, count in targets:
        if _rewrite(path, pattern, replacement, count=count, dry_run=args.dry_run):
            changed += 1
            print(f"  {label}: {path.relative_to(_PKG_ROOT)}")
        else:
            print(f"  unchanged: {path.relative_to(_PKG_ROOT)}")

    print(f"\n{current} -> {new_str}  ({changed} file(s) {label})")
    if not args.dry_run:
        print(
            "\nNext: add a changelog entry, then verify with\n"
            "  uv run pytest tests/test_packaging_versions.py\n"
            "  uv build   # confirm sdist + wheel still build"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
