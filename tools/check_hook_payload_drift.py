#!/usr/bin/env python3
"""Detect drift in the Hermes hook payload fields Mordred consumes.

This tool statically verifies both halves of Mordred's Hermes hook contract:
the contract hook names still exist in ``hermes_cli.plugins.VALID_HOOKS``, and
every core ``invoke_hook("<name>", key=value, ...)`` dispatch site still passes
the payload fields Mordred consumes (``tools/hook_payload_contract.json``).
It uses pure ``ast`` — nothing is imported or executed — so it works against
both an installed wheel and an uninstalled upstream checkout.

Rules:

- A contract hook with **no** dispatch site at all is drift — the hook name
  may still be in ``VALID_HOOKS`` while core stopped firing it.
- A contract field missing at **any** literal dispatch site is drift — the
  plugins read these via ``kwargs.get`` so they would degrade silently.
- A site spreading ``**kwargs`` is statically unknowable and is skipped.
- Imports of ``invoke_hook`` from both ``hermes_cli.plugins`` and
  ``hermes_cli.lifecycle`` are resolved under any local alias.

Exit status: 0 = no drift, 1 = drift (report on stdout), 2 = usage error.

Usage::

    python tools/check_hook_payload_drift.py \
        --hermes-root ../hermes-upstream \
        --contract tools/hook_payload_contract.json
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

#: Directory names never scanned (relative to ``--hermes-root``). ``tests``
#: and third-party ``plugins`` dispatch hooks for their own purposes; the
#: contract is about *core* dispatch sites. ``mordred-hermes`` keeps the
#: vendored-fork self-scan (and the canary test) from matching our own code.
DEFAULT_EXCLUDES = frozenset(
    {
        "__pycache__",
        "node_modules",
        "tests",
        "mordred-hermes",
        "website",
        "web",
        "plugins",
        "docs",
    }
)

#: Callee names that count as a hook dispatch. Core uses the plain import and
#: the ``invoke_hook as _invoke_hook`` alias; attribute calls
#: (``plugins.invoke_hook``) are matched by attribute name.
_DISPATCH_NAMES = frozenset({"invoke_hook", "_invoke_hook"})
_DISPATCH_MODULES = frozenset({"hermes_cli.plugins", "hermes_cli.lifecycle"})


@dataclass(frozen=True)
class DispatchSite:
    """One literal ``invoke_hook("<hook>", ...)`` call in the scanned tree."""

    file: str
    line: int
    fields: frozenset[str]
    has_dynamic_kwargs: bool


def _dispatch_names(tree: ast.AST) -> frozenset[str]:
    """Resolve supported ``invoke_hook`` imports to their local names."""
    names = set(_DISPATCH_NAMES)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module not in _DISPATCH_MODULES:
            continue
        for imported in node.names:
            if imported.name == "invoke_hook":
                names.add(imported.asname or imported.name)
    return frozenset(names)


def _hook_name(node: ast.Call, dispatch_names: frozenset[str]) -> str | None:
    """The literal hook name when ``node`` is a dispatch call, else None."""
    func = node.func
    if isinstance(func, ast.Name):
        callee = func.id
    elif isinstance(func, ast.Attribute):
        callee = func.attr
    else:
        return None
    if callee not in dispatch_names or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def extract_hook_payload_fields(
    root: Path, excludes: frozenset[str] = DEFAULT_EXCLUDES
) -> dict[str, list[DispatchSite]]:
    """Map hook name → dispatch sites found under ``root``.

    Unparseable / undecodable files are skipped: the scan must keep working
    against whatever an upstream checkout contains (templates, py2 relics).
    Hidden directories (``.git``, ``.venv``) are always skipped.
    """
    sites: dict[str, list[DispatchSite]] = {}
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        parents = rel.parts[:-1]
        if any(part in excludes or part.startswith(".") for part in parents):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            continue
        dispatch_names = _dispatch_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            hook = _hook_name(node, dispatch_names)
            if hook is None:
                continue
            sites.setdefault(hook, []).append(
                DispatchSite(
                    file=str(rel),
                    line=node.lineno,
                    fields=frozenset(kw.arg for kw in node.keywords if kw.arg is not None),
                    has_dynamic_kwargs=any(kw.arg is None for kw in node.keywords),
                )
            )
    return sites


def _literal_string_collection(node: ast.expr) -> set[str] | None:
    """Return a statically declared collection of strings, if possible."""
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        values = node.elts
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "frozenset"
        and len(node.args) == 1
        and not node.keywords
    ):
        return _literal_string_collection(node.args[0])
    else:
        return None
    result: set[str] = set()
    for value in values:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return None
        result.add(value.value)
    return result


def _valid_hooks_assignment(node: ast.stmt) -> tuple[bool, ast.expr | None]:
    """Return whether a statement assigns ``VALID_HOOKS`` and its value."""
    if isinstance(node, ast.Assign):
        targets = node.targets
        value = node.value if len(targets) == 1 else None
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
        value = node.value
    elif isinstance(node, ast.AugAssign):
        targets = [node.target]
        value = None
    else:
        return False, None
    matched = any(isinstance(target, ast.Name) and target.id == "VALID_HOOKS" for target in targets)
    return matched, value


def extract_valid_hooks(root: Path) -> set[str] | None:
    """Extract the one canonical module-level ``VALID_HOOKS`` declaration.

    Only ``hermes_cli/plugins.py`` owns this public contract. Missing, nested,
    dynamic, augmented, or multiple declarations are intentionally reported as
    unknowable instead of being masked by stale literals elsewhere in a source
    checkout or in the surrounding site-packages directory.
    """
    path = root / "hermes_cli" / "plugins.py"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
        return None

    assignments: list[ast.expr | None] = []
    for node in tree.body:
        matched, declaration = _valid_hooks_assignment(node)
        if matched:
            assignments.append(declaration)

    if len(assignments) != 1:
        return None
    declaration = assignments[0]
    if declaration is None:
        return None
    return _literal_string_collection(declaration)


def compare_valid_hooks(contract: dict[str, list[str]], valid_hooks: set[str]) -> list[str]:
    """Report contract hook names no longer declared by Hermes."""
    missing = sorted(set(contract) - valid_hooks)
    if not missing:
        return []
    return [f"VALID_HOOKS missing contract hook(s): {', '.join(missing)}"]


def compare(contract: dict[str, list[str]], sites: dict[str, list[DispatchSite]]) -> list[str]:
    """Drift messages for every contract violation (empty list = no drift)."""
    drift: list[str] = []
    for hook in sorted(contract):
        hook_sites = sites.get(hook, [])
        if not hook_sites:
            drift.append(f"{hook}: no invoke_hook dispatch site found — core may have stopped firing this hook")
            continue
        for site in hook_sites:
            if site.has_dynamic_kwargs:
                continue
            missing = sorted(set(contract[hook]) - set(site.fields))
            if missing:
                drift.append(f"{hook}: {site.file}:{site.line} missing payload field(s): {', '.join(missing)}")
    return drift


def load_contract(path: Path) -> dict[str, list[str]]:
    """Load the contract, dropping ``_``-prefixed comment keys."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--hermes-root",
        required=True,
        type=Path,
        help="root of the Hermes source tree to scan (e.g. an upstream clone)",
    )
    parser.add_argument(
        "--contract",
        required=True,
        type=Path,
        help="path to hook_payload_contract.json",
    )
    args = parser.parse_args(argv)
    if not args.hermes_root.is_dir():
        print(f"error: --hermes-root {args.hermes_root} is not a directory")
        return 2

    contract = load_contract(args.contract)
    sites = extract_hook_payload_fields(args.hermes_root)
    valid_hooks = extract_valid_hooks(args.hermes_root)
    drift = []
    if valid_hooks is None:
        drift.append("VALID_HOOKS: expected exactly one static module-level declaration in hermes_cli/plugins.py")
    else:
        drift.extend(compare_valid_hooks(contract, valid_hooks))
    drift.extend(compare(contract, sites))
    if drift:
        print("hook contract drift detected:")
        for entry in drift:
            print(f"  - {entry}")
        return 1
    scanned = sum(len(v) for v in sites.values())
    print(f"hook contract satisfied ({len(contract)} hooks, {scanned} dispatch sites scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
