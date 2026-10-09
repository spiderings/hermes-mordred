"""Guards for the canonical user-facing CLI spelling.

``hermes-mordred`` works across the full supported Hermes range, before plugin
configuration, and on recovery paths. The registered host subcommand is a
compatibility alias, not an operator-facing spelling. Mixing the two forms in
guidance makes first-run and recovery instructions version-dependent.

This test walks every non-docstring string constant in the package and
rejects the space form. It also checks repository Markdown so README, user
guides, and developer sources of truth cannot drift back to mixed spelling.
The explicit compatibility note in ``README.md`` and future-migration item in
``ROADMAP.md`` are the only exceptions. This mirrors the narrower recovery-hint
guard in ``test_keyvault_config_bootstrap.py``.

Known limit (accepted): Python docstrings are developer-facing implementation
notes and remain outside the source-string scan.
"""

from __future__ import annotations

import ast
from pathlib import Path

import mordred_hermes

_PACKAGE_ROOT = Path(mordred_hermes.__file__).parent
_REPO_ROOT = _PACKAGE_ROOT.parents[1]
_SPACE_FORM = "hermes mordred"
_README = _REPO_ROOT / "README.md"
_README_COMPATIBILITY_NOTE = """Once Hermes 0.19.0+ is configured and the plugins are enabled,
`hermes mordred <command>` exposes the same command tree. On older Hermes
versions, or before the first `configure`, keep using `hermes-mordred`.
"""
_ROADMAP = _REPO_ROOT / "docs" / "dev" / "ROADMAP.md"
_ROADMAP_FUTURE_HEADING = "### v2-X4: Canonical Hermes subcommand"


def _docstring_node_ids(tree: ast.Module) -> set[int]:
    """ids of every Constant that is a module/class/function docstring."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            ids.add(id(body[0].value))
    return ids


def _offending_strings(source_file: Path) -> list[str]:
    tree = ast.parse(source_file.read_text(encoding="utf-8"))
    docstrings = _docstring_node_ids(tree)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in docstrings:
            continue
        if _SPACE_FORM in node.value:
            offenders.append(f"{source_file.name}:{node.lineno}: {node.value!r}")
    return offenders


def test_no_user_facing_space_form_guidance() -> None:
    offenders: list[str] = []
    for source_file in sorted(_PACKAGE_ROOT.rglob("*.py")):
        offenders.extend(_offending_strings(source_file))
    assert not offenders, "user-facing strings must use the canonical `hermes-mordred ...` spelling:\n" + "\n".join(
        offenders
    )


def test_markdown_uses_canonical_cli_spelling() -> None:
    markdown_files = [
        _REPO_ROOT / "README.md",
        *sorted((_REPO_ROOT / "docs").rglob("*.md")),
        *sorted((_REPO_ROOT / "tests" / "fixtures").rglob("*.md")),
    ]
    offenders: list[str] = []
    for path in markdown_files:
        text = path.read_text(encoding="utf-8")
        if path == _README:
            text = text.replace(_README_COMPATIBILITY_NOTE, "")
        if path == _ROADMAP and _ROADMAP_FUTURE_HEADING in text:
            before, future = text.split(_ROADMAP_FUTURE_HEADING, 1)
            _, separator, after = future.partition("\n## ")
            text = before + (f"\n## {after}" if separator else "")
        if _SPACE_FORM in text:
            offenders.append(str(path.relative_to(_REPO_ROOT)))
    assert not offenders, "Markdown must use the canonical `hermes-mordred ...` spelling:\n" + "\n".join(offenders)


def test_compatibility_exceptions_remain_documented() -> None:
    readme = _README.read_text(encoding="utf-8")
    roadmap = _ROADMAP.read_text(encoding="utf-8")
    assert _README_COMPATIBILITY_NOTE in readme
    assert _ROADMAP_FUTURE_HEADING in roadmap
    _, future = roadmap.split(_ROADMAP_FUTURE_HEADING, 1)
    future, _, _ = future.partition("\n## ")
    assert "`hermes mordred ...`" in future
