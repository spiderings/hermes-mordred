"""Keep maintained Markdown links inside the repository valid."""

from __future__ import annotations

import argparse
import html
import re
import subprocess
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

_EXCLUDED_DIRS = {".claude", ".git", ".pytest_cache", ".venv"}
_INLINE_LINK_RE = re.compile(r"!?\[[^\]\n]*\]\(\s*(?:<(?P<angle>[^>]+)>|(?P<plain>[^\s)]+))")
_REFERENCE_LINK_RE = re.compile(
    r"^\s*\[[^\]\n]+\]:\s*(?:<(?P<angle>[^>]+)>|(?P<plain>\S+))",
    re.MULTILINE,
)
_HTML_LINK_RE = re.compile(r"\bhref=[\"'](?P<target>[^\"']+)[\"']", re.IGNORECASE)
_EXPLICIT_ANCHOR_RE = re.compile(
    r"<a\s+[^>]*(?:id|name)=[\"'](?P<anchor>[^\"']+)[\"'][^>]*>",
    re.IGNORECASE,
)
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$", re.MULTILINE)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_JAPANESE_OR_CJK_RE = re.compile(r"[\u3040-\u30ff\u3400-\u9fff]")
_CANONICAL_LINE_REF_RE = re.compile(
    r"\b(?:SPEC|PLAN|TODO|PATHS|POLICY|HOOK_PAYLOADS|CI)(?:\.md)?[^\n]{0,100}\bL\d+(?:-\d+)?\b"
)

_MAINTAINED_DEV_DOCS = {
    "CI.md",
    "HOOK_PAYLOADS.md",
    "PATHS.md",
    "PLAN.md",
    "POLICY.md",
    "README.md",
    "ROADMAP.md",
    "SLACK_E2E.md",
    "SPEC.md",
    "TODO.md",
    "UPSTREAM.md",
    "WINDOWS_FEASIBILITY.md",
    "WINDOWS_CONFIG_IO.md",
    "WINDOWS_AUDIT_IO.md",
    "setup.md",
}

_REMOVED_DOC_NAMES = {
    "MIGRATION.md",
    "HARNESS_PRIVACY.md",
    "KEYVAULT_BACKENDS.md",
    "SECRETS_ENV_ENCRYPTION.md",
    "HERMES_BASICS.md",
    "hermes/DESIGN.md",
    "hermes/STRUCTURE.md",
}

_TEXT_SUFFIXES = {".json", ".md", ".py", ".sh", ".toml", ".yaml", ".yml"}

_PLUGIN_PACKAGE_READMES = {
    ROOT / "src" / "mordred_hermes" / plugin / "README.md"
    for plugin in ("extension", "keyvault", "llm_guard", "network", "privacy_check", "wizard")
}


def _git_visible_files(root: Path) -> list[Path]:
    """Return tracked and non-ignored untracked files when Git is available."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        result = None

    if result is not None and result.returncode == 0:
        candidates = (root / relative for relative in result.stdout.split("\0") if relative)
    else:
        # Source archives may not include .git. Their contents are already
        # selected by the package manifest, so a filesystem fallback is safe.
        candidates = root.rglob("*")

    return [
        path
        for path in sorted(candidates)
        if path.is_file() and not any(part in _EXCLUDED_DIRS for part in path.relative_to(root).parts)
    ]


def _markdown_files() -> list[Path]:
    return [path for path in _git_visible_files(ROOT) if path.suffix == ".md"]


def _repository_text_files() -> list[Path]:
    return [path for path in _git_visible_files(ROOT) if path.suffix in _TEXT_SUFFIXES]


def _without_fenced_code(text: str) -> str:
    """Blank fenced blocks while retaining line numbers for diagnostics."""
    output: list[str] = []
    fence: str | None = None
    for line in text.splitlines(keepends=True):
        marker = line.lstrip()[:3]
        if marker in {"```", "~~~"}:
            fence = None if fence == marker else marker if fence is None else fence
            output.append("\n" if line.endswith("\n") else "")
        elif fence is None:
            output.append(line)
        else:
            output.append("\n" if line.endswith("\n") else "")
    return "".join(output)


def _destinations(text: str) -> list[tuple[int, str]]:
    visible = _without_fenced_code(text)
    found: list[tuple[int, str]] = []
    for pattern in (_INLINE_LINK_RE, _REFERENCE_LINK_RE):
        for match in pattern.finditer(visible):
            target = match.group("angle") or match.group("plain")
            found.append((visible.count("\n", 0, match.start()) + 1, target))
    for match in _HTML_LINK_RE.finditer(visible):
        found.append((visible.count("\n", 0, match.start()) + 1, match.group("target")))
    return found


def _github_slug(title: str) -> str:
    title = html.unescape(re.sub(r"<[^>]+>", "", title)).lower()
    title = re.sub(r"[`*_~]", "", title)
    chars = [char for char in title if char in {"-", "_", " "} or unicodedata.category(char)[0] in {"L", "N"}]
    return "".join(chars).strip().replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    anchors = {html.unescape(match.group("anchor")) for match in _EXPLICIT_ANCHOR_RE.finditer(text)}
    occurrences: dict[str, int] = {}
    for match in _HEADING_RE.finditer(_without_fenced_code(text)):
        base = _github_slug(match.group("title"))
        index = occurrences.get(base, 0)
        occurrences[base] = index + 1
        anchors.add(base if index == 0 else f"{base}-{index}")
    return anchors


def _local_target(source: Path, destination: str) -> tuple[Path, str] | None:
    destination = html.unescape(destination.strip())
    if not destination or destination.startswith("//") or _SCHEME_RE.match(destination):
        return None

    path_text, _, fragment = destination.partition("#")
    path_text = unquote(path_text.partition("?")[0])
    if not path_text:
        target = source
    elif path_text.startswith("/"):
        target = ROOT / path_text.lstrip("/")
    else:
        target = source.parent / path_text
    return target.resolve(), unquote(fragment)


def test_local_markdown_links_resolve() -> None:
    failures: list[str] = []
    root = ROOT.resolve()

    for source in _markdown_files():
        text = source.read_text(encoding="utf-8")
        for line, destination in _destinations(text):
            resolved = _local_target(source, destination)
            if resolved is None:
                continue
            target, fragment = resolved
            label = f"{source.relative_to(ROOT)}:{line}: {destination}"
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{label} escapes the repository")
                continue
            if not target.exists():
                failures.append(f"{label} does not exist")
                continue
            if fragment and target.is_file() and target.suffix.lower() == ".md" and fragment not in _anchors(target):
                failures.append(f"{label} has no matching anchor")

    assert not failures, "broken local Markdown links:\n" + "\n".join(failures)


def test_repository_scan_excludes_ignored_files_but_keeps_untracked_files(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text("ignored.md\n.idea/\n", encoding="utf-8")
    (tmp_path / "ignored.md").write_text("local notes\n", encoding="utf-8")
    (tmp_path / "visible.md").write_text("review me\n", encoding="utf-8")
    editor_dir = tmp_path / ".idea"
    editor_dir.mkdir()
    (editor_dir / "scratch.md").write_text("local scratch\n", encoding="utf-8")

    visible = {path.relative_to(tmp_path) for path in _git_visible_files(tmp_path)}

    assert Path("visible.md") in visible
    assert Path(".gitignore") in visible
    assert Path("ignored.md") not in visible
    assert Path(".idea/scratch.md") not in visible


def test_developer_index_is_complete() -> None:
    dev_dir = ROOT / "docs" / "dev"
    actual = {str(path.relative_to(dev_dir)) for path in _markdown_files() if path.is_relative_to(dev_dir)}
    assert actual == _MAINTAINED_DEV_DOCS

    index = (dev_dir / "README.md").read_text(encoding="utf-8")
    missing = sorted(name for name in _MAINTAINED_DEV_DOCS - {"README.md"} if f"./{name}" not in index)
    assert not missing, f"docs/dev/README.md does not index: {missing}"


def test_root_readme_indexes_every_user_document() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    user_dir = ROOT / "docs" / "user"
    user_docs = [path for path in _markdown_files() if path.parent == user_dir]
    missing = [path.name for path in user_docs if f"docs/user/{path.name}" not in readme]
    assert not missing, f"README.md does not index: {missing}"


def test_plugin_packages_do_not_duplicate_canonical_docs() -> None:
    visible_markdown = set(_markdown_files())
    duplicates = sorted(str(path.relative_to(ROOT)) for path in _PLUGIN_PACKAGE_READMES if path in visible_markdown)
    assert not duplicates, f"plugin-local README files duplicate canonical docs: {duplicates}"


def test_removed_documents_are_not_referenced() -> None:
    failures: list[str] = []
    for path in _repository_text_files():
        if path.resolve() == Path(__file__).resolve():
            continue
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for removed in _REMOVED_DOC_NAMES:
                if removed in line:
                    failures.append(f"{path.relative_to(ROOT)}:{line_no}: {removed}")
    assert not failures, "references to removed documents:\n" + "\n".join(failures)


def test_canonical_docs_are_not_cited_by_line_number() -> None:
    failures: list[str] = []
    for path in _repository_text_files():
        if path.resolve() == Path(__file__).resolve():
            continue
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            # Two legacy HOOK_PAYLOADS headings are stable inbound anchors and
            # cannot be renamed; their body explicitly marks the old line refs
            # as historical. No prose or code may add another brittle citation.
            if path.suffix == ".md" and line.lstrip().startswith("#"):
                continue
            if _CANONICAL_LINE_REF_RE.search(line):
                failures.append(f"{path.relative_to(ROOT)}:{line_no}: {line.strip()}")
    assert not failures, "brittle canonical-document line references:\n" + "\n".join(failures)


def test_usage_documents_every_top_level_cli_command() -> None:
    from mordred_hermes.wizard._cli_parsers import _setup_subparser

    parser = argparse.ArgumentParser()
    _setup_subparser(parser, required=False)
    subparsers = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    usage = (ROOT / "docs" / "user" / "USAGE.md").read_text(encoding="utf-8")
    missing = sorted(command for command in subparsers.choices if f"### `{command}`" not in usage)
    assert not missing, f"USAGE.md omits top-level CLI commands: {missing}"


def _direct_subcommands(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


def _documented_spec_cli_tree() -> dict[str, set[str]]:
    spec = (ROOT / "docs" / "dev" / "SPEC.md").read_text(encoding="utf-8")
    match = re.search(r"```text\nstatus\nsetup\n(?P<tail>.*?)\n```", spec, re.DOTALL)
    assert match is not None, "SPEC.md is missing the canonical CLI tree"

    entries: dict[str, str] = {}
    current = ""
    for line in ("status\nsetup\n" + match.group("tail")).splitlines():
        if line[:1].isspace():
            assert current, f"SPEC.md CLI continuation has no parent: {line!r}"
            entries[current] += " " + line.strip()
            continue
        parts = line.split(maxsplit=1)
        current = parts[0]
        entries[current] = parts[1] if len(parts) == 2 else ""

    return {command: set(re.findall(r"[a-z][a-z0-9-]*", children)) for command, children in entries.items()}


def test_spec_cli_tree_matches_parser_direct_subcommands() -> None:
    from mordred_hermes.wizard._cli_parsers import _setup_subparser

    parser = argparse.ArgumentParser()
    _setup_subparser(parser, required=False)
    subparsers = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    documented = _documented_spec_cli_tree()

    assert set(documented) == set(subparsers.choices), "SPEC.md top-level CLI tree differs from the parser"
    mismatches = {
        command: {
            "documented": sorted(documented[command]),
            "parser": sorted(_direct_subcommands(command_parser)),
        }
        for command, command_parser in subparsers.choices.items()
        if documented[command] != _direct_subcommands(command_parser)
    }
    assert not mismatches, f"SPEC.md direct subcommands differ from the parser: {mismatches}"


def test_setup_guides_include_agent_memory_encryption() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_setup = readme.split("### Use it", 1)[1].split("### Verify discovery", 1)[0]
    usage = (ROOT / "docs" / "user" / "USAGE.md").read_text(encoding="utf-8")
    usage_setup = usage.split("## 2. First-run quickstart", 1)[1].split("## 3. Command reference", 1)[0]
    quickstart = (ROOT / "docs" / "user" / "QUICKSTART.md").read_text(encoding="utf-8")
    quickstart_setup = quickstart.split("## 2. First run, in order", 1)[1].split(
        "## 3. Fastest path: secrets encrypted at rest", 1
    )[0]
    spec = (ROOT / "docs" / "dev" / "SPEC.md").read_text(encoding="utf-8")
    spec_setup = spec.split("`setup` is a re-runnable first-run orchestrator", 1)[1].split(
        "## Operational Guarantees & Caveats", 1
    )[0]

    for name, section in {
        "README.md": readme_setup,
        "docs/user/USAGE.md": usage_setup,
        "docs/user/QUICKSTART.md": quickstart_setup,
    }.items():
        assert "encryption enable memory" in section, f"{name} setup sequence omits memory encryption"
    assert "agent-memory encryption" in spec_setup, "SPEC.md setup contract omits memory encryption"


def test_maintained_docs_do_not_embed_a_developer_home_path() -> None:
    failures = [
        str(path.relative_to(ROOT)) for path in _markdown_files() if "/Users/" in path.read_text(encoding="utf-8")
    ]
    assert not failures, f"developer-specific absolute paths in docs: {failures}"


def test_maintained_docs_contain_no_japanese_or_cjk_text() -> None:
    failures = [
        str(path.relative_to(ROOT))
        for path in _markdown_files()
        if _JAPANESE_OR_CJK_RE.search(path.read_text(encoding="utf-8"))
    ]
    assert not failures, f"non-English Japanese/CJK text in maintained docs: {failures}"
