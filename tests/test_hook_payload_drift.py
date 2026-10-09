"""Tests for ``tools/check_hook_payload_drift.py``.

The drift tool statically verifies both ``VALID_HOOKS`` membership and every
core ``invoke_hook("<name>", key=value, ...)`` payload consumed by Mordred.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import textwrap
from pathlib import Path

import pytest

MORDRED_HERMES_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = MORDRED_HERMES_ROOT / "tools"
CONTRACT_PATH = TOOLS_DIR / "hook_payload_contract.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("check_hook_payload_drift", TOOLS_DIR / "check_hook_payload_drift.py")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves ``cls.__module__`` through sys.modules at class
    # creation time — register before exec or the @dataclass decorator fails.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


drift = _load_tool()


def _write(tmp_path: Path, rel: str, body: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")


class TestExtract:
    def test_extracts_literal_invoke_hook_kwargs(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "core.py",
            """\
            from hermes_cli.plugins import invoke_hook as _invoke_hook

            def start(self):
                _invoke_hook(
                    "on_session_start",
                    session_id=self.session_id,
                    model=self.model,
                    platform="cli",
                )
            """,
        )
        sites = drift.extract_hook_payload_fields(tmp_path)
        assert set(sites) == {"on_session_start"}
        (site,) = sites["on_session_start"]
        assert set(site.fields) == {"session_id", "model", "platform"}
        assert not site.has_dynamic_kwargs
        assert site.line > 0

    def test_unaliased_and_attribute_calls_match(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "a.py",
            """\
            from hermes_cli import plugins

            def f():
                plugins.invoke_hook("on_session_end", session_id="s")

            def g():
                invoke_hook("on_session_end", completed=True)
            """,
        )
        sites = drift.extract_hook_payload_fields(tmp_path)
        assert len(sites["on_session_end"]) == 2

    def test_resolves_plugins_and_lifecycle_import_aliases(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "aliases.py",
            """\
            from hermes_cli.lifecycle import invoke_hook as invoke_lifecycle_hook
            from hermes_cli.plugins import invoke_hook as dispatch_plugin_hook

            invoke_lifecycle_hook("on_session_start", session_id="s")
            dispatch_plugin_hook("on_session_end", session_id="s")
            """,
        )
        sites = drift.extract_hook_payload_fields(tmp_path)
        assert set(sites) == {"on_session_start", "on_session_end"}

    def test_does_not_accept_an_alias_imported_from_an_unrelated_module(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "unrelated.py",
            """\
            from unrelated import invoke_hook as invoke_lifecycle_hook

            invoke_lifecycle_hook("on_session_start", session_id="s")
            """,
        )
        assert drift.extract_hook_payload_fields(tmp_path) == {}

    def test_dynamic_kwargs_are_flagged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "b.py",
            """\
            def f(payload):
                invoke_hook("pre_tool_call", **payload)
            """,
        )
        (site,) = drift.extract_hook_payload_fields(tmp_path)["pre_tool_call"]
        assert site.has_dynamic_kwargs

    def test_non_literal_hook_name_is_ignored(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "c.py",
            """\
            def f(name):
                invoke_hook(name, tool_name="x")
            """,
        )
        assert drift.extract_hook_payload_fields(tmp_path) == {}

    def test_default_excludes_skip_tests_and_mordred_hermes(self, tmp_path: Path) -> None:
        body = """\
        def f():
            invoke_hook("on_session_start", session_id="s")
        """
        _write(tmp_path, "tests/t.py", body)
        _write(tmp_path, "mordred-hermes/src/x.py", body)
        assert drift.extract_hook_payload_fields(tmp_path) == {}

    def test_unparseable_file_is_skipped(self, tmp_path: Path) -> None:
        _write(tmp_path, "broken.py", "def f(:\n")
        _write(
            tmp_path,
            "ok.py",
            """\
            def f():
                invoke_hook("on_session_end")
            """,
        )
        assert set(drift.extract_hook_payload_fields(tmp_path)) == {"on_session_end"}


class TestCompare:
    def _sites(self, tmp_path: Path, body: str):
        _write(tmp_path, "core.py", body)
        return drift.extract_hook_payload_fields(tmp_path)

    def test_satisfied_contract_reports_no_drift(self, tmp_path: Path) -> None:
        sites = self._sites(
            tmp_path,
            """\
            def f():
                invoke_hook("pre_tool_call", tool_name="t", args={}, task_id="")
            """,
        )
        assert drift.compare({"pre_tool_call": ["tool_name"]}, sites) == []

    def test_missing_field_is_drift(self, tmp_path: Path) -> None:
        sites = self._sites(
            tmp_path,
            """\
            def f():
                invoke_hook("pre_tool_call", task_id="")
            """,
        )
        report = drift.compare({"pre_tool_call": ["tool_name"]}, sites)
        assert len(report) == 1
        assert "tool_name" in report[0]

    def test_hook_never_dispatched_is_drift(self, tmp_path: Path) -> None:
        sites = self._sites(tmp_path, "x = 1\n")
        report = drift.compare({"pre_api_request": ["provider"]}, sites)
        assert len(report) == 1
        assert "pre_api_request" in report[0]

    def test_dynamic_kwargs_site_is_tolerated(self, tmp_path: Path) -> None:
        sites = self._sites(
            tmp_path,
            """\
            def f(payload):
                invoke_hook("pre_tool_call", **payload)
            """,
        )
        assert drift.compare({"pre_tool_call": ["tool_name"]}, sites) == []

    def test_field_missing_at_any_one_site_is_drift(self, tmp_path: Path) -> None:
        sites = self._sites(
            tmp_path,
            """\
            def f():
                invoke_hook("pre_tool_call", tool_name="t")

            def g():
                invoke_hook("pre_tool_call", task_id="")
            """,
        )
        report = drift.compare({"pre_tool_call": ["tool_name"]}, sites)
        assert len(report) == 1


class TestValidHooks:
    @pytest.mark.parametrize("annotated", [False, True])
    def test_extracts_assign_and_annassign(self, tmp_path: Path, annotated: bool) -> None:
        declaration = (
            'VALID_HOOKS: set[str] = {"pre_tool_call", "on_session_start"}'
            if annotated
            else 'VALID_HOOKS = {"pre_tool_call", "on_session_start"}'
        )
        _write(tmp_path, "hermes_cli/plugins.py", declaration)

        assert drift.extract_valid_hooks(tmp_path) == {"pre_tool_call", "on_session_start"}

    def test_extracts_a_frozenset_literal(self, tmp_path: Path) -> None:
        _write(tmp_path, "hermes_cli/plugins.py", 'VALID_HOOKS = frozenset(("pre_tool_call",))')
        assert drift.extract_valid_hooks(tmp_path) == {"pre_tool_call"}

    def test_dynamic_declaration_is_not_claimed_as_static(self, tmp_path: Path) -> None:
        _write(tmp_path, "hermes_cli/plugins.py", "VALID_HOOKS = load_hooks()")
        assert drift.extract_valid_hooks(tmp_path) is None

    def test_ignores_stale_literals_outside_the_canonical_module(self, tmp_path: Path) -> None:
        _write(tmp_path, "hermes_cli/plugins.py", "VALID_HOOKS = load_hooks()")
        _write(tmp_path, "dependency.py", 'VALID_HOOKS = {"pre_tool_call"}')
        _write(
            tmp_path,
            "hermes_cli/legacy.py",
            """\
            def stale():
                VALID_HOOKS = {"pre_tool_call"}
            """,
        )

        assert drift.extract_valid_hooks(tmp_path) is None

    def test_multiple_or_augmented_canonical_assignments_are_drift(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "hermes_cli/plugins.py",
            """\
            VALID_HOOKS = {"pre_tool_call"}
            VALID_HOOKS = {"pre_tool_call", "on_session_start"}
            """,
        )
        assert drift.extract_valid_hooks(tmp_path) is None

        _write(
            tmp_path,
            "hermes_cli/plugins.py",
            """\
            VALID_HOOKS = {"pre_tool_call"}
            VALID_HOOKS |= {"on_session_start"}
            """,
        )
        assert drift.extract_valid_hooks(tmp_path) is None

    def test_nested_dead_code_is_not_a_module_declaration(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "hermes_cli/plugins.py",
            """\
            if False:
                VALID_HOOKS = {"pre_tool_call"}
            """,
        )
        assert drift.extract_valid_hooks(tmp_path) is None

    def test_contract_hooks_must_be_a_subset(self) -> None:
        report = drift.compare_valid_hooks(
            {"pre_tool_call": ["tool_name"], "on_session_start": ["session_id"]},
            {"pre_tool_call"},
        )
        assert report == ["VALID_HOOKS missing contract hook(s): on_session_start"]


class TestContractFile:
    def _registered_hooks(self) -> set[str]:
        """Hook names Mordred plugins actually register (literal call sites)."""
        hooks: set[str] = set()
        for path in (MORDRED_HERMES_ROOT / "src" / "mordred_hermes").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "register_hook"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    hooks.add(node.args[0].value)
        return hooks

    def test_contract_keys_match_registered_hooks(self) -> None:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        keys = {k for k in contract if not k.startswith("_")}
        assert keys == self._registered_hooks(), (
            "hook_payload_contract.json must list exactly the hooks Mordred "
            "registers — update the contract when plugins add/drop hooks"
        )

    def test_contract_values_are_sorted_field_lists(self) -> None:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        for key, value in contract.items():
            if key.startswith("_"):
                continue
            assert isinstance(value, list), key
            assert all(isinstance(f, str) for f in value), key
            assert value == sorted(value), f"{key}: keep fields sorted"


class TestInstalledHermesCanary:
    def test_installed_hermes_satisfies_contract(self) -> None:
        """The installed hermes-agent package must pass the same check
        upstream-check.yml runs in CI — if this fails, either upstream truly
        drifted (sync brought the drift in) or the contract/excludes need
        updating.

        Pre-split, this scanned a vendored Hermes source tree checked into
        the monorepo alongside this package. Standalone mordred-hermes has no
        such tree — it just depends on the hermes-agent PyPI package — so
        this mirrors upstream-check.yml's approach instead: point the AST
        scanner at wherever the currently-installed hermes-agent's source
        lives (its site-packages parent directory), which works because pip
        installs plain, uncompiled ``.py`` files.
        """
        contract = {
            k: v for k, v in json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).items() if not k.startswith("_")
        }
        hermes_cli = pytest.importorskip("hermes_cli")
        hermes_root = Path(hermes_cli.__file__).resolve().parent.parent
        sites = drift.extract_hook_payload_fields(hermes_root)
        valid_hooks = drift.extract_valid_hooks(hermes_root)
        assert sites, "no invoke_hook dispatch sites found in the installed hermes-agent package"
        assert valid_hooks is not None, "no static VALID_HOOKS declaration found in installed hermes-agent"
        assert drift.compare_valid_hooks(contract, valid_hooks) == []
        assert drift.compare(contract, sites) == []
