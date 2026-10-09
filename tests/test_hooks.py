"""Tests for on_session_start + pre_tool_call hook handlers (Phase E)."""

from __future__ import annotations

import dataclasses
import io
import json
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.privacy_check import _runtime, hooks
from mordred_hermes.privacy_check._exceptions import MordredIntegrityRefused


@pytest.fixture(autouse=True)
def _tool_egress_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests cover the legacy strict tool-name gate only; the tool-egress
    levels have their own suite (test_privacy_check_egress.py)."""
    from mordred_hermes.privacy_check import egress

    monkeypatch.setattr(egress, "load_policy", lambda *a, **k: egress.EgressPolicy(level="off"))


def _audit_entries(log_path: Path) -> list[dict[str, object]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]


def _write_config(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def reset_runtime() -> Iterator[None]:
    _runtime.reset_state_for_tests()
    yield
    _runtime.reset_state_for_tests()


@pytest.fixture
def strict_config(tmp_path: Path) -> Path:
    return _write_config(
        tmp_path / "config.yaml",
        """\
plugins:
  enabled:
    - mordred
  mordred_privacy_check:
    policy: strict
""",
    )


@pytest.fixture
def lenient_config(tmp_path: Path) -> Path:
    return _write_config(
        tmp_path / "config.yaml",
        """\
plugins:
  mordred_privacy_check:
    policy: lenient
""",
    )


@pytest.fixture
def off_config(tmp_path: Path) -> Path:
    return _write_config(
        tmp_path / "config.yaml",
        """\
plugins:
  mordred_privacy_check:
    policy: off
""",
    )


class TestOnSessionStartNoSiblingsDisabled:
    def test_emits_no_origin_skill_marker_once(self, strict_config: Path, tmp_path: Path) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        hooks.on_session_start(session_id="s1", model="m", platform="cli")
        # Second invocation must not duplicate the degraded marker
        hooks.on_session_start(session_id="s2", model="m", platform="cli")
        entries = _audit_entries(audit)
        no_origin = [e for e in entries if e.get("reason") == "mordred.degraded.no_origin_skill"]
        assert len(no_origin) == 1
        assert no_origin[0]["decision"] == "warn"
        assert no_origin[0]["event"] == "on_session_start"

    def test_does_not_poison_process(self, strict_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        hooks.on_session_start()
        assert not _runtime.is_poisoned()


class TestOnSessionStartStrictAbort:
    def test_enabled_sibling_with_registration_error_is_refused(
        self,
        strict_config: Path,
        tmp_path: Path,
    ) -> None:
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        plugins = {
            name: SimpleNamespace(
                enabled=True,
                error=None,
                module=object(),
                hooks_registered=list(_runtime.SIBLING_REQUIRED_HOOKS[name]),
            )
            for name in _runtime.SIBLING_PLUGINS
        }
        plugins["mordred"].error = "synthetic register failure"
        manager = SimpleNamespace(_plugins=plugins)

        with pytest.raises(MordredIntegrityRefused):
            hooks.check_plugin_integrity(plugin_manager=manager)

        assert _runtime.is_poisoned()

    def test_enabled_sibling_missing_mandatory_hook_is_refused(
        self,
        strict_config: Path,
        tmp_path: Path,
    ) -> None:
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        plugins = {
            name: SimpleNamespace(
                enabled=True,
                error=None,
                module=object(),
                hooks_registered=list(_runtime.SIBLING_REQUIRED_HOOKS[name]),
            )
            for name in _runtime.SIBLING_PLUGINS
        }
        plugins["mordred"].hooks_registered.remove("pre_api_request")

        with pytest.raises(MordredIntegrityRefused):
            hooks.check_plugin_integrity(
                plugin_manager=SimpleNamespace(_plugins=plugins),
            )

    def test_strict_with_disabled_sibling_raises_integrity_refusal(self, tmp_path: Path) -> None:
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred
  disabled:
    - mordred
  mordred_privacy_check:
    policy: strict
""",
        )
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=config, audit_path=audit)
        with pytest.raises(MordredIntegrityRefused):
            hooks.on_session_start()
        # Audit landed before the refusal
        entries = _audit_entries(audit)
        block_entries = [e for e in entries if e.get("decision") == "block"]
        assert len(block_entries) == 1
        assert block_entries[0]["reason"] == "mordred.degraded.disable_unprotected"
        assert block_entries[0]["disabled_siblings"] == ["mordred"]
        # Process is poisoned
        assert _runtime.is_poisoned()

    def test_refusal_survives_a_broken_stderr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The stderr presenter must never outrank the refusal.

        Review 2026-07-29: in a host with a closed stderr (daemonized
        gateway) the presenter's ``print`` raises an ordinary
        ``ValueError``, which Hermes's except-Exception hook wrapper would
        swallow — the session would start instead of aborting. Pin that
        the refusal still escapes.
        """
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred
  disabled:
    - mordred
  mordred_privacy_check:
    policy: strict
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        closed_stderr = io.StringIO()
        closed_stderr.close()
        monkeypatch.setattr(sys, "stderr", closed_stderr)
        with pytest.raises(MordredIntegrityRefused):
            hooks.on_session_start()
        assert _runtime.is_poisoned()

    def test_shared_integrity_hook_detects_disabled_mordred_plugin(self, tmp_path: Path) -> None:
        """The integrity gate still refuses when the whole plugin is disabled."""
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred
  disabled:
    - mordred
  mordred_privacy_check:
    policy: strict
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        with pytest.raises(MordredIntegrityRefused):
            hooks.check_plugin_integrity()
        assert _runtime.is_poisoned()

    def test_strict_with_only_legacy_plugin_names_raises_with_migration_hint(self, tmp_path: Path) -> None:
        """An unmigrated config lists the pre-0.2.0a0 names, which Hermes no longer loads."""
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred_privacy_check
    - mordred_network
    - mordred_llm_guard
    - mordred_keyvault
    - mordred_wizard
    - mordred_e2e
  mordred_privacy_check:
    policy: strict
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        with pytest.raises(MordredIntegrityRefused, match="hermes-mordred plugins migrate"):
            hooks.on_session_start()

    def test_strict_with_allowlist_missing_mordred_raises(self, tmp_path: Path) -> None:
        """Opt-in allowlist that excludes ``mordred`` counts as 'disabled'."""
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - some_other_plugin
  mordred_privacy_check:
    policy: strict
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        with pytest.raises(MordredIntegrityRefused) as excinfo:
            hooks.check_plugin_integrity()
        assert "plugins migrate" not in str(excinfo.value)
        assert _runtime.is_poisoned()

    def test_legacy_disabled_name_alone_no_longer_disables_anything(self, tmp_path: Path) -> None:
        """Hermes ignores the old per-component names; ``mordred`` enabled means loadable."""
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred
  disabled:
    - mordred_network
  mordred_privacy_check:
    policy: strict
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        hooks.check_plugin_integrity()
        assert not _runtime.is_poisoned()


class TestComponentIntegrity:
    """The single plugin reports a failed component like a failed sibling plugin used to be reported."""

    def _manager(self, plugin_module: Any) -> SimpleNamespace:
        loaded = SimpleNamespace(
            enabled=True,
            error=None,
            module=plugin_module,
            hooks_registered=sorted(_runtime.SIBLING_REQUIRED_HOOKS["mordred"]),
        )
        return SimpleNamespace(_plugins={"mordred": loaded})

    def test_failed_component_is_refused_in_strict(
        self, strict_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mordred_hermes import plugin

        hooks_by_component = dict(plugin.COMPONENT_REQUIRED_HOOKS)
        hooks_by_component.pop("network")
        monkeypatch.setattr(plugin, "component_errors", lambda: {"network": "RuntimeError: boom"})
        monkeypatch.setattr(plugin, "component_hooks", lambda: hooks_by_component)
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")

        with pytest.raises(MordredIntegrityRefused, match="mordred/network"):
            hooks.check_plugin_integrity(plugin_manager=self._manager(plugin))

    def test_component_missing_a_promised_hook_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import plugin

        hooks_by_component = dict(plugin.COMPONENT_REQUIRED_HOOKS)
        hooks_by_component["keyvault"] = frozenset({"on_session_start"})
        monkeypatch.setattr(plugin, "component_errors", dict)
        monkeypatch.setattr(plugin, "component_hooks", lambda: hooks_by_component)

        assert _runtime.find_unloaded_siblings(self._manager(plugin)) == {"mordred/keyvault"}

    def test_complete_components_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import plugin

        monkeypatch.setattr(plugin, "component_errors", dict)
        monkeypatch.setattr(plugin, "component_hooks", lambda: dict(plugin.COMPONENT_REQUIRED_HOOKS))

        assert _runtime.find_unloaded_siblings(self._manager(plugin)) == set()


class TestOnSessionStartLenientWithDisabled:
    def test_lenient_with_disabled_sibling_warns_and_continues(self, tmp_path: Path) -> None:
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred
  disabled:
    - mordred
  mordred_privacy_check:
    policy: lenient
""",
        )
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=config, audit_path=audit)
        # Should NOT raise
        hooks.on_session_start()
        entries = _audit_entries(audit)
        warn_entries = [e for e in entries if e.get("reason") == "mordred.degraded.disable_unprotected"]
        assert len(warn_entries) == 1
        assert warn_entries[0]["decision"] == "warn"
        # And NOT poisoned
        assert not _runtime.is_poisoned()


class TestPreToolCallStrict:
    @pytest.mark.parametrize("blocked_tool", ["web_fetch", "web_search"])
    def test_blocks_default_blocklist_on_clearnet(self, strict_config: Path, tmp_path: Path, blocked_tool: str) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        result = hooks.pre_tool_call(tool_name=blocked_tool, args={}, task_id="t", session_id="s", tool_call_id="c")
        assert result is not None
        assert result["action"] == "block"
        assert blocked_tool in result["message"]
        # Audit landed
        entries = _audit_entries(audit)
        blocks = [e for e in entries if e.get("event") == "pre_tool_call"]
        assert len(blocks) == 1
        assert blocks[0]["decision"] == "block"
        assert blocks[0]["reason"] == "policy.strict.clearnet"
        assert blocks[0]["tool_name"] == blocked_tool

    def test_allows_unlisted_tool(self, strict_config: Path, tmp_path: Path) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        result = hooks.pre_tool_call(tool_name="read_file")
        assert result is None
        # No pre_tool_call entries for allows
        entries = _audit_entries(audit)
        assert all(e.get("event") != "pre_tool_call" for e in entries)

    @pytest.mark.parametrize("active_path", ["tor", "vpn"])
    def test_allows_web_tools_on_ready_protected_path(
        self,
        strict_config: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        active_path: str,
    ) -> None:
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        monkeypatch.setattr(hooks, "_resolve_active_network_path", lambda: active_path)

        assert hooks.pre_tool_call(tool_name="web_fetch") is None
        assert hooks.pre_tool_call(tool_name="web_search") is None


class TestPreToolCallLenientAndOff:
    def test_lenient_allows_blocklisted_tool(self, lenient_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=lenient_config, audit_path=tmp_path / "audit.log")
        assert hooks.pre_tool_call(tool_name="web_fetch") is None

    def test_off_allows_blocklisted_tool(self, off_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=off_config, audit_path=tmp_path / "audit.log")
        assert hooks.pre_tool_call(tool_name="web_fetch") is None


class TestPoisonDefenseInDepth:
    def test_poisoned_process_blocks_every_tool(self, strict_config: Path, tmp_path: Path) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        _runtime.poison("synthetic poison reason for test")
        # Even tools NOT in the strict blocklist get blocked
        result = hooks.pre_tool_call(tool_name="read_file")
        assert result is not None
        assert result["action"] == "block"
        assert "synthetic poison" in result["message"]
        entries = _audit_entries(audit)
        blocks = [e for e in entries if e.get("event") == "pre_tool_call"]
        assert blocks[0]["reason"] == "mordred.degraded.disable_unprotected"


class TestKwargRobustness:
    def test_extra_kwargs_ignored(self, strict_config: Path, tmp_path: Path) -> None:
        """Hermes adds new payload fields without warning — handlers must tolerate."""
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        # Future-proof: pass an unexpected kwarg
        hooks.on_session_start(session_id="s", model="m", platform="cli", future_field=42)
        result = hooks.pre_tool_call(tool_name="read_file", args={}, future_field="x")
        assert result is None

    def test_missing_tool_name_treated_as_empty(self, strict_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        # No tool_name in payload — must not crash
        result = hooks.pre_tool_call()
        # Empty tool_name is not in blocklist, so allow
        assert result is None


class TestPolicyDefaults:
    def test_missing_section_defaults_to_lenient(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path / "config.yaml", "plugins: {}\n")
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        # Lenient mode allows web_fetch
        assert hooks.pre_tool_call(tool_name="web_fetch") is None

    def test_invalid_policy_value_fails_closed_to_strict(self, tmp_path: Path) -> None:
        # M1 port: an invalid mode in an EXISTING config reads as strict —
        # falling back to lenient let a corrupted value silently downgrade
        # enforcement.
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  mordred_privacy_check:
    policy: bogus
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        result = hooks.pre_tool_call(tool_name="web_fetch")
        assert result is not None
        assert result["action"] == "block"

    def test_missing_config_file_defaults_to_lenient(self, tmp_path: Path) -> None:
        non_existent = tmp_path / "nope.yaml"
        _runtime.ensure_state(config_path=non_existent, audit_path=tmp_path / "audit.log")
        assert hooks.pre_tool_call(tool_name="web_fetch") is None


class TestAllowCloudLlmStrictBool:
    """M2 (security review 2026-06-11): allow_cloud_llm must be a real bool.

    ``bool(section.get(...))`` truthy-coerced YAML strings — a hand-edited
    ``allow_cloud_llm: "false"`` silently *granted* cloud-LLM permission.
    Only ``True`` (the bool) may enable it; anything else reads as False.
    """

    def _config(self, tmp_path: Path, raw: str) -> Path:
        return _write_config(
            tmp_path / "config.yaml",
            f"""\
plugins:
  mordred_privacy_check:
    policy: strict
    allow_cloud_llm: {raw}
""",
        )

    @pytest.mark.parametrize("raw", ['"false"', '"true"', '"yes"', "1"])
    def test_non_bool_values_never_enable(self, raw: str, tmp_path: Path) -> None:
        state = _runtime.ensure_state(
            config_path=self._config(tmp_path, raw),
            audit_path=tmp_path / "audit.log",
        )
        assert state.allow_cloud_llm is False

    def test_real_bool_true_enables(self, tmp_path: Path) -> None:
        state = _runtime.ensure_state(
            config_path=self._config(tmp_path, "true"),
            audit_path=tmp_path / "audit.log",
        )
        assert state.allow_cloud_llm is True


# --------------------------------------------------------------------------- #
# safe_audit_append routing — an audit-write failure must not bypass a        #
# refusal decision (block / MordredIntegrityRefused)                         #
# --------------------------------------------------------------------------- #


class _RaisingAudit:
    """Audit writer whose ``append`` always raises — stands in for disk full,
    a permission flip, or an over-long NDJSON entry.

    Hermes wraps every hook callback in ``except Exception: log & continue``.
    Before the fix, ``state.audit.append(...)`` was called directly and its
    exception propagated straight into that wrapper — swallowed BEFORE the
    ``raise MordredIntegrityRefused`` / ``return {"action": "block"}`` a few
    lines later
    ever executed. That let a broken audit sink silently unblock a strict
    session. ``safe_audit_append`` must swallow this itself so the refusal
    below it is unconditionally reached.
    """

    def append(self, entry: Mapping[str, Any]) -> None:
        raise OSError("simulated disk full")


class TestAuditWriteFailureCannotBypassEnforcement:
    """Regression guard for routing audit writes through
    ``_audit_support.safe_audit_append`` instead of a bare
    ``state.audit.append(...)``. Every refusal path below must still fire
    even when the audit sink itself is broken.
    """

    def test_on_session_start_strict_disabled_sibling_still_refuses(self, tmp_path: Path) -> None:
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred
  disabled:
    - mordred
  mordred_privacy_check:
    policy: strict
""",
        )
        state = _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        _runtime._state = dataclasses.replace(state, audit=_RaisingAudit())
        with pytest.raises(MordredIntegrityRefused):
            hooks.on_session_start()
        # Defense in depth must still engage — the poison flag is the
        # backstop if a higher harness swallows the refusal.
        assert _runtime.is_poisoned()

    def test_pre_tool_call_poisoned_still_blocks(self, strict_config: Path, tmp_path: Path) -> None:
        state = _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        _runtime._state = dataclasses.replace(state, audit=_RaisingAudit())
        _runtime.poison("synthetic poison reason for test")
        result = hooks.pre_tool_call(tool_name="read_file")
        assert result is not None
        assert result["action"] == "block"

    def test_pre_tool_call_strict_allowlist_still_blocks(self, strict_config: Path, tmp_path: Path) -> None:
        state = _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        _runtime._state = dataclasses.replace(state, audit=_RaisingAudit())
        result = hooks.pre_tool_call(tool_name="web_fetch")
        assert result is not None
        assert result["action"] == "block"


# --------------------------------------------------------------------------- #
# _read_section_fail_closed type guards — a PRESENT but wrong-typed          #
# ``plugins`` / ``plugins.mordred_privacy_check`` is damage, not absence     #
# --------------------------------------------------------------------------- #


class TestReadSectionFailClosedTypeGuards:
    """A hand-edited or corrupted ``plugins: "oops"`` (or a wrong-typed own
    section) previously collapsed into the same branch as "plugin not
    configured yet" and returned lenient — silently downgrading enforcement
    on a damaged config. Both directions are asserted: the corrupted shapes
    must fail closed to strict, while genuine absence (no ``plugins:`` key,
    or an empty ``plugins: {}``) must keep resolving lenient.
    """

    def test_non_mapping_plugins_key_fails_closed_to_strict(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path / "config.yaml", 'plugins: "oops"\n')
        assert _runtime.get_active_policy_mode(config_path=config) == "strict"

    def test_non_mapping_own_section_fails_closed_to_strict(self, tmp_path: Path) -> None:
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  mordred_privacy_check: "oops"
""",
        )
        assert _runtime.get_active_policy_mode(config_path=config) == "strict"

    def test_empty_plugins_mapping_stays_lenient(self, tmp_path: Path) -> None:
        # Unchanged: an empty ``plugins: {}`` is the legitimate "nothing
        # configured yet" shape, not damage.
        config = _write_config(tmp_path / "config.yaml", "plugins: {}\n")
        assert _runtime.get_active_policy_mode(config_path=config) == "lenient"

    def test_missing_plugins_key_stays_lenient(self, tmp_path: Path) -> None:
        # Unchanged: no ``plugins:`` key at all is also legitimate absence.
        config = _write_config(tmp_path / "config.yaml", "other: 1\n")
        assert _runtime.get_active_policy_mode(config_path=config) == "lenient"

    def test_valid_section_still_resolves_normally(self, tmp_path: Path) -> None:
        # The type guards must not over-correct: a well-formed section keeps
        # resolving its declared policy.
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  mordred_privacy_check:
    policy: strict
""",
        )
        assert _runtime.get_active_policy_mode(config_path=config) == "strict"
