"""Tests for ``mordred_hermes.llm_guard.harness_detect``.

Harnesses (Codex CLI, Claude CLI, Cursor, ACP clients) bypass Hermes hooks for
their own LLM traffic. Under strict policy
:func:`mordred_llm_guard.harness_detect.check_harness_primary` refuses the
session; under lenient it warns + audits but continues; under off it is a
no-op.

The primary is declared in ``~/.hermes/config.yaml`` under
``plugins.mordred_llm_guard.harness_primary: str``. The wizard will write
this in PR2; in PR1 we only consume it.

Why prefix-based (not equality): ACP clients identify as ``acp-<flavor>``
(e.g. ``acp-claude``), and CLI installers sometimes append a version
suffix (``codex-0.130.0``). False-positive guard: a provider name that
*contains* but does not *start with* a harness keyword (e.g. ``my-cursor-helper``
or ``codex-style-prompt``) must not trigger; only the documented prefixes
``codex``, ``claude-cli``, ``cursor``, ``acp-`` qualify.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest


# Tiny audit writer double — captures appended dicts for assertions.
class _FakeAuditWriter:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Mapping[str, Any]) -> None:
        self.entries.append(entry)


def _write_config(tmp_path: Path, harness_primary: str | None) -> Path:
    """Synthesise ``~/.hermes/config.yaml`` with the given harness declaration."""
    cfg = tmp_path / "config.yaml"
    if harness_primary is None:
        # Section present but no harness key (absent-key path).
        cfg.write_text(
            "plugins:\n  mordred_llm_guard:\n    enabled: true\n",
            encoding="utf-8",
        )
    else:
        cfg.write_text(
            f"plugins:\n  mordred_llm_guard:\n    harness_primary: {harness_primary}\n",
            encoding="utf-8",
        )
    return cfg


# --------------------------------------------------------------------------- #
# strict — refusal path                                                       #
# --------------------------------------------------------------------------- #


class TestStrictRefuses:
    @pytest.mark.parametrize(
        "harness",
        ["codex", "claude-cli", "cursor", "acp-claude", "acp-cline", "codex-0.130.0"],
    )
    def test_known_primary_raises_refused(self, tmp_path: Path, harness: str) -> None:
        from mordred_hermes.llm_guard._exceptions import MordredHarnessRefused
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary=harness)
        audit = _FakeAuditWriter()

        with pytest.raises(MordredHarnessRefused, match=harness):
            check_harness_primary(policy_mode="strict", config_path=cfg, audit=audit)

        # Audit emits the degraded entry BEFORE raising so the refusal is observable.
        assert audit.entries, "audit must record the refusal even on raise"
        entry = audit.entries[-1]
        assert entry["event"] == "on_session_start"
        assert entry["decision"] == "block"
        assert entry["reason"] == "mordred.degraded.disable_unprotected"
        assert entry["harness_primary"] == harness

    def test_refusal_escapes_except_exception(self, tmp_path: Path) -> None:
        """Same propagation contract as :class:`MordredHarnessRefused`."""
        from mordred_hermes.llm_guard._exceptions import MordredHarnessRefused
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary="codex")
        audit = _FakeAuditWriter()

        try:
            try:
                check_harness_primary(policy_mode="strict", config_path=cfg, audit=audit)
            except Exception:
                pytest.fail("refusal must not be swallowed by except Exception")
        except MordredHarnessRefused:
            pass  # expected


# --------------------------------------------------------------------------- #
# lenient — warn + audit, no exception                                        #
# --------------------------------------------------------------------------- #


class TestLenientWarnsButContinues:
    def test_known_primary_warns_and_audits(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary="codex")
        audit = _FakeAuditWriter()

        with caplog.at_level(logging.WARNING, logger="mordred.llm_guard.harness_detect"):
            check_harness_primary(policy_mode="lenient", config_path=cfg, audit=audit)

        # No exception. Audit decision=warn (matches privacy_check
        # mordred.degraded.disable_unprotected lenient semantics).
        assert audit.entries
        entry = audit.entries[-1]
        assert entry["decision"] == "warn"
        assert entry["reason"] == "mordred.degraded.disable_unprotected"
        assert entry["harness_primary"] == "codex"
        # Log line so the user actually sees the degradation.
        assert any("codex" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# off — silent no-op                                                          #
# --------------------------------------------------------------------------- #


class TestOffIsNoop:
    def test_off_skips_audit_even_with_harness(self, tmp_path: Path) -> None:
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary="codex")
        audit = _FakeAuditWriter()

        check_harness_primary(policy_mode="off", config_path=cfg, audit=audit)
        assert audit.entries == [], "off mode must not write to audit"


# --------------------------------------------------------------------------- #
# absent / non-harness — no-op regardless of mode                             #
# --------------------------------------------------------------------------- #


class TestAbsentHarness:
    @pytest.mark.parametrize("policy_mode", ["strict", "lenient", "off"])
    def test_missing_field_is_noop(self, tmp_path: Path, policy_mode: str) -> None:
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary=None)
        audit = _FakeAuditWriter()

        check_harness_primary(policy_mode=policy_mode, config_path=cfg, audit=audit)
        assert audit.entries == []

    @pytest.mark.parametrize("policy_mode", ["strict", "lenient"])
    @pytest.mark.parametrize(
        "non_harness",
        # Strings that mention a harness keyword but do NOT prefix-match.
        ["my-cursor-helper", "anthropic", "codex-style-prompt", "acpd-not-real", ""],
    )
    def test_non_prefix_match_is_noop(self, tmp_path: Path, policy_mode: str, non_harness: str) -> None:
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary=non_harness)
        audit = _FakeAuditWriter()

        check_harness_primary(policy_mode=policy_mode, config_path=cfg, audit=audit)
        assert audit.entries == [], f"non-prefix match must not trigger: harness_primary={non_harness!r}"

    def test_missing_config_file_is_noop(self, tmp_path: Path) -> None:
        """Wizard not yet run — strict must not abort before the user can configure."""
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = tmp_path / "nonexistent.yaml"
        audit = _FakeAuditWriter()

        check_harness_primary(policy_mode="strict", config_path=cfg, audit=audit)
        assert audit.entries == []


# --------------------------------------------------------------------------- #
# Defense in depth — invalid policy_mode treated as lenient                   #
# --------------------------------------------------------------------------- #


class TestInvalidPolicyMode:
    def test_unknown_mode_falls_back_to_lenient(self, tmp_path: Path) -> None:
        """If policy.json got corrupted, fall back to the safer warning path
        rather than either silently allowing (off) or aborting (strict).
        """
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary="codex")
        audit = _FakeAuditWriter()

        check_harness_primary(policy_mode="garbage", config_path=cfg, audit=audit)  # type: ignore[arg-type]
        assert audit.entries
        assert audit.entries[-1]["decision"] == "warn"


# --------------------------------------------------------------------------- #
# Audit fail-open guard (security review H1)                                  #
# --------------------------------------------------------------------------- #


class _RaisingAuditWriter:
    """Audit writer whose ``append`` always raises a plain ``Exception``.

    Simulates disk-full / broken-path / permission-denied at the audit
    boundary. The strict-mode refusal must still fire: if the raw
    ``Exception`` escaped, Hermes' ``except Exception:`` wrapper would
    catch it and continue the session — a fail-open bypass.
    """

    def append(self, entry: Mapping[str, Any]) -> None:
        raise RuntimeError("audit sink unavailable (disk full)")


class TestAuditFailureDoesNotFailOpen:
    def test_strict_refusal_fires_even_when_audit_append_raises(self, tmp_path: Path) -> None:
        from mordred_hermes.llm_guard._exceptions import MordredHarnessRefused
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary="codex")
        audit = _RaisingAuditWriter()

        # The audit write fails, but strict mode must STILL raise the
        # BaseException-derived refusal — not let the plain RuntimeError
        # propagate (which Hermes' except Exception would swallow).
        with pytest.raises(MordredHarnessRefused):
            check_harness_primary(policy_mode="strict", config_path=cfg, audit=audit)

    def test_lenient_continues_when_audit_append_raises(self, tmp_path: Path) -> None:
        from mordred_hermes.llm_guard.harness_detect import check_harness_primary

        cfg = _write_config(tmp_path, harness_primary="codex")
        audit = _RaisingAuditWriter()

        # Lenient mode warns + continues; an audit failure must not turn a
        # non-fatal warning into a crash.
        check_harness_primary(policy_mode="lenient", config_path=cfg, audit=audit)
