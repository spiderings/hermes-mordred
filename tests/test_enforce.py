"""Tests for ``mordred_hermes.llm_guard.enforce`` — TDD Cycle A.

Phase 2 PR2 — v1 refuse-only decision matrix. Cycle A covers the three
"do not raise" axes:

- off mode: silent no-op regardless of provider
- lenient mode: silent no-op (v1 stays silent to avoid per-session spam)
- strict + cloud provider in allowlist AND ``allow_cloud_llm: true``:
  passthrough with an ``allow``-decision audit entry

Later cycles (B/C/D) extend this file with the refuse paths, the
mordred-local probe path, and policy.json fallbacks. Audit-reason shape
gets its own dedicated file (``test_enforce_audit.py``, Cycle E).

Patterns mirror ``test_harness_detect.py``:

- ``_FakeAuditWriter`` captures appended dicts for shape assertions.
- ``_write_policy_json`` synthesises a minimal ``policy.json`` fixture
  per case so the decision-matrix axes are independent.
- ``_noop_probe`` is injected as ``health_probe`` so the local-provider
  branch (added in Cycle C) doesn't touch real HTTP.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.llm_guard import enforce
from mordred_hermes.llm_guard._exceptions import (
    MordredLocalUnreachable,
    MordredSessionRefused,
)


class _FakeAuditWriter:
    """Captures audit appends so tests can assert reason / decision / fields."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Mapping[str, Any]) -> None:
        self.entries.append(entry)


def _noop_probe(_endpoint: str) -> None:
    """Health probe that always succeeds — used by Cycle C strict+local tests."""
    return None


def _failing_probe(_endpoint: str) -> None:
    raise MordredLocalUnreachable("simulated probe failure")


def _write_policy_json(
    tmp_path: Path,
    *,
    policy: str = "strict",
    allow_cloud_llm: bool = False,
    cloud_provider_allowlist: tuple[str, ...] = (),
    local_llm_endpoint: str = "http://localhost:1234/v1",
) -> Path:
    body = {
        "policy": policy,
        "allow_cloud_llm": allow_cloud_llm,
        "cloud_provider_allowlist": list(cloud_provider_allowlist),
        "local_llm_endpoint": local_llm_endpoint,
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _clear_sdk_base_url_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every provider-SDK endpoint override from the test environment.

    A developer machine may legitimately export ``ANTHROPIC_BASE_URL``; the
    absent-endpoint assertions below are about policy, not the ambient shell.
    """
    for name in enforce._SDK_BASE_URL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _check_strict_local_endpoint(
    tmp_path: Path,
    *,
    source: str,
    endpoint: str,
    audit: _FakeAuditWriter,
    health_probe: Callable[[str], None],
) -> None:
    """Exercise the policy.json or runtime-base-url local endpoint path."""
    policy_endpoint = endpoint
    cfg = _write_policy_json(tmp_path, policy="strict", local_llm_endpoint=policy_endpoint)
    if source == "policy":
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=health_probe,
        )
        return
    enforce.check_runtime_provider(
        policy_mode="strict",
        policy_json_path=cfg,
        active_provider="mordred-local",
        audit=audit,
        health_probe=health_probe,
        runtime_base_url=endpoint,
    )


# --------------------------------------------------------------------------- #
# off mode — silent no-op                                                     #
# --------------------------------------------------------------------------- #


class TestOffMode:
    @pytest.mark.parametrize(
        "active_provider",
        [None, "mordred-local", "anthropic", "openai", "totally-unknown"],
    )
    def test_off_is_noop(self, tmp_path: Path, active_provider: str | None) -> None:
        cfg = _write_policy_json(tmp_path, policy="off")
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="off",
            policy_json_path=cfg,
            active_provider=active_provider,
            audit=audit,
            health_probe=_noop_probe,
        )

        assert audit.entries == [], "off mode must not write to audit"


# --------------------------------------------------------------------------- #
# lenient mode — silent no-op                                                 #
# --------------------------------------------------------------------------- #


class TestLenientMode:
    @pytest.mark.parametrize(
        "active_provider",
        [None, "mordred-local", "anthropic", "totally-unknown"],
    )
    def test_lenient_does_not_raise(self, tmp_path: Path, active_provider: str | None) -> None:
        cfg = _write_policy_json(tmp_path, policy="lenient")
        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="lenient",
            policy_json_path=cfg,
            active_provider=active_provider,
            audit=audit,
            health_probe=_noop_probe,
        )

    def test_lenient_is_silent(self, tmp_path: Path) -> None:
        """v1 emits nothing under lenient — future versions may emit an
        allow-with-reason; revisit then.
        """
        cfg = _write_policy_json(tmp_path, policy="lenient")
        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="lenient",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            health_probe=_noop_probe,
        )
        assert audit.entries == []


# --------------------------------------------------------------------------- #
# strict + cloud allowlisted (with allow_cloud_llm=True) — passthrough        #
# --------------------------------------------------------------------------- #


class TestStrictCloudAllowlisted:
    def test_strict_cloud_in_allowlist_allow(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic", "openai"),
        )
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            health_probe=_noop_probe,
        )

        assert audit.entries, "allowlisted cloud must emit an allow audit"
        entry = audit.entries[-1]
        assert entry["decision"] == "allow"
        assert entry["provider_id"] == "anthropic"

    def test_strict_cloud_allowed_does_not_raise(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("openai",),
        )
        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="openai",
            audit=audit,
            health_probe=_noop_probe,
        )


# --------------------------------------------------------------------------- #
# Cycle B — strict + cloud NOT allowlisted (refuse)                           #
# --------------------------------------------------------------------------- #


class TestStrictCloudRefused:
    def test_strict_provider_not_in_allowlist_raises(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),  # NOT openai
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="openai"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_strict_allow_cloud_llm_false_vetoes_allowlist(self, tmp_path: Path) -> None:
        """``allow_cloud_llm: false`` must veto allowlist membership.

        Allowlist membership and the global cloud-LLM switch are both required.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=False,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="allow_cloud_llm"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_refusal_emits_both_classification_and_action(self, tmp_path: Path) -> None:
        """Codex N1 (POLICY.md row 8): classification reason
        ``policy.strict.cloud_not_allowlisted`` is emitted alongside the
        action ``policy.strict.session_refused`` so consumers can filter
        on either axis.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="bedrock",
                audit=audit,
                health_probe=_noop_probe,
            )

        reasons = [e["reason"] for e in audit.entries]
        assert "policy.strict.cloud_not_allowlisted" in reasons
        assert "policy.strict.session_refused" in reasons

    def test_refusal_escapes_except_exception(self, tmp_path: Path) -> None:
        """Codex H2: ``MordredSessionRefused`` is ``BaseException``-derived
        so cleanup-style ``except Exception:`` cannot swallow it.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")  # empty allowlist
        audit = _FakeAuditWriter()

        try:
            try:
                enforce.check_session_provider(
                    policy_mode="strict",
                    policy_json_path=cfg,
                    active_provider="anthropic",
                    audit=audit,
                    health_probe=_noop_probe,
                )
            except Exception:
                pytest.fail("MordredSessionRefused must not be caught by `except Exception`")
        except MordredSessionRefused:
            pass


# --------------------------------------------------------------------------- #
# Cycle B — strict + no active provider (degraded refuse)                     #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset_enforce_state() -> Any:
    """One-shot ``mordred.degraded.no_resolved_provider`` must not leak across tests.

    Autouse + module-scope fixture: tests in classes above that don't touch
    the degraded path are unaffected; degraded tests get a clean slate.
    """
    enforce._reset_state()
    yield
    enforce._reset_state()


class TestStrictDegraded:
    def test_strict_active_provider_none_raises(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="could not be resolved"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_strict_degraded_no_resolved_provider_is_one_shot(self, tmp_path: Path) -> None:
        """POLICY.md row 6: ``mordred.degraded.no_resolved_provider`` is
        one-shot per process. Two consecutive degraded refusals → emitted
        exactly once.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        for _ in range(2):
            with pytest.raises(MordredSessionRefused):
                enforce.check_session_provider(
                    policy_mode="strict",
                    policy_json_path=cfg,
                    active_provider=None,
                    audit=audit,
                    health_probe=_noop_probe,
                )

        n = sum(1 for e in audit.entries if e["reason"] == "mordred.degraded.no_resolved_provider")
        assert n == 1, f"expected exactly one no_resolved_provider audit, got {n}"

    def test_reset_state_re_arms_one_shot(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )
        enforce._reset_state()
        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )
        n = sum(1 for e in audit.entries if e["reason"] == "mordred.degraded.no_resolved_provider")
        assert n == 2


# --------------------------------------------------------------------------- #
# Cycle C — strict + mordred-local (probe gates passthrough)                  #
# --------------------------------------------------------------------------- #


class TestStrictLocal:
    def test_strict_local_passthrough_audits_allow(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_noop_probe,
        )

        assert audit.entries
        entry = audit.entries[-1]
        assert entry["decision"] == "allow"
        assert entry["provider_id"] == "mordred-local"

    def test_strict_local_probe_failure_raises_session_refused(self, tmp_path: Path) -> None:
        """Phase 2 acceptance gate row 4: strict + no local endpoint
        reachable → fails fast and ABORTS the session.

        Codex P2 round 2: ``MordredLocalUnreachable`` inherits from
        :class:`Exception`, which Hermes' hook dispatch
        (``hermes_cli/plugins.py::invoke_hook`` line 1112) catches + logs
        + continues. To actually refuse the session, strict-mode probe
        failures are translated to :class:`MordredSessionRefused`
        (``BaseException``-derived). A sanitized
        :class:`MordredLocalUnreachable` is preserved as ``__cause__`` so
        consumers can classify the failure without leaking URL credentials
        from a transport exception.

        Audit must show exactly one block entry (no allow entry — probe
        runs BEFORE the success audit append).
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused) as excinfo:
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="mordred-local",
                audit=audit,
                health_probe=_failing_probe,
            )
        assert isinstance(excinfo.value.__cause__, MordredLocalUnreachable)
        assert "health probe failed" in str(excinfo.value.__cause__)

        # One block entry, no allow entry, reason=session_refused.
        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry["decision"] == "block"
        assert entry["reason"] == "policy.strict.session_refused"
        assert entry["provider_id"] == "mordred-local"

    def test_strict_local_uses_configured_endpoint(self, tmp_path: Path) -> None:
        """The injected probe receives the endpoint from policy.json."""
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            local_llm_endpoint="http://127.0.0.1:9999/v1",
        )
        seen: list[str] = []

        def _record(endpoint: str) -> None:
            seen.append(endpoint)

        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_record,
        )
        assert seen == ["http://127.0.0.1:9999/v1"]

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://127.0.0.1:1234/v1",
            "https://127.0.0.1:1234/v1",
            "http://[::1]:1234/v1",
            "https://localhost:1234/v1",
        ],
    )
    def test_strict_local_accepts_loopback_http_endpoints(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source: str,
        endpoint: str,
    ) -> None:
        def _loopback_results(host: str, port: int, **_kwargs: Any) -> list[tuple[Any, ...]]:
            assert host == "localhost"
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", port, 0, 0)),
            ]

        monkeypatch.setattr(enforce.socket, "getaddrinfo", _loopback_results)
        seen: list[str] = []
        audit = _FakeAuditWriter()

        _check_strict_local_endpoint(
            tmp_path,
            source=source,
            endpoint=endpoint,
            audit=audit,
            health_probe=seen.append,
        )

        assert seen == [endpoint]
        assert not any(entry["decision"] == "block" for entry in audit.entries)

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://192.168.1.20:1234/v1",
            "https://8.8.8.8/v1",
            "http://169.254.169.254/latest",
            "http://127.0.0.2:1234/v1",
            "http://user:secret@127.0.0.1:1234/v1",
            "http://127.0.0.1:1234/v1?api_key=query-secret",
            "http://127.0.0.1:1234/v1#fragment-secret",
            "ftp://127.0.0.1:1234/v1",
            "http://%31%32%37.0.0.1:1234/v1",
            "http://localhost.evil:1234/v1",
            "not-a-url",
            "http://[::1",
        ],
    )
    def test_strict_local_rejects_non_loopback_or_malformed_before_probe(
        self,
        tmp_path: Path,
        source: str,
        endpoint: str,
    ) -> None:
        probed: list[str] = []
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused) as excinfo:
            _check_strict_local_endpoint(
                tmp_path,
                source=source,
                endpoint=endpoint,
                audit=audit,
                health_probe=probed.append,
            )

        assert probed == []
        assert len(audit.entries) == 1
        assert audit.entries[0]["decision"] == "block"
        assert audit.entries[0]["reason"] == "policy.strict.session_refused"
        assert audit.entries[0]["provider_id"] == "mordred-local"
        assert "secret" not in str(excinfo.value)
        assert "secret" not in json.dumps(audit.entries)

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    def test_strict_local_rejects_localhost_with_any_non_loopback_dns_result_before_probe(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source: str,
    ) -> None:
        def _mixed_results(_host: str, port: int, **_kwargs: Any) -> list[tuple[Any, ...]]:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.7", port)),
            ]

        monkeypatch.setattr(enforce.socket, "getaddrinfo", _mixed_results)
        probed: list[str] = []
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            _check_strict_local_endpoint(
                tmp_path,
                source=source,
                endpoint="http://localhost:1234/v1",
                audit=audit,
                health_probe=probed.append,
            )

        assert probed == []
        assert [entry["decision"] for entry in audit.entries] == ["block"]
        assert "non-loopback" in audit.entries[0]["cause"]

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    def test_strict_local_adds_exact_proxy_bypass_before_probe(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source: str,
    ) -> None:
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8080")
        monkeypatch.setenv("NO_PROXY", "internal.example")
        monkeypatch.setenv("no_proxy", "other.example,localhost")
        seen: list[str] = []

        _check_strict_local_endpoint(
            tmp_path,
            source=source,
            endpoint="http://127.0.0.1:1234/v1",
            audit=_FakeAuditWriter(),
            health_probe=seen.append,
        )

        assert seen == ["http://127.0.0.1:1234/v1"]
        # Lowercase proxy variables take precedence on POSIX/httpx. Do not
        # union the stale uppercase entry: that can broaden direct egress.
        expected = "other.example,localhost,127.0.0.1,::1"
        assert os.environ["NO_PROXY"] == expected
        assert os.environ["no_proxy"] == expected

    @pytest.mark.parametrize("policy_mode", ["off", "lenient", "balanced", "audit"])
    @pytest.mark.parametrize("runtime", [False, True])
    def test_non_strict_modes_do_not_apply_loopback_boundary(
        self,
        tmp_path: Path,
        policy_mode: str,
        runtime: bool,
    ) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy=policy_mode,
            local_llm_endpoint="https://collector.example/v1",
        )
        probed: list[str] = []
        audit = _FakeAuditWriter()
        kwargs = {
            "policy_mode": policy_mode,
            "policy_json_path": cfg,
            "active_provider": "mordred-local",
            "audit": audit,
            "health_probe": probed.append,
        }

        if runtime:
            enforce.check_runtime_provider(**kwargs, runtime_base_url="https://collector.example/v1")
        else:
            enforce.check_session_provider(**kwargs)

        assert probed == []
        assert audit.entries == []


# --------------------------------------------------------------------------- #
# Cycle D — policy.json missing / malformed → safe defaults (failure-closed)  #
# --------------------------------------------------------------------------- #


class TestPolicyJsonFallbacks:
    def test_missing_policy_json_falls_through_to_strict_defaults(self, tmp_path: Path) -> None:
        """No policy.json + strict mode → safe defaults (allow_cloud_llm=False,
        empty allowlist). Cloud provider should be refused.
        """
        missing = tmp_path / "absent.json"
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=missing,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_malformed_policy_json_uses_safe_defaults(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.json"
        path.write_text("this is not json", encoding="utf-8")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allow_cloud_llm_string_treated_as_false(self, tmp_path: Path) -> None:
        """Codex review P2: ``bool("false")`` is ``True`` in Python.

        If a hand-edit or migration tool writes ``allow_cloud_llm: "false"``,
        strict mode must still refuse cloud traffic — only an actual JSON
        boolean ``true`` counts as ``True`` (failure-closed coercion).
        """
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": "false",  # string, not bool
                    "cloud_provider_allowlist": ["anthropic"],
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="allow_cloud_llm"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allow_cloud_llm_string_true_also_treated_as_false(self, tmp_path: Path) -> None:
        """Mirror of the above: ``"true"`` (string) also must fail closed.

        We don't try to be clever about parsing user intent — anything that
        isn't a JSON ``true`` is treated as ``false``. Users who want cloud
        access rerun the wizard.
        """
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": "true",  # string, not bool
                    "cloud_provider_allowlist": ["anthropic"],
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allow_cloud_llm_integer_treated_as_false(self, tmp_path: Path) -> None:
        """Only a real JSON ``true`` counts — ``1`` (int) is not a bool here."""
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": 1,
                    "cloud_provider_allowlist": ["anthropic"],
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_non_list_allowlist_is_treated_as_empty(self, tmp_path: Path) -> None:
        """If the user hand-edited cloud_provider_allowlist to a non-list,
        be defensive and treat it as empty (failure-closed).
        """
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": True,
                    "cloud_provider_allowlist": "anthropic",  # str not list
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allowlist_entries_are_canonicalized_through_alias_table(self, tmp_path: Path) -> None:
        """``_read_policy_settings`` must run allowlist entries through the
        same alias table (``canonicalize_provider``) the runtime provider id
        is compared against, not a bare ``.strip().lower()``. A Hermes alias
        like ``"claude"`` resolves to the canonical ``"anthropic"`` slug.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            cloud_provider_allowlist=("claude", "  GOOGLE  ", "aws"),
        )

        settings = enforce._read_policy_settings(cfg)

        assert settings.cloud_allowlist == frozenset({"anthropic", "gemini", "bedrock"})

    def test_allowlist_empty_string_entries_still_drop_out(self, tmp_path: Path) -> None:
        """A stray comma in the wizard's CSV (``"anthropic,"``) parses to an
        empty-string list entry; canonicalizing must not let it widen the
        allowlist into matching e.g. an unresolved/empty active_provider.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            cloud_provider_allowlist=("anthropic", "", "   "),
        )

        settings = enforce._read_policy_settings(cfg)

        assert settings.cloud_allowlist == frozenset({"anthropic"})

    def test_allowlist_ollama_entry_does_not_grant_generic_custom_provider(self, tmp_path: Path) -> None:
        """``"ollama"`` canonicalizes to ``"custom"`` (Hermes' wildcard bucket
        for an arbitrary OpenAI-compatible ``base_url``, and the canonical
        form of the ``ollama`` local-endpoint alias). Letting an allowlist
        entry resolve to it would turn a narrow grant -- a user writing
        ``["ollama"]`` meaning "allow my local model" -- into permission for
        ANY custom cloud endpoint: a fail-open widening in a strict CLOUD
        allowlist. ``_read_policy_settings`` must drop ``"custom"`` from the
        resulting allowlist rather than admit it as a real provider grant.
        """
        from mordred_hermes._provider_identity import canonicalize_provider

        assert canonicalize_provider("ollama") == "custom"  # basis for this test
        assert canonicalize_provider("claude") == "anthropic"  # existing alias behaviour unaffected

        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            cloud_provider_allowlist=("ollama",),
        )

        settings = enforce._read_policy_settings(cfg)

        assert settings.cloud_allowlist == frozenset()
        assert "custom" not in settings.cloud_allowlist


# --------------------------------------------------------------------------- #
# check_runtime_provider — runtime hook enforcement (no probe, no allow audit)#
# --------------------------------------------------------------------------- #


class TestCheckRuntimeProvider:
    """Codex review P1 round 3: ``on_session_start`` only has access to
    disk-based provider state. Runtime overrides (CLI ``--provider``,
    ``HERMES_INFERENCE_PROVIDER``, oneshot / gateway switches) bypass that
    path, so a per-request check using the live ``pre_api_request.provider``
    kwarg is the authoritative enforcement point.

    Differences from ``check_session_provider``:

    1. **No local probe** — the runtime resolution already chose
       mordred-local; re-probing on every API call would be wasteful and
       could spam the audit on retries.
    2. **No allow audit** — fires on every API call, so the allow path
       stays silent. Block/refused entries still write to audit.
    3. **Degraded path stays silent** — without a runtime provider the
       call would already be malformed upstream; emitting again here
       would duplicate the on_session_start record.
    """

    def test_off_is_noop(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="off")
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="off",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
        )
        assert audit.entries == []

    def test_lenient_is_noop(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="lenient")
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="lenient",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
        )
        assert audit.entries == []

    def test_strict_local_probes_and_allows_silently(self, tmp_path: Path) -> None:
        """Codex review P2 round 4: ``on_session_start`` may not have
        probed (e.g. disk said ``openai`` but runtime is
        ``--provider mordred-local``), so the runtime hook must probe
        when it sees mordred-local. On success: silent allow (per-call
        hook, no audit spam).
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()
        probed: list[str] = []

        def _record(endpoint: str) -> None:
            probed.append(endpoint)

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_record,
        )
        assert probed == ["http://localhost:1234/v1"]
        assert audit.entries == []

    def test_strict_local_refuses_runtime_base_url_different_from_policy_pin(
        self,
        tmp_path: Path,
    ) -> None:
        """A different loopback service is still a different destination."""
        # policy.json points at port 1234, but the runtime resolved to 8000.
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            local_llm_endpoint="http://localhost:1234/v1",
        )
        audit = _FakeAuditWriter()
        probed: list[str] = []

        def _record(endpoint: str) -> None:
            probed.append(endpoint)

        with pytest.raises(MordredSessionRefused, match="differs from the configured"):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="mordred-local",
                audit=audit,
                health_probe=_record,
                runtime_base_url="http://localhost:8000/v1",
            )

        assert probed == []
        assert audit.entries[0]["reason"] == "policy.strict.session_refused"

    def test_strict_local_runtime_allows_client_trailing_slash_normalization(
        self,
        tmp_path: Path,
    ) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            local_llm_endpoint="http://localhost:1234/v1",
        )
        probed: list[str] = []

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=_FakeAuditWriter(),
            health_probe=probed.append,
            runtime_base_url="http://localhost:1234/v1/",
        )

        assert probed == ["http://localhost:1234/v1/"]

    def test_strict_local_falls_back_to_policy_json_when_base_url_missing(self, tmp_path: Path) -> None:
        """Defensive fallback: if the hook is invoked without a runtime
        ``base_url`` (synthetic test payloads, future hook payload
        changes), fall back to the policy.json mirror so we don't
        silently skip the probe.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            local_llm_endpoint="http://localhost:1234/v1",
        )
        audit = _FakeAuditWriter()
        probed: list[str] = []

        def _record(endpoint: str) -> None:
            probed.append(endpoint)

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_record,
            runtime_base_url=None,
        )
        assert probed == ["http://localhost:1234/v1"]

    def test_strict_local_refuses_on_probe_failure(self, tmp_path: Path) -> None:
        """Runtime override to mordred-local + unreachable endpoint → refuse.

        Mirrors the session_start behavior (``MordredSessionRefused`` with
        ``MordredLocalUnreachable`` chained as ``__cause__``).
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused) as excinfo:
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="mordred-local",
                audit=audit,
                health_probe=_failing_probe,
            )
        assert isinstance(excinfo.value.__cause__, MordredLocalUnreachable)
        assert len(audit.entries) == 1
        assert audit.entries[0]["reason"] == "policy.strict.session_refused"
        assert audit.entries[0]["provider_id"] == "mordred-local"

    def test_local_probe_failure_redacts_transport_exception_details(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        def leaking_probe(_endpoint: str) -> None:
            raise MordredLocalUnreachable("request to http://localhost:1234/path-secret?api_key=query-secret failed")

        with pytest.raises(MordredSessionRefused) as excinfo:
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="mordred-local",
                audit=audit,
                health_probe=leaking_probe,
                runtime_base_url="http://localhost:1234/v1",
            )

        rendered = json.dumps(audit.entries) + str(excinfo.value) + str(excinfo.value.__cause__) + caplog.text
        assert "path-secret" not in rendered
        assert "query-secret" not in rendered

    def test_strict_allowlisted_cloud_allows_silently(self, tmp_path: Path) -> None:
        """Allowlisted cloud + allow_cloud_llm=True → silent allow."""
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            runtime_base_url="https://api.anthropic.com",
        )
        assert audit.entries == []

    @pytest.mark.parametrize("runtime_base_url", [None, "", "   "])
    def test_strict_allowlisted_cloud_allows_provider_sdk_default_endpoint(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        runtime_base_url: str | None,
    ) -> None:
        """No base_url means the provider SDK's own endpoint, not an unbound one.

        Hermes stores ``base_url or ""`` and omits it whenever the SDK supplies
        the endpoint (native Anthropic is the common case), so refusing here
        would refuse every request of the most ordinary strict configuration.
        """
        _clear_sdk_base_url_env(monkeypatch)
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            runtime_base_url=runtime_base_url,
        )
        assert audit.entries == []

    @pytest.mark.parametrize("provider", ["bedrock", "vertex", "azure-foundry"])
    def test_strict_refuses_missing_base_url_for_tenant_scoped_provider(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        provider: str,
    ) -> None:
        """Region/tenant/project-scoped providers have no owned default endpoint."""
        _clear_sdk_base_url_env(monkeypatch)
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=(provider,),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="no single provider-owned default endpoint"):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=provider,
                audit=audit,
                runtime_base_url=None,
            )

        assert audit.entries[0]["reason"] == "policy.strict.cloud_endpoint_mismatch"
        assert audit.entries[0]["base_url_overridden"] is False

    def test_strict_bedrock_allows_its_regional_endpoint(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("bedrock",),
        )
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="bedrock",
            audit=audit,
            runtime_base_url="https://bedrock-runtime.us-east-1.amazonaws.com",
        )
        assert audit.entries == []

    def test_cloud_endpoint_host_table_keys_are_canonical(self) -> None:
        """An alias key is unreachable and would leak a non-canonical identity."""
        for provider in enforce._CLOUD_ENDPOINT_HOSTS:
            assert enforce.policy_provider_id(provider) == provider

    def test_infer_cloud_provider_returns_canonical_identities(self) -> None:
        assert enforce.infer_cloud_provider("https://api.x.ai/v1") == "xai"
        assert enforce.infer_cloud_provider("https://api.minimax.io/v1") == "minimax"

    def test_strict_allowlisted_cloud_refuses_runtime_base_url_override(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("openai",),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="not a provider-owned endpoint"):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                runtime_base_url="https://collector.example/v1",
            )

        assert audit.entries[0]["reason"] == "policy.strict.cloud_endpoint_mismatch"
        assert audit.entries[0]["runtime_base_url"] == "https://collector.example"

    def test_endpoint_mismatch_redacts_url_secrets_from_audit_error_and_log(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("openai",),
        )
        audit = _FakeAuditWriter()
        secret_url = "https://audit-user:password-secret@api.openai.com/v1?api_key=query-secret#fragment-secret"

        with pytest.raises(MordredSessionRefused) as excinfo:
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                runtime_base_url=secret_url,
            )

        rendered = json.dumps(audit.entries) + str(excinfo.value) + caplog.text
        for secret in (
            "audit-user",
            "password-secret",
            "query-secret",
            "fragment-secret",
        ):
            assert secret not in rendered
        assert {entry["runtime_base_url"] for entry in audit.entries} == {"https://api.openai.com"}

    def test_endpoint_display_rejects_malformed_and_bounds_length(self) -> None:
        assert enforce.safe_endpoint_for_audit("not a URL?token=secret") == "<invalid>"
        displayed = enforce.safe_endpoint_for_audit(
            "https://api.openai.com/" + ("path-secret-" * 1000) + "?token=secret"
        )
        assert len(displayed) <= 256
        assert "secret" not in displayed

    @pytest.mark.parametrize(
        "env_var",
        ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "AZURE_OPENAI_ENDPOINT"],
    )
    def test_strict_binds_against_ambient_sdk_endpoint_override(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        env_var: str,
    ) -> None:
        """An SDK env override redirects the request while Hermes reports no URL.

        ``openai`` / ``anthropic`` clients constructed without ``base_url`` read
        these variables themselves, so ``agent.base_url`` stays empty even though
        traffic leaves for the override. The absent-endpoint path must therefore
        bind against the ambient value, not wave the request through.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        monkeypatch.setenv(env_var, "https://collector.example/v1")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="not a provider-owned endpoint"):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="anthropic",
                audit=audit,
                runtime_base_url=None,
            )

        assert audit.entries[0]["reason"] == "policy.strict.cloud_endpoint_mismatch"
        assert audit.entries[0]["runtime_base_url"] == "https://collector.example"
        assert audit.entries[0]["base_url_overridden"] is True

    def test_strict_allows_absent_endpoint_when_ambient_override_is_provider_owned(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            runtime_base_url=None,
        )
        assert audit.entries == []

    def test_ambient_override_enumerates_installed_sdk_variables(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        for name in enforce._SDK_BASE_URL_ENV_VARS:
            monkeypatch.delenv(name, raising=False)
        assert enforce.ambient_base_url_override() is None
        monkeypatch.setenv("OPENAI_BASE_URL", "  https://proxy.example/v1  ")
        assert enforce.ambient_base_url_override() == "https://proxy.example/v1"

    def test_strict_non_allowlisted_cloud_refuses(self, tmp_path: Path) -> None:
        """This is the runtime-override hole Codex flagged: even if
        on_session_start saw mordred-local on disk, a CLI ``--provider
        openai`` override means pre_api_request fires with
        ``provider=openai``. Strict + openai-not-in-allowlist → refuse.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")  # empty allowlist
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                runtime_base_url="https://api.openai.com/v1",
            )

        reasons = [e["reason"] for e in audit.entries]
        assert "policy.strict.cloud_not_allowlisted" in reasons
        assert "policy.strict.session_refused" in reasons
        # Provider id is recorded in the audit even though the message
        # is templated on the ``allow_cloud_llm`` flag — consumers can
        # filter on provider regardless of which reason variant fired.
        assert all(e.get("provider_id") == "openai" for e in audit.entries)

    def test_strict_no_provider_refuses_degraded(self, tmp_path: Path) -> None:
        """Codex review P1 round 5: ``_on_session_start_enforce`` now
        only logs (doesn't raise) the degraded path, so if
        ``pre_api_request`` also accepted a missing provider silently
        the strict refuse-only contract would be violated. Runtime
        enforcement must refuse + audit when the resolved provider is
        absent — this is the authoritative degraded refusal point.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
            )

        reasons = [e["reason"] for e in audit.entries]
        assert "mordred.degraded.no_resolved_provider" in reasons
        assert "policy.strict.unconditional_override" in reasons

    def test_audit_failure_does_not_swallow_refusal(self, tmp_path: Path) -> None:
        """Codex review P1 round 6: if ``audit.append(...)`` raises
        :class:`Exception` (e.g. disk full, broken NDJSON path) BEFORE
        we raise :class:`MordredSessionRefused`, Hermes' hook dispatch
        (``invoke_hook`` line 1112) catches the audit ``Exception`` and
        continues — the request would proceed un-refused. Audit writes
        must be best-effort so the ``BaseException`` refusal still
        propagates.
        """

        class _ExplodingAuditWriter:
            def append(self, entry: Mapping[str, Any]) -> None:
                raise RuntimeError("simulated audit log write failure")

        cfg = _write_policy_json(tmp_path, policy="strict")  # empty allowlist
        audit = _ExplodingAuditWriter()

        # Refusal MUST still escape even though every audit write blows up.
        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                runtime_base_url="https://api.openai.com/v1",
            )

    def test_strict_allowlist_is_case_insensitive(self, tmp_path: Path) -> None:
        """Codex review P2 round 5: allowlist entries from policy.json may
        be hand-edited with different casing/whitespace (``OpenAI``,
        `` anthropic ``). Runtime providers are normalized to lowercase
        before lookup, so the allowlist must be normalized the same way
        — otherwise valid configurations are silently refused.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("OpenAI", "  Anthropic  "),
        )
        audit = _FakeAuditWriter()

        # Both lookups must succeed despite the casing/whitespace mismatch.
        for provider, endpoint in (
            ("openai", "https://api.openai.com/v1"),
            ("anthropic", "https://api.anthropic.com"),
        ):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=provider,
                audit=audit,
                runtime_base_url=endpoint,
            )

        # Allow paths stay silent in runtime check.
        assert audit.entries == []

    def test_strict_allowlist_resolves_aliases(self, tmp_path: Path) -> None:
        """A user-authored allowlist entry that is a Hermes *alias* (not the
        canonical slug) must still permit the canonicalized runtime provider.

        Verified finding: ``_read_policy_settings`` used to normalize
        allowlist entries with a bare ``.strip().lower()``, while the
        runtime provider id being compared against is normalized through
        the full alias table via ``canonicalize_provider()``
        (``__init__.py::_resolve_active_provider`` /
        ``_on_pre_api_request_enforce``). A hand-edited
        ``cloud_provider_allowlist: ["claude"]`` — ``"claude"`` is a real
        Hermes alias for ``"anthropic"`` — would therefore never match the
        canonicalized ``"anthropic"`` runtime id, and strict mode would
        refuse a provider the user clearly intended to allow. Without the
        fix (canonicalizing allowlist entries the same way) this test fails
        with ``MordredSessionRefused``.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("claude", "google", "aws"),
        )
        audit = _FakeAuditWriter()

        # "claude" / "google" / "aws" are aliases; the runtime provider id
        # arrives already canonicalized (mirroring
        # ``_on_pre_api_request_enforce``'s ``canonicalize_provider`` call).
        for provider, endpoint in (
            ("anthropic", "https://api.anthropic.com"),
            ("gemini", "https://generativelanguage.googleapis.com/v1beta"),
            ("bedrock", "https://bedrock-runtime.us-east-1.amazonaws.com"),
        ):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=provider,
                audit=audit,
                runtime_base_url=endpoint,
            )

        # Allow paths stay silent in runtime check.
        assert audit.entries == []

    @pytest.mark.parametrize(
        ("runtime_provider", "policy_provider", "endpoint"),
        [
            ("openai-api", "openai", "https://api.openai.com/v1"),
            ("kimi-for-coding", "kimi-coding", "https://api.kimi.com/coding"),
            (
                "tencent-tokenhub",
                "tencent-tokenhub",
                "https://tokenhub.tencentmaas.com/v1",
            ),
            ("solar", "upstage", "https://api.upstage.ai/v1"),
            ("stepfun", "stepfun", "https://api.stepfun.com/v1"),
            ("xai-oauth", "xai", "https://api.x.ai/v1"),
            ("minimax-oauth", "minimax", "https://api.minimax.io/anthropic"),
        ],
    )
    def test_hermes_019_registry_ids_match_stable_policy_identities(
        self,
        tmp_path: Path,
        runtime_provider: str,
        policy_provider: str,
        endpoint: str,
    ) -> None:
        cfg = _write_policy_json(
            tmp_path,
            allow_cloud_llm=True,
            cloud_provider_allowlist=(policy_provider,),
        )
        audit = _FakeAuditWriter()

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider=runtime_provider,
            audit=audit,
            runtime_base_url=endpoint,
        )

        assert audit.entries == []

    @pytest.mark.parametrize(
        ("provider", "endpoint"),
        [
            ("bedrock", "https://bedrock-runtime.us-east-1.amazonaws.com"),
            ("bedrock", "https://bedrock-runtime-fips.us-gov-west-1.amazonaws.com"),
            ("bedrock", "https://bedrock-runtime.cn-north-1.amazonaws.com.cn"),
            ("bedrock", "https://bedrock-runtime.eu-west-1.api.aws"),
            ("vertex", "https://aiplatform.googleapis.com/v1"),
            ("vertex", "https://us-central1-aiplatform.googleapis.com/v1"),
            ("opencode-go", "https://opencode.ai/zen/go/v1"),
            ("opencode-zen", "https://opencode.ai/zen/v1"),
        ],
    )
    def test_shape_bound_cloud_service_endpoints_are_accepted(
        self,
        provider: str,
        endpoint: str,
    ) -> None:
        assert enforce.cloud_endpoint_matches_provider(provider, endpoint)

    @pytest.mark.parametrize(
        ("provider", "endpoint"),
        [
            ("bedrock", "https://s3.us-east-1.amazonaws.com/bucket"),
            ("bedrock", "https://execute-api.us-east-1.amazonaws.com/stage"),
            (
                "bedrock",
                "https://bedrock-runtime.us-east-1.amazonaws.com.collector.example",
            ),
            ("vertex", "https://storage.googleapis.com/bucket"),
            ("vertex", "https://generativelanguage.googleapis.com/v1beta"),
            ("vertex", "https://aiplatform.googleapis.com.collector.example/v1"),
            ("opencode-go", "https://opencode.ai/zen/v1"),
            ("opencode-zen", "https://opencode.ai/zen/go/v1"),
        ],
    )
    def test_unrelated_cloud_service_hosts_do_not_inherit_provider_grant(
        self,
        provider: str,
        endpoint: str,
    ) -> None:
        assert not enforce.cloud_endpoint_matches_provider(provider, endpoint)

    def test_endpoint_table_has_no_broad_vendor_suffixes(self) -> None:
        suffix_constraints = {
            constraint
            for constraints in enforce._CLOUD_ENDPOINT_HOSTS.values()
            for constraint in constraints
            if constraint.startswith(".")
        }
        assert suffix_constraints == set()

    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://my-resource.openai.azure.com/openai/v1",
            "https://my-resource.services.ai.azure.com/anthropic",
        ],
    )
    def test_azure_foundry_requires_future_exact_policy_pin(self, endpoint: str) -> None:
        assert not enforce.cloud_endpoint_matches_provider("azure-foundry", endpoint)

    def test_installed_hermes_registry_https_endpoints_are_all_bound(self) -> None:
        from hermes_cli.auth import PROVIDER_REGISTRY

        missing = {
            provider: endpoint
            for provider, config in PROVIDER_REGISTRY.items()
            for endpoint in (str(config.inference_base_url or ""),)
            if endpoint.startswith("https://") and not enforce.cloud_endpoint_matches_provider(provider, endpoint)
        }

        assert missing == {}

    def test_installed_hermes_auxiliary_and_zai_endpoints_are_all_bound(self) -> None:
        """Keep endpoint ownership synchronized with Hermes resolver seams.

        ``PROVIDER_REGISTRY`` does not enumerate Z.AI's regional probe list or
        the URL literals used by its vision resolver, so registry-only
        coverage missed ``open.bigmodel.cn``.
        """
        from types import CodeType
        from urllib.parse import urlsplit

        from agent import auxiliary_client
        from hermes_cli.auth import ZAI_ENDPOINTS

        def code_urls(code: CodeType) -> set[str]:
            found: set[str] = set()
            for constant in code.co_consts:
                if isinstance(constant, str) and constant.startswith("https://"):
                    found.add(constant)
                elif isinstance(constant, CodeType):
                    found.update(code_urls(constant))
            return found

        def value_urls(value: object) -> set[str]:
            if isinstance(value, str):
                return {value} if value.startswith("https://") else set()
            if isinstance(value, dict):
                return {endpoint for nested in value.values() for endpoint in value_urls(nested)}
            if isinstance(value, (list, tuple, set, frozenset)):
                return {endpoint for nested in value for endpoint in value_urls(nested)}
            return set()

        auxiliary_urls = {
            endpoint
            for name, value in vars(auxiliary_client).items()
            if "BASE_URL" in name
            for endpoint in value_urls(value)
        }
        for seam in (
            auxiliary_client._get_cached_client,
            auxiliary_client._get_provider_chain,
            auxiliary_client.resolve_provider_client,
            auxiliary_client.resolve_vision_provider_client,
        ):
            auxiliary_urls.update(code_urls(seam.__code__))

        # Ignore dynamic URL prefixes such as ``https://bedrock-runtime.``;
        # their completed, region-shaped form is covered separately.
        auxiliary_urls = {
            endpoint for endpoint in auxiliary_urls if not str(urlsplit(endpoint).hostname or "").endswith(".")
        }
        zai_urls = {str(entry[1]) for entry in ZAI_ENDPOINTS}

        assert "https://open.bigmodel.cn/api/paas/v4" in auxiliary_urls
        assert {endpoint for endpoint in auxiliary_urls if enforce.infer_cloud_provider(endpoint) is None} == set()
        assert {
            endpoint for endpoint in zai_urls if not enforce.cloud_endpoint_matches_provider("zai", endpoint)
        } == set()


# --------------------------------------------------------------------------- #
# cloud_attempt_action reader — failure-closed coercion                       #
# --------------------------------------------------------------------------- #


class TestCloudAttemptActionReader:
    """``_read_policy_settings`` parses ``cloud_attempt_action`` from policy.json.

    Mirrors the ``allow_cloud_llm`` failure-closed coercion (``enforce.py``
    Codex P2): only the exact JSON string ``"prompt-once"`` selects the
    prompt path; everything else — missing, unknown, or non-string — falls
    back to the safe default ``"always-block"``.
    """

    def _settings(self, tmp_path: Path, value: object | None) -> Any:
        body: dict[str, Any] = {"policy": "strict"}
        if value is not None:
            body["cloud_attempt_action"] = value
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        return enforce._read_policy_settings(path)

    def test_prompt_once_is_parsed(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, "prompt-once").cloud_attempt_action == "prompt-once"

    def test_always_block_explicit(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, "always-block").cloud_attempt_action == "always-block"

    def test_missing_defaults_to_always_block(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, None).cloud_attempt_action == "always-block"

    def test_unknown_value_defaults_to_always_block(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, "ask-every-time").cloud_attempt_action == "always-block"

    def test_non_string_defaults_to_always_block(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, 123).cloud_attempt_action == "always-block"

    def test_missing_policy_json_defaults_to_always_block(self, tmp_path: Path) -> None:
        settings = enforce._read_policy_settings(tmp_path / "absent.json")
        assert settings.cloud_attempt_action == "always-block"
