"""Tests for ``keyvault.seed_display``.

SPEC.md §Seed phrase display security requires:

- :func:`display_seed` orchestrates the Seed display flow — network
  blackout assert → M4 warning banner → screen-capture pre-check → seed
  display → 60s monotonic timer with capture polling → auto-clear.
- A screen capture detected before or during the window aborts the flow:
  the surface is cleared, ``keyvault.seed_display_aborted_screenshot`` is
  emitted, and :class:`SeedDisplayAborted` is raised.
- The flow consumes an :class:`~mordred_hermes.keyvault.api.SeedDisplayHandle`
  exactly once; the timer is monotonic-clock based (wall-clock tamper
  resistant).

These tests run cross-platform: the macOS Quartz probe is exercised via
an injected fake, and the network probe is always injected so no real
network / OS call is made.
"""

from __future__ import annotations

import sys
import time
from typing import Any

import pytest

from mordred_hermes.keyvault import seed_display as sd
from mordred_hermes.keyvault.api import SeedDisplayExpired, SeedDisplayHandle
from mordred_hermes.keyvault.network_fallback import BlackoutNotAsserted

_SEED = "abandon ability able about above absent absorb abstract absurd abuse access accident"


def _handle(seed: str = _SEED, *, ttl: float = 1000.0) -> SeedDisplayHandle:
    """A live SeedDisplayHandle with a far-future deadline (consume() works)."""
    return SeedDisplayHandle(seed, time.monotonic() + ttl, b"\x00" * 32)


class FakeSurface:
    """Records banner / show / clear calls in order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def banner(self, message: str) -> None:
        self.calls.append(("banner", message))

    def show(self, seed: str) -> None:
        self.calls.append(("show", seed))

    def clear(self) -> None:
        self.calls.append(("clear", ""))

    @property
    def ops(self) -> list[str]:
        return [op for op, _ in self.calls]


class FakeClock:
    """Monotonic clock whose ``sleep`` advances time deterministically."""

    def __init__(self) -> None:
        self.t = 1000.0

    def now(self) -> float:
        return self.t

    def sleep(self, dt: float) -> None:
        self.t += max(dt, 0.0)


def _ok_blackout(*, probe: Any = None) -> None:
    """A blackout_assert that always passes (host is isolated)."""
    return None


def _fail_blackout(*, probe: Any = None) -> None:
    raise BlackoutNotAsserted("network reachable")


def _no_capture() -> str | None:
    return None


# ---------------------------------------------------------------------------
# Blackout gate
# ---------------------------------------------------------------------------


def test_blackout_failure_aborts_before_anything_is_shown() -> None:
    surface = FakeSurface()
    handle = _handle()
    with pytest.raises(BlackoutNotAsserted):
        sd.display_seed(handle, surface, blackout_assert=_fail_blackout, capture_probe=_no_capture)
    assert surface.ops == []  # not even the banner


def test_blackout_runs_before_banner_and_display() -> None:
    surface = FakeSurface()
    clock = FakeClock()
    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        ttl_seconds=2.0,
        clock=clock.now,
        sleep=clock.sleep,
    )
    assert surface.ops[0] == "banner"


# ---------------------------------------------------------------------------
# Happy path: banner → show → auto-clear
# ---------------------------------------------------------------------------


def test_happy_path_shows_seed_then_clears() -> None:
    surface = FakeSurface()
    clock = FakeClock()
    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        ttl_seconds=3.0,
        clock=clock.now,
        sleep=clock.sleep,
    )
    assert surface.ops[0] == "banner"
    assert ("show", _SEED) in surface.calls
    assert surface.ops[-1] == "clear"


def test_banner_warns_about_capture_and_air_gap() -> None:
    surface = FakeSurface()
    clock = FakeClock()
    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        ttl_seconds=2.0,
        clock=clock.now,
        sleep=clock.sleep,
    )
    banner_text = next(msg for op, msg in surface.calls if op == "banner").lower()
    assert "bluetooth" in banner_text
    assert "recording" in banner_text or "recorder" in banner_text


def test_handle_consumed_exactly_once() -> None:
    surface = FakeSurface()
    clock = FakeClock()
    handle = _handle()
    sd.display_seed(
        handle,
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        ttl_seconds=2.0,
        clock=clock.now,
        sleep=clock.sleep,
    )
    # handle is one-shot — a second consume must now fail
    with pytest.raises(RuntimeError):
        handle.consume()


def test_timer_uses_injected_monotonic_clock() -> None:
    """The display window length is measured by the injected clock."""
    surface = FakeSurface()
    clock = FakeClock()
    start = clock.now()
    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        ttl_seconds=10.0,
        poll_interval=0.5,
        clock=clock.now,
        sleep=clock.sleep,
    )
    assert clock.now() - start >= 10.0


def test_capture_probe_polled_during_window() -> None:
    surface = FakeSurface()
    clock = FakeClock()
    polls = 0

    def counting_probe() -> str | None:
        nonlocal polls
        polls += 1
        return None

    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=counting_probe,
        ttl_seconds=5.0,
        poll_interval=0.5,
        clock=clock.now,
        sleep=clock.sleep,
    )
    assert polls > 1  # polled repeatedly, not just once


# ---------------------------------------------------------------------------
# Screenshot abort — pre-display
# ---------------------------------------------------------------------------


def test_capture_detected_before_display_aborts_without_showing() -> None:
    surface = FakeSurface()
    with pytest.raises(sd.SeedDisplayAborted) as exc:
        sd.display_seed(
            _handle(),
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=lambda: "cg_screen_is_being_captured",
        )
    assert exc.value.detector == "cg_screen_is_being_captured"
    assert "show" not in surface.ops


def test_pre_display_abort_emits_audit() -> None:
    surface = FakeSurface()
    entries: list[dict[str, Any]] = []
    with pytest.raises(sd.SeedDisplayAborted):
        sd.display_seed(
            _handle(),
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=lambda: "cg_screen_is_being_captured",
            audit_sink=entries.append,
        )
    assert len(entries) == 1
    assert entries[0]["event"] == "keyvault.seed_display"
    assert entries[0]["decision"] == "block"
    assert entries[0]["reason"] == "keyvault.seed_display_aborted_screenshot"
    assert entries[0]["detector"] == "cg_screen_is_being_captured"


# ---------------------------------------------------------------------------
# Screenshot abort — mid-display
# ---------------------------------------------------------------------------


def test_capture_detected_mid_display_clears_and_aborts() -> None:
    surface = FakeSurface()
    clock = FakeClock()
    state = {"n": 0}

    def probe() -> str | None:
        state["n"] += 1
        return "cg_screen_is_being_captured" if state["n"] >= 3 else None

    entries: list[dict[str, Any]] = []
    with pytest.raises(sd.SeedDisplayAborted) as exc:
        sd.display_seed(
            _handle(),
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=probe,
            audit_sink=entries.append,
            ttl_seconds=60.0,
            poll_interval=0.5,
            clock=clock.now,
            sleep=clock.sleep,
        )
    assert exc.value.detector == "cg_screen_is_being_captured"
    # the seed WAS shown, then the surface was cleared on detection
    assert ("show", _SEED) in surface.calls
    assert surface.ops[-1] == "clear"
    # aborted before the 60s window elapsed
    assert clock.now() - 1000.0 < 60.0
    assert entries[0]["reason"] == "keyvault.seed_display_aborted_screenshot"


def test_pre_display_abort_wipes_seed_from_handle() -> None:
    """A capture detected before display still wipes the seed (code-review L1).

    The seed was never rendered, but a hostile capture environment was
    detected — the handle must be spent so the seed does not linger.
    """
    surface = FakeSurface()
    handle = _handle()
    with pytest.raises(sd.SeedDisplayAborted):
        sd.display_seed(
            handle,
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=lambda: "cg_screen_is_being_captured",
        )
    with pytest.raises(RuntimeError):  # handle already consumed (seed wiped)
        handle.consume()


def test_non_positive_poll_interval_rejected() -> None:
    """poll_interval <= 0 must fail fast, not busy-loop (code-review M1)."""
    surface = FakeSurface()
    for bad in (0.0, -1.0):
        with pytest.raises(ValueError, match="poll_interval"):
            sd.display_seed(
                _handle(),
                surface,
                blackout_assert=_ok_blackout,
                capture_probe=_no_capture,
                poll_interval=bad,
                ttl_seconds=0.05,
            )


def test_audit_sink_failure_chains_onto_aborted() -> None:
    surface = FakeSurface()

    def boom(_entry: dict[str, Any]) -> None:
        raise RuntimeError("audit disk full")

    with pytest.raises(sd.SeedDisplayAborted) as exc:
        sd.display_seed(
            _handle(),
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=lambda: "cg_screen_is_being_captured",
            audit_sink=boom,
        )
    assert isinstance(exc.value.__context__, RuntimeError)


# ---------------------------------------------------------------------------
# Surface always cleared / expired handle
# ---------------------------------------------------------------------------


def test_surface_cleared_even_when_show_raises() -> None:
    clock = FakeClock()

    class ExplodingSurface(FakeSurface):
        def show(self, seed: str) -> None:
            super().show(seed)
            raise OSError("terminal lost")

    surface = ExplodingSurface()
    with pytest.raises(OSError, match="terminal lost"):
        sd.display_seed(
            _handle(),
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=_no_capture,
            ttl_seconds=2.0,
            clock=clock.now,
            sleep=clock.sleep,
        )
    assert surface.ops[-1] == "clear"


def test_expired_handle_raises_before_display() -> None:
    surface = FakeSurface()
    expired = SeedDisplayHandle(_SEED, time.monotonic() - 1.0, b"\x00" * 32)
    with pytest.raises(SeedDisplayExpired):
        sd.display_seed(
            expired,
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=_no_capture,
        )
    assert "show" not in surface.ops


def test_no_audit_emitted_on_clean_completion() -> None:
    surface = FakeSurface()
    clock = FakeClock()
    entries: list[dict[str, Any]] = []
    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        audit_sink=entries.append,
        ttl_seconds=2.0,
        clock=clock.now,
        sleep=clock.sleep,
    )
    assert entries == []


# ---------------------------------------------------------------------------
# Default macOS capture probe
# ---------------------------------------------------------------------------


class _FakeQuartz:
    def __init__(self, *, captured: bool, raises: bool = False) -> None:
        self._captured = captured
        self._raises = raises

    def CGMainDisplayID(self) -> int:
        # CamelCase mirrors the pyobjc CoreGraphics symbol names.
        return 1

    def CGScreenIsBeingCaptured(self, display: int) -> bool:
        if self._raises:
            raise RuntimeError("pyobjc bridge error")
        return self._captured


def test_default_probe_returns_none_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert sd._default_capture_probe() is None


def test_default_probe_returns_none_when_quartz_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")

    def _no_quartz() -> Any:
        raise ImportError("No module named 'Quartz'")

    monkeypatch.setattr(sd, "_import_quartz", _no_quartz)
    assert sd._default_capture_probe() is None  # best-effort: fail open, banner covers it


def test_default_probe_detects_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sd, "_import_quartz", lambda: _FakeQuartz(captured=True))
    assert sd._default_capture_probe() == "cg_screen_is_being_captured"


def test_default_probe_returns_none_when_not_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sd, "_import_quartz", lambda: _FakeQuartz(captured=False))
    assert sd._default_capture_probe() is None


def test_default_probe_swallows_bridge_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sd, "_import_quartz", lambda: _FakeQuartz(captured=False, raises=True))
    assert sd._default_capture_probe() is None  # best-effort


def test_default_probe_handles_missing_symbol(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Quartz build that does not expose ``CGScreenIsBeingCaptured`` fails open.

    Real-world case the operator hit: pyobjc imports fine, but attribute
    access on the symbol raises ``AttributeError``. The probe must still
    return ``None`` rather than crash the seed-display flow.
    """

    class _QuartzMissingSymbol:
        def CGMainDisplayID(self) -> int:
            return 1

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sd, "_import_quartz", lambda: _QuartzMissingSymbol())
    monkeypatch.setattr(sd, "_CAPTURE_PROBE_WARNED", False)
    assert sd._default_capture_probe() is None  # best-effort: fail open


def test_default_probe_bridge_error_warns_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The probe-failure warning fires once per process, not once per poll.

    The probe is polled every ~0.5s across the 60s seed window; an
    un-guarded warning floods the operator's terminal with identical lines
    (the ``CGScreenIsBeingCaptured probe failed`` wall the operator saw).
    """
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sd, "_import_quartz", lambda: _FakeQuartz(captured=False, raises=True))
    monkeypatch.setattr(sd, "_CAPTURE_PROBE_WARNED", False)

    with caplog.at_level("WARNING", logger="mordred.keyvault.seed_display"):
        for _ in range(5):
            assert sd._default_capture_probe() is None  # best-effort: fail open

    probe_warnings = [r for r in caplog.records if "screen-capture detection is unavailable" in r.getMessage()]
    assert len(probe_warnings) == 1


def test_module_imports_without_quartz() -> None:
    """The module must import on any platform — Quartz is call-time lazy."""
    import importlib

    importlib.reload(sd)
    assert hasattr(sd, "display_seed")


# ---------------------------------------------------------------------------
# Early dismiss — operator presses ENTER to clear the seed before the 60s timer
# ---------------------------------------------------------------------------


def test_dismiss_probe_breaks_window_early() -> None:
    """A dismiss probe that fires mid-window clears the seed before the TTL."""
    surface = FakeSurface()
    clock = FakeClock()
    state = {"n": 0}

    def dismiss() -> bool:
        state["n"] += 1
        return state["n"] >= 2  # press ENTER on the 2nd poll

    start = clock.now()
    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        dismiss_probe=dismiss,
        ttl_seconds=60.0,
        poll_interval=0.5,
        clock=clock.now,
        sleep=clock.sleep,
    )
    assert ("show", _SEED) in surface.calls
    assert surface.ops[-1] == "clear"
    # Exited well before the 60s timer would have elapsed.
    assert clock.now() - start < 60.0


def test_dismiss_is_a_clean_completion_no_audit() -> None:
    """An early dismiss is a clean exit, not an abort — no audit entry."""
    surface = FakeSurface()
    clock = FakeClock()
    entries: list[dict[str, Any]] = []
    sd.display_seed(
        _handle(),
        surface,
        blackout_assert=_ok_blackout,
        capture_probe=_no_capture,
        dismiss_probe=lambda: True,
        audit_sink=entries.append,
        ttl_seconds=60.0,
        clock=clock.now,
        sleep=clock.sleep,
    )
    assert entries == []
    assert ("show", _SEED) in surface.calls
    assert surface.ops[-1] == "clear"


def test_capture_takes_precedence_over_dismiss() -> None:
    """Capture AND dismiss both pending → the capture aborts (security first)."""
    surface = FakeSurface()
    clock = FakeClock()
    entries: list[dict[str, Any]] = []
    with pytest.raises(sd.SeedDisplayAborted):
        sd.display_seed(
            _handle(),
            surface,
            blackout_assert=_ok_blackout,
            capture_probe=lambda: "cg_screen_is_being_captured",
            dismiss_probe=lambda: True,
            audit_sink=entries.append,
            ttl_seconds=60.0,
            clock=clock.now,
            sleep=clock.sleep,
        )
    # The abort path ran (audit emitted), not the silent early-dismiss break.
    assert entries[0]["reason"] == "keyvault.seed_display_aborted_screenshot"


def test_default_dismiss_returns_false_when_not_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-interactive stdin → no early dismiss, and stdin is never drained."""

    class _NotATty:
        def isatty(self) -> bool:
            return False

        def readline(self) -> str:  # pragma: no cover - must NOT be called
            raise AssertionError("scripted stdin must never be drained")

    monkeypatch.setattr(sys, "stdin", _NotATty())
    assert sd._default_dismiss_probe() is False


def test_default_dismiss_true_on_pending_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """An interactive TTY with a pending line → True, and the line is drained."""
    drained = {"n": 0}

    class _TtyStdin:
        def isatty(self) -> bool:
            return True

        def readline(self) -> str:
            drained["n"] += 1
            return "\n"

    fake_stdin = _TtyStdin()
    monkeypatch.setattr(sys, "stdin", fake_stdin)
    monkeypatch.setattr(sd.select, "select", lambda r, w, e, t: ([fake_stdin], [], []))
    assert sd._default_dismiss_probe() is True
    assert drained["n"] == 1  # the pending ENTER was drained, not left for the digest prompt


def test_default_dismiss_false_when_nothing_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    class _TtyStdin:
        def isatty(self) -> bool:
            return True

        def readline(self) -> str:  # pragma: no cover - must NOT be called
            raise AssertionError("must not drain when nothing is pending")

    monkeypatch.setattr(sys, "stdin", _TtyStdin())
    monkeypatch.setattr(sd.select, "select", lambda r, w, e, t: ([], [], []))
    assert sd._default_dismiss_probe() is False


def test_default_dismiss_fails_open_on_select_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows: select() rejects stdin → fail open (False), never raise."""

    class _TtyStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdin", _TtyStdin())

    def _boom(*_a: Any, **_kw: Any) -> Any:
        raise OSError("select on stdin unsupported on this platform")

    monkeypatch.setattr(sd.select, "select", _boom)
    assert sd._default_dismiss_probe() is False
