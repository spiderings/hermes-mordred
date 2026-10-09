"""mordred_keyvault.seed_display — Seed phrase display flow orchestrator.

The current contract is documented in SPEC.md §Seed phrase display security.

:func:`display_seed` runs the security-critical flow that puts a BIP39
seed phrase on screen exactly once:

1. **Network blackout assert** — refuse to display unless the host is
   network-isolated. Delegates to
   :func:`mordred_hermes.keyvault.network_fallback.resolve_blackout_assert`
   (which itself prefers ``mordred_network`` and falls back to the OS
   reachability probe). A failure raises before anything is rendered.
2. **M4 warning banner** — :data:`SEED_DISPLAY_BANNER` tells the user to
   physically cut Wi-Fi / Ethernet / Bluetooth / USB tether / hotspot and
   stop every screen recorder / remote-desktop session, because neither
   the blackout check (M4) nor the screenshot probe (M5) sees those.
3. **Screen-capture pre-check** — if a screenshot capture is already in
   progress, abort before the seed is ever consumed.
4. **Display** — :meth:`SeedDisplayHandle.consume` releases the seed
   exactly once; the surface renders it.
5. **60s monotonic timer** — the display window is bounded by
   ``time.monotonic()`` (wall-clock tamper resistant). The capture probe
   is polled across the window; a detected capture clears the surface
   immediately and aborts. On an interactive TTY the operator may press
   ENTER to clear the seed early and advance to the digest prompt; the
   timer is only an upper bound, so this merely *shortens* the exposure.
6. **Auto-clear** — the surface is cleared on every exit path (timer
   elapsed, capture abort, or any exception).

Screenshot detection (M5) is **best-effort**: the macOS ``Quartz``
``CGScreenIsBeingCaptured`` probe is the only detector. Screen recording
(``screencapture -v`` / Loom / OBS / Zoom share) and remote desktop are
NOT detected — the banner is the mitigation. The probe therefore fails
*open*: if it cannot run (non-macOS, missing pyobjc, bridge error) the
flow proceeds. This is the opposite of the blackout assert, which fails
*closed* — network isolation is a hard precondition, screenshot
detection is advisory.

The seed-carrying :class:`~mordred_hermes.keyvault.api.SeedDisplayHandle`
is owned by ``api.py`` (PR4); this module consumes it but does not
relocate it, so ``api.py`` callers are unaffected.

The macOS ``Quartz`` bridge is imported lazily (call time) so this module
imports on any platform — same contract as :mod:`keyvault.native` and
:mod:`keyvault.network_fallback`.
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import select
import sys
import time
from collections.abc import Callable
from typing import Any, NoReturn, Protocol

from ._audit_emit import chain_and_raise, emit_capture
from .api import SeedDisplayExpired, SeedDisplayHandle
from .wrap import AuditSink

_LOG = logging.getLogger("mordred.keyvault.seed_display")

DEFAULT_TTL_SECONDS: float = 60.0
"""Seconds the seed stays on screen before auto-clear (SPEC §M5).

Tracks the same SPEC §M5 "60 seconds" as ``api._SEED_DISPLAY_DEFAULT_TTL_SECONDS``,
but the two are deliberately independent knobs, not one value duplicated:
api's constant bounds how long the *handle* may sit unconsumed, this one
bounds how long the seed stays *on screen* after ``consume()``. Keep both
at the SPEC value if it ever changes.
"""

DEFAULT_POLL_INTERVAL: float = 0.5
"""Seconds between screen-capture probes during the display window."""

_DETECTOR_SCREEN_CAPTURE = "cg_screen_is_being_captured"
"""``detector`` audit-field value for a ``CGScreenIsBeingCaptured`` hit."""

SEED_DISPLAY_BANNER = (
    "SEED PHRASE DISPLAY — read before continuing:\n"
    "  - Physically disconnect Wi-Fi / Ethernet and turn OFF Bluetooth,\n"
    "    USB tethering and personal hotspots. The network-blackout check\n"
    "    only sees the OS standard network stack (M4) — hidden links are\n"
    "    your responsibility.\n"
    "  - View the seed on THIS machine's physical screen only. Stop every\n"
    "    screen recorder, screen-sharing tool and remote-desktop session\n"
    "    (Loom / Zoom share / OBS / VNC / Screen Sharing). Screen-recording\n"
    "    detection is out of scope; only screenshots are detected, and only\n"
    "    on a best-effort basis (M5).\n"
    "  - The seed clears automatically after 60 seconds — or press ENTER\n"
    "    once you have written all 24 words down to clear it now and go\n"
    "    straight to the verification-digest step."
)
"""M4 / M5 pre-display warning banner."""

# A blackout-assert callable — signature-compatible with
# ``network_fallback.blackout_assert`` (accepts an optional ``probe=``).
BlackoutAssert = Callable[..., None]

# Returns the detector name when a screen capture is in progress, else None.
CaptureProbe = Callable[[], "str | None"]

# Returns True when the operator has asked to clear the seed early (pressed
# ENTER once the words are written down); False to keep waiting out the timer.
# Polled once per capture-poll iteration, after the capture probe.
DismissProbe = Callable[[], bool]


class SeedDisplayAborted(Exception):
    """The Seed display flow was aborted because a screen capture was detected.

    Raised by :func:`display_seed` when the capture probe reports a
    capture in progress — either before the seed is shown or during the
    60s window. The surface has been cleared and a
    ``keyvault.seed_display_aborted_screenshot`` audit entry emitted
    before this is raised.

    :attr:`detector` names the detector that fired (currently only
    ``"cg_screen_is_being_captured"``). If the ``audit_sink`` itself
    raised while recording the abort, that exception is chained via
    ``__context__`` (mirrors the PR2 ``recovery._emit_mismatch`` pattern).
    """

    def __init__(self, detector: str) -> None:
        self.detector = detector
        super().__init__(f"seed display aborted — screen capture detected ({detector})")


class SeedDisplaySurface(Protocol):
    """The rendering surface :func:`display_seed` drives.

    Kept abstract so the flow is testable without a real terminal / GUI
    and so the ``hermes mordred keyvault init`` CLI (PR8) can supply its
    own implementation. All three methods must be safe to call more than
    once — :meth:`clear` in particular is invoked on every exit path and
    may run twice on the capture-abort path.
    """

    def banner(self, message: str) -> None:
        """Render the pre-display warning banner."""
        ...

    def show(self, seed: str) -> None:
        """Render the seed phrase."""
        ...

    def clear(self) -> None:
        """Remove the seed phrase from the surface. Idempotent."""
        ...


def _import_quartz() -> Any:
    """Indirection point for ``import Quartz`` (the pyobjc CoreGraphics bundle).

    Uses :func:`importlib.import_module` so mypy strict need not resolve
    the pyobjc bundle on non-macOS CI; tests substitute a fake.
    """
    return importlib.import_module("Quartz")


# Fires the missing-pyobjc warning once per process. The capture probe
# is polled tightly across the 60s display window, so without this guard
# the operator's terminal is flooded with the same warning during init.
_QUARTZ_IMPORT_WARNED = False
# Same once-per-process guard for the probe-call path: a Quartz binding
# that does not expose ``CGScreenIsBeingCaptured`` (raises AttributeError),
# or any pyobjc-bridge error, would otherwise re-warn on every poll across
# the 60s window — the noise the operator sees as a wall of identical lines.
_CAPTURE_PROBE_WARNED = False


def _default_capture_probe() -> str | None:
    """Best-effort macOS screenshot-capture probe (SPEC §M5).

    Returns :data:`_DETECTOR_SCREEN_CAPTURE` when ``CGScreenIsBeingCaptured``
    reports the main display is being captured, else ``None``.

    Fails **open**: a non-macOS host, a missing ``pyobjc-framework-Quartz``,
    or any pyobjc-bridge error all return ``None`` rather than raising —
    screenshot detection is advisory (the banner is the real mitigation),
    unlike the network blackout assert which fails closed.
    """
    if sys.platform != "darwin":
        return None

    try:
        quartz = _import_quartz()
    except ImportError:
        global _QUARTZ_IMPORT_WARNED
        if not _QUARTZ_IMPORT_WARNED:
            _LOG.warning(
                "pyobjc-framework-Quartz is not installed; screen-capture "
                "detection is disabled (best-effort only, M5). Install "
                "hermes-mordred[macos] to enable it."
            )
            _QUARTZ_IMPORT_WARNED = True
        return None

    try:
        # Probes the MAIN display only. A capture confined to a secondary
        # display is not detected — acceptable under the best-effort M5
        # scope (the banner is the real mitigation). Probing every display
        # via CGGetActiveDisplayList is a v2 hardening option.
        captured = bool(quartz.CGScreenIsBeingCaptured(quartz.CGMainDisplayID()))
    except Exception as exc:
        # Best-effort: a bridge error (incl. a Quartz build that lacks the
        # CGScreenIsBeingCaptured symbol) must not crash the display flow.
        # Warn once per process — the probe is polled every ~0.5s across the
        # 60s window, so an un-guarded warning floods the terminal.
        global _CAPTURE_PROBE_WARNED
        if not _CAPTURE_PROBE_WARNED:
            _LOG.warning(
                "screen-capture detection is unavailable on this system; "
                "continuing without it (best-effort only, M5). The seed is "
                "still protected by the on-screen warning banner and the 60s "
                "auto-clear. Underlying probe error: %s: %s",
                type(exc).__name__,
                exc,
            )
            _CAPTURE_PROBE_WARNED = True
        return None

    return _DETECTOR_SCREEN_CAPTURE if captured else None


def _default_dismiss_probe() -> bool:
    """Non-blocking check for an operator early-dismiss keypress (TTY only).

    Returns ``True`` once the operator has pressed ENTER — a line is pending on
    ``stdin`` — to clear the seed early and go straight to the digest prompt.
    Returns ``False`` while nothing is pending.

    Returns ``False`` immediately when ``stdin`` is **not** an interactive TTY:
    a piped / scripted run may already hold the queued digest line on ``stdin``,
    and draining it here would corrupt the later digest prompt. Non-interactive
    runs therefore keep the original behaviour exactly — they wait out the full
    60s timer.

    Fails **open** (like the capture probe, the opposite of the blackout
    assert): any platform / bridge error — e.g. Windows, where ``select`` does
    not accept ``stdin`` — returns ``False``. A probe failure can only cost the
    operator the early-exit convenience, never the security timer.
    """
    try:
        if not sys.stdin.isatty():
            return False
        ready, _writable, _errored = select.select([sys.stdin], [], [], 0)
        if not ready:
            return False
        # A line is pending (a cooked TTY makes select fire only after ENTER).
        # Drain it so it cannot bleed into the digest prompt that follows.
        sys.stdin.readline()
        return True
    except (OSError, ValueError, AttributeError):
        return False


def _emit_abort(audit_sink: AuditSink | None, *, detector: str) -> Exception | None:
    """Best-effort emit of the ``keyvault.seed_display_aborted_screenshot`` entry.

    Returns the sink's exception (if it raised) so the caller can chain it
    as ``__context__`` on :class:`SeedDisplayAborted` — the PR2/PR3 sink
    policy, documented once in :mod:`._audit_emit`.
    """
    return emit_capture(
        audit_sink,
        {
            "event": "keyvault.seed_display",
            "decision": "block",
            "reason": "keyvault.seed_display_aborted_screenshot",
            "detector": detector,
        },
    )


def _abort(audit_sink: AuditSink | None, *, detector: str) -> NoReturn:
    """Emit the abort audit entry and raise :class:`SeedDisplayAborted`.

    Called from :func:`display_seed`'s normal control flow (never from an
    ``except`` handler), so the explicit ``__context__`` assignment is not
    overwritten by the ``raise`` machinery (see :mod:`._audit_emit`).
    """
    sink_exc = _emit_abort(audit_sink, detector=detector)
    chain_and_raise(SeedDisplayAborted(detector), sink_exc)


def display_seed(
    handle: SeedDisplayHandle,
    surface: SeedDisplaySurface,
    *,
    blackout_assert: BlackoutAssert | None = None,
    capture_probe: CaptureProbe | None = None,
    dismiss_probe: DismissProbe | None = None,
    audit_sink: AuditSink | None = None,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Run the Seed phrase display flow (see module docstring).

    Args:
        handle: The seed-carrying handle from ``api.prepare_generate``.
            Consumed exactly once; an expired handle raises
            :class:`~mordred_hermes.keyvault.api.SeedDisplayExpired`.
        surface: The rendering surface.
        blackout_assert: Network-isolation assertion. Defaults to
            ``network_fallback.resolve_blackout_assert()``. Raises
            ``BlackoutNotAsserted`` when the host is reachable.
        capture_probe: Screenshot-capture probe. Defaults to
            :func:`_default_capture_probe`.
        dismiss_probe: Early-dismiss probe — returns ``True`` once the operator
            has pressed ENTER to clear the seed before the timer elapses and
            advance to the digest prompt. Defaults to
            :func:`_default_dismiss_probe` (interactive TTY only; always
            ``False`` off a TTY, so scripted runs are unchanged). The ``ttl``
            timer remains the upper bound: a dismiss only ever *shortens* the
            on-screen exposure.
        audit_sink: Sink for the abort audit entry.
        ttl_seconds: Display-window length (default 60s).
        poll_interval: Seconds between capture probes.
        clock: Monotonic clock (injectable for tests).
        sleep: Sleep function (injectable for tests).

    Raises:
        BlackoutNotAsserted: The host is not network-isolated — nothing
            is rendered, not even the banner.
        SeedDisplayExpired: The handle expired before the seed could be
            consumed.
        SeedDisplayAborted: A screen capture was detected before or
            during the display window.
        ValueError: ``poll_interval`` is not positive.
    """
    # Argument validation first — before any side effect. A non-positive
    # poll_interval would make the timer loop spin (sleep(0)) and hammer
    # the capture probe for the whole window instead of pacing it.
    if poll_interval <= 0:
        raise ValueError(f"poll_interval must be positive (got {poll_interval})")

    # network_fallback is imported lazily so a missing import is a
    # call-time error, consistent with the rest of keyvault.
    if blackout_assert is None:
        from .network_fallback import resolve_blackout_assert

        blackout_assert = resolve_blackout_assert()
    probe: CaptureProbe = capture_probe if capture_probe is not None else _default_capture_probe
    dismiss: DismissProbe = dismiss_probe if dismiss_probe is not None else _default_dismiss_probe

    # 1. Network blackout — hard precondition, fails closed.
    blackout_assert()

    # 2. M4 / M5 warning banner.
    surface.banner(SEED_DISPLAY_BANNER)

    # 3. Pre-display screen-capture check — abort before the seed is even
    #    consumed, so a capture-in-progress never sees the seed.
    detector = probe()
    if detector is not None:
        # The seed was never rendered, but a hostile capture environment
        # was just detected — consume the handle now so its payload is
        # zero-filled immediately rather than lingering until the handle's
        # own deadline. consume() also wipes on an expired handle, so the
        # SeedDisplayExpired it would then raise is suppressed.
        with contextlib.suppress(SeedDisplayExpired):
            handle.consume()
        _abort(audit_sink, detector=detector)

    # 4. Release the seed (one-shot; SeedDisplayExpired propagates).
    seed = handle.consume()

    # 5. Display + monotonic 60s timer with capture polling. ``finally``
    #    guarantees the surface is cleared on every exit path. The operator may
    #    also press ENTER to clear the seed early (once it is written down) and
    #    go straight to the digest prompt — ``dismiss`` is polled AFTER the
    #    capture probe so a capture detected in the same iteration still wins
    #    (security over convenience). The timer stays the upper bound, and a
    #    non-interactive run (where ``dismiss`` is always False) is unchanged.
    try:
        surface.show(seed)
        deadline = clock() + ttl_seconds
        while clock() < deadline:
            sleep(max(0.0, min(poll_interval, deadline - clock())))
            detector = probe()
            if detector is not None:
                # Clear immediately on detection, THEN audit (SPEC: the
                # seed must leave the screen before anything else).
                surface.clear()
                _abort(audit_sink, detector=detector)
            if dismiss():
                # Operator wrote the words down and pressed ENTER — stop holding
                # the seed on screen. A clean early exit, not an abort (no audit
                # entry); the ``finally`` clears the surface.
                break
    finally:
        surface.clear()
