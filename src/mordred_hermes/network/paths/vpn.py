"""Mullvad VPN path — drives the official ``mullvad`` CLI.

PR1 scope: CLI detection, bring-up sequence, status polling, disconnect,
handshake-age liveness probe. PR2 wires :func:`detect_cli` /
:func:`bring_up` / :func:`disconnect` into :mod:`mordred_hermes.network.runtime`
and ties handshake-age failures to the audit log.

Subprocess I/O is factored through an injectable runner so tests can
replace it; production uses :func:`subprocess.run`.

The Mullvad client is daemonized externally — we don't track a
``Popen``. The handle records what *we* asked for so the runtime can decide
whether to preserve lockdown on disconnect.

Platform: macOS Apple Silicon + Ubuntu/Debian. Windows is out of scope
for v1.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol

from ..._policy_types import PolicyMode as PolicyMode
from .._exceptions import BringupFailed
from ..guidance import MACOS_MULLVAD_APP_CLI, mullvad_install_guidance

PATH_NAME: Final[str] = "vpn"

MACOS_APP_BUNDLE_PATH: Final[str] = MACOS_MULLVAD_APP_CLI

DEFAULT_CONNECT_TIMEOUT: Final[float] = 10.0
DEFAULT_POLL_INTERVAL: Final[float] = 0.5
DEFAULT_MAX_HANDSHAKE_AGE_SECONDS: Final[float] = 180.0
DEFAULT_COMMAND_TIMEOUT: Final[float] = 5.0


class SubprocessRunner(Protocol):
    """The injectable command runner contract.

    Deliberately NOT ``Callable[..., CompletedProcess[str]]``: every production
    call site now passes ``timeout=`` so a bounded command cannot hold the
    runtime's lifecycle lock forever, and the elided-argument form let a runner
    without that parameter type-check cleanly and then ``TypeError`` at bring-up.
    Keyword arguments carry defaults so existing ``runner(argv)`` calls remain
    valid for implementers.
    """

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


SettingState = Literal["on", "off", "unknown"]


def _default_runner(
    argv: list[str] | tuple[str, ...],
    *,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Production default for the injectable runner.

    Centralized so tests can swap in a fake and the production path
    retains a single subprocess invocation site.
    """
    return subprocess.run(
        list(argv),
        check=check,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
    )


DEFAULT_RUNNER: Final[SubprocessRunner] = _default_runner
_LOG = logging.getLogger("mordred.network.vpn")


@dataclass(frozen=True, slots=True)
class MullvadHandle:
    """What we configured. The Mullvad daemon owns the actual tunnel state.

    ``lockdown_applied_by_us`` records whether we observed ``off`` and then
    successfully requested ``on``. It is informational, not proof of exclusive
    ownership: Mullvad has no compare-and-swap operation, so another actor may
    enable lockdown between those commands. Strict automatic cleanup therefore
    always preserves ON; only an explicit ``disconnect(...,
    preserve_lockdown=False)`` may turn it off.

    Mullvad CLI 2026.2 removed the separate ``always-require-vpn``
    subcommand; its semantics are now subsumed by ``lockdown-mode``,
    so the handle no longer carries a corresponding flag.
    """

    cli_path: str
    region: str
    lockdown_enforced: bool
    lockdown_applied_by_us: bool = False


def detect_cli(*, which: Callable[[str], str | None] = shutil.which) -> str:
    """Resolve the path to the ``mullvad`` CLI.

    Checks ``$PATH`` first via the injected ``which``; falls back to the
    macOS app bundle location. Raises
    :class:`BringupFailed` if neither is present so the caller can
    surface an actionable error.
    """
    path = which("mullvad")
    if path:
        return path
    if Path(MACOS_APP_BUNDLE_PATH).exists():
        return MACOS_APP_BUNDLE_PATH
    raise BringupFailed(
        f"mullvad client not installed (checked $PATH and macOS app bundle). {mullvad_install_guidance()}"
    )


def bring_up(
    *,
    cli_path: str,
    region: str,
    policy_mode: PolicyMode,
    runner: SubprocessRunner = DEFAULT_RUNNER,
) -> MullvadHandle:
    """Run the configured bring-up sequence.

    Strict mode enforces ``lockdown-mode`` (the kill-switch); lenient
    and off respect the user's existing settings. Region defaults to
    ``auto`` when callers don't pass one.

    Does *not* block on ``Connected`` — call :func:`wait_connected`
    afterwards (split so callers can audit each step independently).

    Codex round 4 P1 (2026-05-14): every step now inspects
    ``returncode`` and raises :class:`BringupFailed` on non-zero so a
    failed ``lockdown-mode set on`` / ``relay`` / ``connect`` cannot
    produce a handle. Without this the runtime would mark the VPN
    path ``READY`` even though Mullvad refused the request — strict
    mode would fail open.

    Mullvad CLI 2026.2 drift (2026-05-20): the standalone
    ``always-require-vpn`` subcommand was removed; its kill-switch
    semantics are now subsumed by ``lockdown-mode``, so strict mode
    only flips that one setting.
    """
    # Only enable a strict kill-switch we observed OFF. The state query and
    # mutation are not atomic (Mullvad exposes no CAS), so even a successful
    # ``set on`` cannot establish exclusive ownership. On later failure we
    # deliberately leave lockdown ON rather than risk disabling a concurrent
    # operator's security setting.
    lockdown_applied = False
    try:
        if policy_mode == "strict":
            lockdown_state = _get_setting_state(runner, cli_path, "lockdown-mode")
            if lockdown_state == "unknown":
                raise BringupFailed(
                    "mullvad lockdown-mode state could not be determined; "
                    "refusing to change an operator-owned kill-switch in strict mode"
                )
            if lockdown_state == "off":
                _run_or_raise(runner, (cli_path, "lockdown-mode", "set", "on"))
                lockdown_applied = True
                confirmed_state = _get_setting_state(runner, cli_path, "lockdown-mode")
                if confirmed_state != "on":
                    raise BringupFailed(
                        "mullvad lockdown-mode did not confirm ON after a successful set command; "
                        f"observed {confirmed_state!r}"
                    )
        # Codex round 6 P1 (2026-05-14): the Mullvad CLI keyword for
        # automatic relay selection is ``any``, not ``auto``. We keep
        # ``auto`` as the user-facing alias (wizard prompt +
        # RuntimeConfig default) and translate at the CLI boundary so
        # the new returncode check from r4-P1 doesn't turn every
        # default-region bring-up into a :class:`BringupFailed`.
        cli_region = "any" if region == "auto" else region
        _run_or_raise(runner, (cli_path, "relay", "set", "location", cli_region))
        _run_or_raise(runner, (cli_path, "connect"))
    except BringupFailed:
        if lockdown_applied:
            _LOG.warning(
                "Mullvad bring-up failed after lockdown-mode was requested ON; "
                "leaving it ON because concurrent ownership cannot be ruled out. "
                "Disable it explicitly only after confirming no other actor relies on it."
            )
        raise
    return MullvadHandle(
        cli_path=cli_path,
        region=region,
        lockdown_enforced=(policy_mode == "strict"),
        lockdown_applied_by_us=lockdown_applied,
    )


def _get_setting_state(runner: SubprocessRunner, cli_path: str, setting: str) -> SettingState:
    """Query ``mullvad <setting> get`` without conflating failure with OFF.

    ``unknown`` covers command errors, non-zero exits, and output drift. In
    strict mode the caller refuses before mutation: treating an unreadable
    operator-owned ON setting as OFF would let a later rollback disable the
    user's pre-existing kill-switch.
    """
    try:
        result = runner(
            (cli_path, setting, "get"),
            timeout=DEFAULT_COMMAND_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    stdout = (result.stdout or "").strip().lower()
    # Mullvad CLI output forms: "Network lockdown when disconnected: on"
    # / "Always require VPN: off". Match the bare value token, never a
    # substring: a stray word ending in "on" (e.g. "...connection") must
    # not be misread as the setting being ON — in strict that would fail
    # OPEN, because bring_up would then skip ``lockdown-mode set on``
    # believing the kill-switch is already active. The value token
    # ("on"/"off") is stable across Mullvad versions even as labels drift.
    match = re.search(r"(?:^|:\s*)(on|off)\s*$", stdout)
    if match is None:
        return "unknown"
    return "on" if match.group(1) == "on" else "off"


def _run_or_raise(runner: SubprocessRunner, argv: tuple[str, ...]) -> None:
    """Invoke ``runner(argv)`` and translate non-zero returncode into
    :class:`BringupFailed`. Empty stderr defaults so the message is
    still actionable when the CLI is silent."""
    try:
        result = runner(argv, timeout=DEFAULT_COMMAND_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BringupFailed(f"mullvad command {' '.join(argv)!r} failed or timed out: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise BringupFailed(f"mullvad command {' '.join(argv)!r} failed (rc={result.returncode}): {detail!r}")


def wait_connected(
    *,
    cli_path: str,
    runner: SubprocessRunner = DEFAULT_RUNNER,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Poll ``mullvad status`` until it reports ``Connected``.

    Raises :class:`BringupFailed` when the timeout elapses. Polling
    interval is conservative so we don't hammer the daemon — the
    bring-up window in practice is 1-3 seconds.
    """
    start = clock()
    while True:
        try:
            result = runner(
                (cli_path, "status"),
                timeout=min(DEFAULT_COMMAND_TIMEOUT, max(timeout, 0.1)),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BringupFailed(f"mullvad status failed or timed out: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise BringupFailed(f"mullvad status failed (rc={result.returncode}): {detail!r}")
        if _status_is_connected(result.stdout or ""):
            return
        if clock() - start > timeout:
            raise BringupFailed(f"mullvad did not reach Connected within {timeout}s")
        sleeper(poll_interval)


def disconnect(
    handle: MullvadHandle,
    *,
    runner: SubprocessRunner = DEFAULT_RUNNER,
    preserve_lockdown: bool = True,
) -> None:
    """Disconnect the tunnel; optionally clear the strict kill-switch.

    Strict-mode sessions preserve lockdown so the user must explicitly opt out
    in a later session.

    Mullvad CLI 2026.2 drift (2026-05-20): the ``always-require-vpn``
    rollback path (Codex round 9 P1-A) is gone — the subcommand was
    removed upstream and ``lockdown-mode`` now covers the same
    "block traffic when not connected" guarantee.
    """
    _run_or_raise(runner, (handle.cli_path, "disconnect"))
    if not preserve_lockdown:
        _run_or_raise(runner, (handle.cli_path, "lockdown-mode", "set", "off"))


def _status_is_connected(stdout: str) -> bool:
    """Parse the Mullvad status token without substring false positives.

    Every non-blank line is examined, not just the first: Mullvad versions differ
    in whether they print the tunnel state first or precede it with a header, and
    pinning to line 0 would report a healthy tunnel as down after a cosmetic CLI
    change. Token discipline is unchanged — ``Not Connected``, ``Connecting``,
    and ``Disconnected`` still do not match.
    """
    prefix = "tunnel status:"
    for raw_line in stdout.splitlines():
        normalized = raw_line.strip().casefold()
        if not normalized:
            continue
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :].strip()
        if normalized == "connected" or normalized.startswith("connected to "):
            return True
    return False


_AGE_TOKEN_RE: Final = re.compile(
    r"(?P<value>\d+)\s+(?P<unit>second|minute|hour|day)s?",
    re.IGNORECASE,
)
_UNIT_SECONDS: Final[dict[str, float]] = {
    "second": 1.0,
    "minute": 60.0,
    "hour": 3600.0,
    "day": 86400.0,
}
# One ``wg show`` handshake line, e.g. "  latest handshake: 1 minute, 30 seconds
# ago". Captures the age text so each peer's compound age is summed on its own
# line (see :func:`parse_handshake_age`) rather than across the whole output.
_HANDSHAKE_LINE_RE: Final = re.compile(r"latest handshake:\s*(?P<age>.*)", re.IGNORECASE)


def parse_handshake_age(wg_show_stdout: str) -> float | None:
    """Return the most-recent handshake age in seconds, or ``None`` if absent.

    ``wg show`` (unscoped) lists EVERY WireGuard interface on the host, so a
    second, unrelated tunnel contributes its own ``latest handshake:`` line.
    We therefore parse each handshake line independently — summing the tokens
    WITHIN a single compound age (``"1 minute, 30 seconds ago"`` → 90s) — and
    return the MINIMUM across peers (the freshest handshake). Summing across
    peers, as an earlier version did, over-estimated the age and caused a
    false ``health() == False`` path-drop whenever another tunnel was present.

    Returns ``None`` when no parsable handshake is found — an all-``(none)``
    output ("never handshook") or malformed / truncated stdout — so callers
    can distinguish "no fresh handshake" from a successfully-parsed age.
    """
    ages: list[float] = []
    for line in wg_show_stdout.splitlines():
        m = _HANDSHAKE_LINE_RE.search(line)
        if m is None:
            continue
        tokens = list(_AGE_TOKEN_RE.finditer(m.group("age")))
        if not tokens:
            # "(none)" or an otherwise unparseable age — this peer has no
            # fresh handshake; skip it rather than poisoning a fresh peer.
            continue
        ages.append(sum(int(t.group("value")) * _UNIT_SECONDS[t.group("unit").lower()] for t in tokens))
    if not ages:
        return None
    return min(ages)


def health(
    handle: MullvadHandle,
    *,
    runner: SubprocessRunner = DEFAULT_RUNNER,
) -> bool:
    """Probe ``mullvad status`` and return ``True`` iff it reports Connected.

    Mullvad-SCOPED by construction (fix 2026-07-13). The previous
    implementation ran an UNSCOPED ``wg show`` and asked
    :func:`parse_handshake_age` for the freshest handshake across EVERY
    WireGuard interface on the host. On a machine with a second, unrelated
    WireGuard tunnel (a corp VPN, a self-hosted peer, the generic-WireGuard
    provider's own ``wg0``) that other interface's fresh handshake masked a
    stale/dead Mullvad tunnel — ``health()`` reported the Mullvad path up
    while Mullvad's OWN tunnel had dropped, defeating the strict kill-switch
    drop detection for the one provider strict mode trusts.

    We now use the Mullvad daemon's own ``Connected`` / ``Disconnected``
    state — the exact signal :func:`wait_connected` polls at bring-up. It is
    inherently scoped to Mullvad's tunnel (``mullvad status`` cannot be fooled
    by a sibling ``wg`` interface) and flips to ``Disconnected`` /
    ``Connecting`` the moment that tunnel drops. The parser requires an exact
    ``Connected`` token or ``Connected to ...`` first line (optionally after
    ``Tunnel status:``), so diagnostics such as ``Not Connected`` cannot mark
    the route ready.

    Trade-off — daemon belief vs kernel handshake ground truth: ``mullvad
    status`` reflects the daemon's connection state, not the WireGuard kernel
    handshake age. In the rare window where the daemon still believes it is
    Connected but the peer has silently gone away, a handshake-age probe of
    Mullvad's OWN interface would notice a little sooner. We accept that: a
    false "healthy" borrowed from a SIBLING interface (the old bug) is a
    strict-mode fail-OPEN and strictly worse than slightly slower drop
    detection, whereas trusting the daemon's Mullvad-specific belief is
    fail-closed against cross-interface masking. Pinning Mullvad's own
    interface name at bring-up for a scoped ``wg show`` is a possible v2
    refinement (:func:`parse_handshake_age` stays for the generic-WireGuard
    provider, whose handle DOES know its interface name).

    Falls back to ``False`` on any subprocess failure — the invocation itself
    failing (``mullvad`` not on PATH → :class:`FileNotFoundError`), a
    ``timeout=`` passed by the liveness worker
    (:class:`subprocess.TimeoutExpired`), or a non-zero return code. All are
    coerced to ``unhealthy`` so the PR2 liveness worker records the path as
    down instead of crashing (matching the prior fail-closed contract, Codex
    P2 / HIGH-3 2026-05-13).
    """
    try:
        result = runner(
            (handle.cli_path, "status"),
            timeout=DEFAULT_COMMAND_TIMEOUT,
        )
    except (FileNotFoundError, PermissionError, subprocess.SubprocessError, OSError):
        return False
    if result.returncode != 0:
        return False
    return _status_is_connected(result.stdout or "")
