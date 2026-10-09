"""Tor path — drives the official ``tor`` daemon as a child subprocess.

Covers rendering, port allocation, bootstrap wait, and lifecycle, plus the
richer control-port liveness probe (``GETINFO circuit-status`` via ``stem`` —
:func:`circuit_status_health`) and the wiring of :func:`start_process` into
:mod:`mordred_hermes.network.runtime`.

Subprocess and socket I/O are factored through injectable callables so
tests can replace them with fakes; production paths use the standard
library defaults.

Bridges / obfs4 / Snowflake are not supported. The
caller is expected to surface a startup warning on censored networks.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from .._exceptions import BringupFailed

_LOG = logging.getLogger("mordred.network.paths.tor")

PATH_NAME: Final[str] = "tor"
DEFAULT_PORT_CANDIDATES: Final[tuple[int, ...]] = (9050, 9150)
DEFAULT_BOOTSTRAP_TIMEOUT: Final[float] = 30.0
DEFAULT_GRACE_SECONDS: Final[float] = 5.0
BOOTSTRAP_DONE_TOKEN: Final[str] = "Bootstrapped 100%"

# Module-level latch: emit the [tor-control]-missing WARNING exactly once
# per process (the 30s liveness worker would spam logs every interval
# otherwise). Reset only from tests; production keeps it sticky.
_STEM_FALLBACK_WARNED: bool = False


class _ProcessLike(Protocol):
    """Subset of :class:`subprocess.Popen` we depend on. Easier to mock."""

    @property
    def stdout(self) -> Iterable[str] | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def poll(self) -> int | None: ...


@dataclass(frozen=True, slots=True)
class TorHandle:
    """Live Tor session. Treat as opaque; only :mod:`network.runtime` should peek."""

    process: _ProcessLike
    socks_port: int
    control_port: int
    data_dir: Path


def render_torrc(*, socks_port: int, control_port: int, data_dir: Path, disable_ipv6: bool = False) -> str:
    """Render the torrc fragment we hand to ``tor -f -``.

    ``IsolateSOCKSAuth`` is set explicitly so an optional process-scoped
    preactivation token (``proxy_env`` injects its SOCKS credential) gets a
    distinct circuit pool without relying on Tor's silent default-on
    behaviour. Per-session/per-skill token changes are not supported by the
    frozen process route.

    ``disable_ipv6`` emits ``ClientUseIPv6 0`` (strict defaults it to True,
    lenient/off to False — see ``network.settings.resolve_disable_ipv6``).
    This only controls Tor's own client connections; it does not disable host
    IPv6 or constrain provider SDK sockets, so the transport flagger cannot
    treat it as leak prevention. It defaults to False here so the parameter is
    purely additive for callers that don't pass it.
    """
    lines = [
        f"SOCKSPort 127.0.0.1:{socks_port} IsolateSOCKSAuth",
        f"ControlPort 127.0.0.1:{control_port}",
        "CookieAuthentication 1",
        f"DataDirectory {data_dir}",
    ]
    if disable_ipv6:
        lines.append("ClientUseIPv6 0")
    return "".join(f"{line}\n" for line in lines)


def pick_free_port(
    *,
    candidates: tuple[int, ...] = DEFAULT_PORT_CANDIDATES,
    socket_factory: Callable[..., Any] = socket.socket,
    host: str = "127.0.0.1",
) -> int:
    """Return the first free adjacent ``(SOCKS, ControlPort)`` pair.

    Tor uses ``socks_port + 1`` for its control socket. Checking only the
    SOCKS port can select a pair whose control port is already occupied (or
    select 65535, whose derived control port is invalid). Both sockets remain
    bound until the pair has been proven available, then close together.
    """
    last_err: OSError | None = None
    for port in candidates:
        try:
            validate_port_pair(port)
        except BringupFailed as exc:
            last_err = OSError(str(exc))
            continue
        sockets: list[Any] = []
        try:
            for candidate in (port, port + 1):
                sock = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(sock)
                sock.bind((host, candidate))
        except OSError as e:
            last_err = e
            continue
        finally:
            for sock in sockets:
                sock.close()
        return port
    raise BringupFailed(
        f"all candidate Tor SOCKS/control port pairs busy or invalid: {candidates} (last error: {last_err})"
    )


def validate_port_pair(socks_port: object) -> None:
    """Require room for the adjacent TCP control port."""
    if isinstance(socks_port, bool) or not isinstance(socks_port, int) or not 0 < socks_port < 65535:
        raise BringupFailed(f"Tor SOCKS port must be in 1..65534 so control port +1 is valid; got {socks_port!r}")


ReadLine = Callable[[float], "str | None"]
"""Bounded-deadline line reader contract.

A callable that, given a ``deadline_seconds`` budget, returns:

- ``str`` — a line was read (caller checks for the bootstrap token)
- ``""`` (empty string) — readiness timeout; no line available within budget
- ``None`` — stdout has reached EOF
"""


def _make_default_read_line(stdout: Iterable[str]) -> tuple[ReadLine, Callable[[], None]]:
    """Return ``(read_line, cleanup)`` honoring a per-call deadline.

    For real ``Popen.stdout`` (has ``fileno``) a daemon thread pumps
    blocking ``readline()`` results into a queue, and ``read_line`` waits
    on that queue with the caller's budget. An earlier version registered
    the pipe with ``selectors.DefaultSelector``, but on Windows that is
    ``select.select``-backed and only accepts sockets (pipes raise
    ``OSError`` WinError 10038); the reader thread gives the same deadline
    semantics on every platform (review 2026-07-29). For test fakes
    (lists, generators) the next item is always available so we just
    iterate; the deadline argument is ignored.

    Codex P1 / HIGH-2 fix (2026-05-13). Previously this function
    ``for line in stdout`` blocked indefinitely whenever tor stopped
    writing — that codepath is now gone.

    After ``cleanup()`` the pump stops queueing lines but deliberately keeps
    draining the OS pipe until EOF. Tor retains stdout for its lifetime; if no
    reader remains after bootstrap, enough later log output fills the pipe and
    blocks the daemon itself.
    """
    fileno_attr = getattr(stdout, "fileno", None)
    if callable(fileno_attr):
        return _make_piped_read_line(stdout)

    iterator = iter(stdout)

    def read_line_iter(deadline_seconds: float) -> str | None:
        del deadline_seconds  # iterables yield immediately or signal EOF
        try:
            return next(iterator)
        except StopIteration:
            return None

    def cleanup_noop() -> None:
        return None

    return read_line_iter, cleanup_noop


def _make_piped_read_line(stdout: Iterable[str]) -> tuple[ReadLine, Callable[[], None]]:
    """Reader-thread ``(read_line, cleanup)`` for a real pipe.

    See :func:`_make_default_read_line` for the contract and the
    portability rationale (selectors cannot watch pipes on Windows).

    Reader-side errors before cleanup are not swallowed on the pump thread: they are
    delivered through the queue and re-raised by ``read_line``, preserving
    the pre-thread behavior where a torn-down pipe raised on the caller's
    thread and surfaced as ``BringupFailed`` with a real ``__cause__``.
    ``cleanup()`` switches the thread to discard/drain mode.
    """
    lines: queue.SimpleQueue[str | BaseException | None] = queue.SimpleQueue()
    draining = threading.Event()
    threading.Thread(
        target=_pump_stdout_lines,
        args=(stdout, lines, draining),
        name="mordred-tor-bootstrap-read",
        daemon=True,
    ).start()
    eof_seen = False

    def read_line(deadline_seconds: float) -> str | None:
        nonlocal eof_seen
        if eof_seen:
            return None
        try:
            item = lines.get(timeout=max(deadline_seconds, 0.0))
        except queue.Empty:
            return ""
        if isinstance(item, BaseException):
            eof_seen = True
            raise item
        if item is None:
            eof_seen = True
        return item

    def cleanup() -> None:
        draining.set()

    return read_line, cleanup


def _pump_stdout_lines(
    stdout: Iterable[str],
    lines: queue.SimpleQueue[str | BaseException | None],
    draining: threading.Event,
) -> None:
    """Pump thread body for :func:`_make_piped_read_line`.

    Blocks in ``readline`` and forwards bootstrap lines into ``lines``.
    Once ``draining`` is set, it consumes and discards all later output so the
    child's pipe never applies backpressure. Errors are delivered only while a
    caller is still reading; the trailing ``None`` sentinel signals EOF.
    """
    try:
        for line in stdout:
            if not draining.is_set():
                lines.put(line)
    except Exception as exc:  # delivered, not swallowed: read_line re-raises
        if not draining.is_set():
            lines.put(exc)
    finally:
        lines.put(None)  # EOF/abandon sentinel


def wait_for_bootstrap(
    process: _ProcessLike,
    *,
    timeout: float = DEFAULT_BOOTSTRAP_TIMEOUT,
    clock: Callable[[], float] = time.monotonic,
    read_line: ReadLine | None = None,
) -> None:
    """Read ``process.stdout`` until ``BOOTSTRAP_DONE_TOKEN`` appears.

    Raises :class:`BringupFailed` if the token is not seen before
    ``timeout`` seconds (per ``clock``) elapse, or if stdout closes
    without producing the token.

    The ``read_line`` callable encapsulates "get next line, honoring a
    per-call deadline". Default reads from ``process.stdout`` via a
    reader thread so an idle real ``tor`` daemon cannot wedge the
    loop. Tests inject a fake that returns ``""`` (readiness timeout)
    or ``None`` (EOF) without touching real file descriptors.
    """
    cleanup: Callable[[], None] | None = None
    if read_line is None:
        stdout = process.stdout
        if stdout is None:
            raise BringupFailed("tor process has no stdout to tail")
        read_line, cleanup = _make_default_read_line(stdout)

    try:
        deadline = clock() + timeout
        while True:
            remaining = deadline - clock()
            if remaining <= 0:
                raise BringupFailed(f"tor bootstrap timeout after {timeout}s")
            line = read_line(remaining)
            if line is None:
                raise BringupFailed("tor stdout closed before bootstrap completed")
            if line == "":
                continue
            if BOOTSTRAP_DONE_TOKEN in line:
                return
    finally:
        if cleanup is not None:
            cleanup()


def stop(handle: TorHandle, *, grace_seconds: float = DEFAULT_GRACE_SECONDS) -> None:
    """Terminate, wait the grace window, then kill if still alive.

    Uses ``process.terminate()`` plus a grace period before ``kill()``.
    Idempotent if
    the process already exited.

    Note on exception types (Codex review P1 / HIGH-1, 2026-05-13):
    real :class:`subprocess.Popen.wait` raises
    :class:`subprocess.TimeoutExpired` (inheriting ``SubprocessError →
    Exception``), *not* the built-in :class:`TimeoutError` (which is an
    ``OSError`` subclass). We must catch the former so the kill
    escalation actually fires in production.
    """
    proc = handle.process
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            return


def health(handle: TorHandle) -> bool:
    """Shallow liveness: subprocess is still running.

    The deeper ``circuit_status_health`` probe (Phase 3 PR3a Task #5) is
    an opt-in via the optional ``[tor-control]`` extra. Lenient / off
    operators keep this shallow check; strict operators wire the deeper
    probe through the runtime's ``tor_health`` injection point.
    """
    return handle.process.poll() is None


# --------------------------------------------------------------------------- #
# Phase 3 PR3a Task #5: ControlPort cookie auth + GETINFO circuit-status      #
# --------------------------------------------------------------------------- #


class _ControllerLike(Protocol):
    """Subset of ``stem.control.Controller`` we depend on.

    The default factory returns a real stem ``Controller``; tests inject
    a ``_FakeController``-style stand-in. Both must support the context-
    manager protocol so the socket closes deterministically.

    Codex review (2026-05-14, P1): the ``authenticate`` signature mirrors
    stem's real ``Controller.authenticate(password=None, chroot_path=None,
    protocolinfo_response=None)`` rather than a custom ``cookie=`` kwarg.
    Stem does PROTOCOLINFO discovery + cookie read internally, so we
    invoke it with no positional args. Fakes that previously accepted
    ``cookie=...`` would have masked the API mismatch.
    """

    def authenticate(self) -> None: ...

    def get_info(self, key: str) -> str: ...

    def close(self) -> None: ...

    def __enter__(self) -> _ControllerLike: ...

    def __exit__(self, *args: object) -> None: ...


ControllerFactory = Callable[..., _ControllerLike]


def _default_controller_factory(*, host: str, port: int) -> _ControllerLike:
    """Lazy import of ``stem.control.Controller``.

    Kept local so module import doesn't pay the stem dep cost (and so
    operators without the ``[tor-control]`` extra never see an
    ``ImportError`` at plugin discovery time). The :class:`ImportError`
    raised here is caught by :func:`circuit_status_health` and surfaces
    as a graceful shallow fallback.
    """
    # No inline `type: ignore` here on purpose: stem is an optional extra, so the
    # error code differs by environment (import-not-found in CI where it is
    # absent, import-untyped on a dev box that installed it). `[[tool.mypy.
    # overrides]]` in pyproject.toml declares stem instead, which covers both.
    from stem.control import Controller

    controller = Controller.from_port(address=host, port=port)
    return cast(_ControllerLike, controller)


def circuit_status_health(
    handle: TorHandle,
    *,
    controller_factory: ControllerFactory | None = None,
    host: str = "127.0.0.1",
) -> bool:
    """Deep liveness via Tor ControlPort ``GETINFO circuit-status``.

    Returns ``True`` when the ControlPort is reachable, authentication
    succeeds, and either the circuit-status reply lists at least one
    well-formed ``BUILT`` circuit, or the reply is inconclusive (empty or
    only in-progress / unknown non-terminal circuits) and Tor's own
    ``GETINFO network-liveness`` verdict is ``up``. The liveness follow-up
    keeps both prior behaviors honest at once: an idle Tor that tore down
    its preemptive circuits stays healthy (liveness ``up``), while a
    running-but-circuit-less Tor whose upstream died reads unhealthy
    (liveness ``down``). FAILED/CLOSED circuits are pruned from
    circuit-status output almost immediately, so the circuit list alone
    cannot tell those two states apart (review 2026-07-29).

    Tor may add circuit states in future protocol revisions. An unknown
    state with a syntactically valid uppercase keyword is treated as
    non-terminal (inconclusive) rather than unhealthy, so a newer local Tor
    cannot cause a false sticky drop by itself. A reply whose well-formed
    circuits are all terminal ``FAILED`` / ``CLOSED``, or a malformed reply
    without a ``BUILT`` circuit, is unhealthy.

    Deliberate consequence: an upstream outage sustained across the
    runtime's consecutive-failure threshold (2 x 30s by default) latches
    the sticky drop even though the tor daemon survives, and the operator
    must re-activate the path. That is the strict-mode fail-closed
    contract — the original BUILT-only probe latched in the same
    situations (plus, wrongly, on idle), and softening the latch itself is
    a runtime design decision, not a probe one (review 2026-07-29).

    Graceful degradation applies only when the deep probe is unavailable:

    - Missing ``control_auth_cookie`` (Tor still bootstrapping or data
      dir wiped) → shallow fallback.
    - ImportError from the default factory (the user did not install
      ``hermes-mordred[tor-control]``) → shallow fallback.
    - Authentication failure (cookie mismatch, daemon rejected) →
      ``False`` (runtime treats as drop). This is different from the
      ImportError case because a present-but-rejected cookie is a real
      Tor problem the operator should see.
    - Any other Exception (unreachable ControlPort, network glitch), or a
      malformed ``GETINFO`` value → ``False``. Logging is deferred to the
      runtime so this stays a pure boolean signal.

    The 30s liveness worker calls this every interval; the controller
    is closed on every call so the control-port socket pool doesn't
    grow.
    """
    cookie_path = handle.data_dir / "control_auth_cookie"
    if not cookie_path.exists():
        # No cookie => Tor still bootstrapping or the data dir was wiped;
        # the deep probe has nothing to authenticate with. Stem would
        # auto-discover this path via PROTOCOLINFO and produce the same
        # outcome, but we short-circuit here to keep the shallow fallback
        # path fast (avoids opening a control-port socket just to fail).
        return health(handle)

    factory = controller_factory or _default_controller_factory
    try:
        controller = factory(host=host, port=handle.control_port)
    except ImportError:
        # Optional [tor-control] extra not installed; fall back gracefully
        # to the shallow process.poll() check. Strict-mode operators need
        # visibility into this downgrade (review H5) so we WARN on the
        # first occurrence; the module-level latch keeps the 30s liveness
        # worker from spamming logs.
        global _STEM_FALLBACK_WARNED
        if not _STEM_FALLBACK_WARNED:
            _LOG.warning(
                "stem not installed; circuit_status_health degraded to shallow process.poll() "
                "fallback. Install the optional dependency to recover deep liveness: "
                "pip install 'hermes-mordred[tor-control]'."
            )
            _STEM_FALLBACK_WARNED = True
        return health(handle)
    except Exception:
        # Anything else at construction time (port unreachable, refused, ...)
        # is treated as drop rather than crash.
        return False

    try:
        try:
            # Codex P1 (2026-05-14): stem's real
            # ``Controller.authenticate`` does PROTOCOLINFO discovery and
            # reads the cookie file itself. The previous ``cookie=`` kwarg
            # raised TypeError on every probe.
            controller.authenticate()
        except Exception:
            return False
        try:
            response = controller.get_info("circuit-status")
        except Exception:
            return False
        verdict = _classify_circuit_status(response)
        if verdict is not None:
            return verdict
        # Inconclusive circuit list: an idle Tor legitimately has no
        # circuits, and a dead-but-alive Tor shows none either because
        # FAILED/CLOSED entries are pruned from GETINFO output almost
        # immediately. Tor's own reachability verdict tells them apart.
        try:
            liveness = controller.get_info("network-liveness")
        except Exception:
            return False
        return liveness.strip() == "up"
    finally:
        with contextlib.suppress(Exception):
            controller.close()


_TERMINAL_CIRCUIT_STATUSES: Final[frozenset[str]] = frozenset({"FAILED", "CLOSED"})


def _classify_circuit_status(response: str) -> bool | None:
    """Classify a ``GETINFO circuit-status`` value; ``None`` is inconclusive.

    Non-empty lines follow torspec ``control-spec §4.1.1``:

    ``<CircuitID> <Status> [<Path>] [BUILD_FLAGS=...] ...``

    Stem strips ``250-`` / ``250+`` reply framing. We validate the circuit
    identifier and status keyword rather than treating every arbitrary string
    as a successful probe; optional trailing fields remain forward-compatible.
    A leading ``circuit-status=`` echo from older Tor versions is tolerated
    in both its standalone-line and attached (``circuit-status=8 BUILT …``)
    forms.

    - ``True`` — at least one well-formed ``BUILT`` circuit. Malformed
      sibling lines cannot veto it: a probe that proves a working circuit
      must not sticky-drop the path over an unparseable neighbor line.
    - ``False`` — a malformed reply with no ``BUILT`` circuit, or
      well-formed circuits that are all in the known terminal ``FAILED`` /
      ``CLOSED`` states.
    - ``None`` — empty, or only in-progress (``LAUNCHED`` / ``EXTENDED`` /
      ``GUARD_WAIT``) / unknown non-terminal circuits. The circuit list
      alone cannot distinguish "healthy but idle" from "cannot build a
      circuit"; :func:`circuit_status_health` resolves the tie with Tor's
      ``network-liveness`` verdict.
    """
    if not isinstance(response, str):
        return False

    lines = _strip_circuit_status_echo(response.splitlines())

    saw_malformed = False
    saw_terminal = False
    saw_nonterminal = False
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        status = _parse_circuit_status_line(line)
        if status is None:
            saw_malformed = True
        elif status == "BUILT":
            return True
        elif status in _TERMINAL_CIRCUIT_STATUSES:
            saw_terminal = True
        else:
            saw_nonterminal = True
    if saw_malformed:
        return False
    if saw_terminal and not saw_nonterminal:
        return False
    return None


def _strip_circuit_status_echo(lines: list[str]) -> list[str]:
    """Drop a leading ``circuit-status=`` echo, standalone or attached.

    lstrip before matching: some Tor builds surface the echo with leading
    whitespace, which must not read as a malformed line.
    """
    if lines:
        first = lines[0].lstrip()
        if first.startswith("circuit-status="):
            lines[0] = first[len("circuit-status=") :]
    return lines


def _parse_circuit_status_line(line: str) -> str | None:
    """The status keyword of one circuit-status line, or ``None`` if malformed."""
    tokens = line.split()
    if len(tokens) < 2:
        return None
    circuit_id, status = tokens[:2]
    if not (1 <= len(circuit_id) <= 16 and circuit_id.isascii() and circuit_id.isalnum()):
        return None
    if not _is_valid_circuit_status_keyword(status):
        return None
    return status


def _is_valid_circuit_status_keyword(status: str) -> bool:
    """Whether ``status`` has Tor's extensible uppercase-keyword shape."""
    return (
        bool(status)
        and status.isascii()
        and status[0].isalpha()
        and all(character.isupper() or character.isdigit() or character == "_" for character in status)
    )


def start_process(
    *,
    binary: str,
    torrc: str,
    popen_factory: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
) -> _ProcessLike:
    """Spawn ``tor -f -`` with the rendered torrc on stdin.

    Production wiring only; tests inject ``popen_factory`` to swap in
    a fake. Kept separate from the higher-level orchestration so the
    per-step behavior is independently testable.
    """
    proc = popen_factory(
        [binary, "-f", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        # errors="replace": text mode defaults to STRICT decoding, so a single
        # non-UTF-8 byte in tor's log output (a relay nickname, a locale-encoded
        # OS error string) makes readline() raise UnicodeDecodeError deep inside
        # the bootstrap tail — killing a bring-up over a cosmetic byte. We only
        # scan these lines for the bootstrap token, so lossy decoding is strictly
        # better than failing. ``runtime._bring_up_tor`` also defends against
        # this, but fixing it at the source keeps the daemon from dying at all.
        errors="replace",
        bufsize=1,
    )
    if proc.stdin is not None:
        proc.stdin.write(torrc)
        proc.stdin.close()
    return cast(_ProcessLike, proc)
