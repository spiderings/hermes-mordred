"""Concrete :class:`Runtime` for ``mordred_network`` (Phase 3 PR2).

Implements the :class:`mordred_hermes.network.api.Runtime` Protocol with:

- A small state machine (``IDLE`` -> ``BRINGING_UP`` -> ``READY`` ->
  ``TEARING_DOWN`` -> ``IDLE``; ``DEGRADED`` for lenient clearnet
  fallback after a Tor / Mullvad bring-up failure).
- Path-specific subprocess handles via the PR1 path modules
  (:mod:`.paths.tor`, :mod:`.paths.vpn`, :mod:`.paths.clearnet`). Every
  external call is exposed as a constructor-injected callable so unit
  tests can swap in fakes without monkey-patching the path modules.
- ``os.environ`` mutation per :mod:`.proxy_env`. The runtime snapshots
  the keys it manages on first apply and restores them on
  :meth:`Runtime.stop`. This is the only writer of those keys inside the
  plugin.
- An M9 liveness worker (daemon thread): probes the current path on a
  configurable interval; ``liveness_failure_threshold`` consecutive
  failures flip a sticky ``_dropped`` flag and emit
  ``network.path_dropped``. The flag is exposed via
  :meth:`Runtime.is_dropped` so PR2 ``hooks.pre_tool_call`` can raise
  :class:`MordredPathDropped` on the next tool call.

Auto-recovery and silent fallback are intentionally absent. Strict-mode
bring-up failure re-raises :class:`BringupFailed`; the PR2 hook layer
translates that to the :class:`BaseException`-derived
:class:`MordredPathBringupFailed` so Hermes' ``except Exception`` filter
in ``hermes_cli.plugins.invoke_hook`` cannot swallow the refusal
(``HOOK_PAYLOADS.md`` §1).
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field, fields
from enum import Enum
from pathlib import Path
from typing import Any, Final, cast

from .._audit_support import AuditWriter as _AuditWriter
from .._audit_support import safe_audit_append
from .._policy_types import ACTIVE_PATHS
from .._policy_types import ActivePath as ActivePath
from .._policy_types import PolicyMode as PolicyMode
from . import proxy_env as proxy_env_mod
from ._exceptions import (
    AlreadySwitching,
    BringupFailed,
    MordredNetworkError,
    PathSwitchRequiresRestart,
    UnknownPath,
)
from .api import NetworkStatus
from .guidance import tor_install_guidance
from .paths import clearnet as clearnet_mod
from .paths import tor as tor_mod
from .vpn_providers import VpnProvider, build_provider

_LOG = logging.getLogger("mordred.network.runtime")


class State(Enum):
    IDLE = "idle"
    BRINGING_UP = "bringing_up"
    READY = "ready"
    TEARING_DOWN = "tearing_down"
    DEGRADED = "degraded"


# Audit reason codes (Phase 3 PR1 freeze, POLICY.md §Audit log reason enum).
_REASON_USE: Final[str] = "network.use"
_REASON_USE_FAILED: Final[str] = "network.use_failed"
_REASON_BRINGUP_FAILED: Final[str] = "network.bringup_failed"
_REASON_PATH_DROPPED: Final[str] = "network.path_dropped"


@dataclass
class RuntimeConfig:
    """Knobs the runtime reads at construction; the values come from
    the wizard's ``policy.json`` plus the ``~/.hermes/config.yaml``
    plugin section. Defaults are safe-by-default so an unconfigured
    runtime runs in ``off`` mode on clearnet.
    """

    policy_mode: PolicyMode = "off"
    default_path: ActivePath = "clearnet"
    tor_binary: str = "tor"
    tor_socks_port: int = 0  # 0 = ask the picker; non-zero = pin
    tor_data_dir: Path = field(default_factory=lambda: Path("~/.hermes/mordred/tor-data").expanduser())
    vpn_provider: str = "mullvad"  # selects the provider behind the "vpn" path
    wireguard_config_path: str | None = None  # for vpn_provider="wireguard"
    custom_up_cmd: tuple[str, ...] = ()  # for vpn_provider="custom"
    custom_down_cmd: tuple[str, ...] = ()
    custom_health_cmd: tuple[str, ...] | None = None
    mullvad_region: str = "auto"
    disable_ipv6: bool = True
    no_proxy_extra: tuple[str, ...] = ()
    liveness_interval_seconds: float = 30.0
    liveness_failure_threshold: int = 2
    # Optional process-scoped Tor SOCKS credential. It must be fixed before
    # first activation because provider clients snapshot proxy URLs.
    isolation_token: str | None = None


RouteConfigFingerprint = tuple[tuple[str, object], ...]


def route_config_fingerprint(config: RuntimeConfig) -> RouteConfigFingerprint:
    """Return a future-proof snapshot of every runtime configuration field.

    Provider clients, Tor/VPN subprocesses, proxy environment, and liveness
    workers are all constructed from ``RuntimeConfig``. Comparing every field
    prevents a force re-discovery or session reload from silently reusing a
    route built with stale binary, port, provider, policy, or leak settings.
    """
    return tuple((item.name, getattr(config, item.name)) for item in fields(config))


@dataclass(slots=True)
class _ActiveHandle:
    """Tag + handle pair held by the runtime while a path is up."""

    path: ActivePath
    handle: Any  # TorHandle | MullvadHandle | ClearnetHandle


def _default_subprocess_counter() -> int:
    """Best-effort count of OS-level child processes of this PID.

    Used in the M3 audit field ``live_subprocess_count`` (TODO.md §3.1
    L335). The signal is *informational* - it tells operators whether
    an in-flight subprocess might be running with the pre-switch proxy
    env. We never block path switches on it.

    Implementation: ``pgrep -P <pid>``. Works on Linux + macOS; on
    Windows ``pgrep`` is absent and we return ``0`` (with the same
    documented caveat). Failures are coerced to ``0`` so a noisy probe
    can never break the actual ``use(path)`` call site.
    """
    try:
        result = subprocess.run(
            ["pgrep", "-P", str(os.getpid())],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, PermissionError, subprocess.SubprocessError, OSError):
        return 0
    if result.returncode not in (0, 1):
        return 0
    return sum(1 for line in result.stdout.split("\n") if line.strip())


class Runtime:
    """Concrete implementation of the PR1 ``api.Runtime`` Protocol.

    A single instance is registered process-wide via
    ``api.set_runtime`` inside the plugin's ``register(ctx)`` (PR2
    hooks layer).

    Thread safety: a re-entrant lock guards the state machine. The
    liveness worker takes the same lock around its read/update of
    ``_failure_count`` / ``_dropped``; callers therefore never see a
    half-applied path switch.
    """

    def __init__(
        self,
        *,
        config: RuntimeConfig | None = None,
        audit: _AuditWriter | None = None,
        env: MutableMapping[str, str] | None = None,
        subprocess_counter: Callable[[], int] = _default_subprocess_counter,
        tor_pick_free_port: Callable[..., int] | None = None,
        tor_start_process: Callable[..., Any] | None = None,
        tor_wait_for_bootstrap: Callable[..., None] | None = None,
        tor_stop: Callable[..., None] | None = None,
        tor_health: Callable[..., bool] | None = None,
        vpn_provider: VpnProvider | None = None,
    ) -> None:
        self._config = config or RuntimeConfig()
        self._audit = audit
        self._env: MutableMapping[str, str] = env if env is not None else os.environ
        self._count_subprocesses = subprocess_counter

        # Path module injectables. Production wires the real path
        # modules; unit tests pass fakes so they never spawn daemons.
        self._tor_pick_port = tor_pick_free_port or tor_mod.pick_free_port
        self._tor_start = tor_start_process or tor_mod.start_process
        self._tor_wait = tor_wait_for_bootstrap or tor_mod.wait_for_bootstrap
        self._tor_stop = tor_stop or tor_mod.stop
        # Deep-by-default liveness: circuit_status_health verifies ControlPort
        # reachability, cookie authentication, and a structurally valid
        # GETINFO circuit-status response. A BUILT circuit is healthy on its
        # own; an empty/LAUNCHED-only response is inconclusive and resolves
        # via Tor's GETINFO network-liveness verdict ("up" → healthy, "down"
        # or query failure → unhealthy), so an idle Tor stays healthy while
        # a running-but-circuit-less Tor whose upstream died reads unhealthy;
        # auth/control/protocol failures remain unhealthy. The probe is
        # signature-compatible with health(handle) and self-degrades to that
        # shallow process check when the optional [tor-control] extra (stem) or
        # control cookie is absent.
        # Tests still override via the tor_health= injection param.
        self._tor_health = tor_health or tor_mod.circuit_status_health
        # The "vpn" path delegates to a selectable provider (Mullvad by
        # default). Production constructs the runtime without a provider,
        # so it is resolved from config here; tests inject a fake.
        self._vpn_provider: VpnProvider = (
            vpn_provider
            if vpn_provider is not None
            else build_provider(
                self._config.vpn_provider,
                wireguard_config_path=self._config.wireguard_config_path,
                custom_up_cmd=self._config.custom_up_cmd,
                custom_down_cmd=self._config.custom_down_cmd,
                custom_health_cmd=self._config.custom_health_cmd,
            )
        )

        # Serializes whole mutating lifecycle operations across the deliberate
        # ``_lock`` release used while joining the liveness worker. Without a
        # second lock, ``stop()`` can enter that window, tear down the handle,
        # and leave the switching caller to resume against ``None``.
        self._operation_lock = threading.RLock()
        self._lock = threading.RLock()
        self._state: State = State.IDLE
        self._active_path: ActivePath = "clearnet"
        self._handle: _ActiveHandle | None = None
        self._env_snapshot: dict[str, str | None] | None = None
        self._last_health: bool = True
        # ``register()`` freezes the route before returning to Hermes, hence
        # before AIAgent constructs any provider client. A different live path
        # after that point would only rewrite os.environ; already-created
        # clients would retain their old direct/proxy transport.
        self._process_route_frozen: bool = False
        self._frozen_path: ActivePath | None = None
        # The configured request can differ from the effective path only when
        # lenient/off bring-up deliberately degraded to clearnet. Remembering
        # both lets session hooks reassert the original configuration as a
        # no-op without mistaking it for a live route change.
        self._last_requested_path: ActivePath | None = None
        self._frozen_requested_path: ActivePath | None = None
        self._frozen_route_config: RouteConfigFingerprint | None = None

        # Liveness worker state.
        self._worker_thread: threading.Thread | None = None
        self._worker_stop = threading.Event()
        self._failure_count: int = 0
        self._dropped: bool = False

    # ------------------------------------------------------------------ #
    # api.Runtime Protocol                                               #
    # ------------------------------------------------------------------ #

    def use(self, path: str) -> None:
        """Switch the active path, mutating env + audit log accordingly."""
        self._acquire_operation_or_raise()
        try:
            self._use(path)
        finally:
            self._operation_lock.release()

    def _acquire_operation_or_raise(self) -> None:
        """Claim a mutation slot without hiding an in-progress lifecycle.

        ``stop`` deliberately waits for a switch to finish so it cannot tear
        down a handle still owned by that switch. A second switch has the
        opposite API contract: fail immediately with ``AlreadySwitching``
        instead of blocking for daemon bring-up or worker shutdown.
        """
        if self._operation_lock.acquire(blocking=False):
            return
        # Do not acquire ``_lock`` on the contention path. The active switch
        # normally holds it across daemon bring-up, so taking it merely to
        # improve an error-message snapshot would turn this fail-immediate API
        # into a wait-for-bring-up API. Enum reference reads are sufficient for
        # this best-effort diagnostic.
        state = self._state.value
        raise AlreadySwitching(f"path lifecycle operation already in progress (state={state})")

    def _use(self, path: str) -> None:
        """Serialized implementation of :meth:`use`."""
        if path not in ACTIVE_PATHS:
            raise UnknownPath(f"unknown network path: {path!r}")
        target = cast(ActivePath, path)
        # Fast path for the process-global route. Session-start hooks may call
        # use() repeatedly, but a ready tor->tor/vpn->vpn request must not
        # restart the daemon or invalidate clients already bound to its port.
        with self._lock:
            if not self._transition_needed(target):
                return
        # Snapshot the subprocess count OUTSIDE the lock (review M1,
        # 2026-05-14): the default counter runs ``pgrep`` with a 2 s
        # timeout. Holding the lock that whole time would block
        # concurrent ``status()`` / ``health()`` readers for up to two
        # seconds. The count is an informational M3 audit field, so a
        # value sampled at the start of the switch is just as useful
        # as one taken at the end.
        subprocess_count = self._count_subprocesses()
        with self._lock:
            # State may have changed while the informational subprocess count
            # was sampled, so repeat the complete transition check.
            if not self._transition_needed(target):
                return
            prev = self._active_path
            try:
                self._switch(target)
            except MordredNetworkError as e:
                self._emit_audit(
                    {
                        "event": _REASON_USE,
                        "decision": "raise",
                        "reason": _REASON_USE_FAILED,
                        "prev_path": prev,
                        "target_path": target,
                        "error": str(e),
                    }
                )
                raise
            self._last_requested_path = target
            self._emit_audit(
                {
                    "event": _REASON_USE,
                    "decision": "override",
                    "reason": _REASON_USE,
                    "prev_path": prev,
                    "new_path": self._active_path,
                    "live_subprocess_count": subprocess_count,
                }
            )

    def activate_and_freeze(self, path: str) -> None:
        """Atomically activate the initial route and seal its configuration.

        Registration keeps the runtime private until this method returns. The
        outer re-entrant lock also prevents a direct reference from interleaving
        another ``use`` between activation and freeze.
        """
        self._acquire_operation_or_raise()
        try:
            self._use(path)
            self.freeze_process_route(expected_path=path)
        finally:
            self._operation_lock.release()

    def status(self) -> NetworkStatus:
        with self._lock:
            return NetworkStatus(
                active_path=self._active_path,
                ready=self._state in (State.READY, State.DEGRADED),
                last_health=self._last_health,
            )

    def health(self) -> bool:
        """Run a synchronous liveness probe of the active path.

        ``clearnet`` is always reported healthy (no subprocess to
        observe). Tor / Mullvad delegate to their PR1 path modules.
        ``IDLE`` is treated as healthy because we have nothing to
        observe yet - the next ``use(path)`` will produce a real probe.
        """
        # Codex round 5 P2 (2026-05-14): snapshot the handle under the
        # lock, then run the (potentially slow) path-specific probe
        # WITHOUT holding the lock. Otherwise a stalled ``wg show`` or
        # ``tor`` poll blocks every concurrent ``status()`` / ``use()``
        # / ``stop()`` caller behind the same lock and breaks the
        # acceptance-gate "switch within 2s" promise.
        with self._lock:
            if self._handle is None:
                self._last_health = True
                return True
            handle_snapshot = self._handle  # tag + inner handle

        h = handle_snapshot.handle
        if handle_snapshot.path == "tor":
            healthy = self._tor_health(h)
        elif handle_snapshot.path == "vpn":
            healthy = self._vpn_provider.health(h)
        else:
            healthy = clearnet_mod.health(h)

        with self._lock:
            # Only persist the new ``last_health`` if the handle we
            # probed is still current — otherwise a path switch that
            # raced us would have replaced it and our result is stale.
            if self._handle is handle_snapshot:
                self._last_health = bool(healthy)
            return bool(healthy)

    def stop(self) -> None:
        """Tear down the active path and join the liveness worker.

        Idempotent: callable from process-exit cleanup even if no path
        was ever activated.
        """
        with self._operation_lock:
            self._stop_worker()
            with self._lock:
                if self._handle is not None:
                    self._teardown_current()
                self._restore_env()
                self._state = State.IDLE
                self._active_path = "clearnet"
                self._reset_liveness()

    # ------------------------------------------------------------------ #
    # Public helpers for hooks layer (PR2-B)                              #
    # ------------------------------------------------------------------ #

    def update_policy_mode(self, policy_mode: PolicyMode) -> None:
        """Refresh the runtime's policy mode from disk state.

        Codex round 9 P1-B (2026-05-14): the hooks layer reads
        ``policy.json`` on every session start. In a long-lived
        process the user can bump policy from ``lenient`` to
        ``strict`` via ``hermes mordred configure``; without this
        method the runtime would keep its registration-time value and
        a Tor bring-up failure would silently fall back to clearnet
        instead of raising :class:`MordredPathBringupFailed`.

        Thread-safe: replaces the policy field on the cached
        :class:`RuntimeConfig` (dataclass is non-frozen for this
        reason). Held under ``_lock`` so a concurrent ``_switch``
        observes a consistent value.
        """
        with self._lock:
            self._config.policy_mode = policy_mode

    def set_isolation_token(self, token: str | None) -> None:
        """Set an optional process-scoped Tor circuit-isolation token.

        The value may only change before first path activation. Provider HTTP
        clients retain the proxy URL they saw at construction, so rewriting
        its SOCKS credential after activation would split one Hermes process
        between stale and current transports.
        """
        with self._lock:
            if token == self._config.isolation_token:
                return
            if self._process_route_frozen or self._handle is not None or self._state in (State.READY, State.DEGRADED):
                raise PathSwitchRequiresRestart(
                    "Tor isolation credentials are process-scoped; changing them after route activation "
                    "would leave existing provider clients stale. Restart Hermes to apply the new credential."
                )
            self._config.isolation_token = token

    def freeze_process_route(self, *, expected_path: str | None = None) -> None:
        """Prevent live path changes after provider clients may be constructed.

        ``network.register`` calls this immediately after the configured path
        reaches a ready/degraded state and before returning control to Hermes.
        Reusing the same ready path remains a no-op; selecting another path
        raises :class:`PathSwitchRequiresRestart`.
        """
        with self._lock:
            if self._handle is None or self._state not in (State.READY, State.DEGRADED):
                raise MordredNetworkError("cannot freeze a network route that is not ready")
            if expected_path is not None and self._last_requested_path != expected_path:
                raise MordredNetworkError(
                    f"cannot freeze route: expected configured path {expected_path!r}, "
                    f"but activation completed for {self._last_requested_path!r}"
                )
            if self._process_route_frozen and self._frozen_path != self._active_path:
                raise PathSwitchRequiresRestart(
                    f"process route was already frozen at {self._frozen_path!r}; "
                    f"it cannot be re-frozen at {self._active_path!r}. Restart Hermes."
                )
            self._process_route_frozen = True
            self._frozen_path = self._active_path
            self._frozen_requested_path = self._last_requested_path or self._active_path
            self._frozen_route_config = route_config_fingerprint(self._config)

    @property
    def process_route_frozen(self) -> bool:
        """Whether provider-client construction has sealed this route."""
        with self._lock:
            return self._process_route_frozen and self._frozen_path is not None

    @property
    def frozen_requested_path(self) -> ActivePath | None:
        """Configured path whose effective transport was frozen."""
        with self._lock:
            return self._frozen_requested_path

    @property
    def frozen_route_config(self) -> RouteConfigFingerprint | None:
        """Configuration snapshot used to build the frozen route."""
        with self._lock:
            return self._frozen_route_config

    def assert_route_config(self, config: RuntimeConfig) -> None:
        """Require ``config`` to match the process-frozen activation snapshot."""
        expected = route_config_fingerprint(config)
        with self._lock:
            if not self._process_route_frozen or self._frozen_route_config is None:
                raise PathSwitchRequiresRestart("process route has no frozen activation configuration; restart Hermes.")
            if expected != self._frozen_route_config:
                raise PathSwitchRequiresRestart(
                    "network configuration changed after the process route was activated. "
                    "Restart Hermes so provider clients, route daemons, and leak controls use one configuration."
                )

    def is_dropped(self) -> bool:
        """Sticky flag - True iff the liveness worker observed
        ``liveness_failure_threshold`` consecutive failures. Cleared on
        the next successful :meth:`use` or :meth:`stop`.
        """
        with self._lock:
            return self._dropped

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    def _transition_needed(self, target: ActivePath) -> bool:
        """Validate a requested transition while ``_lock`` is held."""
        if self._state in (State.BRINGING_UP, State.TEARING_DOWN):
            raise AlreadySwitching(f"path switch already in progress (state={self._state.value})")
        if self._process_route_frozen:
            frozen_path = self._frozen_path
            frozen_requested_path = self._frozen_requested_path
            route_is_reusable = (
                frozen_path is not None
                and frozen_requested_path is not None
                and target == frozen_requested_path
                and self._active_path == frozen_path
                and self._handle is not None
                and self._state in (State.READY, State.DEGRADED)
                and not self._dropped
            )
            if route_is_reusable:
                return False
            raise PathSwitchRequiresRestart(
                f"process network route for configured path {frozen_requested_path!r} is frozen at "
                f"effective path {frozen_path!r}, but the requested path is {target!r} and the current "
                "route is no longer safely reusable "
                f"(active_path={self._active_path!r}, state={self._state.value}, "
                f"handle_present={self._handle is not None}, dropped={self._dropped}). "
                "Restart Hermes so provider clients and the process route are rebuilt together."
            )
        if self._handle is not None and self._state in (State.READY, State.DEGRADED) and target == self._active_path:
            return self._dropped
        return True

    def _reset_liveness(self) -> None:
        """Zero the M9 liveness-worker counters for a fresh observation run.

        Every transition that installs a definitive new path state
        (successful switch, lenient fallback, strict unwind, ``stop``)
        must clear the failure streak and the sticky ``_dropped`` flag so
        the worker judges the new path on its own probes only. Callers
        hold ``_lock``; the accompanying ``_state`` value differs per
        transition and stays at the call site.
        """
        self._failure_count = 0
        self._dropped = False
        self._last_health = True

    def _switch(self, target: ActivePath) -> None:
        """State machine transition: optional teardown -> bring-up -> ready.

        Codex P2 round 2 (2026-05-14): set ``_state = BRINGING_UP``
        BEFORE :meth:`_stop_worker_during_switch` so concurrent
        ``use()`` callers racing through the lock-release window
        observe the in-progress switch and raise
        :class:`AlreadySwitching`. Previously the state was bumped
        *after* teardown, leaving a stale ``READY`` window during the
        worker join.
        """
        self._state = State.BRINGING_UP
        if self._handle is not None:
            self._stop_worker_during_switch()
            self._teardown_current()
        try:
            handle = self._bring_up(target)
        except Exception as raw_error:
            failure = (
                raw_error
                if isinstance(raw_error, BringupFailed)
                else BringupFailed(f"{target} bring-up failed unexpectedly ({type(raw_error).__name__})")
            )
            self._handle = None
            # Normalize the truthful no-route state before either raising or
            # attempting a lenient clearnet fallback. This also covers an
            # unexpected provider/plugin Exception, which previously left the
            # runtime stuck in BRINGING_UP.
            self._restore_env()
            self._active_path = "clearnet"
            self._state = State.IDLE
            self._reset_liveness()
            if self._config.policy_mode == "strict":
                # Codex P2 fix (2026-05-14): the previous path was already
                # torn down before the new bring-up was attempted. If we
                # leave ``_active_path`` and the managed env vars untouched
                # they still point at the now-dead daemon: ``status()``
                # would report Tor active while subsequent spawns inherit
                # ``HTTPS_PROXY=socks5h://127.0.0.1:9050`` pointing at the
                # killed SOCKS port. Restore the pre-runtime env and reset
                # the active path to clearnet so the truthful failure is
                # visible to callers + downstream subprocesses.
                if failure is raw_error:
                    raise
                raise failure from raw_error
            # lenient / off: fall back to clearnet and audit it.
            self._emit_audit(
                {
                    "event": _REASON_BRINGUP_FAILED,
                    "decision": "fallback",
                    "reason": _REASON_BRINGUP_FAILED,
                    "attempted_path": target,
                    "fallback_path": "clearnet",
                    "error": str(failure),
                }
            )
            try:
                fallback_handle = self._bring_up("clearnet")
            except Exception as fallback_error:
                self._handle = None
                self._restore_env()
                self._active_path = "clearnet"
                self._state = State.IDLE
                self._reset_liveness()
                raise BringupFailed(
                    f"clearnet fallback failed unexpectedly ({type(fallback_error).__name__})"
                ) from fallback_error
            self._handle = fallback_handle
            self._active_path = "clearnet"
            self._apply_env("clearnet")
            self._state = State.DEGRADED
            self._reset_liveness()
            self._start_worker()
            return

        self._handle = handle
        self._active_path = target
        self._apply_env(target)
        self._state = State.READY
        self._reset_liveness()
        self._start_worker()

    def _stop_worker_during_switch(self) -> None:
        """Stop the worker while we hold the runtime lock.

        Releases the lock around :meth:`Thread.join` because the worker
        itself acquires the same re-entrant lock - a naive join while
        holding the lock would deadlock.
        """
        if self._worker_thread is None:
            return
        self._worker_stop.set()
        worker = self._worker_thread
        self._worker_thread = None
        self._lock.release()
        try:
            worker.join(timeout=2.0)
        finally:
            self._lock.acquire()

    def _bring_up(self, target: ActivePath) -> _ActiveHandle:
        if target == "clearnet":
            return _ActiveHandle("clearnet", clearnet_mod.start())
        if target == "tor":
            return self._bring_up_tor()
        # target == "vpn"
        return self._bring_up_vpn()

    def _bring_up_tor(self) -> _ActiveHandle:
        port = self._config.tor_socks_port or self._tor_pick_port()
        tor_mod.validate_port_pair(port)
        control_port = port + 1
        torrc = tor_mod.render_torrc(
            socks_port=port,
            control_port=control_port,
            data_dir=self._config.tor_data_dir,
            disable_ipv6=self._config.disable_ipv6,
        )
        try:
            proc = self._tor_start(binary=self._config.tor_binary, torrc=torrc)
        except OSError as spawn_err:
            # Codex round 3 P1 (2026-05-14): ``subprocess.Popen`` raises
            # :class:`FileNotFoundError` / :class:`PermissionError`
            # (both ``OSError``) when the binary is absent or not
            # executable. Translate to :class:`BringupFailed` so the
            # strict-mode escalation in :meth:`_switch` fires and the
            # hooks layer can raise :class:`MordredPathBringupFailed`
            # — otherwise Hermes' ``invoke_hook`` would swallow the
            # OSError as an ordinary :class:`Exception` and strict
            # mode would fail open.
            raise BringupFailed(
                f"tor binary {self._config.tor_binary!r} could not be spawned: {spawn_err}. "
                f"{tor_install_guidance(tor_binary=self._config.tor_binary)}"
            ) from spawn_err
        # Plain-dataclass construction (no side effects), built once so the
        # bring-up-failure cleanup and the success return cannot drift.
        tor_handle = tor_mod.TorHandle(
            process=proc,
            socks_port=port,
            control_port=control_port,
            data_dir=self._config.tor_data_dir,
        )
        try:
            self._tor_wait(proc)
        except Exception as wait_err:
            # Half-started process must not leak even when bring-up fails.
            #
            # The catch is deliberately wider than BringupFailed (mirroring the
            # VPN path's ``except (BringupFailed, OSError)``): ``_tor_wait``
            # tails the daemon's stdout, which is opened in text mode, so a
            # non-UTF-8 byte in Tor's log output raises UnicodeDecodeError — not
            # BringupFailed. Left uncaught that would (a) orphan the spawned tor
            # child, since nothing terminates it, and (b) unwind past _switch's
            # ``except BringupFailed`` with ``_state`` still at BRINGING_UP,
            # bricking the instance so every later use() raises AlreadySwitching
            # forever. Translating to BringupFailed also keeps the strict-mode
            # escalation in _switch reachable, so strict cannot fail open here.
            try:
                self._tor_stop(tor_handle)
            except Exception as cleanup_err:
                _LOG.warning("tor cleanup after bring-up failure: %s", cleanup_err)
            if isinstance(wait_err, BringupFailed):
                raise
            raise BringupFailed(f"tor bootstrap failed: {wait_err}") from wait_err
        return _ActiveHandle("tor", tor_handle)

    def _bring_up_vpn(self) -> _ActiveHandle:
        # Fail-closed kill-switch gate (design §6): strict mode demands a
        # provider that can guarantee a verifiable kill-switch / in-tunnel
        # DNS. A provider without that capability (a bring-your-own
        # WireGuard config, an opaque vendor CLI) is refused here BEFORE
        # any tunnel is brought up, rather than running strict traffic
        # without leak protection. lenient / off skip this gate, so any
        # VPN is usable for normal sessions — only the strict guarantee is
        # reserved for Mullvad-grade providers. Raising BringupFailed lets
        # the _switch strict path escalate to MordredPathBringupFailed.
        provider = self._vpn_provider
        if self._config.policy_mode == "strict" and not provider.capabilities.killswitch:
            raise BringupFailed(
                f"vpn provider {provider.name!r} cannot guarantee a kill-switch, "
                "which strict mode requires. Use a kill-switch-capable provider "
                "(e.g. mullvad), or set policy to lenient/off to use this provider."
            )
        # Codex round 4 P1 (2026-05-14): symmetric to the Tor OSError
        # wrap (r3-P1). Mullvad CLI invocations can raise OSError
        # (binary missing, daemon socket permission, etc.). The strict
        # escalation in :meth:`_switch` catches only BringupFailed, so
        # bare OSError would be swallowed by Hermes' invoke_hook and
        # strict mode would fail open.
        try:
            cli_path = self._vpn_provider.detect_cli()
        except OSError as detect_err:
            raise BringupFailed(f"vpn provider detect failed: {detect_err}") from detect_err
        try:
            vpn_handle = self._vpn_provider.bring_up(
                cli_path=cli_path,
                region=self._config.mullvad_region,
                policy_mode=self._config.policy_mode,
            )
        except OSError as bring_err:
            raise BringupFailed(f"vpn provider bring-up failed: {bring_err}") from bring_err
        # Strict cleanup always preserves lockdown. Mullvad has no atomic
        # compare-and-swap operation, so observing OFF followed by a successful
        # ``set on`` cannot prove exclusive ownership: another actor may have
        # enabled it in between. Turning it OFF after a wait failure could
        # therefore weaken that actor's security posture. Non-strict providers
        # retain the historical applied-by-us cleanup behavior.
        preserve_on_cleanup = self._config.policy_mode == "strict" or not getattr(
            vpn_handle,
            "lockdown_applied_by_us",
            False,
        )
        try:
            self._vpn_provider.wait_connected(cli_path=cli_path)
        except (BringupFailed, OSError) as wait_err:
            # One shared disconnect-cleanup; the re-raise below preserves the
            # two distinct exception contracts: BringupFailed propagates
            # as-is, while a bare OSError is wrapped so the strict-mode
            # escalation in :meth:`_switch` (which catches only
            # BringupFailed) cannot be bypassed by Hermes' ``except
            # Exception`` filter swallowing the OSError (Codex round 4 P1).
            try:
                self._vpn_provider.disconnect(
                    vpn_handle,
                    preserve_lockdown=preserve_on_cleanup,
                )
            except Exception as cleanup_err:
                _LOG.warning("vpn cleanup after wait failure: %s", cleanup_err)
            if isinstance(wait_err, BringupFailed):
                raise
            raise BringupFailed(f"vpn provider wait failed: {wait_err}") from wait_err
        return _ActiveHandle("vpn", vpn_handle)

    def _teardown_current(self) -> None:
        assert self._handle is not None
        self._state = State.TEARING_DOWN
        h = self._handle.handle
        try:
            if self._handle.path == "tor":
                self._tor_stop(h)
            elif self._handle.path == "vpn":
                # Codex r8-P1 symmetry: only roll back the lockdown WE applied.
                # In lenient/off, bring_up leaves a user's pre-existing lockdown
                # untouched (``lockdown_applied_by_us=False``); normal teardown
                # must preserve it too, mirroring the bring-up-failure cleanup
                # (see ``preserve_on_cleanup`` above). Strict always preserves
                # (the kill-switch is required there). ``getattr`` keeps this
                # generic for handles with no lockdown concept (WireGuard /
                # custom) — they default to "preserve", a no-op for them.
                preserve = self._config.policy_mode == "strict" or not getattr(h, "lockdown_applied_by_us", False)
                self._vpn_provider.disconnect(h, preserve_lockdown=preserve)
            else:
                clearnet_mod.stop(h)
        except Exception as e:
            _LOG.warning("tear-down of %s failed: %s", self._handle.path, e)
        self._handle = None

    def _apply_env(self, target: ActivePath) -> None:
        """Mutate the managed env vars to match ``target``.

        First application records a snapshot of every managed key so
        :meth:`_restore_env` can put the user's pre-existing values
        back on :meth:`stop`.
        """
        managed = proxy_env_mod.managed_var_names()
        if self._env_snapshot is None:
            self._env_snapshot = {k: self._env.get(k) for k in managed}
        port = self._config.tor_socks_port or proxy_env_mod.DEFAULT_TOR_SOCKS_PORT
        if self._handle is not None and self._handle.path == "tor":
            tor_handle = self._handle.handle
            port = tor_handle.socks_port
        if self._config.policy_mode == "off" and target != "tor":
            # Policy-off must not silently disable an ambient corporate/user
            # proxy. Restore the exact pre-runtime managed environment when
            # entering clearnet/VPN (also handles an explicit Tor->clearnet
            # switch without leaving Tor's now-dead SOCKS URL behind).
            desired = {key: value for key, value in self._env_snapshot.items() if value is not None}
        else:
            desired = proxy_env_mod.desired_env(
                path=target,
                tor_socks_port=port,
                no_proxy_extra=self._config.no_proxy_extra,
                isolation_token=self._config.isolation_token,
            )
        # Set-then-prune, never pop-then-set. ``self._env`` is the process-global
        # ``os.environ``, and ``_lock`` only serialises the runtime's OWN writers
        # — it cannot stop another thread in this process (a tool-call handler,
        # an httpx worker, another plugin) from calling subprocess.Popen, which
        # snapshots the environment at spawn time. A pop-all-then-set-all
        # sequence therefore leaves a real window in which a child inherits NO
        # proxy vars at all and goes out direct/clearnet — exactly the fail-open
        # leak the strict path exists to prevent. Writing the desired values
        # first and only then dropping the now-unwanted keys means the managed
        # vars are never all-absent mid-switch.
        for k, v in desired.items():
            self._env[k] = v
        for k in managed:
            if k not in desired:
                self._env.pop(k, None)

    def _restore_env(self) -> None:
        if self._env_snapshot is None:
            return
        for k, v in self._env_snapshot.items():
            if v is None:
                self._env.pop(k, None)
            else:
                self._env[k] = v
        self._env_snapshot = None

    def _emit_audit(self, entry: dict[str, Any]) -> None:
        """Best-effort audit append via the shared ``safe_audit_append``.

        Audit failure must never break a path switch (M3 contract:
        ``use(path)`` either completes or raises a network error).
        """
        if self._audit is None:
            return
        safe_audit_append(self._audit, entry, logger=_LOG)

    # ------------------------------------------------------------------ #
    # Liveness worker                                                    #
    # ------------------------------------------------------------------ #

    def _start_worker(self) -> None:
        # Codex round 7 P2-B (2026-05-14): each worker spawn gets its
        # OWN Event. If we shared a single ``Event`` across spawns,
        # ``_start_worker`` would have to ``clear()`` it before
        # starting the new thread — but an orphan from the previous
        # spawn (still stuck in a slow health probe) would observe the
        # cleared signal and resume looping, double-incrementing
        # ``_failure_count``. With a per-worker Event the orphan sees
        # its own (still-set) signal and exits cleanly when it next
        # wakes up.
        if self._worker_thread is not None and self._worker_thread.is_alive():
            return
        stop_event = threading.Event()
        self._worker_stop = stop_event
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            args=(stop_event,),
            name="mordred-network-liveness",
            daemon=True,
        )
        self._worker_thread.start()

    def _stop_worker(self) -> None:
        if self._worker_thread is None:
            return
        self._worker_stop.set()
        worker = self._worker_thread
        self._worker_thread = None
        worker.join(timeout=2.0)

    def _worker_loop(self, stop_event: threading.Event) -> None:
        interval = self._config.liveness_interval_seconds
        threshold = self._config.liveness_failure_threshold
        while not stop_event.wait(interval):
            try:
                healthy = self.health()
            except Exception as e:
                _LOG.warning("network liveness probe raised: %s", e)
                healthy = False
            # Codex round 8 P2 (2026-05-14): re-check stop_event AFTER
            # the probe. The probe runs outside the lock (r5-P2 fix)
            # and may have taken arbitrary time. If the runtime was
            # stopped or the path was switched during the probe, this
            # worker's result is now stale — applying it would
            # double-increment ``_failure_count`` on the new path (or
            # set ``_dropped`` after stop) and trigger false strict
            # refusals.
            if stop_event.is_set():
                return
            with self._lock:
                if healthy:
                    self._failure_count = 0
                    continue
                self._failure_count += 1
                if self._failure_count >= threshold and not self._dropped:
                    self._dropped = True
                    decision = "block" if self._config.policy_mode == "strict" else "warn"
                    self._emit_audit(
                        {
                            "event": _REASON_PATH_DROPPED,
                            "decision": decision,
                            "reason": _REASON_PATH_DROPPED,
                            "path": self._active_path,
                            "consecutive_failures": self._failure_count,
                        }
                    )


__all__ = ["Runtime", "RuntimeConfig", "State"]
