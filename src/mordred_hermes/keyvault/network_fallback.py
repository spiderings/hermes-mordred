"""OS-API network-blackout fallback for ``mordred_keyvault``.

Phase 4 PR5. Before ``keyvault.seed_display`` (PR7) unmasks a Seed
Phrase it must prove the host has no live network path. SPEC.md
§Seed phrase display security:

- The **primary** mechanism is :func:`mordred_hermes.network.api.blackout_assert`.
- The **fallback**, implemented here, is used when the ``mordred_network``
  plugin is not importable: ``keyvault`` calls the macOS reachability API
  (``SCNetworkReachability`` via pyobjc) directly.

Contract (mirrors :mod:`keyvault.native`):

1. ``import mordred_hermes.keyvault.network_fallback`` must succeed on
   **any** platform. The pyobjc bridge is deferred to call time so the
   PR2 primitives (``digest`` / ``backup`` / ``recovery``) stay importable
   on Linux/Windows hosts.
2. :func:`resolve_blackout_assert` is the single entry point callers
   should use. It returns a callable that always raises this module's
   :class:`BlackoutNotAsserted` (never ``mordred_network``'s), so a caller
   only ever catches one exception type.
3. :func:`blackout_assert` **fails closed**: if the OS probe cannot run
   (non-macOS, or macOS without ``pyobjc-framework-SystemConfiguration``)
   it raises :class:`BlackoutNotAsserted` rather than silently allowing a
   Seed display on an un-probeable host.

Detection limits (SPEC.md §Seed phrase display security, M4 caveat): the
probe only sees paths the OS standard network stack exposes. Bluetooth /
USB tethering / personal hotspots and hidden DMA-attached NICs are NOT
detected — physical air-gap remains the user's responsibility, and
``keyvault init`` warns about this in its startup banner (PR8).

Testing seams:

- ``_import_systemconfiguration`` — indirection for ``import
  SystemConfiguration``; tests substitute a function returning a fake.
- ``_query_reachability_flags`` — the pyobjc boundary; tests monkeypatch
  it whole to drive :func:`_os_reachability_probe`.
- ``_import_network_api`` — indirection for the ``mordred_network`` import
  so :func:`resolve_blackout_assert`'s fallback branch is testable in a
  single-package install where the module is always importable.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from typing import Any

# ---------------------------------------------------------------------------
# Exceptions (keyvault-owned; see module docstring point 2)
# ---------------------------------------------------------------------------


class BlackoutNotAsserted(Exception):
    """The host is network-reachable when an isolated host was required.

    Raised by :func:`blackout_assert` (and the wrapper returned by
    :func:`resolve_blackout_assert`) when the reachability probe reports a
    live path, or — fail-closed — when the probe itself cannot run. In the
    latter case the underlying :class:`NetworkFallbackUnavailable` is
    chained via ``__cause__``.

    Mirrors :class:`mordred_hermes.network._exceptions.BlackoutNotAsserted`
    but is a distinct, keyvault-owned class so callers never need to import
    the ``mordred_network`` package to catch a blackout failure.
    """


class NetworkFallbackUnavailable(Exception):
    """The OS reachability probe cannot run on this host.

    Two cases:

    1. ``sys.platform != "darwin"`` — short-circuit, ``__cause__`` is
       ``None``. This fallback uses macOS SystemConfiguration; Linux keyvault
       setup must use the ``mordred_network`` blackout provider.
    2. macOS without ``pyobjc-framework-SystemConfiguration`` — the
       underlying :class:`ImportError` is chained via ``__cause__``.

    Sibling of :class:`BlackoutNotAsserted`, not a subclass:
    :func:`blackout_assert` translates it into :class:`BlackoutNotAsserted`
    so callers have a single type to catch, but lower-level helpers raise
    the more specific class for diagnostics.
    """


# ---------------------------------------------------------------------------
# SCNetworkReachabilityFlags bit values
# (CoreFoundation / SystemConfiguration constants, stable since macOS 10.x)
# ---------------------------------------------------------------------------

_FLAG_TRANSIENT_CONNECTION = 1 << 0
_FLAG_REACHABLE = 1 << 1
_FLAG_CONNECTION_REQUIRED = 1 << 2
_FLAG_CONNECTION_ON_TRAFFIC = 1 << 3
_FLAG_INTERVENTION_REQUIRED = 1 << 4
_FLAG_CONNECTION_ON_DEMAND = 1 << 5
_FLAG_IS_LOCAL_ADDRESS = 1 << 16
_FLAG_IS_DIRECT = 1 << 17

_PROBE_HOST_V4 = b"1.1.1.1"
_PROBE_HOST_V6 = b"2606:4700:4700::1111"
"""Reachability targets. Numeric IP literals (IPv4 + IPv6) so the probe
never triggers a DNS lookup (which would itself be observable network
activity). Both families are probed (security review H3): an IPv4-only
probe would report "isolated" on a dual-stack host whose IPv4 is down
but whose IPv6 still routes, leaking the all-clear to the Seed display."""


def _interpret_reachability_flags(flags: int) -> bool:
    """Return ``True`` when *flags* indicate a usable network path.

    The standard Apple interpretation: the target is reachable right now
    iff ``kSCNetworkReachabilityFlagsReachable`` is set **and**
    ``kSCNetworkReachabilityFlagsConnectionRequired`` is clear (a path that
    still needs to be brought up does not count as currently reachable).

    ``True`` here means "host is online" == NOT blacked out, so
    :func:`blackout_assert` raises.
    """
    if not (flags & _FLAG_REACHABLE):
        return False
    return not (flags & _FLAG_CONNECTION_REQUIRED)


def _import_systemconfiguration() -> Any:
    """Indirection point for ``import SystemConfiguration``.

    Uses :func:`importlib.import_module` (rather than a plain ``import``)
    so mypy strict does not need to statically resolve the pyobjc bundle
    on non-macOS CI runners — ``pyobjc-framework-SystemConfiguration`` is
    only present in the ``[macos]`` extra. Tests substitute a function
    returning a fake namespace.
    """
    return importlib.import_module("SystemConfiguration")


def _query_reachability_flags(host: bytes = _PROBE_HOST_V4) -> int:
    """Return the raw ``SCNetworkReachabilityGetFlags`` value for ``host``.

    Raises:
        NetworkFallbackUnavailable: On non-macOS hosts, when pyobjc is
            missing, or when the ``SCNetworkReachability`` probe fails for
            any reason — a NULL handle, an ``ok=False`` result, or an
            unexpected pyobjc-bridge error. This is the *only* exception
            type the function raises: every failure mode is funnelled here
            so :func:`blackout_assert` can rely on a single type and fail
            closed. Never returns a sentinel ``int`` for a failure.
    """
    if sys.platform != "darwin":
        raise NetworkFallbackUnavailable(
            "OS reachability probe requires macOS; current platform is "
            f"{sys.platform!r}. On Linux, enable the mordred plugin (its network runtime) for the "
            "keyvault blackout check."
        )

    try:
        sc = _import_systemconfiguration()
    except ImportError as exc:
        raise NetworkFallbackUnavailable(
            "pyobjc-framework-SystemConfiguration is not installed; run "
            "`pip install hermes-mordred[macos]` to enable the macOS "
            "network-blackout fallback."
        ) from exc

    # Funnel every pyobjc-bridge failure mode into NetworkFallbackUnavailable:
    # an objc.error from the bridge, or a malformed return that breaks the
    # ``ok, flags`` unpack, must NOT escape as a foreign exception type — the
    # contract above and blackout_assert's fail-closed catch depend on it.
    try:
        target = sc.SCNetworkReachabilityCreateWithName(None, host)
        if target is None:
            raise NetworkFallbackUnavailable(f"SCNetworkReachabilityCreateWithName returned NULL for {host!r}")

        ok, flags = sc.SCNetworkReachabilityGetFlags(target, None)
        if not ok:
            raise NetworkFallbackUnavailable("SCNetworkReachabilityGetFlags failed to read reachability flags")
        return int(flags)
    except NetworkFallbackUnavailable:
        raise
    except Exception as exc:
        raise NetworkFallbackUnavailable(
            f"SCNetworkReachability probe failed unexpectedly: {type(exc).__name__}: {exc}"
        ) from exc


def _os_reachability_probe() -> bool:
    """Return ``True`` if the host has a usable network path (== online).

    The default probe used by :func:`blackout_assert`. Probes both IPv4
    and IPv6 targets and reports reachable if EITHER routes (security
    review H3) — an IPv4-only probe would miss live IPv6 egress on a
    dual-stack host. Raises :class:`NetworkFallbackUnavailable` when the
    OS probe cannot run — the exception is **not** swallowed into
    ``False`` because a coerced ``False`` would let a Seed display
    through on an un-probeable host.
    """
    for host in (_PROBE_HOST_V4, _PROBE_HOST_V6):
        if _interpret_reachability_flags(_query_reachability_flags(host)):
            return True
    return False


def blackout_assert(*, probe: Callable[[], bool] | None = None) -> None:
    """Raise :class:`BlackoutNotAsserted` unless the host is isolated.

    Signature-compatible with
    :func:`mordred_hermes.network.api.blackout_assert`: the *probe* returns
    ``True`` when reachability is detected.

    Fails closed: if the probe raises :class:`NetworkFallbackUnavailable`
    (the OS probe cannot run), this still raises :class:`BlackoutNotAsserted`
    — with the cause chained — rather than allowing the caller to proceed.

    Args:
        probe: Reachability probe. Defaults to :func:`_os_reachability_probe`.
            Tests and callers may inject a deterministic probe.

    Raises:
        BlackoutNotAsserted: The host is reachable, or the probe could not
            run (fail closed).
    """
    probe_fn = probe if probe is not None else _os_reachability_probe
    try:
        reachable = probe_fn()
    except NetworkFallbackUnavailable as exc:
        raise BlackoutNotAsserted(
            "cannot verify network isolation: the OS reachability probe is "
            "unavailable on this host; refusing (fail closed)"
        ) from exc

    if reachable:
        raise BlackoutNotAsserted("network reachability detected; expected an isolated host")


def _import_network_api() -> Any:
    """Indirection point for the ``mordred_network`` API import.

    In a v1 single-package install ``mordred_hermes.network.api`` is always
    importable, so tests substitute a function raising :class:`ImportError`
    to exercise :func:`resolve_blackout_assert`'s fallback branch.
    """
    return importlib.import_module("mordred_hermes.network.api")


def resolve_blackout_assert() -> Callable[..., None]:
    """Return the blackout-assert callable to use, with fallback resolution.

    Primary: when ``mordred_network`` is importable, delegate to
    :func:`mordred_hermes.network.api.blackout_assert`, translating its
    ``BlackoutNotAsserted`` into this module's :class:`BlackoutNotAsserted`
    so the caller catches a single type.

    Fallback: when ``mordred_network`` is not importable, return this
    module's OS-API :func:`blackout_assert` directly.

    The returned callable accepts the same ``probe=`` keyword as
    :func:`blackout_assert` and always raises this module's
    :class:`BlackoutNotAsserted` on a reachable host.
    """
    try:
        network_api = _import_network_api()
    except ImportError:
        return blackout_assert

    from mordred_hermes.network._exceptions import (
        BlackoutNotAsserted as _NetworkBlackoutNotAsserted,
    )

    def _delegating_blackout_assert(*, probe: Callable[[], bool] | None = None) -> None:
        try:
            network_api.blackout_assert(probe=probe)
        except _NetworkBlackoutNotAsserted as exc:
            raise BlackoutNotAsserted(str(exc)) from exc

    return _delegating_blackout_assert
