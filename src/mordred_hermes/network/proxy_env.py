"""Proxy environment variables — pure mapping from network path to env vars.

This module is read-only by design. It computes the ``{HTTPS_PROXY: ...}``
dict that **should** be in ``os.environ`` for a given network path; the
network runtime is the sole writer that actually mutates the process
environment (and tracks the prior values so it can restore on
process exit).

The Tor URL scheme is always ``socks5h://`` so DNS resolution happens
inside the Tor circuit. Plain ``http://`` proxy URLs are
forbidden because the system resolver leaks queries before the request
ever hits the proxy.

``NO_PROXY`` always contains ``localhost,127.0.0.1,::1`` regardless of
path so `mordred-local` stays on loopback instead of being sent through Tor.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import quote

from .._policy_types import ACTIVE_PATHS
from .._policy_types import ActivePath as ActivePath
from ._exceptions import UnknownPath

_LOCALHOST_DEFAULTS: Final[tuple[str, ...]] = ("localhost", "127.0.0.1", "::1")
# Codex round 5 P1 (2026-05-14): include lowercase variants. POSIX tools
# (curl, wget, python ``requests`` httplib) honour the lowercase forms;
# if we only manage the uppercase keys, pre-existing ``https_proxy=...``
# in the parent env would survive a Tor switch and leak child traffic
# through the old clearnet proxy.
_UPPER_PROXY_KEYS: Final[tuple[str, ...]] = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
_LOWER_PROXY_KEYS: Final[tuple[str, ...]] = ("https_proxy", "http_proxy", "all_proxy")
_PROXY_KEYS: Final[tuple[str, ...]] = (*_UPPER_PROXY_KEYS, *_LOWER_PROXY_KEYS)
_MANAGED_KEYS: Final[frozenset[str]] = frozenset((*_PROXY_KEYS, "NO_PROXY", "no_proxy"))

DEFAULT_TOR_SOCKS_PORT: Final[int] = 9050

# RFC 1929 encodes each SOCKS5 username/password length in a single octet,
# so each field is capped at 255 bytes. A longer credential is rejected by
# Tor — ``_tor_proxy_url`` substitutes a stable digest above this length.
_MAX_SOCKS_CRED_LEN: Final[int] = 255


def managed_var_names() -> set[str]:
    """Return the set of env var names this module manages.

    PR2 ``runtime`` enumerates this set when switching paths to know
    which keys to clear from ``os.environ`` before applying the new
    desired set.
    """
    return set(_MANAGED_KEYS)


def desired_env(
    *,
    path: ActivePath,
    tor_socks_port: int = DEFAULT_TOR_SOCKS_PORT,
    no_proxy_extra: Iterable[str] = (),
    isolation_token: str | None = None,
) -> dict[str, str]:
    """Compute the env vars that should be set for the given path.

    Returns only keys that *should* be present — callers must clear
    keys in :func:`managed_var_names` that are absent from the result.

    Raises :class:`UnknownPath` for any value outside ``tor`` / ``vpn``
    / ``clearnet``. The narrow ``Literal`` typing catches this at
    static-check time; the runtime check defends against
    config-file-driven flips (the policy.json field is plain string at
    the storage layer).

    ``isolation_token`` (Tor path only) injects an optional process-scoped
    SOCKS5 credential so Tor's ``IsolateSOCKSAuth`` assigns that Hermes
    process its own circuit pool. The runtime must choose it before route
    activation; per-session/per-skill tokens are deferred. ``None`` / empty
    leaves the URL credential-free. It is a silent no-op on clearnet / vpn,
    which carry no SOCKS proxy.
    """
    if path not in ACTIVE_PATHS:
        raise UnknownPath(f"unknown network path: {path!r}")

    env: dict[str, str] = {}
    if path == "tor":
        proxy_url = _tor_proxy_url(tor_socks_port, isolation_token)
        for key in _PROXY_KEYS:
            env[key] = proxy_url

    # Codex round 5 P1 (2026-05-14): emit both casings so POSIX tools
    # using ``no_proxy`` (e.g. curl, requests' httplib) honour the same
    # bypass list as tools reading ``NO_PROXY``.
    no_proxy_value = _build_no_proxy(no_proxy_extra)
    env["NO_PROXY"] = no_proxy_value
    env["no_proxy"] = no_proxy_value
    return env


def _tor_proxy_url(socks_port: int, isolation_token: str | None) -> str:
    """Build the ``socks5h://`` Tor proxy URL, optionally carrying a
    process-scoped preactivation credential for circuit isolation.

    When ``isolation_token`` is a non-empty string it becomes both the
    SOCKS username and password (percent-encoded), so Tor's
    ``IsolateSOCKSAuth`` (set in ``paths.tor.render_torrc``) maps the
    process to its own circuit pool. An empty or ``None`` token yields the
    bare URL with no userinfo — backward compatible with callers that do not
    opt into a process token.

    The credential is percent-encoded with ``safe=""`` so a token
    containing ``:`` / ``@`` / ``/`` cannot break out of the userinfo and
    hijack the host or port.

    A token whose encoded form exceeds ``_MAX_SOCKS_CRED_LEN`` (RFC 1929's
    255-octet field limit) is replaced by its sha256 hexdigest so Tor does
    not reject the SOCKS auth — distinctness (hence isolation) is preserved
    by the hash.
    """
    if isolation_token:
        cred = quote(isolation_token, safe="")
        if len(cred) > _MAX_SOCKS_CRED_LEN:
            # sha256 hexdigest is 64 ASCII chars — URL-safe and well within
            # the 255-octet limit, while keeping distinct tokens distinct.
            cred = hashlib.sha256(isolation_token.encode("utf-8")).hexdigest()
        return f"socks5h://{cred}:{cred}@127.0.0.1:{socks_port}"
    return f"socks5h://127.0.0.1:{socks_port}"


def _build_no_proxy(extras: Iterable[str]) -> str:
    """Join localhost defaults + user extras, deduped, order preserved."""
    seen: set[str] = set()
    ordered: list[str] = []
    for entry in (*_LOCALHOST_DEFAULTS, *extras):
        if entry in seen:
            continue
        seen.add(entry)
        ordered.append(entry)
    return ",".join(ordered)


# --------------------------------------------------------------------------- #
# Phase 3 PR3a Task #4: SOCKS5h library compatibility allowlist               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LibraryRequirement:
    """Minimum HTTP client library version that grew ``socks5h://`` support.

    ``unverified_baseline`` is cleared once
    ``tests/integration/test_socks5h_libs.py`` empirically exercised the
    library against an in-process SOCKS5 inspector. ``notes`` carries the
    verified behaviour and any operator caveat.
    """

    library: str
    min_version: str
    notes: str
    unverified_baseline: bool = True


SOCKS5H_LIBRARY_REQUIREMENTS: Final[Mapping[str, LibraryRequirement]] = {
    "httpx": LibraryRequirement(
        library="httpx",
        min_version="0.27.0",
        notes=(
            "Verified at httpx 0.28.1 + socksio 1.0.0 "
            "(tests/integration/test_socks5h_libs.py): the socksio transport "
            "defers DNS to the proxy for BOTH socks5:// and socks5h:// URLs, "
            "so a socks5h:// HTTPS_PROXY is honoured and even a misconfigured "
            "socks5:// cannot leak. socks5h:// URL-scheme support landed in "
            "httpx 0.27.x."
        ),
        unverified_baseline=False,
    ),
    "urllib3": LibraryRequirement(
        library="urllib3",
        min_version="2.0.0",
        notes=(
            "Verified at urllib3 2.7.0 + PySocks 1.7.1 "
            "(tests/integration/test_socks5h_libs.py): "
            "urllib3.contrib.socks.SOCKSProxyManager honours the socks5h:// "
            "scheme with server-side DNS. The 1.26.x branch only knows "
            "socks5://."
        ),
        unverified_baseline=False,
    ),
    "requests": LibraryRequirement(
        library="requests",
        min_version="2.32.0",
        notes=(
            "Verified at requests 2.33.1 (urllib3 2.x + PySocks 1.7.1, "
            "tests/integration/test_socks5h_libs.py): requests[socks] honours "
            "the scheme distinction -- socks5h:// = remote DNS, socks5:// = "
            "local DNS. Needs urllib3 with socks5h support (2.x); the 1.26.x "
            "branch leaks DNS."
        ),
        unverified_baseline=False,
    ),
    "aiohttp": LibraryRequirement(
        library="aiohttp",
        min_version="3.10.0",
        notes=(
            "Verified at aiohttp 3.13.5 + aiohttp-socks 0.11.0 "
            "(tests/integration/test_socks5h_libs.py). CAVEAT: python-socks "
            "(the aiohttp-socks engine) does NOT parse the socks5h:// URL "
            "scheme -- ProxyConnector.from_url('socks5h://...') raises "
            "ValueError. Remote DNS requires socks5:// + an explicit "
            "rdns=True. A caller forwarding Mordred's socks5h:// HTTPS_PROXY "
            "straight into from_url must translate the scheme first."
        ),
        unverified_baseline=False,
    ),
}


def evaluate_library_compatibility(
    *,
    active_path: ActivePath,
    declared_libs: Iterable[str],
) -> list[str]:
    """Surface SOCKS5h-incompatibility warnings for declared HTTP libraries.

    The runtime / hooks layer or wizard can pass a list of libraries the
    user's environment ships (auto-detected via ``pip list`` or declared in
    their config). This helper checks each against the allowlist:

    - Off-path (clearnet / vpn): SOCKS5h does not apply, return ``[]``.
    - Library on allowlist: trust it (PR3c playbook ensures min_version
      is achievable). No warning.
    - Library NOT on allowlist: emit one human-readable warning per
      library pointing the operator at the unknown entry.

    v1 is advisory only -- the warnings surface to logs / CLI output;
    they do not block session start. v2 may auto-detect installed
    versions and downgrade lenient/abort.
    """
    if active_path != "tor":
        return []
    warnings: list[str] = []
    for lib in declared_libs:
        if lib in SOCKS5H_LIBRARY_REQUIREMENTS:
            continue
        warnings.append(
            f"{lib}: unknown SOCKS5h compatibility (not in v1 allowlist); "
            "verify the library honours socks5h:// URL scheme or add an entry "
            "to mordred_hermes.network.proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS"
        )
    return warnings
