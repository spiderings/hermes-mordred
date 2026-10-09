"""Shared fail-closed runtime gate for the destructive at-rest seals.

``encryption enable env`` and ``encryption enable config`` both delete the
plaintext after enrolling and rely on a macOS startup shim in the interpreter
that actually runs ``hermes`` to materialize it again. That interpreter is
usually NOT the venv driving this command, and the managed runtime venv is
recreated (dropping the non-PyPI mordred install) on every ``hermes``
self-update — so before any destructive step the seal probes that runtime and
refuses when the shim is missing.

The gate has **two** checks, because "the interpreter that should run hermes"
and "the interpreter that is running the gateway right now" are different
questions. The 2026-06-25 incident answered the first one correctly (the managed
venv had mordred) while the live gateway ran from a repo ``.venv`` that did not,
so the seal removed a plaintext the running process could never unseal. After the
primary probe passes, the gate therefore probes every *running* gateway
interpreter that belongs to a different environment (see
:func:`...keyvault._runtime_probe.discover_running_gateway_runtimes`) and refuses
on the first failure. Gateway discovery is best-effort: when it finds nothing —
including because ``ps`` is unavailable — the gate behaves exactly as before,
since refusing on an inconclusive scan would make the seal impossible on exotic
hosts.

The gate logic was previously duplicated line-for-line in
:mod:`.env_decrypt_cli` and :mod:`.config_decrypt_cli`. The two seals are the
same security decision and must never drift apart, so the shared core lives
here; each module supplies only its target-specific guidance text (whole
pre-wrapped lines, so the operator-facing messages stay byte-identical to the
text they replaced).

Heavy imports stay function-local so this module imports on any platform,
matching the wizard CLI convention.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

from . import _term

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault._runtime_probe import GatewayRuntime

#: Runtime probe signature: called ``probe(home=..., runtime_python=...)`` ->
#: ``(ok, detail)``. ``runtime_python`` is omitted for the primary check (the
#: probe resolves the runtime itself) and supplied when the gate probes a
#: specific *running* gateway interpreter. Injectable so tests can fake the
#: runtime check (matching the ``backend=`` / ``store=`` injection style); each
#: seal supplies its production probe.
RuntimeProbe = Callable[..., "tuple[bool, str]"]

#: Running-gateway discovery signature: ``discover(home=...) -> [GatewayRuntime]``.
GatewayDiscovery = Callable[..., "list[GatewayRuntime]"]


def _default_gateway_discovery(*, home: Path) -> list[GatewayRuntime]:
    """Production discovery of the live gateway processes (import kept lazy)."""
    from ..keyvault._runtime_probe import discover_running_gateway_runtimes

    return discover_running_gateway_runtimes(home=home)


def _install_lines(python: Path) -> str:
    """The two-line "install the wheel here" remedy for ``python``."""
    extra = "macos" if sys.platform == "darwin" else "keyvault,telegram"
    return (
        "  Install the matching Mordred build into that interpreter:\n"
        f"    uv pip install --python {python} 'hermes-mordred[{extra}]'\n"
    )


def _expected_runtime_python(home: Path) -> Path:
    """The interpreter the seal expects to run ``hermes``, for guidance text."""
    if sys.platform == "win32":
        import os

        from .._windows_runtime import resolve_windows_python
        from ._uninstall_hermes_env import find_hermes_launcher

        selected = resolve_windows_python(
            home, find_hermes_launcher(home), override=os.environ.get("MORDRED_HERMES_PYTHON")
        )
        return selected or (home / "hermes-agent" / "venv" / "Scripts" / "python.exe")
    from ..keyvault._runtime_probe import discover_runtime_python

    return discover_runtime_python(home=home) or (home / "hermes-agent" / "venv" / "bin" / "python3")


def _emit_runtime_refusal(*, home: Path, target: str, detail: str, mechanism: str, rerun_tail: str) -> None:
    """Refusal for the primary check: the *expected* runtime cannot handle the seal."""
    _term.emit_error(
        f"refusing to vault-seal {target} — {detail}.\n"
        f"{mechanism}"
        f"{_install_lines(_expected_runtime_python(home))}"
        f"{rerun_tail}"
    )


def _emit_gateway_refusal(
    *,
    home: Path,
    target: str,
    gateway: GatewayRuntime,
    detail: str,
    mechanism: str,
    rerun_tail: str,
) -> None:
    """Refusal for the running-gateway check, naming the live interpreter (and pid)."""
    where = f"{gateway.python}" + (f" (pid {gateway.pid})" if gateway.pid is not None else "")
    _term.emit_error(
        f"refusing to vault-seal {target} — a hermes gateway is RUNNING from a different\n"
        f"  interpreter that cannot handle the seal: {where}.\n"
        f"  probe: {detail}.\n"
        f"{mechanism}"
        f"{_install_lines(gateway.python)}"
        "  ...or stop that gateway and restart it from the interpreter this check expects\n"
        f"  ({_expected_runtime_python(home)}), so the shim runs in the process that reads\n"
        "  the sealed file,\n"
        f"{rerun_tail}"
    )


def _interpreter_key(python: Path) -> tuple[str, str]:
    """Identity of an interpreter for "did we already probe this?".

    Environment (the ``bin/`` directory, symlinks resolved) **and** basename:
    ``/usr/local/bin/python3.11`` and ``…/python3.13`` share a directory but not a
    ``site-packages``, so the name has to be part of the key or the second one
    would be skipped unprobed. The cost is one redundant probe when a gateway
    runs a venv's ``python`` while the primary check resolved its ``python3``.
    """
    from ..keyvault._runtime_probe import environment_key

    return environment_key(python), python.name


def _probe_gateway(probe: RuntimeProbe, *, home: Path, python: Path) -> tuple[bool, str]:
    """Run ``probe`` against ``python``, turning a *raising* probe into a failure.

    Fail closed: an exception (a non-UTF-8 stderr, a broken injected probe) means
    we could not prove the running gateway can unseal the file, which is exactly
    the case this gate refuses on — not a traceback out of the CLI.
    """
    try:
        return probe(home=home, runtime_python=python)
    except Exception as exc:
        return False, f"probing that interpreter raised {exc!r}"


def _gateway_gate(
    *,
    home: Path,
    probe: RuntimeProbe,
    discovery: GatewayDiscovery,
    target: str,
    mechanism: str,
    rerun_tail: str,
) -> int:
    """Probe every running gateway interpreter that differs from the primary one.

    Returns 1 on the first failure (fail closed), else 0. Discovery problems are
    *not* failures: an empty or raising discovery leaves the pre-existing gate
    behavior untouched, so a host without a usable ``ps`` can still seal.
    """
    try:
        gateways = list(discovery(home=home))
    except Exception:
        # Broad on purpose: a diagnostic scan must never break a seal mid-flight.
        return 0
    if not gateways:
        return 0

    from ..keyvault._runtime_probe import discover_runtime_python

    primary = discover_runtime_python(home=home)
    primary_key = None if primary is None else _interpreter_key(primary)
    for gateway in gateways:
        if primary_key is not None and _interpreter_key(gateway.python) == primary_key:
            continue  # the very interpreter we already probed
        ok, detail = _probe_gateway(probe, home=home, python=gateway.python)
        if ok:
            continue
        _emit_gateway_refusal(
            home=home, target=target, gateway=gateway, detail=detail, mechanism=mechanism, rerun_tail=rerun_tail
        )
        return 1
    return 0


def runtime_gate(
    *,
    home: Path,
    platform: str,
    runtime_probe: RuntimeProbe | None,
    force_runtime_unverified: bool,
    default_probe: RuntimeProbe,
    target: str,
    mechanism: str,
    rerun_tail: str,
    gateway_discovery: GatewayDiscovery | None = None,
    supported_platforms: tuple[str, ...] = ("darwin",),
) -> int:
    """Fail-closed macOS gate for a destructive seal of ``target``.

    Returns 1 (after printing actionable guidance) when the interpreter that
    runs ``hermes`` — or one that is running a gateway right now — cannot handle
    a sealed ``target`` at startup, else 0. A no-op (0) off macOS — the plaintext
    is kept there anyway — and when ``force_runtime_unverified`` is set, which
    skips both checks silently and seals anyway.

    ``mechanism`` is the caller's explanation of its startup shim and
    ``rerun_tail`` closes with its re-run / force guidance; both are
    newline-terminated-line blocks slotted verbatim into the message.
    ``gateway_discovery`` is injectable for tests.
    """
    if platform not in supported_platforms or force_runtime_unverified:
        return 0
    probe = runtime_probe or default_probe
    ok, detail = probe(home=home)
    if not ok:
        _emit_runtime_refusal(home=home, target=target, detail=detail, mechanism=mechanism, rerun_tail=rerun_tail)
        return 1
    return _gateway_gate(
        home=home,
        probe=probe,
        discovery=gateway_discovery or _default_gateway_discovery,
        target=target,
        mechanism=mechanism,
        rerun_tail=rerun_tail,
    )
