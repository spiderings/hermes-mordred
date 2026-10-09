"""Runtime-interpreter probe for the at-rest ``.env`` seal (design note §8.2).

``encryption enable env`` deletes the plaintext ``~/.hermes/.env`` on macOS,
trusting the startup shim (:func:`._runtime_env.install_vault_env_decrypt`, wired
through the ``hermes_agent.plugins`` entry point) to re-inject the enrolled
secrets when ``hermes`` boots. That shim only runs if ``mordred_hermes`` is
installed in the interpreter that actually runs ``hermes`` — which is **not** the
interpreter running this CLI when the operator drives Mordred from a dev venv.
The managed runtime venv (``~/.hermes/hermes-agent/venv``) is uv-managed and
recreated on every ``hermes`` self-update, which silently drops the non-PyPI
``mordred_hermes``. The seal would then strand the operator: the plaintext is
gone but the runtime cannot decrypt the vault copy.

This module verifies, *before* the destructive delete, that the **runtime**
interpreter can actually run the injection shim. The caller (``env_decrypt_cli``)
refuses fail-closed when it cannot.

**Why the process table is authoritative.** :func:`discover_runtime_python`
answers "which interpreter *should* run ``hermes``" (operator override → managed
venv → ``hermes`` on ``$PATH``). That is not the same question as "which
interpreter *is* running the gateway right now", and the 2026-06-25 incident is
the difference: the gateway had been started from a repo checkout's ``.venv``
(``…/Mordred-Hermes/.venv/bin/python -m hermes_cli.main gateway run --replace``)
that had neither ``mordred_hermes`` nor the decrypt ``.pth``, while the managed
venv — the one the probe checked, and the one named by ``gateway_state.json``'s
recorded ``argv`` — had both. The seal passed its check, deleted the plaintext,
and the *running* gateway could not unseal it ("Provider authentication failed").
So :func:`discover_running_gateway_runtimes` reads the live process table (``ps``)
and treats the state file's ``pid`` as a *locator* only: its recorded ``argv`` is
whatever was written at launch time and lied in the incident, while ``ps`` reports
what the kernel actually exec'd.

Heavy imports stay function-local; this module imports on any platform.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Final, NamedTuple

from .._home import hermes_home as _hermes_home

__all__ = [
    "GatewayDiscoveryUnavailable",
    "GatewayRuntime",
    "discover_running_gateway_pythons",
    "discover_running_gateway_runtimes",
    "discover_runtime_python",
    "environment_key",
    "require_stopped_windows_gateways",
    "runtime_config_decrypt_available",
    "runtime_env_injection_available",
    "runtime_memory_encryption_available",
]

#: Env override: operator points us at the exact interpreter that runs ``hermes``.
RUNTIME_PYTHON_ENV = "MORDRED_HERMES_RUNTIME_PYTHON"

#: Seconds to wait for the probe subprocess before treating it as unavailable.
_PROBE_TIMEOUT_S = 20.0

#: Never inherited by a probe: the two that would falsify its answer, and the
#: memory key, which no probe needs.
_PROBE_ENV_STRIPPED: Final = frozenset({"PYTHONPATH", "PYTHONHOME", "HERMES_MEMORY_KEY"})

#: Cap on launcher-wrapper indirection while resolving an interpreter (a bash
#: ``hermes`` that exec's a venv ``hermes`` that has a python shebang = depth 2).
_MAX_LAUNCHER_HOPS = 5

#: Bytes read from a launcher before giving up. The shebang is line 1 and the
#: ``exec`` line is a handful of lines in; anything past this cap is not a
#: launcher we can understand, and reading it unbounded would let a hostile or
#: merely huge file at a path taken from *another process's* argv balloon this
#: process (a 600 MB file cost 1.8 GB RSS before this cap).
_LAUNCHER_READ_LIMIT = 64 * 1024

#: Same idea for ``gateway_state.json``: only a small JSON object is expected.
_STATE_READ_LIMIT = 64 * 1024

#: ``O_CLOEXEC`` where the platform has it (this module imports everywhere).
_O_CLOEXEC: int = getattr(os, "O_CLOEXEC", 0)

#: ``O_NONBLOCK`` where the platform has it — opening a FIFO without it blocks
#: until a writer appears, which would hang the CLI on a path we do not control.
_O_NONBLOCK: int = getattr(os, "O_NONBLOCK", 0)

# The probe runs *inside the runtime interpreter*. It must prove the env-injection
# shim will both be DISCOVERED (its entry point is registered, so Hermes calls
# ``register()``) and WORK (the hot-path imports it performs at startup resolve).
# A bare ``import mordred_hermes`` is too weak: a stray ``src`` on ``PYTHONPATH``
# imports without the package being installed or entry-point-registered, which is
# exactly the false-positive that lets the seal strand the operator.
_PROBE_SRC = """
import sys
try:
    from importlib.metadata import entry_points
    eps = [e for e in entry_points(group="hermes_agent.plugins") if e.name == "mordred"]
    if not eps:
        sys.stderr.write("mordred plugin not registered in this runtime")
        sys.exit(11)
    plugin = eps[0].load()
    if not callable(getattr(plugin, "register", None)):
        sys.stderr.write("mordred plugin exposes no register()")
        sys.exit(12)
    # The single plugin registers the keyvault component (the env shim) itself.
    if not any(module == "mordred_hermes.keyvault" for _c, module in getattr(plugin, "COMPONENTS", ())):
        sys.stderr.write("mordred plugin does not register the keyvault component")
        sys.exit(12)
    # The exact hot-path imports install_vault_env_decrypt -> inject_vault_env do
    # at startup (see keyvault._runtime_env). Importing them here catches a partial
    # install (mordred present but its crypto / pyobjc deps missing), not just a
    # total absence.
    import mordred_hermes.keyvault._runtime_env  # the shim module itself
    from mordred_hermes.keyvault import vault  # AES-GCM vault (cryptography / blake3 / argon2)
    from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend  # device key (pyobjc Security)
    from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorStore  # anchor store
    import dotenv  # .env parser
except Exception as exc:  # noqa: BLE001 - any failure means the shim won't run
    sys.stderr.write(repr(exc))
    sys.exit(13)
sys.exit(0)
"""

# The config.yaml analogue of ``_PROBE_SRC``. Unlike ``.env`` (an entry-point
# plugin Hermes calls at startup), ``config.yaml`` is materialized by a ``.pth``
# startup hook (``mordred_hermes_config_decrypt.pth`` -> ``_pth_bootstrap`` ->
# ``install_config_decrypt`` -> ``materialize_config``). So the probe must prove
# the hook is INSTALLED in this runtime's site-packages (else it never fires at
# boot) AND that the materialize hot-path imports resolve. The probe runs with
# ``MORDRED_CONFIG_DECRYPT=0`` (see caller), so the ``.pth`` is neutralized for the
# probe process itself and cannot open the vault / prompt Touch ID here.
_CONFIG_PROBE_SRC = """
import sys
try:
    from mordred_hermes.keyvault._config_bootstrap import config_hook_installed
    if not config_hook_installed():
        sys.stderr.write("config-decrypt .pth startup hook not installed in this runtime")
        sys.exit(21)
    # The exact hot-path imports the .pth hook performs at boot. Importing them
    # here catches a partial install (mordred present but its crypto / pyobjc deps
    # missing), not just a total absence.
    import mordred_hermes._pth_bootstrap  # the .pth target module
    from mordred_hermes.keyvault import _config_bootstrap  # materialize / reseal
    from mordred_hermes.keyvault import _storage, vault  # AES-GCM vault (cryptography / blake3 / argon2)
    from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend  # device key (pyobjc Security)
    from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorStore  # anchor store
except Exception as exc:  # noqa: BLE001 - any failure means the hook won't decrypt
    sys.stderr.write(repr(exc))
    sys.exit(22)
sys.exit(0)
"""

# The agent-memory analogue. Memory encryption wraps upstream's private
# ``tools/memory_tool.py`` seam, so capability here is not "is mordred installed"
# but "does THIS runtime's memory_tool still have a seam we can wrap" — a
# vendored or newer Hermes can refactor it out from under a perfectly healthy
# install. The shape is echoed on stdout for the caller's message.
_MEMORY_PROBE_SRC = """
import sys
try:
    from mordred_hermes.keyvault._memory_hook import memory_seam_shape, seam_check
    if sys.platform == "linux":
        from mordred_hermes.keyvault._memory_key import MEMORY_KEY_PROVIDER_VERSION
        if MEMORY_KEY_PROVIDER_VERSION != 1:
            sys.exit(33)
    ok, reason = seam_check()
    if not ok:
        sys.stderr.write(reason or "the memory seam is unsupported")
        sys.exit(31)
    sys.stdout.write(memory_seam_shape())
except Exception as exc:  # noqa: BLE001 - any failure means the hook won't seal
    sys.stderr.write(repr(exc))
    sys.exit(32)
sys.exit(0)
"""


def _read_file_head(path: Path, limit: int) -> str | None:
    """Read at most ``limit`` bytes of ``path``; ``None`` unless it is a regular file.

    Used for every file whose path came from somewhere we do not control (a
    launcher named in another process's argv, the gateway state file). ``open``
    goes through ``os.open`` with ``O_NONBLOCK`` so a FIFO cannot block us waiting
    for a writer, and ``fstat`` on the *opened descriptor* rejects anything that is
    not a regular file — no device, socket or FIFO is ever read.
    """
    try:
        fd = os.open(path, os.O_RDONLY | _O_NONBLOCK | _O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)
    return data.decode("utf-8", errors="replace")


def _interpreter_from_shebang(rest: str) -> Path | None:
    """Parse the interpreter path out of a shebang body (after ``#!``)."""
    try:
        parts = shlex.split(rest)
    except ValueError:
        # An unbalanced quote in a (possibly hostile) launcher must not raise
        # out of discovery — mirror the guard in ``_exec_target``.
        return None
    if not parts:
        return None
    # ``/usr/bin/env python3`` -> not a concrete runtime path; ``/path/bin/python`` -> the path.
    if parts[0].endswith("env") and len(parts) > 1:
        return None
    return Path(parts[0])


def _exec_target(text: str) -> Path | None:
    """Return the ``bin/hermes`` a shell wrapper ``exec``s, if it is one.

    Takes the launcher's already-read (and length-capped) text so the file is
    opened exactly once, under :func:`_read_file_head`'s guards.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("exec "):
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            continue
        for token in tokens[1:]:
            if token.startswith(("-", "$")):
                continue
            return Path(token)
    return None


def _sibling_python(launcher: Path) -> Path | None:
    """The ``python`` alongside a ``bin/hermes`` launcher, if present."""
    for name in ("python3", "python"):
        candidate = launcher.with_name(name)
        if candidate.exists():
            return candidate
    return None


def _within_current_prefix(path: Path) -> bool:
    """Whether ``path`` lives inside the interpreter running *this* CLI.

    Used to reject the sibling-python guess fallback when it would just point
    back at the dev venv driving this command — that venv has mordred (it must,
    to run this code) but is exactly the one that may NOT be the real ``hermes``
    runtime, so letting it validate itself is the false-pass we must avoid.
    """
    try:
        path.resolve().relative_to(Path(sys.prefix).resolve())
    except (ValueError, OSError):
        return False
    return True


def _python_for_launcher(path: Path) -> Path | None:
    """Resolve the Python interpreter behind a ``hermes`` launcher at ``path``.

    A ``hermes`` on ``$PATH`` is either a console script whose shebang names the
    venv's python, or a shell wrapper that ``exec``s another ``bin/hermes`` (the
    host wrapper does ``unset PYTHONPATH; exec "<venv>/bin/hermes" "$@"``). We
    follow the shebang / ``exec`` target without ever *executing* the launcher,
    then take the python next to the resolved ``bin/hermes``. Returns ``None`` if
    nothing resolvable is found within :data:`_MAX_LAUNCHER_HOPS`.

    Every read goes through :func:`_read_file_head` (regular files only, capped),
    because running-gateway discovery calls this with a path lifted out of another
    process's argv — see :func:`_python_from_gateway_argv`, which additionally
    refuses any launcher path that is not absolute.
    """
    seen: set[Path] = set()
    current = path
    for _ in range(_MAX_LAUNCHER_HOPS):
        try:
            current = current.resolve()
        except OSError:
            return None
        if current in seen:
            return None
        seen.add(current)
        text = _read_file_head(current, _LAUNCHER_READ_LIMIT)
        if not text:
            return None
        lines = text.splitlines()
        if not lines:
            return None
        shebang = lines[0]
        if shebang.startswith("#!"):
            interp = _interpreter_from_shebang(shebang[2:])
            if interp is not None and interp.name.startswith("python"):
                return interp if interp.exists() else None
        target = _exec_target(text)
        if target is None:
            # Not a recognizable wrapper: guess the python beside it — but never
            # the dev venv running this CLI (that would let it pose as the runtime).
            return _guarded_sibling_python(current)
        current = target
    return None


def _guarded_sibling_python(current: Path) -> Path | None:
    """Sibling-python guess that refuses the dev venv running this CLI.

    The sibling fallback exists for unrecognizable wrappers, but a sibling
    inside ``sys.prefix`` is exactly the venv driving this command — letting
    it validate itself is the false-pass :func:`_within_current_prefix`
    guards against, so it yields ``None`` instead.
    """
    sibling = _sibling_python(current)
    if sibling is not None and _within_current_prefix(sibling):
        return None
    return sibling


def _managed_runtime_python(home: Path) -> Path | None:
    """The python in Hermes's managed runtime venv, if it exists.

    This is the deterministic, non-shadowable signal: the host installs the
    Hermes runtime at ``<home>/hermes-agent/venv``. Preferring it over
    ``which hermes`` avoids validating the very dev venv whose mismatch with the
    runtime causes the bug.
    """
    base = home / "hermes-agent" / "venv" / "bin"
    for name in ("python3", "python"):
        candidate = base / name
        if candidate.exists():
            return candidate
    return None


#: ``site`` prints ``sys.path``; the managed launcher's shows the active install venv.
_SITE_PACKAGES = re.compile(r"'(/[^']+/venv)/lib/python[0-9.]+/site-packages'")


def _desktop_runtime_python(home: Path) -> Path | None:
    """The venv python behind Hermes Desktop's managed launcher, if present.

    Hermes Desktop (and the git/bootstrap install it uses) runs a standalone
    Python that selects ``<home>/installs/<id>/environments/<id>/venv`` at
    startup; neither ``<home>/hermes-agent/venv`` nor ``hermes`` on PATH
    exists. Ask the launcher itself: ``--run-module site`` prints ``sys.path``,
    which contains that environment's site-packages.
    """
    launcher = home / "hermes-agent" / ".hermes" / "bin" / "hermes"
    if not launcher.is_file() or not os.access(launcher, os.X_OK):
        return None
    try:
        proc = subprocess.run(
            [str(launcher), "--run-module", "site"],
            capture_output=True,
            text=True,
            timeout=20,
            env={k: v for k, v in os.environ.items() if k not in _PROBE_ENV_STRIPPED},
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for match in _SITE_PACKAGES.finditer(proc.stdout):
        for name in ("python3", "python"):
            candidate = Path(match.group(1)) / "bin" / name
            if candidate.exists():
                return candidate
    return None


def discover_runtime_python(home: Path | None = None, explicit: str | Path | None = None) -> Path | None:
    """Resolve the interpreter that actually runs ``hermes``, or ``None``.

    Order, most authoritative first:

    1. ``explicit`` argument or :data:`RUNTIME_PYTHON_ENV` — operator override.
    2. ``<home>/hermes-agent/venv/bin/python`` — Hermes's managed runtime venv
       (deterministic; not shadowable by an activated dev venv).
    3. Hermes Desktop's managed launcher (``<home>/hermes-agent/.hermes/bin/hermes``)
       — the install venv it selects (see :func:`_desktop_runtime_python`).
    4. the ``hermes`` launcher on ``$PATH`` — its shebang / ``exec`` target.

    Step 2 is deliberately tried before step 3 so an activated dev venv whose
    ``hermes`` shadows the host one cannot pose as the runtime.
    """
    home = _hermes_home() if home is None else home

    override = explicit if explicit is not None else os.environ.get(RUNTIME_PYTHON_ENV)
    if sys.platform == "win32":
        from .._windows_runtime import resolve_windows_python

        if override is not None:
            return resolve_windows_python(home, override=str(override))
        managed = resolve_windows_python(home)
        if managed is not None:
            return managed
        import shutil

        launcher = shutil.which("hermes")
        return None if launcher is None else resolve_windows_python(home, launcher=Path(launcher))
    if override:
        candidate = Path(override)
        return candidate if candidate.exists() else None

    managed = _managed_runtime_python(home)
    if managed is not None:
        return managed

    desktop = _desktop_runtime_python(home)
    if desktop is not None:
        return desktop

    import shutil

    launcher = shutil.which("hermes")
    if launcher is not None:
        return _python_for_launcher(Path(launcher))
    return None


# -----------------------------------------------------------------------------
# Running-gateway discovery (POSIX) — see the module docstring for why the
# process table, and not ``gateway_state.json``'s recorded argv, is the source.
# -----------------------------------------------------------------------------

#: Seconds to wait for a ``ps`` inventory. Discovery is best-effort: a slow or
#: missing ``ps`` degrades to "no gateway found", never to an exception.
_PS_TIMEOUT_S = 5.0

#: Deterministic, minimal environment for ``ps`` (also how the executable is
#: looked up: :mod:`subprocess` resolves the program through ``env["PATH"]``).
_PS_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

#: Hermes's gateway supervision state file, relative to the Hermes home. Only its
#: ``pid`` is used, as a locator for a ``ps -p`` query.
_GATEWAY_STATE_NAME = "gateway_state.json"

#: An interpreter basename: ``python``, ``python3``, ``python3.13``…
_PYTHON_BASENAME = re.compile(r"^python[0-9.]*$")

#: Console-script basenames that launch Hermes (``hermes gateway run …``).
_LAUNCHER_BASENAMES = frozenset({"hermes"})

#: Shells that may appear as ``argv[0]`` of a ``#!/usr/bin/env bash`` launcher
#: (the kernel rewrites ``<wrapper> gateway run`` to ``bash <wrapper> gateway run``).
_SHELL_BASENAMES = frozenset({"bash", "sh", "zsh", "dash", "ksh"})

#: ``python -m <this> … gateway run`` is the gateway's module entry point.
_GATEWAY_MODULE_PREFIX = "hermes_cli"


class GatewayRuntime(NamedTuple):
    """A live ``hermes … gateway run`` process and the interpreter running it.

    ``pid`` is ``None`` only if a row's pid could not be read (the interpreter is
    still actionable without it; the pid is diagnostic sugar for the operator).
    """

    pid: int | None
    python: Path


def environment_key(python: Path) -> str:
    """Identity of the Python *environment* an interpreter belongs to.

    Comparing fully resolved interpreter paths is wrong here: every venv's
    ``bin/python`` is a symlink to the same base interpreter, so ``resolve()``
    would report the managed runtime venv and a repo ``.venv`` as the *same*
    interpreter — exactly the mismatch this check exists to catch. The
    interpreter's directory (with symlinked parents resolved) identifies the
    environment instead: two pythons in one ``bin/`` share one ``site-packages``.
    """
    try:
        return os.path.realpath(str(python.parent))
    except OSError:  # pragma: no cover - realpath rarely raises
        return str(python.parent)


def _ps(args: list[str]) -> str | None:
    """Run ``ps`` with ``args``; ``None`` on any failure (missing, timeout, rc!=0)."""
    try:
        proc = subprocess.run(
            ["ps", *args],
            capture_output=True,
            text=True,
            timeout=_PS_TIMEOUT_S,
            env=_PS_ENV,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _is_own_uid(uid_field: str) -> bool:
    """Whether a ``ps`` uid column names this user (rows of others are not ours)."""
    return uid_field.isdigit() and int(uid_field) == os.getuid()


def _parse_scan_rows(out: str | None) -> list[tuple[int | None, str]]:
    """``ps -axo pid=,uid=,args=`` -> ``(pid, args)`` for this user's rows.

    Whitespace-split with ``maxsplit`` (no shell parsing): the columns are fixed
    and only the trailing ``args`` may contain spaces. Malformed rows are skipped.
    """
    rows: list[tuple[int | None, str]] = []
    for line in (out or "").splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        pid_field, uid_field, args = fields
        if not pid_field.isdigit() or not _is_own_uid(uid_field):
            continue
        rows.append((int(pid_field), args))
    return rows


def _parse_pid_rows(out: str | None, pid: int) -> list[tuple[int | None, str]]:
    """``ps -p <pid> -o uid=,args=`` -> ``(pid, args)`` for this user's rows."""
    rows: list[tuple[int | None, str]] = []
    for line in (out or "").splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or not _is_own_uid(fields[0]):
            continue
        rows.append((pid, fields[1]))
    return rows


def _process_alive(pid: int) -> bool:
    """Whether ``pid`` names a live process (``EPERM`` counts as alive)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _state_file_pid(home: Path) -> int | None:
    """The live pid recorded in ``<home>/gateway_state.json``, if any.

    Only the pid is trusted — the file's recorded ``argv`` named the managed venv
    while the process actually ran from a repo ``.venv`` (module docstring).
    """
    raw = _read_file_head(home / _GATEWAY_STATE_NAME, _STATE_READ_LIMIT)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    pid = data.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    return pid if _process_alive(pid) else None


def _module_arg(tokens: list[str]) -> str | None:
    """The module name following ``-m``, if the argv runs one."""
    for index, token in enumerate(tokens[:-1]):
        if token == "-m":
            return tokens[index + 1]
    return None


def _has_gateway_run(tokens: list[str]) -> bool:
    """Whether the argv contains the adjacent ``gateway run`` verb pair."""
    return any(tokens[i] == "gateway" and tokens[i + 1] == "run" for i in range(len(tokens) - 1))


def _has_launcher_token(tokens: list[str]) -> bool:
    """Whether any token names a ``hermes`` launcher (path not required to exist)."""
    return any(Path(token).name in _LAUNCHER_BASENAMES for token in tokens)


def _absolute_launcher_token(tokens: list[str]) -> Path | None:
    """The first token that is an **absolute** path to a ``hermes`` launcher.

    Absoluteness is a hard requirement, not a nicety: these tokens come from
    another process's argv, and a relative one would be resolved against *this*
    CLI's working directory — letting a file named ``hermes`` in the operator's
    cwd decide which interpreter we execute.
    """
    for token in tokens:
        candidate = Path(token)
        if candidate.is_absolute() and candidate.name in _LAUNCHER_BASENAMES:
            return candidate
    return None


def _is_gateway_argv(tokens: list[str]) -> bool:
    """Whether an argv is a Hermes gateway process.

    Four accepted shapes, all requiring an adjacent ``gateway run``:

    1. ``<python> -m hermes_cli.main gateway run …`` — supervisor form.
    2. ``<python> <…/bin/hermes> gateway run …`` — a console script *as the kernel
       reports it*: a ``#!`` exec is rewritten to ``[interpreter, script, …]``, so
       ``hermes gateway run`` normally appears in this form, never as shape 3.
    3. ``<…/bin/hermes> gateway run …`` — argv[0] preserved as the script.
    4. ``bash <…/bin/hermes> gateway run …`` — a ``#!/usr/bin/env bash`` wrapper,
       likewise rewritten by the kernel; the launcher path must be absolute.
    """
    if len(tokens) < 3 or not _has_gateway_run(tokens):
        return False
    name = Path(tokens[0]).name
    if _PYTHON_BASENAME.match(name):
        module = _module_arg(tokens)
        if module is not None:
            return module.startswith(_GATEWAY_MODULE_PREFIX)
        return _has_launcher_token(tokens[1:])  # shape 2
    if name in _LAUNCHER_BASENAMES:
        return True  # shape 3
    return name in _SHELL_BASENAMES and _absolute_launcher_token(tokens[1:]) is not None  # shape 4


def _python_from_gateway_argv(tokens: list[str]) -> Path | None:
    """The interpreter behind a gateway argv, or ``None`` when argv cannot say.

    For the python-first shapes (1 and 2) the interpreter *is* ``argv[0]`` — no
    file is read. Only the launcher shapes (3 and 4) fall back to reading the
    launcher, and only when its path is absolute.
    """
    exe = Path(tokens[0])
    if _PYTHON_BASENAME.match(exe.name):
        return exe
    launcher = exe if exe.is_absolute() and exe.name in _LAUNCHER_BASENAMES else _absolute_launcher_token(tokens[1:])
    return None if launcher is None else _python_for_launcher(launcher)


def _proc_exe_python(pid: int | None) -> Path | None:
    """``/proc/<pid>/exe`` on Linux — used only when ``argv`` cannot name the python.

    Deliberately a *fallback*, not the preferred source: the kernel resolves the
    symlink, so a process running a venv's ``bin/python`` reports the **base**
    interpreter, whose ``site-packages`` is not the venv's. Probing that would
    answer the wrong question — the same trap :func:`environment_key` and
    :func:`_accept_interpreter` avoid by never resolving an interpreter path. It
    is still the best answer when ``argv[0]`` is relative or gone.
    """
    if pid is None or not sys.platform.startswith("linux"):
        return None
    try:
        target = Path(os.readlink(f"/proc/{pid}/exe"))
    except OSError:
        return None
    return target if _PYTHON_BASENAME.match(target.name) else None


def _accept_interpreter(path: Path) -> Path | None:
    """Vet a candidate we are about to *execute*; ``None`` rejects it.

    Requires an absolute path to a regular, executable file owned by this user or
    root, writable by neither group nor world, and sitting in a directory that is
    not world-writable — otherwise the interpreter could be swapped under us
    between this check and the probe. The path itself is deliberately **not**
    resolved: a venv's ``bin/python`` is a symlink to the base interpreter, and
    following it would probe the wrong ``site-packages``.

    A rejection means "skip this candidate", so an unusually permissive host
    silently loses the extra check rather than blocking a seal.
    """
    if not path.is_absolute():
        return None
    try:
        info = path.stat()  # follows the symlink: we want the target's mode
        parent = path.parent.stat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
        return None
    if parent.st_mode & stat.S_IWOTH:
        return None
    if info.st_uid not in (0, os.getuid()) or not os.access(path, os.X_OK):
        return None
    return path


def _gateway_python_for_row(pid: int | None, args: str) -> Path | None:
    """The vetted interpreter for one ``ps`` row, or ``None`` if it is not a gateway.

    ``argv`` is preferred and ``/proc/<pid>/exe`` is consulted only when argv
    yields nothing usable (see :func:`_proc_exe_python` for why the kernel's
    symlink-resolved answer is the *worse* one for a venv).
    """
    tokens = args.split()
    if not _is_gateway_argv(tokens):
        return None
    argv_python = _python_from_gateway_argv(tokens)
    accepted = None if argv_python is None else _accept_interpreter(argv_python)
    if accepted is not None:
        return accepted
    fallback = _proc_exe_python(pid)
    return None if fallback is None else _accept_interpreter(fallback)


def _collect_gateway_runtimes(home: Path) -> list[GatewayRuntime]:
    """Both discovery sources, deduplicated by environment + interpreter name."""
    rows: list[tuple[int | None, str]] = []
    state_pid = _state_file_pid(home)
    if state_pid is not None:
        rows.extend(_parse_pid_rows(_ps(["-p", str(state_pid), "-o", "uid=,args="]), state_pid))
    rows.extend(_parse_scan_rows(_ps(["-axo", "pid=,uid=,args="])))

    # Dedupe on (environment, interpreter name): two gateway processes from one
    # venv need one probe, while /usr/bin/python3.11 and /usr/bin/python3.13 share
    # a directory but not a site-packages and must stay separate candidates.
    found: dict[tuple[str, str], GatewayRuntime] = {}
    for pid, args in rows:
        python = _gateway_python_for_row(pid, args)
        if python is None:
            continue
        found.setdefault((environment_key(python), python.name), GatewayRuntime(pid=pid, python=python))
    return list(found.values())


def discover_running_gateway_runtimes(home: Path | None = None) -> list[GatewayRuntime]:
    """Interpreters of the ``hermes … gateway run`` processes running *right now*.

    On Windows, an unknown inventory raises GatewayDiscoveryUnavailable.
    POSIX discovery retains its historical best-effort behavior and never raises
    into the CLI: a missing ``ps``, a denied ``/proc``, an unparseable state file
    or any other surprise degrades to an empty list. Callers must therefore treat
    "no gateway found" as "unknown", not as proof that nothing is running.

    Sources, in order: the live pid in ``<home>/gateway_state.json`` (queried with
    ``ps -p``), then a full ``ps -axo`` scan. Only rows owned by this user are
    considered — a gateway running as root or as another account is *not*
    reported, and therefore not probed, because its interpreter is outside what
    this CLI can inspect or fix; see the module docstring for why the process
    table wins over the state file's recorded argv.
    """
    if sys.platform == "win32":
        from ._windows_processes import inspect_windows_gateway_runtimes

        inventory = inspect_windows_gateway_runtimes(_hermes_home() if home is None else home)
        if inventory.state == "unknown":
            raise GatewayDiscoveryUnavailable("Windows gateway inventory is unknown: " + "; ".join(inventory.reasons))
        return list(inventory.runtimes)
    if os.name != "posix":
        return []
    try:
        return _collect_gateway_runtimes(_hermes_home() if home is None else home)
    except Exception:
        # Broad on purpose: discovery is advisory, and raising here would abort a
        # seal (or `status`) over an unreadable process table.
        return []


class GatewayDiscoveryUnavailable(RuntimeError):
    """A Windows lifecycle transition cannot prove relevant gateways stopped."""


def require_stopped_windows_gateways(home: Path) -> None:
    """Refuse unknown or running gateways, with no force bypass.

    Windows lifecycle callers must call this directly: the legacy wizard's
    diagnostic discovery wrapper intentionally catches errors and is not a gate.
    Filesystem lifecycle locks and final generation checks remain required.
    """
    from ._windows_processes import inspect_windows_gateway_runtimes

    inventory = inspect_windows_gateway_runtimes(home)
    if inventory.state == "unknown":
        raise GatewayDiscoveryUnavailable("Windows gateway inventory is unknown: " + "; ".join(inventory.reasons))
    if inventory.runtimes:
        raise GatewayDiscoveryUnavailable("Stop running Windows Hermes gateways before changing memory custody")


def discover_running_gateway_pythons(home: Path | None = None) -> list[Path]:
    """The interpreter paths of :func:`discover_running_gateway_runtimes`."""
    return [runtime.python for runtime in discover_running_gateway_runtimes(home=home)]


def _resolve_runtime_python(home: Path | None, runtime_python: Path | None) -> tuple[Path | None, str]:
    """Resolve the interpreter to probe, or ``(None, detail)`` when none is found.

    Shared by the three capability probes: an explicit ``runtime_python`` wins, else
    :func:`discover_runtime_python` resolves it from ``home``.
    """
    home = _hermes_home() if home is None else home
    if sys.platform == "win32":
        python = discover_runtime_python(home=home, explicit=runtime_python)
    else:
        python = runtime_python if runtime_python is not None else discover_runtime_python(home=home)
    if python is None:
        return None, (
            "could not locate the interpreter that runs `hermes` "
            "(looked for <home>/hermes-agent/venv, Hermes Desktop's launcher and `hermes` on PATH); "
            f"set {RUNTIME_PYTHON_ENV} to point at it"
        )
    return python, ""


def _run_runtime_probe(
    python: Path,
    probe_src: str,
    *,
    timeout: float,
    extra_env: dict[str, str] | None = None,
    hermes_startup: bool = False,
) -> tuple[subprocess.CompletedProcess[str] | None, str]:
    """Run ``probe_src`` in ``python`` with a sanitized env.

    Returns ``(proc, error_detail)``: ``proc`` is ``None`` on a launch failure
    (``error_detail`` set), else the completed process (``error_detail`` empty).
    ``PYTHONPATH`` / ``PYTHONHOME`` are stripped so the probe sees exactly what the
    host's ``hermes`` wrapper sees (it ``unset``s both) — a stray ``PYTHONPATH``
    must not make a runtime look capable when it is not. ``HERMES_MEMORY_KEY`` is
    stripped too: no probe needs the memory key, so it never enters a child
    process's environment from here. ``extra_env`` is overlaid last (e.g. a
    hook-disable flag). Any timeout / OSError is a fail-closed miss.
    """
    env = {k: v for k, v in os.environ.items() if k not in _PROBE_ENV_STRIPPED}
    if extra_env:
        env.update(extra_env)
    try:
        with contextlib.ExitStack() as stack:
            command = [str(python), "-c", probe_src]
            if hermes_startup:
                directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="mordred-probe-"))
                script = Path(directory) / "hermes"
                script.write_text(probe_src, encoding="utf-8")
                command = [str(python), str(script)]
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
            )
    except subprocess.TimeoutExpired:
        return None, f"probing the hermes runtime ({python}) timed out after {timeout:g}s"
    except OSError as exc:
        return None, f"could not run the hermes runtime ({python}): {exc}"
    return proc, ""


def _probe_capability(
    home: Path | None,
    runtime_python: Path | None,
    *,
    timeout: float,
    probe_src: str,
    can: str,
    cannot: str,
    ok_suffix: Callable[[str], str] | None = None,
) -> tuple[bool, str]:
    """Shared control flow for the three ``runtime_*_available`` probes.

    Resolves the runtime interpreter (fail-closed, via :func:`_resolve_runtime_python`),
    then runs ``probe_src`` there via :func:`_run_runtime_probe` with
    ``PYTHONPATH`` / ``PYTHONHOME`` / ``HERMES_MEMORY_KEY`` stripped and
    ``MORDRED_CONFIG_DECRYPT=0`` set — an exported ``MORDRED_CONFIG_DECRYPT=1``
    would otherwise force-engage the config-decrypt ``.pth`` hook in the probe
    process, opening the vault (and prompting Touch ID) merely to answer a
    capability question. Any launch error, timeout, or non-zero exit is
    **unavailable** (fail-closed): we never claim capability we could not prove.

    ``can`` / ``cannot`` complete the success and failure details
    (``"hermes runtime (…) can {can}"`` / ``"the hermes runtime (…) cannot
    {cannot}: {reason}"``); ``ok_suffix`` may append text derived from the
    probe's stdout on success.
    """
    python, locate_err = _resolve_runtime_python(home, runtime_python)
    if python is None:
        return False, locate_err
    proc, run_err = _run_runtime_probe(python, probe_src, timeout=timeout, extra_env={"MORDRED_CONFIG_DECRYPT": "0"})
    if proc is None:
        return False, run_err
    if proc.returncode == 0:
        suffix = ok_suffix(proc.stdout or "") if ok_suffix is not None else ""
        return True, f"hermes runtime ({python}) can {can}{suffix}"
    reason = (proc.stderr or proc.stdout or "unknown error").strip()
    return False, f"the hermes runtime ({python}) cannot {cannot}: {reason}"


def runtime_env_injection_available(
    *,
    home: Path | None = None,
    runtime_python: Path | None = None,
    timeout: float = _PROBE_TIMEOUT_S,
) -> tuple[bool, str]:
    """Whether the Hermes runtime can decrypt a sealed ``.env`` at startup.

    ``ok`` is ``True`` only when the runtime interpreter has the
    ``mordred`` plugin (with its keyvault component) registered *and* the shim's hot-path imports
    resolve there. Shared semantics: :func:`_probe_capability`.
    """
    return _probe_capability(
        home,
        runtime_python,
        timeout=timeout,
        probe_src=_PROBE_SRC,
        # Asymmetric on purpose (pre-split wording): success speaks of *injecting*
        # the sealed .env at startup, failure of not being able to *decrypt* it.
        can="inject a sealed .env",
        cannot="decrypt a sealed .env",
    )


def runtime_config_decrypt_available(
    *,
    home: Path | None = None,
    runtime_python: Path | None = None,
    timeout: float = _PROBE_TIMEOUT_S,
) -> tuple[bool, str]:
    """Whether the Hermes runtime can decrypt a sealed ``config.yaml`` at startup.

    The ``config.yaml`` analogue of :func:`runtime_env_injection_available`. ``ok``
    is ``True`` only when the runtime interpreter has the config-decrypt ``.pth``
    startup hook installed *and* the materialize hot-path imports resolve there
    (the explicit ``config_hook_installed()`` + import checks in the probe source
    do the verification). Shared semantics: :func:`_probe_capability`.
    """
    return _probe_capability(
        home,
        runtime_python,
        timeout=timeout,
        probe_src=_CONFIG_PROBE_SRC,
        can="decrypt a sealed config.yaml",
        cannot="decrypt a sealed config.yaml",
    )


def runtime_memory_encryption_available(
    *,
    home: Path | None = None,
    runtime_python: Path | None = None,
    timeout: float = _PROBE_TIMEOUT_S,
) -> tuple[bool, str]:
    """Whether the Hermes runtime can seal agent memory at rest.

    The ``memories/*.md`` analogue of :func:`runtime_env_injection_available`.
    ``ok`` is ``True`` only when ``mordred_hermes.keyvault._memory_hook`` imports
    in that interpreter *and* classifies its ``tools.memory_tool`` as a seam it
    can wrap; the detail then names the shape, read from the probe's stdout (``?``
    if it printed nothing) — a seal must never be promised on a runtime that would
    then read the sealed files as garbage. Shared semantics:
    :func:`_probe_capability`.
    """
    return _probe_capability(
        home,
        runtime_python,
        timeout=timeout,
        probe_src=_MEMORY_PROBE_SRC,
        can="encrypt agent memory",
        cannot="encrypt agent memory",
        ok_suffix=lambda out: f" (seam {out.strip() or '?'})",
    )


_MEMORY_KEY_PROBE_SRC = """
import os
import sys
from pathlib import Path
try:
    from mordred_hermes.keyvault._memory_key import MEMORY_KEY_PROVIDER_VERSION, load_linux_memory_key
    from mordred_hermes.keyvault._memory_hook import memory_hook_installed
    if not memory_hook_installed():
        sys.exit(36)
    from mordred_hermes.keyvault.memory_crypto import seal, unseal
    if MEMORY_KEY_PROVIDER_VERSION != 1:
        sys.exit(33)
    key = load_linux_memory_key(home=Path(os.environ["HERMES_HOME"]))
    payload = b"mordred-runtime-memory-probe"
    blob = seal(payload, key=key, name="MEMORY.md")
    if unseal(blob, key=key, name="MEMORY.md") != payload:
        sys.exit(34)
except Exception:
    sys.exit(35)
sys.exit(0)
"""


def runtime_memory_key_available(
    *,
    home: Path,
    runtime_python: Path | None = None,
    timeout: float = 10.0,
) -> tuple[bool, str]:
    """Unwrap via the installed runtime, without reporting any secret output."""
    python, reason = _resolve_runtime_python(home, runtime_python)
    if python is None:
        return False, reason
    proc, error = _run_runtime_probe(
        python,
        _MEMORY_KEY_PROBE_SRC,
        hermes_startup=True,
        timeout=timeout,
        extra_env={"HERMES_HOME": str(home), "MORDRED_CONFIG_DECRYPT": "0"},
    )
    if proc is None:
        return False, error
    if proc.returncode != 0:
        return False, "Hermes runtime could not unwrap and verify the TPM memory key"
    return True, "Hermes runtime verified the TPM memory key"
