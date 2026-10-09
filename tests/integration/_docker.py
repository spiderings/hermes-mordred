"""Docker-compose lifecycle helper for hermetic integration tests.

PR3b: backs ``test_tor.py`` (and any future test that wants an
ephemeral, network-isolated dependency). Kept dependency-free: no
docker SDK, just shells out to ``docker compose`` so the helper works
anywhere the CLI works (CI runners, Linux dev boxes, Colima/OrbStack
on macOS).

Skip semantics
--------------

``skip_reason_if_unavailable()`` returns the human-readable reason the
caller should pass to ``pytest.skip(...)`` / ``pytestmark.skipif(...)``,
or ``None`` when docker is usable. This collapses three orthogonal
checks (env override, OS, binary presence) into one decision so the
tests stay declarative.

Bootstrap detection
-------------------

Tor signals readiness on stdout with ``Bootstrapped 100%``; we tail the
combined logs of the named service and return as soon as the token
appears, with a per-attempt deadline (default 240s — cold CI runners
have been observed past 120s). A missed deadline usually means the
bootstrap wedged on a bad guard/directory draw rather than being merely
slow, so :func:`compose_up` recreates the container once (fresh draw)
before raising :class:`BootstrapTimeout`. Stdout tail is the same
mechanism :mod:`paths.tor` uses for the native spawn case, so a
regression in either path surfaces the same way.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

DEFAULT_BOOTSTRAP_TIMEOUT: Final[float] = 240.0
DEFAULT_BOOTSTRAP_ATTEMPTS: Final[int] = 2
DEFAULT_DOWN_TIMEOUT: Final[float] = 30.0
DEFAULT_POLL_INTERVAL: Final[float] = 1.0

_SKIP_ENV_VAR: Final[str] = "MORDRED_SKIP_DOCKER_TESTS"


class DockerUnavailable(RuntimeError):
    """Raised when the helper is invoked despite docker being unusable.

    Tests should call :func:`skip_reason_if_unavailable` first and skip
    cleanly; this exception covers the "called anyway" path so a typo
    in the skip guard surfaces loudly instead of silently passing.
    """


class BootstrapTimeout(RuntimeError):
    """The container did not emit the readiness token before the deadline."""


def _docker_binary() -> str | None:
    """Return the docker binary path, or ``None`` if it isn't on $PATH."""
    return shutil.which("docker")


def _compose_subcommand(docker_bin: str) -> list[str] | None:
    """Return the argv prefix for compose, or ``None`` if compose is missing.

    Prefers the v2 plugin (``docker compose``) since v1 (``docker-compose``)
    is past EOL. Probing via ``--version`` is a client-only check.
    """
    try:
        result = subprocess.run(
            [docker_bin, "compose", "version"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 0:
        return [docker_bin, "compose"]
    return None


def _daemon_responsive(docker_bin: str) -> bool:
    """Probe ``docker info`` so the skip-guard catches "binary installed
    but daemon not running" — common on dev machines where the user
    starts Docker Desktop / Colima manually.

    Short timeout because the daemon is local; if it takes more than 5
    seconds to respond, treat as unavailable and skip.
    """
    try:
        result = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and bool((result.stdout or "").strip())


def skip_reason_if_unavailable() -> str | None:
    """Return a skip reason, or ``None`` when docker compose is ready.

    The order matters — we check the explicit opt-out first so dev
    machines with docker installed but no daemon running can still
    short-circuit, then OS (Windows is outside the supported matrix), then the
    binary itself.
    """
    if os.environ.get(_SKIP_ENV_VAR) == "1":
        return f"{_SKIP_ENV_VAR}=1"
    if sys.platform.startswith("win"):
        return "docker integration tests are Linux/macOS-only"
    docker_bin = _docker_binary()
    if docker_bin is None:
        return "docker binary not on $PATH"
    if _compose_subcommand(docker_bin) is None:
        return "`docker compose` v2 plugin not available"
    if not _daemon_responsive(docker_bin):
        return "docker daemon not responding to `docker info`"
    return None


def _resolve_compose() -> list[str]:
    """Return the compose argv prefix or raise :class:`DockerUnavailable`."""
    docker_bin = _docker_binary()
    if docker_bin is None:
        raise DockerUnavailable("docker binary not on $PATH")
    prefix = _compose_subcommand(docker_bin)
    if prefix is None:
        raise DockerUnavailable("`docker compose` v2 plugin not available")
    return prefix


def _run_compose(
    project_dir: Path,
    args: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``docker compose -f <project_dir>/docker-compose.yml <args...>``.

    ``project_dir`` is bound to ``--project-directory`` so relative
    paths inside the compose file resolve against the test-tree
    location regardless of the pytest invocation cwd.
    """
    prefix = _resolve_compose()
    compose_file = project_dir / "docker-compose.yml"
    if not compose_file.exists():
        raise DockerUnavailable(f"compose file missing: {compose_file}")
    argv = [
        *prefix,
        "-f",
        str(compose_file),
        "--project-directory",
        str(project_dir),
        *args,
    ]
    return subprocess.run(
        argv,
        check=check,
        text=True,
        capture_output=capture,
        timeout=timeout,
    )


def _wait_for_bootstrap_token(
    project_dir: Path,
    service: str,
    token: str,
    timeout: float,
    *,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
) -> None:
    """Tail ``docker compose logs <service>`` until ``token`` appears.

    Polls in a loop rather than streaming so the helper stays
    subprocess-only (no extra threads, no async). Each poll re-reads
    the full log buffer — Tor's bootstrap log fits in a few KB so
    re-reads are cheap. Raises :class:`BootstrapTimeout` past the
    deadline.
    """
    deadline = time.monotonic() + timeout
    combined = ""
    while time.monotonic() < deadline:
        proc = _run_compose(
            project_dir,
            ["logs", "--no-color", service],
            check=False,
            capture=True,
            timeout=30.0,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        if token in combined:
            return
        time.sleep(poll_interval)
    # Attach the last log buffer we saw so a CI timeout is debuggable
    # without re-running — an empty tail usually means the service
    # never logged to stdout (see the torrc `Log notice stdout` note).
    tail = "\n".join(combined.splitlines()[-20:]).strip()
    detail = tail or "<no output captured from `docker compose logs`>"
    raise BootstrapTimeout(f"service {service!r} did not emit {token!r} within {timeout}s; last log tail:\n{detail}")


def _teardown(project_dir: Path) -> None:
    """``compose down --volumes --remove-orphans``, escalating to
    ``compose kill`` if the graceful path stalls."""
    try:
        _run_compose(
            project_dir,
            ["down", "--volumes", "--remove-orphans"],
            check=False,
            capture=True,
            timeout=DEFAULT_DOWN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        _run_compose(
            project_dir,
            ["kill"],
            check=False,
            capture=True,
            timeout=DEFAULT_DOWN_TIMEOUT,
        )


@contextmanager
def compose_up(
    *,
    project_dir: Path,
    service: str,
    bootstrap_token: str | None = None,
    timeout: float = DEFAULT_BOOTSTRAP_TIMEOUT,
    attempts: int = DEFAULT_BOOTSTRAP_ATTEMPTS,
) -> Iterator[None]:
    """Bring up the compose project; tear down on exit even on failure.

    ``bootstrap_token`` controls readiness detection:

    - non-empty string → tail logs for the substring (Tor uses
      ``Bootstrapped 100%``), waiting up to ``timeout`` seconds per
      attempt. If the token never appears the container is recreated
      from scratch and the wait restarts, up to ``attempts`` total
      tries — a wedged Tor bootstrap (bad guard/directory draw) rarely
      recovers by waiting longer, but a fresh container re-rolls the
      draw. The last attempt raises :class:`BootstrapTimeout`.
    - ``None`` → return immediately after ``compose up -d`` succeeds.

    Teardown calls ``compose down --volumes --remove-orphans`` so each
    test module starts from a clean slate; the bind-mount data dir is
    untouched (it lives in the test tree, not a docker volume).
    """
    if attempts < 1:
        raise ValueError(f"attempts must be >= 1, got {attempts}")
    if skip_reason_if_unavailable() is not None:
        raise DockerUnavailable(skip_reason_if_unavailable() or "")

    _run_compose(project_dir, ["up", "-d", service], timeout=180.0)
    try:
        if bootstrap_token:
            for attempt in range(1, attempts + 1):
                try:
                    _wait_for_bootstrap_token(project_dir, service, bootstrap_token, timeout)
                    break
                except BootstrapTimeout:
                    if attempt == attempts:
                        raise
                    _teardown(project_dir)
                    _run_compose(project_dir, ["up", "-d", service], timeout=180.0)
        yield
    finally:
        _teardown(project_dir)


def container_alive(project_dir: Path, service: str) -> bool:
    """Best-effort check used by integration tests that hold a handle.

    ``compose ps -q <service>`` prints the container ID when up, empty
    otherwise. Used for ``paths.tor.health``-style probes from tests
    that build a ``TorHandle`` pointing at the docker service.
    """
    try:
        result = _run_compose(
            project_dir,
            ["ps", "-q", service],
            check=False,
            capture=True,
            timeout=10.0,
        )
    except (DockerUnavailable, subprocess.TimeoutExpired):
        return False
    return bool((result.stdout or "").strip())
