"""``hermes mordred keyvault {enable-se,enable-tpm}`` — native-helper build CLI.

Extracted from :mod:`keyvault_cli` (v2-OS2 follow-up b). These are the commands
that build + install the platform hardware-helper binaries from source:

- ``enable-se``  — macOS Secure Enclave helper (``native/sekey-helper``).
- ``enable-tpm`` — Linux TPM 2.0 helper (``native/tpmkey-helper``).

Each build step is a module-level seam so the orchestration is unit-testable
with no Swift/Rust toolchain and no hardware (the build / probe are mocked).
The argparse adapters (``cli_enable_*``) are wired in :mod:`cli`.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import _term

__all__ = [
    "cli_enable_se",
    "cli_enable_tpm",
    "cli_enable_winkey",
    "enable_se",
    "enable_tpm",
    "enable_winkey",
]


# -----------------------------------------------------------------------------
# enable-se — build + ad-hoc-sign + install the Secure Enclave helper.
#
# Installs the CryptoKit ``dataRepresentation`` helper
# (``native/sekey-helper``) for newly-created wrapping keys. Existing helper,
# PyObjC-Keychain, and software keys stay in their original namespaces and are
# reached by the backend's ordered fallback; installation never promotes them.
# The helper needs only an ad-hoc codesign — no entitlement, no provisioning
# profile, no paid Apple Developer account.
#
# Each step is a module-level seam so the orchestration is unit-testable with
# no Swift toolchain and no Secure Enclave (the build / probe are mocked).
# -----------------------------------------------------------------------------


def _se_platform_reason() -> str | None:
    """Return why the SE helper can't be built here, or ``None`` when it can.

    The CryptoKit ``SecureEnclave`` APIs exist only on macOS (Apple Silicon or
    a T2 Mac). A coarse ``Darwin`` guard is enough; true SE *presence* is
    confirmed by the post-install probe.
    """
    import platform

    if platform.system() != "Darwin":
        return f"Secure Enclave requires macOS on Apple Silicon (this host is {platform.system() or 'unknown'})"
    return None


def _missing_build_tools() -> list[str]:
    """Return the build tools (``swift``, ``codesign``) not found on ``PATH``."""
    import shutil

    return [tool for tool in ("swift", "codesign") if shutil.which(tool) is None]


def _locate_sekey_source() -> Path | None:
    """Locate the ``sekey-helper`` source tree (delegates to ``_seckey_helper``)."""
    from ..keyvault import _seckey_helper

    return _seckey_helper._locate_helper_source()


def _run_sekey_build(src: Path, *, install_dir: Path | None, unattended: bool | None) -> tuple[int, str]:
    """Run ``build.sh`` in ``src``; return ``(returncode, combined_output)``.

    ``install_dir`` is forwarded as ``MORDRED_SEKEY_INSTALL_DIR``.
    ``unattended`` is retained in this private seam for call compatibility,
    but intentionally is not put in the build environment: authorization
    policy is baked into a key when it is generated, while this command only
    compiles and installs a binary.
    """
    import os
    import subprocess

    del unattended
    env = dict(os.environ)
    if install_dir is not None:
        env["MORDRED_SEKEY_INSTALL_DIR"] = str(install_dir)
    try:
        proc = subprocess.run(
            ["bash", str(src / "build.sh")],
            cwd=str(src),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"failed to run build.sh: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _verify_sekey_helper(*, install_dir: Path | None = None) -> bool:
    """Probe the freshly-installed helper to confirm Secure Enclave access.

    When ``install_dir`` is given (``enable-se --install-dir``), the binary just
    installed there is preferred — ``_find_helper`` only searches
    ``MORDRED_SEKEY_HELPER`` / ``~/.local/bin`` / ``PATH``, so a custom,
    not-on-PATH install dir would otherwise yield a false verification failure.
    (Mirror of :func:`_verify_tpmkey_helper`.)
    """
    from ..keyvault import _seckey_helper

    binary: str | None = None
    if install_dir is not None:
        candidate = install_dir / _seckey_helper._HELPER_NAME
        if candidate.is_file():
            binary = str(candidate)
    if binary is None:
        binary = _seckey_helper._find_helper()
    if binary is None:
        return False
    try:
        _seckey_helper._HelperSecKeyOps(binary).probe()
        return True
    except Exception:
        return False


def enable_se(
    *,
    install_dir: Path | None = None,
    unattended: bool | None = None,
    home: Path | None = None,
) -> int:
    """Build + ad-hoc-sign + install the SE helper, then verify it works.

    Returns ``0`` when the helper is usable and ``1`` on any
    platform/build/verify failure. Installing or refreshing the helper does not
    migrate an existing wrapping key. The backend continues resolving existing
    helper-store, legacy PyObjC-Keychain, and software keys in their original
    namespaces; only later fresh key creation selects the helper.

    ``unattended`` is accepted for CLI/API compatibility but rejected when set:
    the policy is chosen at key generation, not helper installation. Set
    ``MORDRED_SEKEY_UNATTENDED=1`` on the later init/recovery command instead.
    """
    if unattended is not None:
        _term.emit_error(
            "--unattended cannot be applied while installing the helper: the "
            "authorization policy is chosen when a wrapping key is generated. "
            "Install without this flag, then set MORDRED_SEKEY_UNATTENDED=1 "
            "when running keyvault init/recovery."
        )
        return 1

    reason = _se_platform_reason()
    if reason is not None:
        _term.emit_error(reason)
        return 1

    missing = _missing_build_tools()
    if missing:
        _term.emit_error(
            f"missing build tool(s): {', '.join(missing)}. "
            "Install the Xcode command-line tools first (xcode-select --install)."
        )
        return 1

    src = _locate_sekey_source()
    if src is None:
        _term.emit_error(
            "could not locate the sekey-helper sources (native/sekey-helper). "
            "Build from a source checkout of mordred-hermes."
        )
        return 1

    print(
        "Building the Secure Enclave signing helper (Swift) — this can take several minutes on first run...",
        flush=True,
    )
    rc, output = _run_sekey_build(src, install_dir=install_dir, unattended=unattended)
    if rc != 0:
        _term.emit_error(f"sekey-helper build failed:\n{output}")
        return 1

    if not _verify_sekey_helper(install_dir=install_dir):
        _term.emit_error(
            "helper installed but the Secure Enclave probe failed; the keyvault will keep using the software fallback."
        )
        return 1

    print(output.strip() or "Secure Enclave helper installed.")

    print(
        "Secure Enclave helper installed and hardware probe succeeded. "
        "Existing wrapping keys remain in their current backend namespace; "
        "a later fresh key creation will use the hardware helper."
    )
    return 0


def cli_enable_se(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault enable-se [--install-dir P]``."""
    install_dir = Path(args.install_dir) if getattr(args, "install_dir", None) else None
    return enable_se(install_dir=install_dir)


# -----------------------------------------------------------------------------
# enable-tpm — build + install the Linux TPM 2.0 helper (v2-OS2 Phase 2c).
#
# The Linux counterpart to enable-se: builds the ``mordred-hermes-tpmkey`` Rust
# helper (``native/tpmkey-helper``) and verifies it. The TPM is Tier 2
# (machine-bound) — the key cannot leave the chip, but there is no per-use
# user-presence gate; helper installers do not expose a key-policy flag.
# Each step is a module-level seam so the orchestration is unit-testable with
# no Rust toolchain and no TPM.
# -----------------------------------------------------------------------------


def _tpm_platform_reason() -> str | None:
    """Return why the TPM helper can't be built here, or ``None`` when it can.

    The ``tss-esapi`` / libtss2 backend is Linux-only (Windows TPM via CNG is a
    separate future helper). A coarse ``Linux`` guard is enough; true TPM
    *presence* is confirmed by the post-install probe.
    """
    import platform

    if platform.system() != "Linux":
        return f"TPM 2.0 keyvault requires Linux (this host is {platform.system() or 'unknown'})"
    return None


def _missing_tpm_build_tools() -> list[str]:
    """Return the build tools (``cargo``) not found on ``PATH``."""
    import shutil

    return [tool for tool in ("cargo",) if shutil.which(tool) is None]


def _locate_tpmkey_source() -> Path | None:
    """Locate the ``tpmkey-helper`` source tree (delegates to ``_seckey_helper``)."""
    from ..keyvault import _seckey_helper

    return _seckey_helper._locate_tpmkey_source()


def _run_tpmkey_build(src: Path, *, install_dir: Path | None) -> tuple[int, str]:
    """Run ``build.sh`` in ``src``; return ``(returncode, combined_output)``.

    ``install_dir`` is forwarded as ``MORDRED_TPMKEY_INSTALL_DIR``. The TPM is
    Tier 2 with no per-use gate, so there is no ``unattended`` env var (cf.
    :func:`_run_sekey_build`).
    """
    import os
    import subprocess

    env = dict(os.environ)
    if install_dir is not None:
        env["MORDRED_TPMKEY_INSTALL_DIR"] = str(install_dir)
    try:
        proc = subprocess.run(
            ["bash", str(src / "build.sh")],
            cwd=str(src),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"failed to run build.sh: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _verify_tpmkey_helper(*, install_dir: Path | None = None) -> bool:
    """Probe the freshly-installed helper to confirm TPM access.

    When ``install_dir`` is given (``enable-tpm --install-dir``), the binary
    just installed there is preferred — ``find_tpmkey_helper`` only searches
    ``MORDRED_TPMKEY_HELPER`` / ``~/.local/bin`` / ``PATH``, so a custom,
    not-on-PATH install dir would otherwise yield a false verification failure.
    """
    from ..keyvault import _seckey_helper

    binary: str | None = None
    if install_dir is not None:
        candidate = install_dir / _seckey_helper._TPM_HELPER_NAME
        if candidate.is_file():
            binary = str(candidate)
    if binary is None:
        binary = _seckey_helper.find_tpmkey_helper()
    if binary is None:
        return False
    try:
        _seckey_helper._HelperSecKeyOps(binary).probe()
        return True
    except Exception:
        return False


def enable_tpm(
    *,
    install_dir: Path | None = None,
    home: Path | None = None,
) -> int:
    """Build + install the TPM helper, then verify it works.

    Returns ``0`` on success, ``1`` on any guard/build/verify failure. Linux
    fails closed when no usable TPM helper exists; there is no software P-256
    fallback. ``home`` is accepted for symmetry with the other keyvault
    commands; the helper resolves its key-blob store from ``HERMES_HOME``
    itself.
    """
    del home  # the helper resolves its store via HERMES_HOME; accepted for symmetry

    reason = _tpm_platform_reason()
    if reason is not None:
        _term.emit_error(reason)
        return 1

    missing = _missing_tpm_build_tools()
    if missing:
        _term.emit_error(
            f"missing build tool(s): {', '.join(missing)}. Install the Rust toolchain first (https://rustup.rs)."
        )
        return 1

    src = _locate_tpmkey_source()
    if src is None:
        _term.emit_error(
            "could not locate the tpmkey-helper sources (native/tpmkey-helper). "
            "Build from a source checkout of mordred-hermes."
        )
        return 1

    print(
        "Building the TPM 2.0 signing helper (Rust) — this can take several minutes on first run...",
        flush=True,
    )
    rc, output = _run_tpmkey_build(src, install_dir=install_dir)
    if rc != 0:
        _term.emit_error(f"tpmkey-helper build failed:\n{output}")
        return 1

    if not _verify_tpmkey_helper(install_dir=install_dir):
        _term.emit_error(
            "helper installed but the TPM probe did not succeed, so no "
            "hardware key is active. On Linux the keyvault fails closed (there is "
            "no software fallback off macOS), so keyvault operations needing a "
            "hardware key error until a working helper is in place. Check that "
            "this host exposes a TPM 2.0 device (/dev/tpmrm0 or /dev/tpm0) and "
            "that your user may access it (commonly membership in the `tss` "
            "group), then re-run `hermes-mordred keyvault enable-tpm`."
        )
        return 1

    print(output.strip() or "TPM 2.0 helper installed.")
    print(
        "TPM 2.0 helper installed and hardware probe succeeded. "
        "Existing TPM-backed keys remain available; keys created later "
        "will use this helper."
    )
    return 0


def cli_enable_tpm(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault enable-tpm [--install-dir P]``.

    The TPM is Tier 2 (machine-bound) with no per-use gate.
    """
    install_dir = Path(args.install_dir) if getattr(args, "install_dir", None) else None
    return enable_tpm(install_dir=install_dir)


# Windows CNG/TPM helper: installation is separate from key provisioning.
def _missing_winkey_build_tools() -> list[str]:
    import shutil

    missing = [name for name in ("cargo", "rustc") if shutil.which(name) is None]
    if shutil.which("powershell.exe") is None and shutil.which("pwsh.exe") is None:
        missing.append("PowerShell")
    return missing


def _locate_winkey_source() -> Path | None:
    """Only this installed package, or its exact editable checkout, may supply source."""
    import importlib.resources

    packaged = Path(str(importlib.resources.files("mordred_hermes"))) / "_native" / "winkey-helper"
    module = Path(__file__).resolve()
    checkout = module.parents[3]
    candidates = [packaged]
    # No unbounded ancestor search: bind native sources to this package's src tree.
    if module == checkout / "src" / "mordred_hermes" / "wizard" / "keyvault_native_cli.py":
        candidates.append(checkout / "native" / "winkey-helper")
    for candidate in candidates:
        if all((candidate / name).is_file() for name in ("build.ps1", "Cargo.toml", "Cargo.lock", "src/main.rs")):
            return candidate
    return None


def _run_winkey_build(src: Path, *, install_dir: Path) -> tuple[int, str]:
    import os
    import shutil
    import subprocess
    import sys

    from .._windows_runtime import scrubbed_environment

    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if powershell is None:
        return 1, "PowerShell executable not found"
    env = scrubbed_environment(os.environ)
    env.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    try:
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                # Applies only to this bound-script child process; no host
                # execution policy is persisted or changed.
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(src / "build.ps1"),
                "-OwnedInstall",
                "-InstallDir",
                str(install_dir),
                "-Python",
                sys.executable,
            ],
            cwd=str(src),
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"winkey-helper build failed: {exc}"
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _verify_winkey_helper(*, install_dir: Path) -> tuple[bool, str]:
    """Probe precisely the newly installed file, never an ambient old helper."""
    from ..keyvault import _seckey_helper

    binary = install_dir / _seckey_helper._WIN_HELPER_NAME
    if not binary.is_file():
        return False, "freshly installed helper is missing"
    try:
        _seckey_helper._HelperSecKeyOps(str(binary)).probe()
    except Exception as exc:
        return False, str(exc)
    return True, ""


def enable_winkey(*, install_dir: Path | None = None, home: Path | None = None) -> int:
    """Build and probe Windows TPM custody under the existing user token."""
    import sys

    from .._home import hermes_home

    if sys.platform != "win32":
        _term.emit_error("Windows CNG TPM helper requires native Windows.")
        return 1
    missing = _missing_winkey_build_tools()
    if missing:
        _term.emit_error(f"missing build tools: {', '.join(missing)}. Install Rust MSVC and Visual C++ Build Tools.")
        return 1
    src = _locate_winkey_source()
    if src is None:
        _term.emit_error("could not locate packaged native/winkey-helper sources; reinstall a source-complete wheel.")
        return 1
    target = install_dir if install_dir is not None else (home if home is not None else hermes_home()) / "bin"
    rc, output = _run_winkey_build(src, install_dir=target)
    if rc:
        _term.emit_error(f"winkey-helper build failed (exit {rc}):\n{output}")
        return 1
    ok, reason = _verify_winkey_helper(install_dir=target)
    if not ok:
        _term.emit_error(f"Windows TPM probe failed: {reason}. No hardware readiness or software fallback is claimed.")
        return 1
    print(
        "Windows TPM helper installed and hardware probe succeeded under the current user token. "
        "Machine-bound custody has no per-use presence; memory encryption requires its own enable flow."
    )
    return 0


def cli_enable_winkey(args: argparse.Namespace) -> int:
    install_dir = Path(args.install_dir) if getattr(args, "install_dir", None) else None
    return enable_winkey(install_dir=install_dir)
