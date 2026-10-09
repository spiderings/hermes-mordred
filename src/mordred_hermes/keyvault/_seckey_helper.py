"""Subprocess ``_SecKeyOps`` backed by the ad-hoc-signed ``mordred-hermes-sekey`` CLI.

An unsigned / ad-hoc-signed Python interpreter cannot carry the
``keychain-access-groups`` entitlement, so persisting Secure Enclave keys
*in the Keychain* fails with ``errSecMissingEntitlement`` (-34018). The fix
is a small helper binary that Python shells out to: it uses CryptoKit
``SecureEnclave.P256`` and stores the key's ``dataRepresentation`` as a file
(never the Keychain), so no entitlement, provisioning profile, or paid
Developer account is needed — an ad-hoc ``codesign --sign -`` is enough.

This module is the Python half: it locates the helper
(:func:`_find_helper`), drives the JSON-over-stdio protocol
(:func:`_run_helper`), and exposes :class:`_HelperSecKeyOps`, which satisfies
the :class:`mordred_hermes.keyvault._seckey_backend._SecKeyOps` Protocol.

The boundary is identical to the pyobjc ops: every method returns plain
``bytes`` / ``None`` or raises
:class:`mordred_hermes.keyvault._seckey_errors._OpsError` carrying the raw
``OSStatus`` + domain. That lets :class:`_SecKeyBackend`'s existing
error-translation logic (``_translate_error``, ``errSec*`` branches) run
unchanged regardless of whether the SE op went through pyobjc or the helper.

The Swift source and wire protocol live in
``mordred-hermes/native/sekey-helper/`` (see its README).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ._seckey_errors import _OPS_REASONS, _OpsError

# Helper executable name (as installed by native/sekey-helper/build.sh).
_HELPER_NAME = "mordred-hermes-sekey"

# Linux TPM 2.0 helper executable name (native/tpmkey-helper/build.sh). It
# speaks the identical JSON-over-stdio protocol as the Secure-Enclave helper,
# so :class:`_HelperSecKeyOps` drives either one unchanged.
_TPM_HELPER_NAME = "mordred-hermes-tpmkey"

# Windows CNG helper executable name (native/winkey-helper/build script). Same
# JSON-over-stdio protocol as the SE / TPM helpers (CNG Platform Crypto Provider
# / TPM-backed ECDH P-256), so :class:`_HelperSecKeyOps` drives it unchanged.
_WIN_HELPER_NAME = "mordred-hermes-winkey.exe"

# Wall-clock budget for a single helper invocation. Generous because the
# ``ecdh`` command blocks on the Touch ID / passcode system prompt — the user
# must physically approve it. A missing helper or a hung op fails fast enough
# for callers either way.
_TIMEOUT_SECONDS = 120.0


def _find_named_helper(env_var: str, name: str) -> str | None:
    """Locate a helper binary by env override, then ``~/.local/bin``, then PATH.

    The resolution order is identical for every backend helper (Secure
    Enclave, TPM, …) — only the env-var name and binary name differ:

    1. ``env_var`` — an explicit absolute path. When set it is
       authoritative: a missing target yields ``None`` (we do NOT silently
       fall through to the default search, so a typo surfaces as "no helper"
       rather than picking up a different binary).
    2. ``~/.local/bin/<name>`` — the default install location.
    3. ``<name>`` on ``PATH``.
    """
    env = os.environ.get(env_var)
    if env:
        path = Path(env).expanduser()
        return str(path) if path.is_file() else None

    local = Path.home() / ".local" / "bin" / name
    if local.is_file():
        return str(local)

    return shutil.which(name)


def find_sekey_helper() -> str | None:
    """Locate the macOS Secure-Enclave helper (``mordred-hermes-sekey``)."""
    return _find_named_helper("MORDRED_SEKEY_HELPER", _HELPER_NAME)


def find_tpmkey_helper() -> str | None:
    """Locate the Linux TPM 2.0 helper (``mordred-hermes-tpmkey``)."""
    return _find_named_helper("MORDRED_TPMKEY_HELPER", _TPM_HELPER_NAME)


def find_winkey_helper() -> str | None:
    """Locate the native Windows executable in the selected Hermes profile.

    An explicit override is authoritative, including an empty/invalid value.
    Search only absolute PATH entries: Windows executable lookup may otherwise
    implicitly include the current directory or expand PATHEXT to a script.
    Existence and suffix checks are not publisher/authenticity verification;
    the operator must trust the selected installation and PATH directories.
    """
    from mordred_hermes._home import hermes_home

    def executable(path: Path) -> str | None:
        if path.is_absolute() and path.suffix.lower() == ".exe" and path.is_file():
            return str(path)
        return None

    override = os.environ.get("MORDRED_WINKEY_HELPER")
    if override is not None:
        return executable(Path(override).expanduser()) if override else None

    installed = executable(hermes_home() / "bin" / _WIN_HELPER_NAME)
    if installed is not None:
        return installed
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(entry)
        if directory.is_absolute():
            found = executable(directory / _WIN_HELPER_NAME)
            if found is not None:
                return found
    return None


# Back-compat alias: the original Secure-Enclave-only locator. Production
# callers (``_default_ops``, ``probe_capability``) and tests still reference
# ``_find_helper`` / monkeypatch it, so it remains exactly
# ``find_sekey_helper``.
def _find_helper() -> str | None:
    """Deprecated alias for :func:`find_sekey_helper` (back-compat)."""
    return find_sekey_helper()


def _is_native_source(
    candidate: Path,
    *,
    manifest_name: str,
    entry_rel: tuple[str, ...],
    needle: str,
) -> bool:
    """Shared validation core behind the per-backend ``_is_*_source`` checks.

    ``enable_se`` / ``enable_tpm`` *execute* the ``build.sh`` their locator
    resolves to, so matching on ``build.sh`` alone would let a writable
    ancestor (e.g. ``/tmp/native/sekey-helper/build.sh``) hijack the build.
    Require the build manifest (``manifest_name``, containing the expected
    package-name ``needle``) and the entry-point source (``entry_rel``,
    joined onto ``candidate``) too, so a bare planted ``build.sh`` is
    rejected.
    """
    manifest = candidate / manifest_name
    entry = candidate.joinpath(*entry_rel)
    if not ((candidate / "build.sh").is_file() and manifest.is_file() and entry.is_file()):
        return False
    try:
        return needle in manifest.read_text(encoding="utf-8")
    except OSError:
        return False


def _locate_native_source(subdir: str, is_source: Callable[[Path], bool]) -> Path | None:
    """Shared resolution core behind the per-backend ``_locate_*_source`` locators.

    The ``enable-se`` / ``enable-tpm`` ceremonies build their helper from
    source, so they must find the source directory before invoking
    ``build.sh``. Resolution (identical for every backend helper):

    1. **Source checkout** — walk up from this module to a
       ``native/<subdir>`` directory (editable install / repo clone).
    2. **Installed wheel** — a ``_native/<subdir>`` copy shipped inside the
       package (added to the wheel separately; see packaging).

    Each candidate is validated by ``is_source`` so a decoy ``build.sh``
    cannot hijack the build. Returns the directory :class:`~pathlib.Path`,
    or ``None`` when neither is present (e.g. a wheel install without the
    bundled sources).

    The parents-walk anchors on this module's ``__file__``; this helper
    must stay in a module under ``src/mordred_hermes/keyvault/`` or the
    source-checkout resolution silently changes origin.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "native" / subdir
        if is_source(candidate):
            return candidate
    # Installed-wheel fallback: a package-data copy under the package root.
    try:
        from importlib.resources import files

        packaged = Path(str(files("mordred_hermes").joinpath("_native", subdir)))
        if is_source(packaged):
            return packaged
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    return None


def _is_sekey_source(candidate: Path) -> bool:
    """True when ``candidate`` is a genuine ``mordred-hermes-sekey`` Swift package.

    Anti-hijack rationale lives on :func:`_is_native_source`; the Swift
    manifest is ``Package.swift`` and the entry point
    ``Sources/<name>/main.swift``.
    """
    return _is_native_source(
        candidate,
        manifest_name="Package.swift",
        entry_rel=("Sources", _HELPER_NAME, "main.swift"),
        needle=f'name: "{_HELPER_NAME}"',
    )


def _locate_helper_source() -> Path | None:
    """Locate the ``sekey-helper`` Swift source tree (``build.sh`` + sources).

    Resolution order and anti-hijack rationale live on
    :func:`_locate_native_source`; candidates are validated by
    :func:`_is_sekey_source`.
    """
    return _locate_native_source("sekey-helper", _is_sekey_source)


def _is_tpmkey_source(candidate: Path) -> bool:
    """True when ``candidate`` is a genuine ``mordred-hermes-tpmkey`` crate.

    Anti-hijack rationale lives on :func:`_is_native_source`; the Cargo
    manifest is ``Cargo.toml`` and the entry point ``src/main.rs``.
    """
    return _is_native_source(
        candidate,
        manifest_name="Cargo.toml",
        entry_rel=("src", "main.rs"),
        needle=f'name = "{_TPM_HELPER_NAME}"',
    )


def _locate_tpmkey_source() -> Path | None:
    """Locate the ``tpmkey-helper`` Rust source tree (``build.sh`` + Cargo crate).

    Mirror of :func:`_locate_helper_source` for the Linux TPM 2.0 helper
    (``native/tpmkey-helper``); resolution order and anti-hijack rationale
    live on :func:`_locate_native_source`, with candidates validated by
    :func:`_is_tpmkey_source`.
    """
    return _locate_native_source("tpmkey-helper", _is_tpmkey_source)


def _normalize_reason(value: Any) -> str | None:
    """Validate a helper-supplied ``reason`` against the neutral taxonomy.

    Returns the value only when it is a recognised member of
    :data:`mordred_hermes.keyvault._seckey_errors._OPS_REASONS`
    (``NOT_FOUND`` / ``EXISTS`` / ``UNAVAILABLE`` / ``AUTH_DENIED``);
    anything else — including ``None`` or an unknown future reason —
    becomes ``None`` so dispatch falls back to the numeric status. This
    keeps an older client forward-compatible: a helper may add reasons
    without breaking it (it just loses the neutral shortcut).
    """
    return value if isinstance(value, str) and value in _OPS_REASONS else None


def _run_helper(
    binary: str,
    payload: dict[str, Any],
    *,
    env_override: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Invoke the helper once with ``payload`` on stdin, return parsed stdout.

    Raises:
        _OpsError: On spawn failure, timeout, a non-JSON response, a JSON
            ``{"error": {...}}`` object (carrying the helper's raw
            ``status``/``domain``), or a non-zero exit without an error
            object. ``domain="helper"`` (with ``status=-1``) marks failures
            originating in this bridge rather than in Security.framework, so
            ``_translate_error`` maps them to the conservative
            ``auth_failed`` default. The non-JSON and non-zero-exit messages
            include a truncated ``proc.stderr`` snippet alongside the
            existing ``proc.stdout`` snippet, since the helper prints its
            real failure cause to stderr.
    """
    try:
        env = None
        if env_override is not None:
            env = dict(os.environ)
            env[env_override[0]] = env_override[1]
        proc = subprocess.run(
            [binary],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            timeout=_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise _OpsError(-1, "helper", f"helper timed out after {_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise _OpsError(-1, "helper", f"failed to spawn helper {binary!r}: {exc}") from exc

    # ``proc.stderr`` is where the Swift/Rust helper prints its real
    # failure cause (Security.framework message, panic text, etc.) — the
    # ``{"error": {...}}`` JSON-on-stdout path already carries that detail
    # structurally, but the two failure modes below (non-JSON stdout,
    # non-zero exit with no error object) previously discarded stderr
    # entirely, leaving only a stdout snippet (usually ``b''``) and the
    # return code to diagnose a production helper failure. Truncated to a
    # modest length and folded into the exception message only — never
    # logged at INFO+ — mirroring the existing stdout-snippet policy.
    # The truncation only bounds message size; it is NOT redaction (anything
    # sensitive the helper prints would be at the START of stderr). The helper
    # is trusted not to print secrets to stderr; this is a diagnostics aid.
    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        stdout_snippet = proc.stdout[:200]
        stderr_snippet = proc.stderr[:200]
        raise _OpsError(
            -1,
            "helper",
            f"helper returned non-JSON (exit {proc.returncode}): stdout={stdout_snippet!r} stderr={stderr_snippet!r}",
        ) from exc

    if not isinstance(response, dict):
        raise _OpsError(-1, "helper", f"helper returned non-object JSON: {response!r}")

    if "error" in response:
        error = response["error"]
        if not isinstance(error, dict):
            raise _OpsError(-1, "helper", "helper returned an invalid error object")
        status = error.get("status", -1)
        if not isinstance(status, int) or isinstance(status, bool):
            raise _OpsError(-1, "helper", "helper returned an invalid error status")
        raise _OpsError(
            status,
            str(error.get("domain", "helper")),
            str(error.get("message", "")),
            reason=_normalize_reason(error.get("reason")),
        )

    if proc.returncode != 0:
        stderr_snippet = proc.stderr[:200]
        raise _OpsError(
            -1,
            "helper",
            f"helper exited {proc.returncode} without an error object; stderr={stderr_snippet!r}",
        )

    return response


def _hex_field(response: dict[str, Any], key: str) -> bytes:
    """Decode a hex-encoded field from a success response.

    A trusted helper always returns the documented field, but a malformed
    value must still surface as :class:`_OpsError` (not a raw
    ``KeyError``/``ValueError``) so the ops boundary contract holds: every
    failure is an ``_OpsError``.
    """
    try:
        return bytes.fromhex(response[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise _OpsError(-1, "helper", f"helper response missing or invalid {key!r}") from exc


class _HelperSecKeyOps:
    """``_SecKeyOps`` implementation that delegates to the signed CLI.

    One method call == one helper process invocation (the protocol is
    request/response per process). Tags and peer public keys cross the
    boundary as hex; the cleartext ``key_id`` never does (the tag is a
    SHA-256 prefix derived in :mod:`_seckey_errors`).
    """

    def __init__(
        self,
        binary: str,
        *,
        env_override: tuple[str, str] | None = None,
    ) -> None:
        self._binary = binary
        self._env_override = env_override

    def with_store_override(self, env_name: str, store: Path) -> _HelperSecKeyOps:
        """Clone this helper ops with an explicit per-keyvault blob store."""

        return _HelperSecKeyOps(
            self._binary,
            env_override=(env_name, os.fspath(store)),
        )

    def _invoke(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Invoke while preserving the historical two-argument seam."""

        if self._env_override is None:
            return _run_helper(self._binary, payload)
        return _run_helper(
            self._binary,
            payload,
            env_override=self._env_override,
        )

    def create_keypair(self, tag: bytes, label: str, *, unattended: bool = False) -> bytes:
        response = self._invoke(
            {"cmd": "generate", "tag_hex": tag.hex(), "label": label, "unattended": unattended},
        )
        return _hex_field(response, "public_key_hex")

    def copy_public_key(self, tag: bytes) -> bytes:
        response = self._invoke({"cmd": "public_key", "tag_hex": tag.hex()})
        return _hex_field(response, "public_key_hex")

    def delete_key(self, tag: bytes) -> None:
        # Acknowledge deletion or confirmed absence; ambiguous native state refuses.
        response = self._invoke({"cmd": "delete", "tag_hex": tag.hex()})
        if response.get("ok") is not True:
            raise _OpsError(-1, "helper", "helper did not acknowledge deletion")

    def key_exchange(self, tag: bytes, peer_pub: bytes) -> bytes:
        response = self._invoke(
            {"cmd": "ecdh", "tag_hex": tag.hex(), "peer_pub_hex": peer_pub.hex()},
        )
        return _hex_field(response, "shared_hex")

    def probe(self) -> None:
        response = self._invoke({"cmd": "probe"})
        if response.get("ok") is not True:
            raise _OpsError(-1, "helper", "helper did not pass the probe")


def _helper_ops_or_none(find: Callable[[], str | None]) -> _HelperSecKeyOps | None:
    """Locate a helper binary via ``find`` and wrap it, or ``None`` when absent.

    Centralizes the "``None`` means not installed" construction shared by
    every platform branch in ``_seckey_backend`` (ops selection and
    capability probing). Callers decide what an absent helper means — fall
    back (macOS pyobjc) or fail closed (Linux / Windows). ``find`` is passed
    as a callable and invoked here, so call sites that spell it
    ``_seckey_helper._find_helper`` resolve the module attribute at call
    time and tests monkeypatching the finder still intercept.
    """
    binary = find()
    if binary is None:
        return None
    return _HelperSecKeyOps(binary)
