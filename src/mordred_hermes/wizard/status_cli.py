"""``hermes-mordred status`` — the at-a-glance Mordred dashboard.

UX review 2026-06-11: Mordred state was scattered over five read commands
(``network status`` / ``encryption status`` / ``vault status`` /
``keyvault list`` / ``policy show``). This module aggregates the answer
to "how am I protected right now?" into one screen:

- **policy**     — the active policy mode (same source as the install hook).
- **network**    — configured default path, plus live runtime state when one
  is registered in this process.
- **keyvault**   — initialised?, key count, hardware-helper presence.
- **encryption** — the four at-rest targets via
  :func:`mordred_hermes.wizard.encryption_cli.collect_status`.

Side-effect-free by the same contract as ``encryption status``: never
prompts, never opens the vault cold path, never touches the Secure
Enclave or TPM — on-disk reads and PATH lookups only. Heavy imports stay
function-local so the module imports on any platform.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .._home import hermes_home as _hermes_home
from .._policy_io import (
    policy_transaction_marker_for_config,
    policy_transaction_warning,
)
from ..keyvault._identity import resolve_root
from . import _term
from .encryption_cli import (
    EXPOSED_LEGEND_BODY,
    STATUS_LEGEND_BODY,
    WORKSPACE_LEGEND_BODY,
    TargetStatus,
    WorkspacePaths,
    _default_workspace_paths,
    collect_status,
    status_mark,
    style_mark,
)

__all__ = [
    "StatusReport",
    "cli_status",
    "collect",
    "render_json",
    "render_text",
    "status",
]

_LOG = logging.getLogger("mordred.wizard.status_cli")

_POLICY_MODE_DETAILS = {
    "strict": "blocks on policy violations",
    "lenient": "warns and audits; continues",
    "off": "guards disabled",
}

#: Resolve the platform hardware-helper binary, or None. Injected in tests.
HelperFinder = Callable[[str], str | None]


@dataclass(frozen=True)
class StatusReport:
    """Aggregated, side-effect-free snapshot of Mordred's protection state."""

    policy_mode: str
    network_configured_path: str
    network_live: bool
    network_active_path: str | None
    network_ready: bool | None
    keyvault_initialized: bool
    keyvault_key_count: int
    keyvault_helper_installed: bool
    keyvault_detail: str
    encryption: list[TargetStatus]

    def to_dict(self) -> dict[str, object]:
        return {
            "policy": {"mode": self.policy_mode},
            "network": {
                "configured_path": self.network_configured_path,
                "live": self.network_live,
                "active_path": self.network_active_path,
                "ready": self.network_ready,
            },
            "keyvault": {
                "initialized": self.keyvault_initialized,
                "key_count": self.keyvault_key_count,
                "helper_installed": self.keyvault_helper_installed,
                "detail": self.keyvault_detail,
            },
            "encryption": [s.to_dict() for s in self.encryption],
        }


# -----------------------------------------------------------------------------
# Section collectors — each reads on-disk state only and never raises.
# -----------------------------------------------------------------------------
def _policy_mode(home: Path) -> str:
    """The active policy mode, from the same source the install hook uses."""
    from ..privacy_check._runtime import get_active_policy_mode

    return str(get_active_policy_mode(config_path=home / "config.yaml"))


def _network_state(home: Path) -> tuple[str, bool, str | None, bool | None]:
    """(configured_path, live, active_path, ready) without bringing anything up."""
    from ..network import api
    from ..network._exceptions import MordredNetworkError
    from ..network.settings import read_default_path

    # log= must be passed: with ``log=None`` the shared YAML loader swallows
    # the malformed-config warning entirely and corrupted config.yaml would
    # silently render as the clearnet default (review 2026-07-29).
    configured = read_default_path(home / "config.yaml", log=_LOG)
    try:
        live_status = api.status()
    except MordredNetworkError:
        return configured, False, None, None
    return configured, True, live_status.active_path, live_status.ready


def _keyvault_state(home: Path) -> tuple[bool, int, str]:
    """(initialized, key_count, detail) from meta.json — no backend, no prompt."""
    from ..keyvault import _native_key_id, _storage

    root = _storage.resolve_keyvault_dir(home)
    try:
        with _storage.keyvault_read_lock(root) as profile_present:
            if not profile_present:
                return False, 0, "not initialised"
            _storage.assert_keyvault_active(root)
            meta = _storage.load_meta(root)
    except _storage.KeyvaultCorruptError as exc:
        return False, 0, f"meta.json corrupt — {exc}"
    except OSError as exc:  # KeyvaultPermissionError (bad mode / not a regular file)
        return False, 0, f"keyvault unreadable — {exc}"
    count = len(meta.get("keys", {}))
    if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
        return False, 0, "incomplete native-key provisioning — reset required"
    if count == 0:
        return False, 0, "not initialised"
    detail = f"{count} key" + ("" if count == 1 else "s")
    # No canonical home->audit-log-path helper exists to reuse: every
    # existing ``DEFAULT_AUDIT_PATH`` (privacy_check._runtime,
    # network/__init__, llm_guard/__init__) is a module-global tied to the
    # real ``HERMES_BASE``, not parameterized by an arbitrary ``home`` — a
    # bad fit for a status collector that must stay confined to whatever
    # ``home`` it was given (e.g. a test's ``tmp_path``). The layout itself
    # is established by :func:`_audit_support.build_audit_writer` ("The
    # default log is ``<HERMES_BASE>/mordred/audit.log``") and mirrored by
    # ``keyvault._storage.resolve_keyvault_dir``'s sibling ``mordred`` dir.
    audit_path = home / "mordred" / "audit.log"
    return True, count, f"{detail}{_audit_key_detail(meta, audit_path)}"


def _is_legacy_audit_profile(meta: Mapping[str, object]) -> bool:
    """True if ``meta`` predates a9's profile-scoped native key ids.

    Mirrors :func:`privacy_check.audit._select_audit_native_key`'s legacy
    test: exactly one key row, and that row carries no
    ``NATIVE_KEY_ID_FIELD``. Malformed metadata (missing/wrong-shaped
    ``keys``) defensively reads as "not legacy" rather than raising —
    a legacy misclassification just falls through to the ordinary
    "no audit wrapping key" branch below, which is already correct for a
    scoped profile.
    """
    from ..keyvault import _native_key_id

    keys = meta.get("keys")
    if not isinstance(keys, Mapping) or len(keys) != 1:
        return False
    (row,) = keys.values()
    if not isinstance(row, Mapping):
        return False
    return _native_key_id.NATIVE_KEY_ID_FIELD not in row


def _audit_log_is_mral_encrypted(audit_path: Path) -> bool:
    """Best-effort read of the audit log's own header — never raises.

    Only used for the legacy-profile branch, where meta.json carries no
    audit-key metadata at all and so cannot prove either outcome (see
    :func:`_audit_key_detail`). The MRAL wire format's line 0 is a JSON
    header with ``fmt == MAGIC``; a plaintext NDJSON log's first line never
    carries that field. A missing file, permission error, empty file,
    non-JSON first line, or a huge/binary blob must all resolve to "not
    encrypted" — this reads at most a few KB, never the whole file, and
    never raises into ``status``'s never-raise contract.
    """
    from .._audit_io import read_first_line
    from ..keyvault.log_encryption import MAGIC

    try:
        first_line = read_first_line(audit_path, limit=4096)
    except OSError:
        return False
    if not first_line or first_line[:1] != b"{":
        return False
    try:
        header = json.loads(first_line)
    except ValueError:  # JSONDecodeError / UnicodeDecodeError both subclass it
        return False
    return isinstance(header, dict) and header.get("fmt") == MAGIC.decode("ascii")


def _audit_key_detail(meta: Mapping[str, object], audit_path: Path) -> str:
    """Describe audit-log encryption state, which is otherwise invisible.

    A keyvault whose audit wrapping key never committed still reports as a
    healthy N-key vault while ``make_audit_writer`` silently falls back to
    plaintext NDJSON. The stranded pending-without-committed case is worse than
    "not provisioned": provisioning refuses to adopt a native key of unproven
    durability, so every retry re-refuses and the audit log stays plaintext
    permanently.

    A legacy profile (pre-a9, no profile-scoped native key ids) never gets
    ``AUDIT_KEY_FIELD``/``PENDING_AUDIT_KEY_FIELD`` written at all — those are
    only written by ``wizard._keyvault_init`` — even though
    ``privacy_check.audit.make_audit_writer`` resolves the legacy global audit
    key and encrypts normally for it. Claiming "plaintext" there would be a
    false negative and claiming "encrypted" unconditionally would be a false
    *positive* (the legacy key has a real history of becoming unusable with a
    silent plaintext fallback), so that branch alone falls back to reading
    what the audit log file itself shows. Presence/file checks only — this
    must never raise from ``status``.
    """
    from ..keyvault import _native_key_id

    committed = _native_key_id.AUDIT_KEY_FIELD in meta
    pending = _native_key_id.PENDING_AUDIT_KEY_FIELD in meta
    if committed:
        return "; audit log encrypted"
    if pending:
        return (
            "; audit-log encryption INCOMPLETE — a previous provisioning attempt was "
            "interrupted, retries will not recover it, and the audit log stays plaintext"
        )
    if _is_legacy_audit_profile(meta):
        if _audit_log_is_mral_encrypted(audit_path):
            return "; audit log encrypted (legacy key)"
        return "; audit log plaintext"
    return "; audit log plaintext (no audit wrapping key)"


def _default_helper_finder(platform: str) -> str | None:
    """Locate the installed hardware-helper binary for this OS (PATH/file lookup only)."""
    from ..keyvault import _seckey_helper

    if platform == "darwin":
        return _seckey_helper._find_helper()
    if platform.startswith("linux"):
        return _seckey_helper.find_tpmkey_helper()
    if platform == "win32":
        return _seckey_helper.find_winkey_helper()
    return None


# -----------------------------------------------------------------------------
# Aggregation + rendering
# -----------------------------------------------------------------------------
def collect(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    on_path: Callable[[str], bool] | None = None,
    helper_finder: HelperFinder | None = None,
) -> StatusReport:
    finder = helper_finder if helper_finder is not None else _default_helper_finder
    # status never raises: the helper lookup walks PATH and the home dir,
    # either of which can blow up in odd environments (e.g. Path.home()
    # RuntimeError in a container with no passwd entry) — degrade to
    # "not installed" instead (review 2026-06-12).
    try:
        helper_installed = finder(platform) is not None
    except Exception:
        helper_installed = False
    configured, live, active_path, ready = _network_state(home)
    kv_initialized, kv_count, kv_detail = _keyvault_state(home)
    return StatusReport(
        policy_mode=_policy_mode(home),
        network_configured_path=configured,
        network_live=live,
        network_active_path=active_path,
        network_ready=ready,
        keyvault_initialized=kv_initialized,
        keyvault_key_count=kv_count,
        keyvault_helper_installed=helper_installed,
        keyvault_detail=kv_detail,
        encryption=collect_status(home=home, root=root, platform=platform, workspace=workspace, on_path=on_path),
    )


def render_text(report: StatusReport, *, color: bool = False) -> str:
    policy_detail = _POLICY_MODE_DETAILS.get(report.policy_mode)
    policy = f"{report.policy_mode} ({policy_detail})" if policy_detail else report.policy_mode
    if report.network_live:
        ready = "ready" if report.network_ready else "not ready"
        network = f"{report.network_active_path} (live, {ready})"
    else:
        network = f"{report.network_configured_path} (configured; runtime not active in this process)"
    helper = "hardware helper installed" if report.keyvault_helper_installed else "no hardware helper"
    if report.keyvault_initialized:
        keyvault = f"initialised ({report.keyvault_detail}; {helper})"
    else:
        keyvault = f"{report.keyvault_detail} ({helper})"
    lines = [
        _term.heading("Mordred status:", enabled=color),
        f"  policy mode : {policy}",
        f"  network     : {network}",
        f"  keyvault    : {keyvault}",
        "  encryption  :",
    ]
    width = max((len(s.target) for s in report.encryption), default=0)
    marks = [status_mark(s) for s in report.encryption]
    mark_w = max((len(m) for m in marks), default=0)
    for s, mark in zip(report.encryption, marks, strict=True):
        cell = style_mark(mark, mark.ljust(mark_w), enabled=color)
        lines.append(f"    {s.target.ljust(width)}  [{cell}]  {s.detail}")
    if "exposed" in marks:
        lines.append(_term.hint(f"    alert: {EXPOSED_LEGEND_BODY}", enabled=color))
    if "paused" in marks:
        lines.append(_term.hint(f"    legend: {STATUS_LEGEND_BODY}", enabled=color))
    if "sealed" in marks or "open" in marks:
        lines.append(_term.hint(f"    workspace: {WORKSPACE_LEGEND_BODY}", enabled=color))
    return "\n".join(lines)


def render_json(report: StatusReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def status(
    *,
    home: Path,
    root: Path,
    platform: str,
    workspace: WorkspacePaths,
    as_json: bool = False,
    on_path: Callable[[str], bool] | None = None,
    helper_finder: HelperFinder | None = None,
) -> int:
    """Print the aggregated report. Always returns 0 (read-only).

    An interrupted policy write is warned about on stderr first: it silently
    forces every reader closed to strict mode, and ``status`` is where an
    operator looks when providers suddenly start refusing.
    """
    pending = policy_transaction_warning(policy_transaction_marker_for_config(home / "config.yaml"))
    if pending is not None:
        _term.emit_warn(pending)
    report = collect(
        home=home,
        root=root,
        platform=platform,
        workspace=workspace,
        on_path=on_path,
        helper_finder=helper_finder,
    )
    if as_json:
        print(render_json(report))
    else:
        print(render_text(report, color=_term.should_color(sys.stdout)))
    return 0


# -----------------------------------------------------------------------------
# CLI adapter wired in cli.py
# -----------------------------------------------------------------------------
def cli_status(args: argparse.Namespace) -> int:
    """argparse handler for ``status [--json]`` — resolves production defaults."""
    home = _hermes_home()
    return status(
        home=home,
        root=resolve_root(None),
        platform=sys.platform,
        workspace=_default_workspace_paths(),
        as_json=bool(getattr(args, "json", False)),
    )
