"""``~/.hermes/mordred/credentials/network.json`` writer (Phase 3 PR3a Task #6b).

Persists env-var REFERENCES (not secrets) plus non-secret network settings
(relay country, killswitch toggle). The actual Mullvad account number lives
in ``~/.hermes/.env`` (see :mod:`env_file_writer`); this file just tells the
runtime which env-var name to read.

Contract (PATHS.md §192-§208 "credentials directory"):
- Dir mode 0700, file mode 0600.
- JSON shape::

    {
      "mullvad": {
        "account_id_env": "MORDRED_MULLVAD_ACCOUNT",
        "relay_country": "auto" | "<2-letter>",
        "killswitch": bool
      }
    }

- Atomic write (tempfile + ``os.replace``) via PolicyWriter's pipeline.
- Refuses ``account_id_env`` values that don't look like POSIX env-var
  names -- defence against a configure-time mistake that would persist
  an actual secret in the JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .._config_io import CONFIG_LIMIT, CanonicalPaths, canonical_session
from .._private_fs import PrivateFSError
from .policy_writer import _atomic_write_text, _bounded_utf8, _windows, _write_checked_private

# Same env-name shape rule as env_file_writer -- uppercase, alnum + underscore.
_VALID_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")


@runtime_checkable
class CredentialsWriter(Protocol):
    """Persists per-domain credential metadata (env-var refs + flags)."""

    def write_network(
        self,
        path: Path,
        *,
        mullvad_account_id_env: str,
        mullvad_relay_country: str,
        mullvad_killswitch: bool,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class JSONCredentialsWriter:
    """Production :class:`CredentialsWriter` writing one JSON document.

    Mode 0600 on the file, 0700 on the parent. Idempotent via the byte-
    compare short-circuit in :func:`_atomic_write_text`.
    """

    def write_network(
        self,
        path: Path,
        *,
        mullvad_account_id_env: str,
        mullvad_relay_country: str,
        mullvad_killswitch: bool,
    ) -> None:
        if not _VALID_ENV_NAME.fullmatch(mullvad_account_id_env):
            raise ValueError(
                "refusing to write account_id_env: "
                "must be an uppercase POSIX env-var name (the actual secret "
                "lives in ~/.hermes/.env)"
            )
        body = {
            "mullvad": {
                "account_id_env": mullvad_account_id_env,
                "relay_country": mullvad_relay_country,
                "killswitch": mullvad_killswitch,
            }
        }
        # Pretty-print so a curious user can read it with ``cat``. No
        # sort_keys -- the dict-literal order doubles as the documented field
        # order (account_id_env first, then relay, then flags).
        text = json.dumps(body, indent=2, sort_keys=False) + "\n"
        if _windows():
            data = _bounded_utf8(text, CONFIG_LIMIT)
            if path.name != "network.json" or path.parent.name != "credentials" or path.parent.parent.name != "mordred":
                raise ValueError("credentials must be under canonical home/mordred/credentials")
            published = False
            try:
                with canonical_session(CanonicalPaths(path.parent.parent.parent), scope="policy", create=True):
                    published = _write_checked_private(path, data)
            except PrivateFSError as exc:
                if published:
                    exc.commit_state = "uncertain"
                raise
            return
        # Preserve the existing POSIX directory creation path.
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _atomic_write_text(path, text, mode=0o600)
