"""Default file paths owned or written by the wizard plugin.

Centralises the few constants that ``policy_writer.py``, ``upgrade.py``,
``policy_explainer.py``, ``audit_cli.py``, and ``install_dispatch.py``
all need so they share a single source of truth (and tests can override
via explicit kwargs).

PATHS.md row owners (Phase 1):

- ``~/.hermes/config.yaml``           — read+write (round-trip via ruamel)
- ``~/.hermes/mordred/policy.json``   — sole writer (privacy_check / llm_guard / network read)
- ``~/.hermes/mordred/audit.log``     — wizard READS (privacy_check writes)

OpenClaw legacy base (Story 1.5 migration source, read-only for wizard);
the per-artifact paths under it are derived by ``openclaw_migration`` itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from .._home import HERMES_BASE

DEFAULT_HERMES_CONFIG_PATH: Final = HERMES_BASE / "config.yaml"
DEFAULT_MORDRED_DIR: Final = HERMES_BASE / "mordred"
DEFAULT_POLICY_JSON_PATH: Final = DEFAULT_MORDRED_DIR / "policy.json"
DEFAULT_AUDIT_LOG_PATH: Final = DEFAULT_MORDRED_DIR / "audit.log"

# OpenClaw legacy source (PATHS.md §Migration from legacy OpenClaw paths).
DEFAULT_OPENCLAW_BASE: Final = Path.home() / ".openclaw" / "mordred"
