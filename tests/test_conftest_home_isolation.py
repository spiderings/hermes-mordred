"""Regression test for the root conftest.py self-isolation guard.

Confirms the whole suite imported ``mordred_hermes`` against the throwaway
``HERMES_HOME`` set by ``tests/conftest.py`` (or an explicit override), never
against the developer's real ``~/.hermes``.
"""

from __future__ import annotations

import os
from pathlib import Path

import mordred_hermes._home as _home


def test_hermes_base_matches_env_hermes_home_not_the_real_dotfile_home() -> None:
    assert "HERMES_HOME" in os.environ

    expected = Path(os.environ["HERMES_HOME"]).resolve()
    assert _home.HERMES_BASE.resolve() == expected
    assert _home.HERMES_BASE.resolve() != (Path.home() / ".hermes").resolve()
    # Deliberately no ``is_dir()`` check: an explicit ``HERMES_HOME`` (CI pins
    # one) need not exist yet — only the conftest-created default does.
