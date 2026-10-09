"""Make the ``mordred_hermes`` package importable when the suite runs without an
editable install. In CI the package is installed (``pip install -e .``); locally
this adds the plugin's ``src`` root to the path so ``mordred_hermes.extension.*``
resolves either way."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# tests/extension/conftest.py -> repo root is two levels up; the package lives
# under ``src`` in this plugin-only layout.
_SRC = Path(__file__).resolve().parents[2] / "src"
if _SRC.exists() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))


@pytest.fixture(autouse=True)
def _memory_encryption_on(request, monkeypatch):
    """Telegram requires sealed agent memory; tests opt out with @pytest.mark.memory_plain."""
    if request.node.get_closest_marker("memory_plain"):
        return
    try:
        from mordred_hermes.extension.telegram import memory_guard
    except ImportError:
        return
    monkeypatch.setattr(memory_guard, "memory_encryption_active", lambda home=None: True)
