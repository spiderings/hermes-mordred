"""``mordred-local`` synthetic Hermes provider.

Declarative ``ProviderProfile`` subclass that points at a local OpenAI-
compatible endpoint (LM Studio / Ollama / vLLM). Hermes' core HTTP transport
talks to the configured ``base_url`` directly: ``ProviderProfile`` is
declarative and Hermes owns the streaming pipeline, so Mordred does not ship a
separate streaming wrapper.

Registration is **explicit** (Codex B1). ``register_mordred_local()`` is
called from ``llm_guard/__init__.py`` inside ``register(ctx)``; the upstream
``providers._discover_providers()`` scanner does not find entry-point
plugins, so a module-import side effect would never land the profile in
the registry.

Phase 2 fields are read from ``~/.hermes/mordred/policy.json``
(``local_llm_endpoint`` / ``local_llm_model_id``). The wizard
(``mordred_hermes.wizard.configure``) is the sole writer; this module is
read-only.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Final

from providers import register_provider
from providers.base import ProviderProfile

from .._home import HERMES_BASE
from .._policy_io import load_policy_mapping

_LOG = logging.getLogger("mordred.llm_guard.local_adapter")

DEFAULT_POLICY_JSON_PATH: Final[Path] = HERMES_BASE / "mordred" / "policy.json"
DEFAULT_LOCAL_ENDPOINT: Final[str] = "http://localhost:1234/v1"
# Single source of truth for the synthetic provider's registry name.
# ``enforce._LOCAL_PROVIDER_NAME`` re-exports this so the strict-mode
# decision matrix can route on the same identifier without a duplicated
# string literal (review LOW finding #2).
LOCAL_PROVIDER_NAME: Final[str] = "mordred-local"


# mypy --strict ``disallow_subclassing_any`` cannot tell that the upstream
# ``providers.base.ProviderProfile`` is a real dataclass because the
# ``providers`` module is ``ignore_missing_imports`` in pyproject.toml.
# Subclassing is the documented integration point for new provider profiles
# (see ``providers/__init__.py`` docstring), so suppress just this site.
class MordredLocalProfile(ProviderProfile):  # type: ignore[misc]
    """``mordred-local`` profile — OpenAI chat-completions wire to local URL."""


def build_mordred_local_profile(
    *,
    policy_json_path: Path = DEFAULT_POLICY_JSON_PATH,
) -> MordredLocalProfile:
    """Construct (but do not register) the ``mordred-local`` profile.

    Reads ``policy.json`` for the configured endpoint; falls back to
    :data:`DEFAULT_LOCAL_ENDPOINT` when the file is absent or malformed.
    Tests call this directly to inspect the profile without touching the
    process-wide provider registry.
    """
    endpoint = _read_endpoint(policy_json_path)
    return MordredLocalProfile(
        name=LOCAL_PROVIDER_NAME,
        api_mode="chat_completions",
        display_name="Mordred Local",
        description="Local OpenAI-compatible endpoint enforced by mordred_llm_guard",
        env_vars=(),
        base_url=endpoint,
    )


def register_mordred_local(
    *,
    policy_json_path: Path = DEFAULT_POLICY_JSON_PATH,
) -> MordredLocalProfile:
    """Register the ``mordred-local`` profile with the Hermes provider registry.

    Idempotent: re-invocation is safe (upstream ``register_provider`` is
    last-writer-wins). Returns the registered profile so callers can
    inspect ``base_url`` etc.

    Called from ``mordred_hermes.llm_guard.register(ctx)``. Tests call it
    directly with a synthetic ``policy_json_path``.
    """
    profile = build_mordred_local_profile(policy_json_path=policy_json_path)
    register_provider(profile)
    _LOG.debug("registered mordred-local provider with base_url=%s", profile.base_url)
    return profile


def _read_endpoint(policy_json_path: Path) -> str:
    """Read ``local_llm_endpoint`` from ``policy.json`` with safe fallback."""
    data = load_policy_mapping(policy_json_path, log=_LOG)
    endpoint = data.get("local_llm_endpoint")
    if isinstance(endpoint, str) and endpoint:
        return endpoint
    return DEFAULT_LOCAL_ENDPOINT
