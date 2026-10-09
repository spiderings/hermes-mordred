"""mordred_privacy_check — skill metadata enforcement and audit logging.

Phase 1.1 wires two Hermes hooks:

- ``on_session_start`` — load policy snapshot, run H3 Path B sibling-disable
  detection, emit one-shot ``mordred.degraded.no_origin_skill`` marker.
- ``pre_tool_call`` — generic strict-mode tool-name allowlist (no per-skill
  enforcement available; ``origin_skill`` is absent from the payload — see
  HOOK_PAYLOADS.md §4).

State is loaded lazily on the first hook invocation, so ``register()``
itself stays cheap and side-effect-free at plugin discovery time.
"""

import contextlib

from . import hooks
from ._typing import PluginContext


def register(ctx: PluginContext) -> None:
    """Hermes plugin entry point — wires the two Phase 1 hooks and the network guidance."""
    ctx.register_hook("on_session_start", hooks.on_session_start)
    ctx.register_hook("pre_tool_call", hooks.pre_tool_call)
    register_section = getattr(ctx, "register_system_prompt_section", None)
    if register_section is not None:
        # An older Hermes without prompt sections: the hook still enforces.
        with contextlib.suppress(Exception):
            register_section("mordred.network", hooks.network_prompt_section, max_chars=1200)
