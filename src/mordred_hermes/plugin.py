"""``mordred`` — the single Hermes entry-point plugin for the whole Mordred bundle.

Hermes lists and gates plugins by entry-point name, so Mordred registers once
(``hermes_agent.plugins``: ``mordred = "mordred_hermes.plugin"``) and this
module's :func:`register` wires every component in a fixed order:

1. ``keyvault``      — agent-memory seam first, then the at-rest ``.env``
                        decrypt shim, so vault secrets are in ``os.environ``
                        before any other component reads the environment.
2. ``llm_guard``     — loopback proxy bypass, the ``mordred-local`` profile,
                        auxiliary-client guards, session / request enforcement.
3. ``network``       — the process-wide Tor / VPN / clearnet route and hooks.
4. ``privacy_check`` — tool-call policy and the session-start integrity gate.
5. ``e2e``           — encrypted gateway dispatch, outbound re-encryption and
                        the read-only Telegram tools.
6. ``wizard``        — the ``hermes mordred`` CLI subcommand.

Components 1-4 and 6 keep the relative order they had as separate plugins
(Hermes loaded those alphabetically: keyvault, llm_guard, network,
privacy_check, wizard). ``e2e`` used to load first only because its old name
sorted first; it now loads after the runtime guards it relies on.

Failure semantics match the six-plugin layout:

* The sibling-integrity gate (``check_plugin_integrity``) is registered first,
  once, before any component. Components that register the very same callback
  are deduplicated. A failure here propagates.
* A ``BaseException`` from a component (Mordred's deliberate fail-closed
  refusals, ``SystemExit``) propagates exactly as before.
* An ordinary ``Exception`` from one component used to fail only that plugin:
  Hermes disposed its registrations and the others kept running, and the
  integrity gate reported it at session start (strict: refuse; lenient/off:
  warn). The same is done here per component: its registrations are disposed,
  the failure is recorded (:func:`component_errors`), the other components
  still register, and the gate reports the failed component.
"""

from __future__ import annotations

import importlib
import logging
import threading
from collections.abc import Callable
from typing import Any, Final

from ._plugin_identity import PLUGIN_NAME

__all__ = [
    "COMPONENTS",
    "COMPONENT_REQUIRED_HOOKS",
    "PLUGIN_NAME",
    "component_errors",
    "component_hooks",
    "register",
]

_LOG = logging.getLogger("mordred.plugin")

#: ``(component id, module)`` in registration order. Each module exposes ``register(ctx)``.
COMPONENTS: Final[tuple[tuple[str, str], ...]] = (
    ("keyvault", "mordred_hermes.keyvault"),
    ("llm_guard", "mordred_hermes.llm_guard"),
    ("network", "mordred_hermes.network"),
    ("privacy_check", "mordred_hermes.privacy_check"),
    ("e2e", "mordred_hermes.extension.gateway_plugin"),
    ("wizard", "mordred_hermes.wizard"),
)

#: Minimum hook surface each component promises. The integrity gate checks it
#: per component (recorded here) and, as a union, against Hermes's own ledger
#: for the ``mordred`` plugin. The wizard is CLI-only.
COMPONENT_REQUIRED_HOOKS: Final[dict[str, frozenset[str]]] = {
    "keyvault": frozenset({"on_session_start", "on_session_end"}),
    "llm_guard": frozenset({"on_session_start", "pre_api_request"}),
    "network": frozenset({"on_session_start", "on_session_end", "pre_api_request", "pre_tool_call"}),
    "privacy_check": frozenset({"on_session_start", "pre_tool_call"}),
    "e2e": frozenset({"on_session_start", "pre_gateway_dispatch"}),
    "wizard": frozenset(),
}

_STATE_LOCK = threading.Lock()
_component_errors: dict[str, str] = {}
_component_hooks: dict[str, frozenset[str]] = {}


def component_errors() -> dict[str, str]:
    """Components whose ``register`` raised an ordinary exception in the latest pass."""
    with _STATE_LOCK:
        return dict(_component_errors)


def component_hooks() -> dict[str, frozenset[str]]:
    """Hook names each successfully registered component holds (latest pass).

    A component that registered a callback already registered by the bundle
    (the shared integrity gate) is credited with that hook too.
    """
    with _STATE_LOCK:
        return dict(_component_hooks)


class _ComponentContext:
    """Per-component view of Hermes's ``PluginContext``.

    Forwards everything to the real context, and additionally:

    * skips a ``register_hook`` whose ``(hook, callback)`` pair the bundle has
      already registered in this pass (one plugin must not run the same
      callback twice per event);
    * keeps the registration handles Hermes returns, so a component that fails
      part-way can be unwound like a failed plugin used to be.
    """

    def __init__(self, ctx: Any, seen_hooks: set[tuple[str, int]]) -> None:
        self._ctx = ctx
        self._seen_hooks = seen_hooks
        self.handles: list[Any] = []
        self.hooks: set[str] = set()
        self._own_hook_keys: set[tuple[str, int]] = set()

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> Any:
        key = (hook_name, id(callback))
        if key in self._seen_hooks:
            self.hooks.add(hook_name)
            return None
        handle = self._ctx.register_hook(hook_name, callback)
        self._seen_hooks.add(key)
        self._own_hook_keys.add(key)
        self.hooks.add(hook_name)
        self.handles.append(handle)
        return handle

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._ctx, name)
        if not name.startswith("register_") or not callable(attr):
            return attr

        def tracked(*args: Any, **kwargs: Any) -> Any:
            handle = attr(*args, **kwargs)
            self.handles.append(handle)
            return handle

        return tracked

    def dispose(self) -> None:
        """Release what this component registered (best-effort, newest first)."""
        for handle in reversed(self.handles):
            dispose = getattr(handle, "dispose", None)
            if callable(dispose):
                try:
                    dispose()
                except Exception:
                    _LOG.debug("disposing a failed component's registration raised", exc_info=True)
        self.handles.clear()
        self.hooks.clear()
        # A later component registering the same callback must not be skipped
        # as a duplicate of a registration that no longer exists.
        self._seen_hooks.difference_update(self._own_hook_keys)
        self._own_hook_keys.clear()


def register(ctx: Any) -> None:
    """Hermes plugin entry point for ``mordred`` — see the module docstring."""
    from .privacy_check.hooks import check_plugin_integrity

    with _STATE_LOCK:
        _component_errors.clear()
        _component_hooks.clear()

    # First and outside any containment: every later session-start callback
    # runs behind the integrity gate, and failing to install it fails the plugin.
    ctx.register_hook("on_session_start", check_plugin_integrity)
    seen_hooks: set[tuple[str, int]] = {("on_session_start", id(check_plugin_integrity))}

    for component, module_name in COMPONENTS:
        view = _ComponentContext(ctx, seen_hooks)
        try:
            module = importlib.import_module(module_name)
            module.register(view)
        except Exception as exc:
            view.dispose()
            message = f"{type(exc).__name__}: {exc}"
            with _STATE_LOCK:
                _component_errors[component] = message
            _LOG.error("Mordred component %r failed to register: %s", component, message, exc_info=True)
            continue
        with _STATE_LOCK:
            _component_hooks[component] = frozenset(view.hooks)

    # Hermes Desktop: keep the setup page in place whatever installed Mordred
    # (installer, the agent itself, plain pip). Best-effort; a no-op when the
    # files are current, and never touches config.yaml.
    try:
        from .desktop.install import ensure_page

        ensure_page()
    except Exception as exc:
        _LOG.warning("Mordred desktop page not placed: %s", type(exc).__name__)
