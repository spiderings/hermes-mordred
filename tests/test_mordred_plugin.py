"""The single ``mordred`` Hermes plugin (``mordred_hermes.plugin``).

Pins the load order, the de-duplication of the shared integrity hook, and the
failure semantics carried over from the six-plugin layout: a component's
ordinary exception is contained (and reported by the integrity gate), a
``BaseException`` refusal propagates.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

import pytest

from mordred_hermes import plugin
from mordred_hermes.privacy_check.hooks import check_plugin_integrity


class _Handle:
    def __init__(self, ctx: _FakeContext, entry: tuple[str, str, Any]) -> None:
        self._ctx = ctx
        self._entry = entry

    def dispose(self) -> None:
        if self._entry in self._ctx.registrations:
            self._ctx.registrations.remove(self._entry)


class _FakeContext:
    """Records registrations in order; handles can dispose them like Hermes's ledger."""

    def __init__(self) -> None:
        self.registrations: list[tuple[str, str, Any]] = []

    def _add(self, kind: str, key: str, value: Any) -> _Handle:
        entry = (kind, key, value)
        self.registrations.append(entry)
        return _Handle(self, entry)

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> _Handle:
        return self._add("hook", hook_name, callback)

    def register_cli_command(self, name: str, **_kwargs: Any) -> _Handle:
        return self._add("cli", name, None)

    def hooks(self, name: str) -> list[Any]:
        return [value for kind, key, value in self.registrations if kind == "hook" and key == name]


def _component(name: str, calls: list[str], body: Callable[[Any], None] | None = None) -> ModuleType:
    module = ModuleType(f"_fake_mordred_{name}")

    def register(ctx: Any) -> None:
        calls.append(name)
        if body is not None:
            body(ctx)

    module.register = register  # type: ignore[attr-defined]
    return module


@pytest.fixture
def fake_components(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., list[str]]]:
    installed: list[str] = []

    def install(**bodies: Callable[[Any], None] | None) -> list[str]:
        calls: list[str] = []
        components = []
        for name, body in bodies.items():
            module = _component(name, calls, body)
            sys.modules[module.__name__] = module
            installed.append(module.__name__)
            components.append((name, module.__name__))
        monkeypatch.setattr(plugin, "COMPONENTS", tuple(components))
        return calls

    yield install
    for name in installed:
        sys.modules.pop(name, None)


def test_entry_point_components_load_in_the_documented_order() -> None:
    assert [component for component, _module in plugin.COMPONENTS] == [
        "keyvault",
        "llm_guard",
        "network",
        "privacy_check",
        "e2e",
        "wizard",
    ]
    assert set(plugin.COMPONENT_REQUIRED_HOOKS) == {component for component, _module in plugin.COMPONENTS}


def test_integrity_gate_is_registered_first_and_only_once(fake_components: Callable[..., list[str]]) -> None:
    def registers_gate(ctx: Any) -> None:
        ctx.register_hook("on_session_start", check_plugin_integrity)
        ctx.register_hook("on_session_end", lambda **_: None)

    calls = fake_components(a=registers_gate, b=registers_gate)
    ctx = _FakeContext()

    plugin.register(ctx)

    assert calls == ["a", "b"]
    assert ctx.registrations[0] == ("hook", "on_session_start", check_plugin_integrity)
    assert ctx.hooks("on_session_start") == [check_plugin_integrity]
    assert len(ctx.hooks("on_session_end")) == 2  # distinct callbacks are not deduplicated
    # A component whose registration was deduplicated is still credited with the hook.
    assert plugin.component_hooks() == {
        "a": frozenset({"on_session_start", "on_session_end"}),
        "b": frozenset({"on_session_start", "on_session_end"}),
    }
    assert plugin.component_errors() == {}


def test_failing_component_is_contained_and_unwound(fake_components: Callable[..., list[str]]) -> None:
    def partial_then_fail(ctx: Any) -> None:
        ctx.register_hook("pre_tool_call", lambda **_: None)
        raise RuntimeError("boom")

    def healthy(ctx: Any) -> None:
        ctx.register_hook("pre_api_request", lambda **_: None)

    calls = fake_components(first=partial_then_fail, second=healthy)
    ctx = _FakeContext()

    plugin.register(ctx)

    assert calls == ["first", "second"]
    assert ctx.hooks("pre_tool_call") == []  # the failed component's registration was disposed
    assert len(ctx.hooks("pre_api_request")) == 1
    assert ctx.hooks("on_session_start") == [check_plugin_integrity]
    assert plugin.component_errors() == {"first": "RuntimeError: boom"}
    assert set(plugin.component_hooks()) == {"second"}


def test_disposed_duplicate_does_not_hide_a_later_registration(fake_components: Callable[..., list[str]]) -> None:
    def shared(**_: Any) -> None:
        return None

    def register_then_fail(ctx: Any) -> None:
        ctx.register_hook("on_session_end", shared)
        raise RuntimeError("boom")

    def register_same(ctx: Any) -> None:
        ctx.register_hook("on_session_end", shared)

    fake_components(first=register_then_fail, second=register_same)
    ctx = _FakeContext()

    plugin.register(ctx)

    assert ctx.hooks("on_session_end") == [shared]


class _Refusal(BaseException):
    pass


def test_fail_closed_refusal_propagates(fake_components: Callable[..., list[str]]) -> None:
    def refuse(_ctx: Any) -> None:
        raise _Refusal("refusing process startup")

    calls = fake_components(first=refuse, second=None)

    with pytest.raises(_Refusal):
        plugin.register(_FakeContext())
    assert calls == ["first"]


def test_system_exit_propagates(fake_components: Callable[..., list[str]]) -> None:
    def exit_(_ctx: Any) -> None:
        raise SystemExit(1)

    fake_components(first=exit_)

    with pytest.raises(SystemExit):
        plugin.register(_FakeContext())


def test_rediscovery_resets_component_state(fake_components: Callable[..., list[str]]) -> None:
    def fail(_ctx: Any) -> None:
        raise RuntimeError("boom")

    fake_components(first=fail)
    plugin.register(_FakeContext())
    assert plugin.component_errors() == {"first": "RuntimeError: boom"}

    fake_components(first=None)
    plugin.register(_FakeContext())
    assert plugin.component_errors() == {}
    assert plugin.component_hooks() == {"first": frozenset()}


def test_non_hook_registrations_are_forwarded(fake_components: Callable[..., list[str]]) -> None:
    def cli(ctx: Any) -> None:
        ctx.register_cli_command("mordred", help="x")

    fake_components(wizard=cli)
    ctx = _FakeContext()

    plugin.register(ctx)

    assert ("cli", "mordred", None) in ctx.registrations


def test_entry_module_source_does_not_look_like_a_category_plugin() -> None:
    """Hermes classifies entry points by scanning the module source for markers.

    ``register_memory_provider`` / ``MemoryProvider`` / cron markers make it an
    exclusive plugin and ``register_provider`` + ``ProviderProfile`` a model
    provider; either would keep Hermes from loading ``mordred`` as a normal plugin.
    """
    import inspect

    source = inspect.getsource(plugin)[:8192]
    for marker in ("register_memory_provider", "MemoryProvider", "register_cron_scheduler", "CronScheduler"):
        assert marker not in source
    assert not ("register_provider" in source and "ProviderProfile" in source)
