"""Tests for the session-boundary ``.env`` reseal sweep.

The keyvault plugin heals a stray plaintext ``~/.hermes/.env`` (the ``[exposed]``
drift: vault-managed yet plaintext on disk) by resealing it into the vault on the
``on_session_start`` / ``on_session_end`` plugin hooks. This is the proactive twin
of the write-guard (:mod:`mordred_hermes.keyvault._env_write_guard`), which only
catches drift created *through the host writer*; a plaintext left by another path
(e.g. ``gateway setup``) is otherwise missed.

These tests exercise the platform gate, opt-out safety, no-op cheapness (the vault
is never opened when there is nothing to do — so no spurious Touch ID), fail-open
behavior, and the ``register()`` wiring. The merge correctness of ``reseal`` itself
lives in ``test_wizard_env_decrypt_cli.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _env_write_guard
from mordred_hermes.keyvault._runtime_env import _env_optout_marker_path


def _make_home(tmp_path: Path, *, with_env: bool, with_optout: bool) -> Path:
    """A fake ``~/.hermes`` home, optionally seeded with a plaintext ``.env`` and/or
    the reversible-disable opt-out marker."""
    home = tmp_path / "hermes"
    home.mkdir()
    if with_env:
        (home / ".env").write_text("ANTHROPIC_API_KEY=sk-x\n", encoding="utf-8")
    if with_optout:
        marker = _env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("", encoding="utf-8")
    return home


def _patch_reseal(monkeypatch: pytest.MonkeyPatch, behavior: Any) -> list[Path]:
    """Replace ``keyvault._env_reseal.reseal_env`` with a recording fake driven by
    ``behavior(home, root) -> int``; also stub ``default_vault_root`` so nothing
    touches the real vault. Returns the list of ``home`` values reseal was called
    with (empty == reseal never invoked == no vault open / no Touch ID).

    ``_env_write_guard.reseal_stray_env_if_present`` does
    ``from ._env_reseal import reseal_env`` *inside* the function body (a fresh
    lookup every call, not a module-import-time binding — see that module's
    "Heavy imports stay function-local" contract), so patching the attribute on
    ``_env_reseal`` here is picked up correctly without needing to reach into
    ``_env_write_guard``'s own namespace.
    """
    from mordred_hermes.keyvault import _env_reseal

    calls: list[Path] = []

    def _fake(*, home: Path, root: Path, **_kw: Any) -> int:
        calls.append(home)
        return behavior(home, root)

    monkeypatch.setattr(_env_reseal, "reseal_env", _fake)
    monkeypatch.setattr(_env_write_guard, "default_vault_root", lambda: Path("/tmp/_vault_root"))
    return calls


class TestReseelStrayEnv:
    def test_reseals_and_returns_true_on_darwin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = _make_home(tmp_path, with_env=True, with_optout=False)

        def _success(home: Path, _root: Path) -> int:
            (home / ".env").unlink()  # a real reseal removes the plaintext
            return 0

        calls = _patch_reseal(monkeypatch, _success)
        result = _env_write_guard.reseal_stray_env_if_present(home=home, platform="darwin")

        assert result is True
        assert calls == [home]
        assert not (home / ".env").exists()

    def test_noop_off_darwin_keeps_plaintext(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Off macOS the read shim is a no-op, so removing the plaintext would
        # strand the secrets. The sweep must do nothing and keep the file.
        home = _make_home(tmp_path, with_env=True, with_optout=False)
        calls = _patch_reseal(monkeypatch, lambda _h, _r: 0)

        result = _env_write_guard.reseal_stray_env_if_present(home=home, platform="linux")

        assert result is False
        assert calls == []  # vault never opened off macOS
        assert (home / ".env").exists()

    def test_noop_when_disabled_optout(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Reversible-disable: the plaintext is the intentional live copy, not drift.
        home = _make_home(tmp_path, with_env=True, with_optout=True)
        calls = _patch_reseal(monkeypatch, lambda _h, _r: 0)

        result = _env_write_guard.reseal_stray_env_if_present(home=home, platform="darwin")

        assert result is False
        assert calls == []  # never reseal an intentionally-disabled env
        assert (home / ".env").exists()

    def test_noop_when_no_plaintext(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The common clean case: nothing to do, so the vault is never opened
        # (guards against a spurious Touch ID on every session).
        home = _make_home(tmp_path, with_env=False, with_optout=False)
        calls = _patch_reseal(monkeypatch, lambda _h, _r: 0)

        result = _env_write_guard.reseal_stray_env_if_present(home=home, platform="darwin")

        assert result is False
        assert calls == []

    def test_returns_false_when_reseal_keeps_plaintext(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # reseal returns 0 but leaves the plaintext (read-back mismatch / unremovable):
        # that is not an actual reseal, so the helper reports False.
        home = _make_home(tmp_path, with_env=True, with_optout=False)
        _patch_reseal(monkeypatch, lambda _h, _r: 0)  # does NOT remove .env

        result = _env_write_guard.reseal_stray_env_if_present(home=home, platform="darwin")

        assert result is False
        assert (home / ".env").exists()

    def test_never_raises_when_reseal_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = _make_home(tmp_path, with_env=True, with_optout=False)

        def _boom(_h: Path, _r: Path) -> int:
            raise RuntimeError("vault locked")

        _patch_reseal(monkeypatch, _boom)

        # Must swallow and report False; the plaintext is left for `status` to flag.
        result = _env_write_guard.reseal_stray_env_if_present(home=home, platform="darwin")

        assert result is False
        assert (home / ".env").exists()


class TestReseelQuietlyDelegates:
    def test_reseal_quietly_delegates_to_helper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The write-guard's reconcile callback now delegates to the shared helper.
        seen: list[str] = []

        def _spy(**_kwargs: Any) -> bool:
            seen.append("called")
            return False

        monkeypatch.setattr(_env_write_guard, "reseal_stray_env_if_present", _spy)
        _env_write_guard._reseal_quietly()

        assert seen == ["called"]


class _FakeCtx:
    """Hermes PluginContext stand-in. Records ``register_hook`` names; can be told
    to reject a given hook to prove ``register()`` survives a host rejection."""

    def __init__(self, *, raise_on: set[str] | None = None) -> None:
        self.hooks: list[str] = []
        self.registered: list[tuple[str, Any]] = []
        self._raise_on = raise_on or set()

    def register_hook(self, hook_name: str, callback: Any) -> None:
        if hook_name in self._raise_on:
            raise RuntimeError("host rejected hook")
        self.hooks.append(hook_name)
        self.registered.append((hook_name, callback))

    def callbacks_for(self, hook_name: str) -> list[Any]:
        return [callback for name, callback in self.registered if name == hook_name]


def _isolate_register(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the installers ``register()`` calls so the wiring test never reads the
    real vault, patches the host writer, or wraps the upstream memory seam."""
    from mordred_hermes import keyvault
    from mordred_hermes.keyvault import _memory_hook, _runtime_env

    monkeypatch.setattr(_runtime_env, "install_vault_env_decrypt", lambda **_k: 0)
    monkeypatch.setattr(_env_write_guard, "install_env_write_guard", lambda **_k: False)
    monkeypatch.setattr(_memory_hook, "install_memory_hook", lambda **_k: False)
    monkeypatch.setattr(keyvault, "_install_journey_guard", lambda: None)


class TestRegisterWiring:
    def test_register_wires_both_session_hooks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault

        _isolate_register(monkeypatch)
        ctx = _FakeCtx()
        keyvault.register(ctx)

        assert ctx.hooks.count("on_session_start") == 3
        assert "on_session_end" in ctx.hooks

    def test_register_wires_the_memory_check_itself(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A count only proves *three* callbacks arrived. The sealed-but-locked
        diagnosis is the one the operator never sees fail, so pin its identity."""
        from mordred_hermes import keyvault

        _isolate_register(monkeypatch)
        ctx = _FakeCtx()
        keyvault.register(ctx)

        assert keyvault._on_session_memory_check in ctx.callbacks_for("on_session_start")
        assert keyvault._on_session_reseal in ctx.callbacks_for("on_session_start")
        assert keyvault._on_session_reseal in ctx.callbacks_for("on_session_end")

    def test_register_installs_the_journey_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The import hook covers a process it engaged in; ``register()`` covers the
        one the ``.pth`` gate never matched."""
        from mordred_hermes import keyvault

        _isolate_register(monkeypatch)
        installed: list[str] = []
        monkeypatch.setattr(keyvault, "_install_journey_guard", lambda: installed.append("journey"))

        keyvault.register(_FakeCtx())

        assert installed == ["journey"]

    def test_journey_guard_installation_is_fail_open(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A host without ``agent.learning_mutations`` must be a silent no-op."""
        from mordred_hermes import keyvault
        from mordred_hermes.keyvault import _memory_hook

        def _boom(_module: Any) -> bool:
            raise RuntimeError("upstream renamed everything")

        monkeypatch.setattr(_memory_hook, "install_journey_guard", _boom)
        keyvault._install_journey_guard()  # must not raise

    def test_register_installs_the_memory_hook_before_the_vault_shim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A fail-closed vault raise must not cost the memory seam its wrapper —
        upstream would then truncate already-sealed files."""
        from mordred_hermes import keyvault
        from mordred_hermes.keyvault import _memory_hook, _runtime_env

        installed: list[str] = []

        def _boom(**_kwargs: Any) -> int:
            raise RuntimeError("vault present but unverifiable")

        monkeypatch.setattr(_runtime_env, "install_vault_env_decrypt", _boom)
        monkeypatch.setattr(_env_write_guard, "install_env_write_guard", lambda **_k: False)
        monkeypatch.setattr(_memory_hook, "install_memory_hook", lambda **_k: bool(installed.append("memory")))

        with pytest.raises(RuntimeError, match="unverifiable"):
            keyvault.register(_FakeCtx())

        assert installed == ["memory"]

    def test_register_survives_hook_rejection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault

        _isolate_register(monkeypatch)
        ctx = _FakeCtx(raise_on={"on_session_end"})
        keyvault.register(ctx)  # must not raise

        assert "on_session_start" in ctx.hooks
        assert "on_session_end" not in ctx.hooks


class TestOnSessionMemoryCheck:
    """Upstream's ``agent_init`` swallows a failed ``load_from_disk``, so a sealed
    memory whose key is missing shows up as an empty memory with no signal."""

    def test_callback_invokes_the_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault
        from mordred_hermes.keyvault import _memory_hook

        seen: list[dict[str, Any]] = []
        monkeypatch.setattr(_memory_hook, "warn_when_memory_is_locked", lambda **kw: bool(seen.append(kw)))
        keyvault._on_session_memory_check(session_id="abc")
        assert seen == [{}]  # the host payload is absorbed, not forwarded

    def test_callback_swallows_a_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault
        from mordred_hermes.keyvault import _memory_hook

        def _boom(**_kwargs: Any) -> bool:
            raise RuntimeError("stat blew up")

        monkeypatch.setattr(_memory_hook, "warn_when_memory_is_locked", _boom)
        keyvault._on_session_memory_check()  # must not raise into the session boundary


class TestOnSessionResealCallback:
    """The hook callback itself: it must invoke the helper, ignore the host's hook
    payload kwargs, and never let a helper failure escape into the session boundary."""

    def test_callback_invokes_helper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault

        seen: list[dict[str, Any]] = []
        monkeypatch.setattr(_env_write_guard, "reseal_stray_env_if_present", lambda **kw: bool(seen.append(kw)))
        keyvault._on_session_reseal()
        assert seen == [{}]  # called once, with no args of its own

    def test_callback_ignores_hook_payload_kwargs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault

        seen: list[dict[str, Any]] = []
        monkeypatch.setattr(_env_write_guard, "reseal_stray_env_if_present", lambda **kw: bool(seen.append(kw)))
        # The host fires the hook with a payload; the callback must absorb it and
        # still call the helper with no arguments.
        keyvault._on_session_reseal(session_id="abc", messages=[])
        assert seen == [{}]

    def test_callback_swallows_helper_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault

        def _boom(**_kwargs: Any) -> bool:
            raise RuntimeError("reseal blew up")

        monkeypatch.setattr(_env_write_guard, "reseal_stray_env_if_present", _boom)
        keyvault._on_session_reseal()  # must not raise into the session boundary
