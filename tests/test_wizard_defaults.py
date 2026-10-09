"""Unit tests for ``wizard._defaults`` — the lazy production-default seams.

Two contracts matter: an injected fake is returned unchanged (the test seam
every keyvault-facing command relies on), and the production classes are
imported only *inside* the resolvers, so importing the module never pulls the
crypto / Keychain / prompt_toolkit stacks (the ``audit_cli``
minimal-install guarantee — see ``test_audit_cli.TestMinimalInstallImport``).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from mordred_hermes.wizard import _defaults


class TestIsMissingKeyvaultStack:
    """The shared predicate that classifies a ``ModuleNotFoundError`` as a
    missing ``[keyvault]`` crypto-stack dependency (used by ``cli.dispatch`` to
    emit an install hint and by ``status`` to degrade gracefully)."""

    @pytest.mark.parametrize("name", ["argon2", "cryptography", "blake3", "argon2.low_level"])
    def test_matches_crypto_stack_and_submodules(self, name: str) -> None:
        exc = ModuleNotFoundError(f"No module named {name!r}", name=name)
        assert _defaults.is_missing_keyvault_stack(exc) is True

    @pytest.mark.parametrize("name", ["numpy", "requests", "mordred_hermes.keyvault.vault"])
    def test_rejects_unrelated_modules(self, name: str) -> None:
        exc = ModuleNotFoundError(f"No module named {name!r}", name=name)
        assert _defaults.is_missing_keyvault_stack(exc) is False

    def test_rejects_nameless_error(self) -> None:
        # A hand-raised ModuleNotFoundError with no ``name`` must not be
        # misclassified as a missing crypto dependency.
        assert _defaults.is_missing_keyvault_stack(ModuleNotFoundError("mystery")) is False


class TestPassThrough:
    """An injected (non-None) value is returned as-is, no import triggered."""

    def test_backend_passthrough(self) -> None:
        sentinel = object()
        assert _defaults.resolve_backend(sentinel) is sentinel  # type: ignore[arg-type]

    def test_store_passthrough(self) -> None:
        sentinel = object()
        assert _defaults.resolve_store(sentinel) is sentinel  # type: ignore[arg-type]

    def test_prompt_io_passthrough(self) -> None:
        sentinel = object()
        assert _defaults.resolve_prompt_io(sentinel) is sentinel  # type: ignore[arg-type]


class TestLazyProductionDefaults:
    """``None`` builds the production class — resolved at *call* time, so a
    monkeypatched class in the source module is honoured (proving the import
    happens inside the function, not at module import)."""

    def test_backend_default_is_seckey_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _seckey_backend

        class _Fake:
            pass

        monkeypatch.setattr(_seckey_backend, "_SecKeyBackend", _Fake)
        assert isinstance(_defaults.resolve_backend(None), _Fake)

    def test_store_default_is_keychain_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _anchor_keychain, _seckey_helper

        class _Fake:
            pass

        monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: None)
        monkeypatch.setattr(_anchor_keychain, "KeychainAnchorStore", _Fake)
        assert isinstance(_defaults.resolve_store(None), _Fake)

    def test_store_default_is_helper_owned_when_the_helper_is_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _anchor_keychain, _seckey_helper

        class _Fake:
            def __init__(self, *_a: object, **_kw: object) -> None:
                pass

        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: "/x/mordred-hermes-sekey")
        monkeypatch.setattr(_anchor_keychain, "HelperAnchorStore", _Fake)
        assert isinstance(_defaults.resolve_store(None), _Fake)

    def test_prompt_io_default_is_prompt_toolkit_io(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import configure

        class _Fake:
            pass

        monkeypatch.setattr(configure, "PromptToolkitIO", _Fake)
        assert isinstance(_defaults.resolve_prompt_io(None), _Fake)


class TestImportLight:
    """Importing ``_defaults`` must not require the ``[keyvault]`` extra.

    Same subprocess-blocker technique as
    ``test_audit_cli.TestMinimalInstallImport`` (blocking in-process would
    race the copies other tests already imported).
    """

    _IMPORT_UNDER_BLOCKER = textwrap.dedent(
        """
        import sys

        class _Blocker:
            BLOCKED = ("cryptography", "blake3", "argon2", "prompt_toolkit")

            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in self.BLOCKED:
                    raise ModuleNotFoundError(f"No module named {name!r} (blocked by test)")
                return None

        sys.meta_path.insert(0, _Blocker())

        import mordred_hermes.wizard._defaults  # noqa: F401
        """
    )

    def test_defaults_imports_without_heavy_stacks(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-c", self._IMPORT_UNDER_BLOCKER],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert proc.returncode == 0, f"_defaults needs a heavy stack at import time:\n{proc.stderr}"
