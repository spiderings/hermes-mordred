"""Shared per-module test helpers with byte-identical bodies, deduplicated
from multiple test modules (test-infrastructure refactor).

``_init_empty_vault`` was duplicated verbatim across ``test_keyvault_env_reseal.py``,
``test_wizard_config_decrypt_cli.py``, ``test_wizard_encryption_cli.py``,
``test_wizard_env_decrypt_cli.py``, and ``test_wizard_memory_cli.py``.

``_writer`` was duplicated verbatim across ``test_configure.py``,
``test_policy_writer.py``, ``test_upgrade.py``, and ``test_wizard_network_init.py``
(``test_openclaw_migration.py`` has a deliberately different body — its own
``_writer`` namespaces paths under a ``hermes/`` subdirectory — and keeps its
own copy).

Not a ``test_*`` module, so pytest does not collect it.
"""

from __future__ import annotations

from pathlib import Path

from mordred_hermes.keyvault import _identity, vault
from mordred_hermes.wizard.policy_writer import PolicyWriter

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"


def _init_empty_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )


class PlatformSys:
    """Override a module's OS dispatch while forwarding live argv/stdio state."""

    def __init__(self, platform: str) -> None:
        self.platform = platform

    def __getattr__(self, name: str):
        import sys

        return getattr(sys, name)
