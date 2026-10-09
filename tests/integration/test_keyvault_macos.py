"""Live Secure-Enclave integration test for the production ``_SecKeyBackend``.

Gated by ``MORDRED_KEYVAULT_LIVE=1``. Skipped by default so CI and a
plain ``pytest -q`` stay hermetic — CI cannot satisfy the Touch ID /
passcode prompt that ``unwrap_dek`` triggers (SPEC.md review HIGH-4), so
this exercises the real ``Security.framework`` path only on a developer
Mac with a Secure Enclave (Apple Silicon or T2 Intel).

Run manually:

.. code-block:: bash

   MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py -v

Approve the biometric prompt when it appears during ``unwrap_dek``.

SPEC.md review HIGH-5: when the gate is ON we do NOT silently skip on a
missing Enclave — that would let a regression that breaks capability
detection pass unnoticed. We ``pytest.fail`` instead.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from pathlib import Path

import pytest

from mordred_hermes.keyvault import native, wrap
from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend

pytestmark = pytest.mark.integration

_LIVE_GATE_ENV = "MORDRED_KEYVAULT_LIVE"


def _require_live_enclave() -> None:
    """Skip when the gate is off; fail (not skip) when on but unusable."""
    if os.environ.get(_LIVE_GATE_ENV) != "1":
        pytest.skip(f"set {_LIVE_GATE_ENV}=1 to run live Secure Enclave integration tests")
    if sys.platform != "darwin":
        pytest.fail(f"{_LIVE_GATE_ENV}=1 but platform is {sys.platform!r}; run on macOS with a Secure Enclave")
    if not native.is_secure_enclave_available():
        pytest.fail(
            f"{_LIVE_GATE_ENV}=1 but is_secure_enclave_available() is False — "
            "Secure Enclave unreachable (no SEP, locked, or pyobjc missing). "
            "Install with `pip install hermes-mordred[macos]` on Enclave-capable hardware."
        )


@pytest.fixture
def live_key_id() -> str:
    """A per-run unique key_id so repeated runs never collide in the
    Keychain. Cleanup happens in the test's ``finally`` block."""
    return f"mordred-itest-{time.time_ns()}"


class _FixedPassphrase:
    """Minimal ``PromptIO`` stand-in returning a constant passphrase, so a live
    ``vault init`` runs non-interactively (``init`` only calls ``ask_password``)."""

    def __init__(self, passphrase: str) -> None:
        self._passphrase = passphrase

    def ask_password(self, _prompt: str) -> str:
        return self._passphrase


def _config_vault_root(home: Path) -> Path:
    """The vault root the config-decrypt hook and wizard agree on for a home:
    ``<home>/mordred/vault`` (``_identity.default_vault_root`` / wizard
    ``_default_root``)."""
    return home / "mordred" / "vault"


def test_capability_probe_reports_true_on_enclave_hardware() -> None:
    """``is_secure_enclave_available`` runs a real generate-then-delete
    probe (``.privateKeyUsage`` only — no prompt)."""
    _require_live_enclave()
    assert native.is_secure_enclave_available() is True


def test_signed_helper_is_selected_when_present() -> None:
    """When the signed ``mordred-hermes-sekey`` helper is installed, the
    default backend ops must route through it (not the in-process pyobjc
    path). This guards the discovery + wiring so the round-trip tests below
    are actually exercising the helper. Skipped when the helper is absent.
    """
    _require_live_enclave()

    from mordred_hermes.keyvault import _seckey_backend, _seckey_helper

    if _seckey_helper._find_helper() is None:
        pytest.skip(
            "signed helper not installed; build it via native/sekey-helper/build.sh or set MORDRED_SEKEY_HELPER"
        )
    assert isinstance(_seckey_backend._default_ops(), _seckey_helper._HelperSecKeyOps)


def test_generate_wrap_unwrap_roundtrip_through_real_enclave(live_key_id: str) -> None:
    """Full Tier-1 protection path: generate an Enclave wrapping key,
    wrap a DEK offline, then unwrap it through the authorization
    boundary. The unwrap step triggers a biometric / passcode prompt —
    approve it.
    """
    _require_live_enclave()
    backend = _SecKeyBackend()
    audit: list[dict[str, object]] = []
    dek = bytes(range(32))

    try:
        public_key = wrap.generate_wrapping_key(live_key_id, backend=backend)
        assert len(public_key) == 65 and public_key[0] == 0x04

        # Public-key lookup is unprivileged — no prompt, must round-trip.
        assert wrap.get_wrapping_key_public(live_key_id, backend=backend) == public_key

        blob = wrap.wrap_dek(dek, live_key_id, backend=backend)
        assert len(blob) == wrap.HEADER_LEN

        # Authorization boundary — approve the prompt.
        recovered = wrap.unwrap_dek(blob, live_key_id, audit_sink=audit.append, backend=backend)
        assert recovered == dek
        assert audit and audit[-1]["reason"] == "keyvault.unwrap_authorized"
    finally:
        wrap.delete_wrapping_key(live_key_id, backend=backend)

    # After deletion the key is gone — public lookup must fail.
    with pytest.raises(WrapKeyNotFound):
        wrap.get_wrapping_key_public(live_key_id, backend=backend)


def test_delete_is_idempotent_on_real_keychain(live_key_id: str) -> None:
    """Deleting a never-generated key is a contractual no-op."""
    _require_live_enclave()
    backend = _SecKeyBackend()
    backend.delete_enclave_key(live_key_id)  # must not raise


def test_encrypt_decrypt_roundtrip_through_real_enclave(live_key_id: str, tmp_path: Path) -> None:
    """L453: ``api.encrypt`` / ``api.decrypt`` AES-GCM roundtrip with the
    per-envelope DEK wrapped and unwrapped through real Secure Enclave
    authorization. The ``decrypt`` step triggers a biometric / passcode
    prompt — approve it.
    """
    _require_live_enclave()
    from mordred_hermes.keyvault import api

    backend = _SecKeyBackend()
    audit: list[dict[str, object]] = []
    seed = "test seed phrase one two three four"
    passphrase = "correct horse battery staple"
    pow_bytes = bytes(range(32))
    secret = b"the-protected-secret-payload"

    try:
        _handle, expected_digest = api.prepare_generate(seed, passphrase, pow_bytes)
        api.generate(
            seed,
            passphrase,
            pow_bytes,
            expected_digest,
            key_id=live_key_id,
            backend=backend,
            audit_sink=audit.append,
            home=tmp_path,
        )
        envelope_id = api.encrypt(live_key_id, secret, "itest", backend=backend, audit_sink=audit.append, home=tmp_path)
        # Authorization boundary — approve the prompt.
        recovered = api.decrypt(
            live_key_id, envelope_id, "itest", backend=backend, audit_sink=audit.append, home=tmp_path
        )
        assert recovered == secret
        assert any(e.get("reason") == "keyvault.unwrap_authorized" for e in audit)
    finally:
        wrap.delete_wrapping_key(live_key_id, backend=backend)


def test_enable_se_builds_installs_and_verifies_helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end ``hermes mordred keyvault enable-se``.

    Builds + ad-hoc-signs + installs the CryptoKit Secure Enclave helper, then
    verifies the SE probe succeeds through it — proving real hardware SE works
    from a plain (unsigned) interpreter with no paid Apple Developer account.
    Needs the Xcode/Swift toolchain. Installs into a temp dir (pointed at via
    ``MORDRED_SEKEY_HELPER``) so the operator's ``~/.local/bin`` is untouched.
    """
    _require_live_enclave()
    from mordred_hermes.wizard import keyvault_native_cli

    missing = keyvault_native_cli._missing_build_tools()
    if missing:
        pytest.skip(f"missing build tool(s) {missing}; install the Xcode command-line tools")

    install_dir = tmp_path / "bin"
    monkeypatch.setenv("MORDRED_SEKEY_HELPER", str(install_dir / "mordred-hermes-sekey"))
    rc = keyvault_native_cli.enable_se(install_dir=install_dir, home=tmp_path)
    assert rc == 0
    assert (install_dir / "mordred-hermes-sekey").is_file()


def test_config_decrypt_lifecycle_through_real_enclave(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """v2-F8 end-to-end on a real Secure Enclave (ROADMAP v2-F8 final item).

    Exercises the full ``config.yaml`` at-rest lifecycle through the CryptoKit SE
    helper — startup decrypt (``materialize_config``) and shutdown reseal
    (``reseal_config``) — plus the ``enable``/``disable`` wizard path:

      init vault → enable-config-decrypt (enroll + marker) → reseal (seal at
      rest, drop plaintext) → materialize (transparent decrypt on next start) →
      round-trip stability → disable (recover sealed plaintext, drop marker).

    The wrapping key is generated ``.privateKeyUsage``-only
    (``MORDRED_SEKEY_UNATTENDED=1``) — the correct policy for an unattended
    startup hook — so the real-Enclave ECDH runs with no Touch ID prompt.
    ``HERMES_HOME`` is redirected into ``tmp_path`` so the SE key blob store and
    home are isolated; the only login-Keychain residue (the device anchor) is
    removed in ``finally``.
    """
    _require_live_enclave()
    from mordred_hermes.keyvault import _seckey_backend, _seckey_helper
    from mordred_hermes.keyvault._anchor_keychain import default_anchor_store
    from mordred_hermes.keyvault._config_bootstrap import _marker_path, materialize_config, reseal_config
    from mordred_hermes.keyvault._identity import vault_identity
    from mordred_hermes.wizard import config_decrypt_cli, vault_cli

    if _seckey_helper._find_helper() is None:
        pytest.skip("signed helper not installed; build it via native/sekey-helper/build.sh")

    # time_ns() keeps the vault root — and thus the login-Keychain anchor label —
    # unique across runs even when pytest recycles a tmp_path number (mirrors the
    # live_key_id fixture rationale), so a crashed prior run can't block init.
    home = tmp_path / f"hermes-home-{time.time_ns()}"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))  # isolates SE blob store + home resolution
    monkeypatch.setenv("MORDRED_SEKEY_UNATTENDED", "1")  # .privateKeyUsage-only → no prompt
    root = _config_vault_root(home)
    anchor_label = vault_identity(root)

    config_path = home / "config.yaml"
    original = b"# mordred itest config\nmodel: test-model\nplugins:\n  mordred-x: {}\n"
    config_path.write_bytes(original)

    try:
        # Real-SE wrapping key + vault (unattended → no prompt on later ECDH).
        assert vault_cli.init(root=root, prompt_io=_FixedPassphrase("itest-passphrase")) == 0
        # The CryptoKit helper — NOT the software P-256 fallback — must be the path,
        # else this would not be a hardware Secure Enclave e2e.
        assert isinstance(_seckey_backend._default_ops(), _seckey_helper._HelperSecKeyOps)

        # enable-config-decrypt: enroll config.yaml into the vault + write the opt-in marker.
        # This dev .venv lacks the config-decrypt .pth hook, so bypass the macOS runtime gate
        # (force_runtime_unverified); the real-Enclave seal/reseal lifecycle driven directly below
        # is what this test verifies. Mirrors cli_enable's platform=sys.platform.
        assert (
            config_decrypt_cli.enable(home=home, root=root, platform=sys.platform, force_runtime_unverified=True) == 0
        )
        assert _marker_path(home).exists()
        # The SE private key persisted as a CryptoKit dataRepresentation blob under the
        # isolated home — concrete proof the real Enclave path ran (software keys live
        # in the Keychain, never as a *.bin blob here).
        sekey_blobs = list((home / "mordred" / "keyvault" / "sekey").glob("*.bin"))
        assert sekey_blobs, "expected a Secure Enclave key blob — real SE path did not run"

        # reseal-on-stop: re-enroll if changed, then remove the on-disk plaintext so
        # config.yaml is encrypted at rest between sessions.
        assert reseal_config(root=root, home=home) == 1
        assert not config_path.exists()

        # decrypt-on-start: the .pth hook's materialize step decrypts the enrolled
        # config back onto disk through the real Enclave. THIS is the transparent decrypt.
        assert materialize_config(root=root, home=home) == 1
        assert config_path.read_bytes() == original

        # Round-trip is stable across a second seal/unseal cycle.
        assert reseal_config(root=root, home=home) == 1
        assert not config_path.exists()
        assert materialize_config(root=root, home=home) == 1
        assert config_path.read_bytes() == original

        # disable-config-decrypt recovers a sealed-away plaintext and drops the marker.
        assert reseal_config(root=root, home=home) == 1
        assert not config_path.exists()
        assert config_decrypt_cli.disable(home=home, root=root) == 0
        assert not _marker_path(home).exists()
        assert config_path.read_bytes() == original
    finally:
        # SE key blobs live under tmp_path (auto-removed); only the login-Keychain
        # device anchor is real-system residue.
        with contextlib.suppress(Exception):
            default_anchor_store().delete(anchor_label)


def test_config_decrypt_fail_closed_on_missing_anchor_through_real_enclave(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v2-F8 fail-closed on a real Enclave: when config.yaml is marked
    vault-managed but the device anchor is gone (deletion), the startup
    materialize refuses (``VaultError``) rather than booting Hermes on a
    default / stale config.
    """
    _require_live_enclave()
    from mordred_hermes.keyvault import _seckey_helper, vault
    from mordred_hermes.keyvault._anchor_keychain import default_anchor_store
    from mordred_hermes.keyvault._config_bootstrap import materialize_config, reseal_config
    from mordred_hermes.keyvault._identity import vault_identity
    from mordred_hermes.wizard import config_decrypt_cli, vault_cli

    if _seckey_helper._find_helper() is None:
        pytest.skip("signed helper not installed; build it via native/sekey-helper/build.sh")

    # time_ns() keeps the vault root — and thus the login-Keychain anchor label —
    # unique across runs even when pytest recycles a tmp_path number (mirrors the
    # live_key_id fixture rationale), so a crashed prior run can't block init.
    home = tmp_path / f"hermes-home-{time.time_ns()}"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("MORDRED_SEKEY_UNATTENDED", "1")
    root = _config_vault_root(home)
    anchor_label = vault_identity(root)
    (home / "config.yaml").write_bytes(b"model: itest\n")

    try:
        assert vault_cli.init(root=root, prompt_io=_FixedPassphrase("itest-passphrase")) == 0
        # dev .venv lacks the .pth hook → bypass the macOS runtime gate (see the lifecycle test).
        assert (
            config_decrypt_cli.enable(home=home, root=root, platform=sys.platform, force_runtime_unverified=True) == 0
        )
        assert reseal_config(root=root, home=home) == 1  # plaintext sealed away

        # Simulate device-anchor deletion: the marker still promises a vault-managed
        # config, so materialize must fail closed (not fall back to a default config).
        default_anchor_store().delete(anchor_label)
        with pytest.raises(vault.VaultError):
            materialize_config(root=root, home=home)
    finally:
        with contextlib.suppress(Exception):
            default_anchor_store().delete(anchor_label)
