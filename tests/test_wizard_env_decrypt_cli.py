"""Tests for ``hermes mordred encryption {enable,disable,purge} env``.

The ``.env`` target completes the toggle model config.yaml already has, but with
``.env``'s **memory-only** runtime injection (the plaintext is removed on enable;
the startup shim injects from the vault into ``os.environ``, never re-writing
plaintext). Three states:

- **enable**  → enroll ``<home>/.env`` into the vault; on macOS remove the
  plaintext (no secret at rest) and clear the opt-out marker so the runtime
  injects.
- **disable** → restore a readable plaintext ``<home>/.env`` (conflict-safe) and
  write the opt-out marker so the runtime stops injecting — *reversible*, the
  vault copy is kept.
- **purge**   → restore the plaintext, then ``unenroll_file('.env')`` from the
  vault and clear the marker — *destructive*, back to plain unencrypted.

The runtime shim (:func:`...keyvault._runtime_env.install_vault_env_decrypt`)
honors the opt-out marker: a disabled env target is not injected even when still
enrolled.

Built on the software fakes so the real init → enroll → hot-path-open path runs
on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, _runtime_env, vault
from mordred_hermes.keyvault._runtime_env import _env_optout_marker_path
from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.wizard import _runtime_gate, env_decrypt_cli

from ._helpers import _init_empty_vault
from ._keyvault_fakes import FakeAnchorStore, FakeBackend, FixedPassphrasePromptIO

_PASSPHRASE = "correct horse battery staple"
_ENV_A = b"ANTHROPIC_API_KEY=sk-secret\n"
_ENV_B = b"ANTHROPIC_API_KEY=sk-other\n"


def _vault_env(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> bytes | None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        return opened.read_file(".env") if ".env" in opened.list_files() else None


@pytest.fixture(autouse=True)
def _runtime_injection_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default the macOS runtime probe to *available* for the existing enable
    tests, which exercise the enroll/delete logic rather than the runtime gate.

    The gate itself is covered by :class:`TestRuntimeGate`, which injects its own
    ``runtime_probe=`` and so is unaffected by this default. Running-gateway
    discovery is defaulted to "none found" for the same reason — and so no test
    ever reads this host's real process table.
    """
    monkeypatch.setattr(env_decrypt_cli, "_default_runtime_probe", lambda *, home, runtime_python=None: (True, "ok"))
    monkeypatch.setattr(_runtime_gate, "_default_gateway_discovery", lambda *, home: [])


# -----------------------------------------------------------------------------
# enable
# -----------------------------------------------------------------------------
class TestEnable:
    def test_enrolls_and_removes_plaintext_on_macos(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A  # enrolled
        assert not (home / ".env").exists()  # no plaintext at rest on macOS
        assert not _env_optout_marker_path(home).exists()  # injection ON

    def test_already_sealed_reenable_is_noop_success(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        # Re-running enable when env is already sealed (enrolled, injection ON, no
        # plaintext) must succeed as a no-op, not error "nothing to protect".
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        assert env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store) == 0
        assert not (home / ".env").exists()  # sealed: no plaintext to re-enroll

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0  # idempotent, not exit 1
        assert _vault_env(root, backend, store) == _ENV_A  # still enrolled, unchanged
        out = capsys.readouterr()
        assert "already vault-managed" in (out.out + out.err)
        assert "nothing to protect" not in (out.out + out.err)

    def test_keeps_plaintext_off_macos(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)

        rc = env_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A  # enrolled
        # the runtime shim is a no-op off darwin, so removing the plaintext would
        # strand Hermes — keep it (status reports "inactive on this OS").
        assert (home / ".env").read_bytes() == _ENV_A

    def test_missing_env_is_error(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 1
        assert _vault_env(root, backend, store) is None

    def test_auto_creates_vault_when_missing(self, tmp_path: Path) -> None:
        """A first enable with no vault creates it inline (prompting once for a
        passphrase), then enrolls — no manual ``vault init`` needed."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        (home / ".env").write_bytes(_ENV_A)

        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="linux",
            backend=backend,
            store=store,
            prompt_io=FixedPassphrasePromptIO(_PASSPHRASE),
        )
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A  # vault created + .env enrolled

    def test_auto_creates_vault_then_removes_plaintext_on_macos(self, tmp_path: Path) -> None:
        """macOS path: a first enable with no vault creates it inline, enrolls
        `.env`, then removes the plaintext (the runtime injects from the vault)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        (home / ".env").write_bytes(_ENV_A)

        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            prompt_io=FixedPassphrasePromptIO(_PASSPHRASE),
        )
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A
        assert not (home / ".env").exists()  # plaintext removed after a clean enroll

    def test_keeps_plaintext_if_disk_diverges_from_vault(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """macOS enable must not delete a plaintext that does not match the enrolled bytes."""
        from mordred_hermes.wizard import vault_cli

        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        # simulate the enrolled copy differing from what is on disk at unlink time
        monkeypatch.setattr(vault_cli, "add_and_verify", lambda **_k: (0, _ENV_B))

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_A  # plaintext NOT deleted
        assert "leaving the plaintext" in capsys.readouterr().err.lower()

    def test_keeps_plaintext_if_disk_unreadable_at_verify(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """If the on-disk .env cannot be re-read at verify time (current -> None),
        enable must not proceed to unlink — it warns and fails safe (return 0)."""
        from mordred_hermes.wizard import vault_cli

        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)

        # the enroll "succeeds" but the plaintext vanishes before the verify read,
        # so env_path.read_bytes() raises and `current` becomes None.
        def _enroll_then_remove_plaintext(**_k: object) -> tuple[int, bytes]:
            (home / ".env").unlink()
            return 0, _ENV_A

        monkeypatch.setattr(vault_cli, "add_and_verify", _enroll_then_remove_plaintext)

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0
        assert "leaving the plaintext" in capsys.readouterr().err.lower()

    def test_mismatch_check_runs_before_unlink_is_ever_attempted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Multi-fault: the on-disk plaintext both mismatches the enrolled bytes
        AND would blow up if unlinking were ever attempted on it. The mismatch
        check inside ``_delete_enrolled_plaintext`` must run and return FIRST —
        the same "leaving the plaintext in place" message as a lone mismatch
        (see ``test_keeps_plaintext_if_disk_diverges_from_vault``) — never
        reaching the unlink step at all.

        Mutation-sensitive: swapping the mismatch-check block and the unlink
        block inside ``_delete_enrolled_plaintext`` makes this fail — the
        unlink would run first, trip the injected AssertionError below, and
        the plaintext would be gone instead of kept.
        """
        from mordred_hermes.wizard import vault_cli

        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        # The enrolled copy differs from what's on disk (mismatch) ...
        monkeypatch.setattr(vault_cli, "add_and_verify", lambda **_k: (0, _ENV_B))
        # ... AND unlinking it would also fail, if the code ever got that far.
        real_unlink = Path.unlink
        env_path = home / ".env"

        def _boom_if_unlinking_env(self: Path, *a: object, **k: object) -> None:
            if self == env_path:
                raise AssertionError("unlink must not run before the mismatch check has returned")
            real_unlink(self, *a, **k)

        monkeypatch.setattr(Path, "unlink", _boom_if_unlinking_env)

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)

        assert rc == 0
        assert env_path.read_bytes() == _ENV_A  # kept — the unlink path was never reached
        assert "leaving the plaintext" in capsys.readouterr().err.lower()

    def test_enable_unlocks_the_enclave_once(self, tmp_path: Path) -> None:
        """enable() must open the vault — one Secure-Enclave unlock, i.e. one Touch ID
        prompt — exactly once: the enroll and the pre-delete verify share a single open."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)

        before = sum(1 for call in backend.calls if call[0] == "ecdh")
        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        after = sum(1 for call in backend.calls if call[0] == "ecdh")

        assert rc == 0
        assert not (home / ".env").exists()  # plaintext removed after the verified enroll
        assert after - before == 1  # a single device-key unlock for enroll + verify

    def test_clears_optout_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        marker = _env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")

        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert not marker.exists()


# -----------------------------------------------------------------------------
# disable (reversible)
# -----------------------------------------------------------------------------
class TestDisable:
    def test_restores_plaintext_and_writes_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert not (home / ".env").exists()  # sealed by enable

        rc = env_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_A  # recovered from the vault
        assert _env_optout_marker_path(home).exists()  # injection OFF
        assert _vault_env(root, backend, store) == _ENV_A  # vault copy kept (reversible)

    def test_keeps_diverging_plaintext_and_warns(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        # operator put a DIFFERENT plaintext back by hand
        (home / ".env").write_bytes(_ENV_B)

        rc = env_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_B  # never silently overwritten
        assert "drift" in capsys.readouterr().err.lower()

    def test_idempotent_unmanaged(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        rc = env_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0


# -----------------------------------------------------------------------------
# purge (destructive)
# -----------------------------------------------------------------------------
class TestPurge:
    def test_unenrolls_and_restores_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)

        rc = env_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_A  # secret not lost
        assert _vault_env(root, backend, store) is None  # removed from the vault
        assert not _env_optout_marker_path(home).exists()

    def test_backs_up_diverging_vault_copy_before_purge(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The vault copy must never be destroyed silently when it differs from disk."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        # operator put a DIFFERENT plaintext back by hand before purging
        (home / ".env").write_bytes(_ENV_B)

        rc = env_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_B  # on-disk kept
        assert (home / ".env.vault-purged").read_bytes() == _ENV_A  # vault copy preserved, not lost
        assert _vault_env(root, backend, store) is None
        assert "vault-purged" in capsys.readouterr().err


# -----------------------------------------------------------------------------
# runtime shim honors the opt-out marker
# -----------------------------------------------------------------------------
class TestRuntimeOptOut:
    def test_install_skips_when_optout_marker_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        marker = _env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")

        called = {"inject": False}

        def _spy(**_: object) -> int:
            called["inject"] = True
            return 5

        monkeypatch.setattr(_runtime_env.sys, "platform", "darwin")
        monkeypatch.setattr(_runtime_env, "_hermes_home", lambda: home)
        monkeypatch.setattr(_runtime_env, "default_vault_root", lambda: tmp_path / "v")
        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)

        assert _runtime_env.install_vault_env_decrypt(environ={}) == 0
        assert called["inject"] is False  # opt-out → never opens the vault

    def test_install_injects_when_marker_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        called = {"inject": False}

        def _spy(**_: object) -> int:
            called["inject"] = True
            return 3

        monkeypatch.setattr(_runtime_env.sys, "platform", "darwin")
        monkeypatch.setattr(_runtime_env, "_hermes_home", lambda: home)
        monkeypatch.setattr(_runtime_env, "default_vault_root", lambda: tmp_path / "v")
        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)

        assert _runtime_env.install_vault_env_decrypt(environ={}) == 3
        assert called["inject"] is True


# -----------------------------------------------------------------------------
# reseal — reconcile a plaintext that reappeared while the vault still seals .env
# -----------------------------------------------------------------------------
_ENV_MULTI = b"A=1\nB=2\n"


def _seal(root: Path, home: Path, backend: FakeBackend, store: FakeAnchorStore, content: bytes) -> None:
    """Enroll ``content`` and reach the sealed macOS state (plaintext removed)."""
    _init_empty_vault(root, backend, store)
    (home / ".env").write_bytes(content)
    env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
    assert not (home / ".env").exists()  # sealed


class TestReseal:
    def test_merges_partial_write_without_losing_secrets(self, tmp_path: Path) -> None:
        """The core fix: a host write past the seal is a *partial* file; reseal must
        MERGE it onto the vault copy, never adopt it wholesale (which would drop the
        other enrolled secrets)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, _ENV_MULTI)
        # host writes only the just-set key (it started from an empty file)
        (home / ".env").write_bytes(b"C=3\n")

        rc = env_decrypt_cli.reseal(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env").exists()  # plaintext removed again
        assert _vault_env(root, backend, store) == b"A=1\nB=2\nC=3\n"  # A and B survived

    def test_overrides_existing_key(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, _ENV_MULTI)
        (home / ".env").write_bytes(b"A=9\n")  # operator updated an existing key

        rc = env_decrypt_cli.reseal(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert _vault_env(root, backend, store) == b"A=9\nB=2\n"  # A updated in place, B kept
        assert not (home / ".env").exists()

    def test_redundant_plaintext_is_just_removed(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, b"A=1\n")
        (home / ".env").write_bytes(b"A=1\n")  # identical to the vault copy

        rc = env_decrypt_cli.reseal(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env").exists()
        assert _vault_env(root, backend, store) == b"A=1\n"  # unchanged

    def test_noop_when_no_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, b"A=1\n")  # sealed, no plaintext on disk

        rc = env_decrypt_cli.reseal(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env").exists()  # not recreated
        assert _vault_env(root, backend, store) == b"A=1\n"

    def test_keeps_plaintext_when_opted_out(self, tmp_path: Path) -> None:
        """In the reversible *disabled* state the on-disk plaintext is the intentional
        live copy — reseal must not merge it away."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, b"A=1\n")
        env_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)  # opt-out marker + plaintext
        (home / ".env").write_bytes(b"B=2\n")  # operator edits the disabled-state plaintext

        rc = env_decrypt_cli.reseal(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == b"B=2\n"  # untouched
        assert _vault_env(root, backend, store) == b"A=1\n"  # vault unchanged

    def test_noop_when_not_enrolled(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / ".env").write_bytes(b"A=1\n")  # plaintext but no vault / not enrolled

        rc = env_decrypt_cli.reseal(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0
        assert (home / ".env").read_bytes() == b"A=1\n"  # left alone

    def test_merge_preserves_values_with_special_chars(self, tmp_path: Path) -> None:
        """A host write of a value with a space + '#' (or an escaped newline) must
        survive the merge intact — bare re-emission would truncate it at the inline
        comment / line break and silently corrupt the secret."""
        from io import StringIO

        from dotenv import dotenv_values

        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, b"A=1\n")
        (home / ".env").write_bytes(b'B="hello # world"\nC="line1\\nline2"\n')

        rc = env_decrypt_cli.reseal(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env").exists()
        enrolled = _vault_env(root, backend, store).decode("utf-8")
        vals = dotenv_values(stream=StringIO(enrolled), interpolate=False)
        assert vals == {"A": "1", "B": "hello # world", "C": "line1\nline2"}

    def test_reseal_unlocks_the_enclave_once(self, tmp_path: Path) -> None:
        """reseal must open the vault — one Secure-Enclave unlock (one Touch ID) —
        exactly once: read-base, enroll-merged, and the verify read-back all share a
        single open (guards against a regression back to a two-open reseal)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, _ENV_MULTI)
        (home / ".env").write_bytes(b"C=3\n")  # partial plaintext slipped past the seal

        before = sum(1 for call in backend.calls if call[0] == "ecdh")
        rc = env_decrypt_cli.reseal(home=home, root=root, backend=backend, store=store)
        after = sum(1 for call in backend.calls if call[0] == "ecdh")

        assert rc == 0
        assert after - before == 1  # one device-key unlock for read-base + enroll + verify
        assert not (home / ".env").exists()
        assert _vault_env(root, backend, store) == b"A=1\nB=2\nC=3\n"


class TestEnableReconcilesDrift:
    def test_enable_merges_on_drift_instead_of_clobbering(self, tmp_path: Path) -> None:
        """Running ``enable`` while drifted must reconcile via merge, not re-enroll the
        partial plaintext wholesale (the old footgun that dropped secrets)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, _ENV_MULTI)
        (home / ".env").write_bytes(b"C=3\n")  # partial plaintext slipped past the seal

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env").exists()
        assert _vault_env(root, backend, store) == b"A=1\nB=2\nC=3\n"  # merged, nothing lost

    def test_enable_sweeps_stale_reseal_temp(self, tmp_path: Path) -> None:
        """A reseal temp stranded by a prior crash (a plaintext at rest) is swept by
        the next ``enable``, so the documented remedy actually clears the exposure."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        (home / ".env.reseal.tmp").write_bytes(b"stale\n")  # leftover from a crash

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env.reseal.tmp").exists()  # swept


# -----------------------------------------------------------------------------
# runtime gate — refuse to seal .env when the `hermes` runtime cannot decrypt it
# -----------------------------------------------------------------------------
def _boom_probe(*, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
    raise AssertionError("runtime probe must not be consulted on this path")


class TestRuntimeGate:
    """macOS fail-closed gate: sealing deletes the plaintext, so it must first
    prove the interpreter that runs ``hermes`` can re-inject it at startup. When
    it cannot, ``enable`` refuses and leaves every byte of state untouched.
    """

    def _setup(self, tmp_path: Path) -> tuple[Path, Path, FakeBackend, FakeAnchorStore]:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        return root, home, backend, store

    def test_refuses_and_keeps_state_when_runtime_cannot_inject(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = self._setup(tmp_path)
        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=lambda *, home, runtime_python=None: (False, "mordred_keyvault plugin not registered"),
        )
        assert rc == 1
        assert (home / ".env").read_bytes() == _ENV_A  # plaintext untouched
        assert _vault_env(root, backend, store) is None  # nothing enrolled
        assert not _env_optout_marker_path(home).exists()  # marker untouched
        out = capsys.readouterr()
        assert "refusing to vault-seal .env" in (out.err + out.out)

    def test_force_bypasses_the_gate(self, tmp_path: Path) -> None:
        root, home, backend, store = self._setup(tmp_path)
        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=_boom_probe,  # must not be consulted under force
            force_runtime_unverified=True,
        )
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A  # enrolled
        assert not (home / ".env").exists()  # sealed despite an unverified runtime

    def test_gate_not_applied_off_macos(self, tmp_path: Path) -> None:
        root, home, backend, store = self._setup(tmp_path)
        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="linux",
            backend=backend,
            store=store,
            runtime_probe=_boom_probe,  # off macOS the gate never runs
        )
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A  # enrolled
        assert (home / ".env").read_bytes() == _ENV_A  # plaintext kept off macOS

    def test_drift_reseal_path_is_also_gated(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        # Enrolled + injection ON + a stray plaintext on macOS routes enable() to
        # the drift/reseal branch, which also deletes the plaintext. The gate sits
        # before that branch, so a regressed runtime must block reseal too.
        root, home, backend, store = self._setup(tmp_path)
        assert (
            env_decrypt_cli.enable(
                home=home,
                root=root,
                platform="darwin",
                backend=backend,
                store=store,
                runtime_probe=lambda *, home, runtime_python=None: (True, "ok"),
            )
            == 0
        )
        assert not (home / ".env").exists()  # cleanly sealed first

        (home / ".env").write_bytes(_ENV_B)  # a host write drops a partial plaintext back (drift)
        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=lambda *, home, runtime_python=None: (False, "mordred dropped from the runtime"),
        )
        assert rc == 1
        assert (home / ".env").read_bytes() == _ENV_B  # drift plaintext kept, not deleted by reseal
        out = capsys.readouterr()
        assert "refusing to vault-seal .env" in (out.err + out.out)


class TestRunningGatewayGate:
    """The gate's second check at the CLI boundary: a gateway running from a
    *different* interpreter that cannot inject must block the seal, leaving the
    plaintext and the vault exactly as they were (the 2026-06-25 incident shape).
    """

    def _setup(self, tmp_path: Path) -> tuple[Path, Path, FakeBackend, FakeAnchorStore]:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        return root, home, backend, store

    def _gateway_python(self, tmp_path: Path) -> Path:
        bindir = tmp_path / "repo" / ".venv" / "bin"
        bindir.mkdir(parents=True)
        python = bindir / "python"
        python.write_text("")
        return python

    def test_refuses_when_the_running_gateway_cannot_inject(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root, home, backend, store = self._setup(tmp_path)
        gateway = self._gateway_python(tmp_path)
        monkeypatch.setattr(
            _runtime_gate, "_default_gateway_discovery", lambda *, home: [GatewayRuntime(pid=4242, python=gateway)]
        )
        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            # The expected runtime is fine; the interpreter actually serving the
            # gateway is not — exactly what stranded the operator in the incident.
            runtime_probe=lambda *, home, runtime_python=None: (
                (True, "ok") if runtime_python is None else (False, "mordred_keyvault plugin not registered")
            ),
        )
        assert rc == 1
        assert (home / ".env").read_bytes() == _ENV_A  # plaintext untouched
        assert _vault_env(root, backend, store) is None  # nothing enrolled
        assert not _env_optout_marker_path(home).exists()  # marker untouched
        err = capsys.readouterr().err
        assert "refusing to vault-seal .env" in err
        assert f"{gateway} (pid 4242)" in err

    def test_proceeds_when_the_running_gateway_can_inject(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root, home, backend, store = self._setup(tmp_path)
        gateway = self._gateway_python(tmp_path)
        monkeypatch.setattr(
            _runtime_gate, "_default_gateway_discovery", lambda *, home: [GatewayRuntime(pid=9, python=gateway)]
        )
        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=lambda *, home, runtime_python=None: (True, "ok"),
        )
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A
        assert not (home / ".env").exists()

    def test_force_bypasses_the_running_gateway_check_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root, home, backend, store = self._setup(tmp_path)

        def _never(*, home: Path) -> list[GatewayRuntime]:
            raise AssertionError("--force-runtime-unverified must skip discovery entirely")

        monkeypatch.setattr(_runtime_gate, "_default_gateway_discovery", _never)
        rc = env_decrypt_cli.enable(
            home=home,
            root=root,
            platform="darwin",
            backend=backend,
            store=store,
            runtime_probe=_boom_probe,
            force_runtime_unverified=True,
        )
        assert rc == 0
        assert not (home / ".env").exists()  # sealed anyway, as documented
