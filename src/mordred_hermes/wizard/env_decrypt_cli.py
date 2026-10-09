"""``hermes mordred encryption {enable,disable,purge} env`` — .env at-rest toggle.

The ``.env`` target mirrors config.yaml's toggle but with ``.env``'s memory-only
runtime model: on enable the plaintext is removed (the runtime shim injects the
enrolled copy into ``os.environ`` at startup — see
:mod:`mordred_hermes.keyvault._runtime_env`), so no secret is left at rest.

Three state transitions (not symmetric — documented per verb):

- **enable**  — enroll ``<home>/.env`` into the vault, clear the opt-out marker,
  and (on macOS) remove the plaintext. Off macOS the runtime shim is a no-op, so
  the plaintext is kept to avoid stranding Hermes.
- **disable** — restore a readable plaintext ``<home>/.env`` (decrypting from the
  vault if enable had removed it; never overwriting a diverging on-disk copy) and
  write the opt-out marker so the runtime stops injecting. *Reversible*: the vault
  copy is kept.
- **purge**   — restore the plaintext, ``unenroll_file('.env')`` from the vault,
  and clear the marker. *Destructive*: back to plain, unencrypted.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..keyvault._runtime_env import _env_optout_marker_path
from . import _term
from ._runtime_gate import RuntimeProbe, runtime_gate
from ._vault_open import _vault_present

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from ._flow_session import FlowSession
    from .configure import PromptIO

__all__ = ["disable", "enable", "purge", "reseal"]

_ENV_NAME = ".env"


def _default_runtime_probe(*, home: Path, runtime_python: Path | None = None) -> tuple[bool, str]:
    """Production runtime probe: can the interpreter that runs ``hermes`` decrypt
    a sealed ``.env``? Imported lazily so this module stays import-light.

    ``runtime_python`` pins a specific interpreter — the gate passes it when
    probing an interpreter that is running a gateway *right now*; omitted, the
    probe resolves the expected runtime itself.
    """
    from ..keyvault._runtime_probe import runtime_env_injection_available

    return runtime_env_injection_available(home=home, runtime_python=runtime_python)


def _runtime_gate(
    *,
    home: Path,
    platform: str,
    runtime_probe: RuntimeProbe | None,
    force_runtime_unverified: bool,
) -> int:
    """Fail-closed macOS gate for the destructive seal.

    Returns 1 (after printing actionable guidance) when the interpreter that runs
    ``hermes`` — or one that is running a gateway right now — cannot inject a
    sealed ``.env`` at startup, else 0. A no-op (0) off macOS — the plaintext is
    kept there anyway — and when ``force_runtime_unverified`` is set. The gate
    core is shared with ``config_decrypt_cli`` via
    :func:`._runtime_gate.runtime_gate`; only the .env-specific guidance text
    lives here (it is reused for both the expected-runtime and the
    running-gateway refusal).
    """
    return runtime_gate(
        home=home,
        platform=platform,
        runtime_probe=runtime_probe,
        force_runtime_unverified=force_runtime_unverified,
        default_probe=_default_runtime_probe,
        target=".env",
        mechanism=(
            "  A sealed .env is injected at startup only by the mordred plugin in the\n"
            "  interpreter that runs `hermes`. hermes-mordred is not installed in that\n"
            "  runtime — install the wheel there before sealing the file\n"
        ),
        rerun_tail=(
            "  then re-run `encryption enable env`. To seal anyway (secrets stay\n"
            "  unreadable until the runtime has mordred), pass --force-runtime-unverified."
        ),
    )


def _handle_missing_plaintext(root: Path, home: Path, env_path: Path) -> int:
    """Resolve ``enable`` when there is no plaintext ``<home>/.env`` to enroll.

    Returns 0 — a success **no-op** — when env is already in the sealed steady
    state (enrolled, injection ON, no plaintext at rest): re-running ``enable env``
    (or ``enable all``) must not report "nothing to protect" for something that is
    in fact already enabled. Otherwise returns 1 (genuinely nothing to protect).
    """
    if _env_enrolled(root) and not _env_optout_marker_path(home).exists():
        print(".env is already vault-managed and sealed (no plaintext at rest); nothing to do.")
        return 0
    _term.emit_error(f"no .env at {env_path} — nothing to protect.")
    return 1


#: Legacy reseal temp file. Older ``reseal`` builds staged the merged ``.env``
#: through this 0o600 file before enrolling; the current :func:`reseal` enrolls the
#: merged bytes through a single vault open and never creates it. Kept so the
#: status reader can still flag — and :func:`enable` can still sweep — a leftover
#: one that an interrupted older reseal may have stranded at rest during upgrade.
_RESEAL_TMP_NAME = ".env.reseal.tmp"


def _env_enrolled(root: Path) -> bool:
    """Whether ``.env`` is enrolled per the manifest — cheap, no device unlock.

    Reads the newest manifest's *unverified* plaintext body (the ``files`` keys
    are operational metadata, not secret), so the drift / reseal decision needs
    neither the master key nor a passphrase — the same read
    :func:`.encryption_cli._enrolled_names` does, scoped to ``.env``.
    """
    from .encryption_cli import _enrolled_names

    return _ENV_NAME in _enrolled_names(root)


def _write_optout_marker(home: Path) -> None:
    marker = _env_optout_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("opt-out\n", encoding="utf-8")


def _restore_plaintext(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None,
    store: AnchorStore | None,
    flow_session: FlowSession | None = None,
) -> int:
    """Guarantee a readable plaintext ``<home>/.env`` without losing operator edits.

    - No vault here → nothing enrolled to restore; keep whatever plaintext exists.
    - Vault present, ``.env`` enrolled, plaintext missing → decrypt it back.
    - Vault present, ``.env`` enrolled, plaintext **present** → keep the on-disk
      copy (it is the live one); warn if it diverges from the vault copy rather
      than silently overwriting it.

    Returns 0 normally; 1 only when the plaintext is missing *and* the vault is
    present but cannot be opened to recover it (fail-closed — do not pretend a
    secret is on disk when it is not).
    """
    from ..keyvault import _storage
    from . import vault_cli

    env_path = home / _ENV_NAME
    if not _vault_present(root):
        return 0

    opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store, flow_session=flow_session)
    if opened is None:
        return 0 if env_path.exists() else 1
    with opened:
        if _ENV_NAME not in opened.list_files():
            return 0
        vault_bytes = opened.read_file(_ENV_NAME)

    if env_path.exists():
        if env_path.read_bytes() != vault_bytes:
            _term.emit_warn(
                f".env drift — the on-disk {env_path} differs from the vault copy; "
                "keeping the on-disk one (not overwriting)."
            )
        return 0

    _storage.atomic_write(env_path, vault_bytes)
    return 0


def reseal(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Reconcile a plaintext ``.env`` that reappeared while the vault still seals it.

    Thin CLI-facing wrapper: the actual merge-and-reseal logic is
    ``keyvault``-owned (:func:`mordred_hermes.keyvault._env_reseal.reseal_env`) so
    that :mod:`mordred_hermes.keyvault._env_write_guard` — which runs this same
    reconciliation from the ``on_session_start`` / ``on_session_end`` plugin
    hooks — never has to import ``wizard`` (it used to; a ``keyvault -> wizard``
    layering inversion — see that module's docstring). This function keeps only
    the public name / signature its callers already depend on (:func:`enable`'s
    drift branch below, and the existing ``reseal`` test suite).

    For the macOS sealed state only — callers gate on platform. See
    :func:`mordred_hermes.keyvault._env_reseal.reseal_env` for the full
    contract: a no-op (returns 0) when there is no plaintext, ``.env`` is not
    enrolled, or the env target is in the reversible *disabled* state; returns 1
    when the vault is present but cannot be opened or the re-enroll itself
    fails; on a read-back mismatch or an unremovable plaintext it returns 0 —
    in every non-clean case the plaintext is kept so no secret is stranded.
    """
    from ..keyvault._env_reseal import reseal_env

    return reseal_env(home=home, root=root, backend=backend, store=store)


def _should_reseal_instead(*, platform: str, home: Path, root: Path) -> bool:
    """Whether ``enable`` should merge-reseal instead of enrolling from scratch.

    The caller has already established that a plaintext ``.env`` is on disk;
    this is the remaining test — the vault already manages ``.env``, injection
    is ON (no opt-out marker), and we are on macOS. Together that means a host
    write slipped a *partial* .env past the seal, so re-enrolling it wholesale
    would drop every other enrolled secret; merging is the safe path instead.
    Split out of :func:`enable` for cyclomatic headroom only — same three
    conditions, same order, same short-circuiting.
    """
    return platform == "darwin" and not _env_optout_marker_path(home).exists() and _env_enrolled(root)


def _delete_enrolled_plaintext(env_path: Path, enrolled: bytes | None) -> None:
    """Remove the plaintext ``.env`` after a clean macOS enroll, or explain why not.

    Split out of :func:`enable` for cyclomatic headroom only — the read/compare/
    unlink sequence, both guard conditions, and both warning messages are
    unchanged; this always leaves ``enable`` returning 0 either way (a failure
    here is reported, not propagated as an error code), exactly as before.

    Guards against a concurrent edit between ``add_and_verify()``'s read and
    now (never delete an on-disk copy that no longer matches what was
    enrolled) and against an unlink failure being reported as success while
    the plaintext remains at rest.
    """
    try:
        current: bytes | None = env_path.read_bytes()
    except OSError:
        current = None
    # `enrolled` is bytes whenever add_and_verify returned rc==0, so the None
    # check is a defensive belt-and-suspenders: if that contract ever loosens,
    # fail safe and keep the plaintext rather than delete it unverified.
    if enrolled is None or current != enrolled:
        _term.emit_warn(
            ".env was enrolled but the on-disk copy no longer matches the vault "
            "(changed during enable?) — leaving the plaintext in place; re-run enable."
        )
        return
    try:
        env_path.unlink()
    except OSError as exc:
        _term.emit_warn(
            f".env enrolled but the plaintext at {env_path} could not be removed: {exc} "
            "— remove it by hand (it is still readable at rest)."
        )
        return
    print(".env is now vault-managed; the plaintext was removed (the runtime injects it at startup).")


def enable(
    *,
    home: Path,
    root: Path,
    platform: str,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    prompt_io: PromptIO | None = None,
    runtime_probe: RuntimeProbe | None = None,
    force_runtime_unverified: bool = False,
    flow_session: FlowSession | None = None,
) -> int:
    """Enroll ``<home>/.env`` into the vault and turn runtime injection on.

    If no vault exists yet, one is created first (prompting once for a recovery
    passphrase) — ``encryption enable`` drives the vault, so a fresh install need
    not run ``vault init`` by hand. Returns 0 on success, 1 when there is no
    ``.env`` to protect, the vault cannot be created, or the enroll fails
    (unverifiable vault, device key-store error). On macOS the plaintext is
    removed only after a clean enroll, so a failure never strands the operator
    without a readable ``.env``.

    On macOS the seal is **fail-closed on the runtime**: before any destructive
    step it probes the interpreter that actually runs ``hermes`` (see
    :mod:`...keyvault._runtime_probe`) and refuses (rc 1) when that runtime lacks
    the mordred injection shim — otherwise the deleted plaintext would be
    undecryptable at startup. The same probe is then run against every *running*
    ``hermes gateway`` interpreter from a different environment, because that is
    the process which must unseal the file in practice. ``runtime_probe`` is
    injectable for tests; ``force_runtime_unverified`` bypasses both checks
    (advanced; seals anyway).

    ``flow_session`` (a guided flow: ``setup``, ``encryption enable all``, the
    Telegram / Desktop setup) shares the flow's passphrase, open vault and key
    policy with its other steps, so the flow asks for a passphrase once and
    unlocks the vault at most once (see :mod:`._flow_session`).
    """
    from . import vault_cli

    # Sweep a reseal temp stranded by a prior crash (a 0o600 plaintext at rest):
    # `reseal` removes its own on success/failure, so a leftover is always garbage,
    # and sweeping here makes `encryption enable env` the reliable cleanup remedy.
    (home / _RESEAL_TMP_NAME).unlink(missing_ok=True)

    env_path = home / _ENV_NAME
    if not env_path.is_file():
        return _handle_missing_plaintext(root, home, env_path)

    # Fail-closed runtime check (macOS only): sealing deletes the plaintext and
    # relies on the startup shim to re-inject it — but that shim runs only if the
    # interpreter that actually runs `hermes` has mordred installed. The dev venv
    # driving this command is often NOT that runtime, and the managed runtime venv
    # is recreated (dropping the non-PyPI mordred) on every `hermes` self-update.
    # Gating here — before the reseal branch and the enroll/delete below — covers
    # every destructive path. Off macOS the plaintext is kept anyway, so no gate.
    gate = _runtime_gate(
        home=home, platform=platform, runtime_probe=runtime_probe, force_runtime_unverified=force_runtime_unverified
    )
    if gate != 0:
        return gate

    # Drift reconciliation: the vault already manages .env, injection is ON (no
    # opt-out marker), and we are on macOS, yet a plaintext is on disk. That means
    # a host write slipped a *partial* .env past the seal — re-enrolling it
    # wholesale here would drop every other enrolled secret, so merge instead.
    if _should_reseal_instead(platform=platform, home=home, root=root):
        return reseal(home=home, root=root, backend=backend, store=store)

    rc = vault_cli.ensure_initialised(
        root=root, prompt_io=prompt_io, backend=backend, store=store, flow_session=flow_session
    )
    if rc != 0:
        return rc  # could not create the vault (reason already printed)

    # Enroll and read the enrolled copy back through the *same* vault open, so the
    # device key (Secure Enclave / Touch ID) is unlocked once for both — the
    # pre-delete verify below no longer costs a second prompt.
    rc, enrolled = vault_cli.add_and_verify(
        root=root, name=_ENV_NAME, source=env_path, backend=backend, store=store, flow_session=flow_session
    )
    if rc != 0:
        return rc  # vault_cli.add_and_verify already printed the reason

    _env_optout_marker_path(home).unlink(missing_ok=True)  # injection ON

    if platform == "darwin":
        # Only remove the plaintext if it provably matches the enrolled copy: a
        # concurrent edit between add_and_verify()'s read and now must NOT be
        # deleted unvaulted, and an unlink failure must NOT be reported as success
        # while the plaintext remains at rest.
        _delete_enrolled_plaintext(env_path, enrolled)
    else:
        print(
            ".env enrolled into the vault, but the runtime decrypt shim is macOS-only — the plaintext was "
            "kept so Hermes still reads it on this OS (status: inactive on this OS)."
        )
    return 0


def disable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    flow_session: FlowSession | None = None,
) -> int:
    """Restore a readable plaintext ``.env`` and stop runtime injection (reversible).

    The vault copy is left intact so re-enabling is immediate. Returns 0 on
    success, 1 only when a sealed-away plaintext cannot be recovered from the
    vault (fail-closed). ``flow_session`` (``uninstall``) lends the flow's
    already open vault, so restoring several targets unlocks it once.
    """
    rc = _restore_plaintext(home=home, root=root, backend=backend, store=store, flow_session=flow_session)
    if rc != 0:
        return rc
    _write_optout_marker(home)
    print(".env decryption disabled (opt-out marker written); the vault copy is kept for re-enable.")
    return 0


def purge(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Remove ``.env`` from the vault entirely, restoring the plaintext first.

    Destructive: the encrypted copy is gone afterwards. The vault copy is never
    lost silently — if it is the only copy it is restored to ``<home>/.env``, and
    if the on-disk ``.env`` *diverges* from it the vault copy is saved to a
    ``.env.vault-purged`` sidecar before unenrolling. Returns 0 on success, 1 when
    the vault is present but cannot be opened to recover / unenroll.
    """
    from ..keyvault import _storage, anchor, vault
    from . import vault_cli

    env_path = home / _ENV_NAME

    if _vault_present(root):
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        if opened is None:
            return 0 if env_path.exists() else 1
        with opened:
            try:
                if _ENV_NAME in opened.list_files():
                    vault_bytes = opened.read_file(_ENV_NAME)
                    if not env_path.exists():
                        _storage.atomic_write(env_path, vault_bytes)  # restore the only copy
                    elif env_path.read_bytes() != vault_bytes:
                        backup = home / ".env.vault-purged"
                        _storage.atomic_write(backup, vault_bytes)
                        _term.emit_warn(
                            f"on-disk .env differs from the vault copy — saved the vault copy to {backup} "
                            "before purging (nothing is lost)."
                        )
                    opened.unenroll_file(_ENV_NAME)
            except (vault.VaultError, anchor.AnchorError, OSError) as exc:
                _term.emit_error(f"cannot purge .env from the vault: {exc}")
                return 1

    _env_optout_marker_path(home).unlink(missing_ok=True)
    print(".env purged from the vault; the plaintext is on disk and unencrypted.")
    return 0
