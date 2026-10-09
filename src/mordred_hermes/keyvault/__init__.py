"""mordred_keyvault — hardware-backed key and at-rest secret management.

The public API covers key generation, envelope encryption, backup/recovery,
vault lifecycle, audit-log encryption, and extension wallet signing. At plugin
registration time this module installs the transparent environment decrypt
shim, the agent-memory encryption hook, the host ``.env`` write guard, the
shared integrity gate, and best-effort session-boundary resealing.

Native protection is selected by capability: Secure Enclave on supported
macOS systems and TPM 2.0 through the packaged helper on Linux. Pure crypto and
storage layers remain cross-platform and accept injected backends for tests.
"""

import contextlib
from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point.

    Installs the agent-memory encryption hook FIRST: it wraps upstream's
    ``tools/memory_tool.py`` read/write seam so ``~/.hermes/memories/*.md`` are
    AES-256-GCM sealed at rest under ``HERMES_MEMORY_KEY``. It goes before the
    fail-closed env shim below because that shim's deliberate raise must not cost
    the memory seam its wrapper — an unwrapped seam truncates sealed files.
    Arming and the key are read per call, so the order against the key injection
    does not matter. Fail-closed, and deliberately not wrapped in a swallowing
    ``try``/``except``: its one deliberate refusal stops the process (an armed
    operator whose memory seam cannot be wrapped must not start and overwrite
    sealed files), and any other exception is a bug that must keep its traceback.
    A no-op where the operator has not opted in. The ``.pth`` bootstrap arms the
    same installation through a post-import hook, for processes that never reach
    plugin discovery. Immediately after it, the journey-mutation guard is installed
    for the mirror-image case: a process that reaches plugin discovery but that the
    ``.pth`` gate never engaged in (see :func:`_install_journey_guard`).

    Then installs the runtime env transparent-decrypt shim (design note §8.2 item 3):
    on macOS, secrets enrolled in the at-rest vault are decrypted and injected
    into ``os.environ`` at startup, so an unattended process reads them from the
    vault instead of plaintext on disk. Fail-closed — a present-but-unverifiable
    vault raises rather than starting with unverified secret provisioning. A no-op
    where no vault is set up or off macOS.

    Also installs the write-side guard: it wraps the host ``.env`` writer so a
    ``hermes config set`` / setup write made while the env target is sealed is
    resealed back into the vault (merged, not clobbered) instead of leaving a
    partial plaintext at rest. Best-effort and fail-open — it must never break
    startup or a host config write (unlike the fail-closed read shim above).

    Finally, registers a session-boundary reseal sweep on ``on_session_start`` and
    ``on_session_end``: the read shim injects from the vault but never deletes an
    on-disk plaintext, and the write guard only catches writes through the host
    writer — so a plaintext left by another path (e.g. ``gateway setup``) would
    stay ``[exposed]`` until a manual ``encryption enable env``. The sweep heals it
    automatically at each session boundary (macOS only, opt-out-aware, fail-open).
    A resealed *changed* value takes effect for the next process; the running
    process keeps whatever the read shim injected at startup.

    Also on ``on_session_start``, reports a sealed memory this process cannot
    open: upstream's ``agent_init`` swallows a failed ``load_from_disk()``, so
    without it a locked memory looks exactly like an empty one.
    """
    from ._memory_hook import install_memory_hook

    install_memory_hook()
    _install_journey_guard()

    from ._runtime_env import install_vault_env_decrypt

    install_vault_env_decrypt()

    from ..privacy_check.hooks import check_plugin_integrity

    # This gate is intentionally not best-effort: every live runtime sibling
    # must still detect when privacy_check itself was explicitly disabled.
    ctx.register_hook("on_session_start", check_plugin_integrity)

    try:
        from ._env_write_guard import install_env_write_guard

        install_env_write_guard()
    except Exception:  # fail-open: never break startup — but leave a debug breadcrumb
        import logging

        logging.getLogger(__name__).debug("env write guard not installed", exc_info=True)

    # Heal stray plaintext `.env` drift at session boundaries. Best-effort and
    # fail-open: a missing or rejecting ``register_hook`` (older / vendored host)
    # must never break startup, and each hook registers independently.
    for _hook_name in ("on_session_start", "on_session_end"):
        with contextlib.suppress(Exception):
            ctx.register_hook(_hook_name, _on_session_reseal)

    with contextlib.suppress(Exception):
        ctx.register_hook("on_session_start", _on_session_memory_check)


def _install_journey_guard() -> None:
    """Guard the journey mutations from ``register()`` as well as from the import hook.

    ``agent/learning_graph`` indexes memory chunks by their RAW file offsets while
    ``delete_node`` / ``edit_node`` mutate through the decrypted seam, so over a
    sealed file the two views disagree and deleting the one garbage card the UI
    shows removes a real entry. The ``.pth`` import hook covers that, but only in a
    process it engaged in — a host that never matched the ``.pth`` gate, or an
    embedded caller, reaches ``register()`` and nothing else.

    Fail-open and lazy, unlike the memory seam above: a missing or refactored
    ``agent.learning_mutations`` is a silent no-op (the guard is defence in depth —
    the read seam already refuses to hand a sealed file back as entries), and a
    guard problem must never break startup.

    Importing the module here is the same trade ``_load_memory_tool`` already
    makes: ``register()`` runs inside plugin discovery, well after the host has
    imported ``agent``, and this module is pure stdlib at import time.
    """
    try:
        import importlib

        from ._memory_hook import install_journey_guard

        install_journey_guard(importlib.import_module("agent.learning_mutations"))
    except Exception:
        import logging

        logging.getLogger(__name__).debug("journey guard not installed", exc_info=True)


def _on_session_memory_check(**_kwargs: Any) -> None:
    """``on_session_start`` callback: warn once when agent memory is sealed but locked.

    Fail-open — a diagnosis must never break a session boundary."""
    with contextlib.suppress(Exception):
        from ._memory_hook import warn_when_memory_is_locked

        warn_when_memory_is_locked()


def _on_session_reseal(**_kwargs: Any) -> None:
    """``on_session_start`` / ``on_session_end`` callback: reseal a stray plaintext
    ``.env`` back into the vault. Fail-open — a reseal problem must never break a
    session boundary (mirrors the write guard's swallow)."""
    with contextlib.suppress(Exception):
        from ._env_write_guard import reseal_stray_env_if_present

        reseal_stray_env_if_present()
