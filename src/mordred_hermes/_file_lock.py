"""Shared private-lockfile + ``flock`` primitive -- root pure-stdlib module.

Single-sources the cross-process mutex body that was independently
copy-pasted, near-verbatim, across four call sites:

* :func:`mordred_hermes.extension.pairing._state_lock` -- the
  ``~/.hermes/extension/.lock`` mutex guarding ``pending.json`` /
  ``state.json`` read-modify-write cycles.
* :func:`mordred_hermes.wizard.env_file_writer._dotenv_lock` -- the
  ``~/.hermes/.env.lock`` mutex shared by every Mordred dotenv writer.
* :func:`mordred_hermes.wizard.policy_writer._policy_write_lock` -- the
  ``.policy-write.lock`` mutex serializing ``config.yaml`` / ``policy.json``
  transactions.
* :func:`mordred_hermes.keyvault._extension_config._wallet_file_lock` -- the
  ``~/.hermes/extension/.wallet.lock`` mutex added for ``wallet.json``.

What is shared is exactly the security-critical file-descriptor lifecycle,
which every copy had to get right independently:

1. ``os.open`` with ``O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW`` (plus
   ``O_NONBLOCK`` where the original used it) at mode ``0o600`` -- a symlinked
   or pre-planted lock path is refused by the kernel, the descriptor is not
   inherited across ``exec``, and a raced FIFO cannot block the open.
2. ``fstat`` on the *opened descriptor* (never the path) asserting a regular
   file at exactly mode ``0o600`` -- so a lock file an attacker widened or
   swapped for a directory/device fails closed instead of granting a mutex
   that excludes nobody.
3. ``flock(LOCK_EX)`` -> ``yield`` -> ``flock(LOCK_UN)`` -> ``os.close``, with
   the unlock in a ``finally`` nested *inside* the close ``finally`` so an
   exception raised by the body still releases the lock before the descriptor
   goes away.

What is **not** shared is everything the copies genuinely disagree on, because
folding those differences into this module would have meant weakening one call
site to match another:

* The in-process ``threading.RLock`` (and ``policy_writer``'s reentrancy-depth
  bookkeeping) stays at the call site -- ``_wallet_file_lock`` deliberately has
  none, and ``policy_writer``'s depth counter is specific to its nested
  transactions.
* Creating / validating the parent directory stays at the call site --
  ``pairing`` goes through ``_ext_dir()``, the wizard writers through
  ``_ensure_real_directory``, and ``_extension_config``'s caller has already
  run ``_validate_extension_dir``.
* Every raised exception stays byte-identical in type, ``args`` and ``errno``.
  The copies disagree here in ways no single message could cover:
  ``OSError("extension state lock must be a mode-0600 regular file")`` (one
  arg, ``errno is None``) vs ``OSError(errno.EPERM, "dotenv lock must be a
  mode-0600 regular file", str(lock_path))`` vs a ``WalletConfigError``
  carrying a deliberately content-free message. So each failure point is a
  ``NoReturn`` callback owned by the importing module, invoked from the same
  ``try`` / ``except`` position the original ``raise`` occupied -- which also
  preserves each one's exception chaining (``raise ... from exc`` where the
  original had it, implicit ``__context__`` where it did not, and a bare
  re-raise of the original ``OSError`` where the copy never wrapped it).

``fcntl`` stays optional exactly as in every copy (``if fcntl is not None``),
so importers remain importable on platforms that lack it; there the context
manager degrades to the same "open + mode check, no advisory lock" behaviour
the originals had.
"""

from __future__ import annotations

import contextlib
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Final, NoReturn

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]

#: Every Mordred lock file is private to the owning user, both at creation
#: (the ``os.open`` mode argument) and on the post-open ``fstat`` assertion.
LOCK_MODE: Final = 0o600

_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)

#: Raised-by-the-caller hooks. They return :data:`typing.NoReturn` rather than
#: an exception instance so the ``raise`` statement itself stays in the
#: importing module, keeping both the exception type/args and its ``__cause__``
#: / ``__context__`` chaining exactly as that module produced them before.
UnsafeLockHandler = Callable[[Path], NoReturn]
LockOSErrorHandler = Callable[[Path, OSError], NoReturn]


@contextlib.contextmanager
def private_flock(
    lock_path: Path,
    *,
    on_unsafe: UnsafeLockHandler,
    nonblock: bool = True,
    on_open_error: LockOSErrorHandler | None = None,
    on_lock_error: LockOSErrorHandler | None = None,
    suppress_unlock_errors: bool = False,
) -> Iterator[None]:
    """Hold an exclusive ``flock`` on a private (mode-0600, regular) lock file.

    ``lock_path``'s parent must already exist and be trustworthy: this helper
    owns the descriptor, not the directory (see the module docstring).

    :param on_unsafe: invoked when the opened descriptor is not a regular file
        at mode ``0o600``. Must raise — every handler here is ``NoReturn``, and
        one that returns anyway is refused with :exc:`RuntimeError` rather than
        letting the guarded body run without a validated lock.
    :param nonblock: add ``O_NONBLOCK`` to the open flags. ``True`` for the
        three writers that used it; ``False`` for ``_wallet_file_lock``, which
        never did.
    :param on_open_error: invoked when ``os.open`` fails. ``None`` re-raises
        the original :exc:`OSError` unchanged (``pairing``'s behaviour).
    :param on_lock_error: invoked when ``flock(LOCK_EX)`` fails. ``None``
        propagates the original :exc:`OSError` unchanged.
    :param suppress_unlock_errors: swallow an :exc:`OSError` from the
        ``flock(LOCK_UN)`` in the exit path (``_wallet_file_lock``'s
        behaviour). The descriptor is closed either way, which releases the
        advisory lock regardless.
    """
    flags = os.O_RDWR | os.O_CREAT | _O_CLOEXEC | _O_NOFOLLOW
    if nonblock:
        flags |= _O_NONBLOCK
    try:
        fd = os.open(lock_path, flags, LOCK_MODE)
    except OSError as exc:
        if on_open_error is None:
            raise
        on_open_error(lock_path, exc)
        _handler_returned("on_open_error")
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != LOCK_MODE:
            on_unsafe(lock_path)
            _handler_returned("on_unsafe")
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as exc:
                if on_lock_error is None:
                    raise
                on_lock_error(lock_path, exc)
                _handler_returned("on_lock_error")
        try:
            yield
        finally:
            _unlock(fd, suppress=suppress_unlock_errors)
    finally:
        os.close(fd)


def _handler_returned(name: str) -> NoReturn:
    """Structural backstop: a failure handler that *returns* is itself a failure.

    The handler types are ``NoReturn`` and ``mypy --strict`` enforces that at
    the four call sites, but a lambda or a ``# type: ignore`` could still
    return — and returning would run the guarded read-modify-write with no
    validated lock held. Fail closed instead of falling through.
    """
    raise RuntimeError(f"{name} returned instead of raising; refusing to proceed without a valid lock")


def _unlock(fd: int, *, suppress: bool) -> None:
    """Release the advisory lock; a no-op where ``fcntl`` is unavailable.

    With ``suppress`` an :exc:`OSError` from ``LOCK_UN`` is swallowed (the
    wallet lock's behaviour); otherwise it propagates. Either way the caller
    closes the descriptor next, which releases the lock regardless.
    """
    if fcntl is None:
        return
    if suppress:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
