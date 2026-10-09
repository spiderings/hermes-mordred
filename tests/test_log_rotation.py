"""Unit tests for the shared audit-log rotation/timestamp/retention helpers.

Covers :mod:`mordred_hermes._log_rotation` -- the pure-stdlib module that
single-sources what used to be near-verbatim duplicated across
``privacy_check.audit``, ``keyvault.log_encryption``, and
``wizard.openclaw_migration``:

* :func:`utcnow_iso` / :func:`today_utc_date` -- format shape.
* :func:`next_rotation_target` -- collision-free rotation targets, proven
  byte-identical to ``keyvault.log_encryption``'s pre-refactor inline
  collision loop across a table of existing-file scenarios.
* :func:`sweep_retention` -- age-based deletion of rotated siblings.
* :func:`rotate_and_compress` -- the whole rotate-then-gzip-then-sweep body,
  which ``privacy_check.audit`` and ``keyvault.log_encryption`` carried
  byte-for-byte identical copies of apart from the logger they warned on.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mordred_hermes._log_rotation import (
    next_rotation_target,
    rotate_and_compress,
    sweep_retention,
    today_utc_date,
    utcnow_iso,
)

_ISO_MS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# --------------------------------------------------------------------------- #
# utcnow_iso / today_utc_date -- format shape                                 #
# --------------------------------------------------------------------------- #


def test_utcnow_iso_matches_millisecond_iso_shape() -> None:
    assert _ISO_MS_RE.match(utcnow_iso())


def test_utcnow_iso_is_close_to_wall_clock() -> None:
    # utcnow_iso() truncates (not rounds) microseconds down to milliseconds,
    # so the parsed timestamp can read up to ~1ms *earlier* than `before`
    # even though it was sampled after it -- hence the small lower-bound slack.
    before = datetime.now(UTC)
    stamped = datetime.strptime(utcnow_iso(), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    after = datetime.now(UTC)
    assert before - timedelta(milliseconds=1) <= stamped <= after + timedelta(seconds=1)


def test_today_utc_date_matches_date_shape() -> None:
    assert _DATE_RE.match(today_utc_date())


def test_today_utc_date_matches_wall_clock_date() -> None:
    assert today_utc_date() == datetime.now(UTC).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
# next_rotation_target -- collision-free suffix picking                       #
# --------------------------------------------------------------------------- #


def _old_inline_collision_loop(path: Path, date_suffix: str) -> Path:
    """Reproduces ``keyvault.log_encryption._rotate``'s PRE-refactor inline loop.

    Kept here (rather than re-imported, since it no longer exists in
    ``log_encryption.py`` after the refactor) purely to prove that
    :func:`next_rotation_target` computes the identical target for every
    scenario in :data:`_ROTATION_SCENARIOS` -- i.e. the collapse in
    ``log_encryption.py::_rotate`` was behavior-preserving.
    """
    target = path.with_name(f"{path.name}.{date_suffix}")
    n = 0
    while target.exists() or target.with_suffix(target.suffix + ".gz").exists():
        n += 1
        target = path.with_name(f"{path.name}.{date_suffix}.{n}")
    return target


def test_no_existing_file_returns_unsuffixed_target(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    target = next_rotation_target(log, "2026-05-16")
    assert target == tmp_path / "audit.log.2026-05-16"


def test_plain_collision_bumps_to_numeric_suffix(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    (tmp_path / "audit.log.2026-05-16").write_text("x")
    target = next_rotation_target(log, "2026-05-16")
    assert target == tmp_path / "audit.log.2026-05-16.1"


def test_gz_collision_also_bumps_the_suffix(tmp_path: Path) -> None:
    # A prior rotation that was already gzipped must still be skipped, even
    # though the un-suffixed .gz sibling (not the raw file) is what exists.
    log = tmp_path / "audit.log"
    (tmp_path / "audit.log.2026-05-16.gz").write_text("x")
    target = next_rotation_target(log, "2026-05-16")
    assert target == tmp_path / "audit.log.2026-05-16.1"


def test_chained_collisions_skip_every_taken_suffix(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    (tmp_path / "audit.log.2026-05-16").write_text("x")
    (tmp_path / "audit.log.2026-05-16.1.gz").write_text("x")
    (tmp_path / "audit.log.2026-05-16.2").write_text("x")
    target = next_rotation_target(log, "2026-05-16")
    assert target == tmp_path / "audit.log.2026-05-16.3"


_ROTATION_SCENARIOS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("no prior rotation", ()),
    ("raw same-day collision", ("audit.log.2026-05-16",)),
    ("gzipped same-day collision", ("audit.log.2026-05-16.gz",)),
    ("both raw and gz for the base suffix", ("audit.log.2026-05-16", "audit.log.2026-05-16.gz")),
    (
        "chain of three prior rotations",
        ("audit.log.2026-05-16", "audit.log.2026-05-16.1.gz", "audit.log.2026-05-16.2"),
    ),
    ("unrelated file with a similar prefix is ignored", ("audit.log.2026-05-1X-not-a-rotation",)),
    ("different date suffix does not collide", ("audit.log.2026-05-17",)),
)


def test_next_rotation_target_matches_old_inline_loop_for_every_scenario(tmp_path: Path) -> None:
    """Byte-identity proof: new helper == old ``log_encryption`` inline loop.

    For each existing-file scenario, seed the SAME directory tree twice (in
    isolated subdirectories) and assert the shared helper and the reproduced
    pre-refactor inline loop compute the identical rotation target -- this is
    exactly the equivalence the refactor plan required verifying before
    collapsing ``log_encryption._rotate``'s inline loop onto the shared call.
    """
    for name, existing in _ROTATION_SCENARIOS:
        new_dir = tmp_path / f"new_{name.replace(' ', '_')}"
        old_dir = tmp_path / f"old_{name.replace(' ', '_')}"
        new_dir.mkdir()
        old_dir.mkdir()
        for fname in existing:
            (new_dir / fname).write_text("x")
            (old_dir / fname).write_text("x")

        new_target = next_rotation_target(new_dir / "audit.log", "2026-05-16")
        old_target = _old_inline_collision_loop(old_dir / "audit.log", "2026-05-16")

        assert new_target.name == old_target.name, name


# --------------------------------------------------------------------------- #
# sweep_retention -- age-based deletion of rotated siblings                   #
# --------------------------------------------------------------------------- #


def test_sweep_retention_deletes_files_older_than_cutoff(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    old = tmp_path / "audit.log.2025-01-01.gz"
    old.write_bytes(b"\x1f\x8b" + b"\0" * 10)
    ancient = (datetime.now(UTC) - timedelta(days=35)).timestamp()
    os.utime(old, (ancient, ancient))

    sweep_retention(log, retention_days=30)
    assert not old.exists()


def test_sweep_retention_keeps_recent_files(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    recent = tmp_path / "audit.log.2026-06-01.gz"
    recent.write_bytes(b"\x1f\x8b" + b"\0" * 10)
    recent_ts = (datetime.now(UTC) - timedelta(days=2)).timestamp()
    os.utime(recent, (recent_ts, recent_ts))

    sweep_retention(log, retention_days=30)
    assert recent.exists()


def test_sweep_retention_ignores_files_without_matching_prefix(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    unrelated = tmp_path / "other.log.2020-01-01.gz"
    unrelated.write_bytes(b"x")
    ancient = (datetime.now(UTC) - timedelta(days=999)).timestamp()
    os.utime(unrelated, (ancient, ancient))

    sweep_retention(log, retention_days=30)
    assert unrelated.exists(), "sweep must only touch <name>.* siblings, never unrelated files"


def test_sweep_retention_tolerates_file_removed_between_iterdir_and_stat(tmp_path: Path) -> None:
    """A file that vanishes mid-sweep (e.g. a concurrent cleanup) is skipped, not raised."""
    log = tmp_path / "audit.log"
    victim = tmp_path / "audit.log.2020-01-01.gz"
    victim.write_bytes(b"x")

    real_stat = Path.stat

    def flaky_stat(self: Path, *args: object, **kwargs: object) -> object:
        if self == victim:
            raise FileNotFoundError(victim)
        return real_stat(self, *args, **kwargs)  # type: ignore[arg-type]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Path, "stat", flaky_stat)
        sweep_retention(log, retention_days=30)  # must not raise

    # The file itself was never actually removed by the sweep (only its
    # stat() was intercepted), so it is still present afterward.
    assert victim.exists()


# --------------------------------------------------------------------------- #
# rotate_and_compress -- the shared rotate/gzip/sweep body                    #
# --------------------------------------------------------------------------- #


def test_rotate_and_compress_gzips_aside_and_leaves_the_active_path_free(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    log.write_bytes(b'{"ts":"x"}\n')

    rotate_and_compress(log, "2026-05-16", retention_days=30, log=logging.getLogger("test.rotate"))

    assert not log.exists()
    assert (tmp_path / "audit.log.2026-05-16.gz").is_file()
    assert not (tmp_path / "audit.log.2026-05-16").exists()


def test_rotate_and_compress_is_a_no_op_when_there_is_nothing_to_rotate(tmp_path: Path) -> None:
    rotate_and_compress(tmp_path / "audit.log", "2026-05-16", retention_days=30, log=logging.getLogger("test.rotate"))
    assert list(tmp_path.iterdir()) == []


def test_rotate_and_compress_sweeps_expired_siblings(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    log.write_bytes(b"active\n")
    stale = tmp_path / "audit.log.2020-01-01.gz"
    stale.write_bytes(b"old")
    old = (datetime.now(UTC) - timedelta(days=99)).timestamp()
    os.utime(stale, (old, old))

    rotate_and_compress(log, "2026-05-16", retention_days=30, log=logging.getLogger("test.rotate"))

    assert not stale.exists()
    assert (tmp_path / "audit.log.2026-05-16.gz").is_file()


def test_rotate_and_compress_keeps_the_raw_file_and_warns_on_the_callers_logger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A gzip failure loses nothing, and the warning carries the *caller's* logger.

    The logger is the one thing the two former copies did not share
    (``mordred.privacy_check.audit`` vs ``mordred.keyvault.log_encryption``), so
    it must stay caller-supplied rather than becoming this module's own.
    """
    from mordred_hermes import _log_rotation

    def failing_gzip(source: Path, target: Path) -> None:
        raise OSError("gzip exploded")

    monkeypatch.setattr(_log_rotation, "compress_rotated_file", failing_gzip)

    log = tmp_path / "audit.log"
    log.write_bytes(b"payload\n")

    with caplog.at_level(logging.WARNING, logger="test.caller.logger"):
        rotate_and_compress(log, "2026-05-16", retention_days=30, log=logging.getLogger("test.caller.logger"))

    assert [record.name for record in caplog.records] == ["test.caller.logger"]
    assert "audit gzip rotation failed" in caplog.text
    # The rotated content survived un-gzipped -- nothing was lost.
    assert (tmp_path / "audit.log.2026-05-16").read_bytes() == b"payload\n"


def test_rotate_and_compress_fails_closed_when_the_path_is_swapped_mid_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The inode re-check is what stops a fresh active file landing on a foreign inode."""
    log = tmp_path / "audit.log"
    log.write_bytes(b"payload\n")
    impostor = tmp_path / "impostor"
    impostor.write_bytes(b"not ours\n")

    real_replace = os.replace

    def replace_then_swap(src: object, dst: object) -> None:
        real_replace(src, dst)  # type: ignore[arg-type]
        real_replace(impostor, dst)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", replace_then_swap)

    with pytest.raises(OSError, match="audit path changed during rotation"):
        rotate_and_compress(log, "2026-05-16", retention_days=30, log=logging.getLogger("test.rotate"))
