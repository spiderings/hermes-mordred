"""Branch coverage for the shared hot-path open-failure reporter.

Clause order is load-bearing: ``AnchorMismatch`` / ``AnchorCorrupt`` must be
matched before their ``AnchorError`` base or a rollback / tamper event would be
flattened into the generic "cannot open vault" message.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import anchor
from mordred_hermes.keyvault._exceptions import WrapError
from mordred_hermes.keyvault._vault_open_report import report_hot_open_failure


@pytest.mark.parametrize("exc_type", [anchor.AnchorMismatch, anchor.AnchorCorrupt])
def test_freshness_failures_are_reported_as_possible_tampering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], exc_type: type[anchor.AnchorError]
) -> None:
    with report_hot_open_failure(tmp_path):
        raise exc_type("pin differs")
    err = capsys.readouterr().err
    assert "possible tampering" in err
    assert "pin differs" in err
    assert str(tmp_path) in err


def test_generic_anchor_error_gets_the_generic_message(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with report_hot_open_failure(tmp_path):
        raise anchor.AnchorError("boom")
    err = capsys.readouterr().err
    assert "cannot open vault at" in err
    assert "possible tampering" not in err


def test_missing_anchor_points_at_vault_init(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with report_hot_open_failure(tmp_path):
        raise anchor.AnchorMissing("no anchor")
    assert "run `vault init` first" in capsys.readouterr().err


def test_device_key_store_failure_names_the_key_store(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with report_hot_open_failure(tmp_path):
        raise WrapError("enclave unavailable")
    err = capsys.readouterr().err
    assert "device key store error" in err
    assert "enclave unavailable" in err


def test_unlisted_exceptions_propagate_untouched(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(RuntimeError, match="not ours"), report_hot_open_failure(tmp_path):
        raise RuntimeError("not ours")
    assert capsys.readouterr().err == ""
