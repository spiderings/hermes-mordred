"""Explicitly gated ordinary-user CNG custody in a new retained task profile.

Set MORDRED_TEST_WINDOWS_CUSTODY_LIVE=1 and MORDRED_WINDOWS_CUSTODY_TEST_ROOT
only in an authorized Windows native validation run. The root must already
exist; each run creates a UUID child. Failure preserves that child and journals
for explicit reconciliation. No existing fixture keys or user profiles are used.
"""

from __future__ import annotations

import hmac
import os
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("MORDRED_TEST_WINDOWS_CUSTODY_LIVE") != "1",
    reason="explicit ordinary-user Windows TPM custody validation only",
)
def test_real_cng_memory_and_independent_audit_custody_survive_new_session():
    from mordred_hermes._private_fs import open_confidential_directory, open_private_directory
    from mordred_hermes.keyvault._runtime_probe import require_stopped_windows_gateways
    from mordred_hermes.keyvault._windows_custody import windows_custody_session

    value = os.environ.get("MORDRED_WINDOWS_CUSTODY_TEST_ROOT")
    if not value:
        pytest.fail("a retained isolated validation root is required")
    root = Path(value)
    with open_confidential_directory(root):
        pass
    home = root / ("custody-" + uuid.uuid4().hex)
    require_stopped_windows_gateways(home)
    print(f"Isolated custody fixture: {home}")
    with windows_custody_session(home, create=True) as session:
        key = session.enroll_memory()
        memory = session.lease("memory")
        audit = session.enroll_role("audit")
        matches = hmac.compare_digest(session.load_memory_key(), key)
        assert matches, "memory custody roundtrip failed"
    with windows_custody_session(home) as session:
        matches = hmac.compare_digest(session.load_memory_key(), key)
        assert matches, "memory custody roundtrip failed"
        session.validate_lease(memory)
        session.backend_for(audit)
    # No hooks were armed and no memory was written; explicit opt-out satisfies
    # the same checked purge precondition a completed disable ceremony supplies.
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("memory-vault.optout", b"1\n")
    with windows_custody_session(home) as session:
        session.delete_role(memory)
        assert session.resolve_memory_key() is None
        session.validate_lease(audit)
        session.delete_role(audit, erase_authorized=True)
    # Successful native cleanup leaves only checked empty ownership/lock state.
    with windows_custody_session(home) as session:
        assert session.resolve_memory_key() is None
