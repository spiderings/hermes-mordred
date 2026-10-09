"""Closed audit-log reason vocabulary.

``ReasonCode`` is deliberately a ``Literal`` so mypy catches drift between
emit sites and consumers. ``docs/dev/POLICY.md`` owns the current meaning and
live/reserved status of all 31 values. Existing strings are compatibility
surfaces: add or retire behavior without renaming an established code.

Two values are reserved and have no current emit site:

- ``policy.strict.local_stream_interrupted`` — no reliable plugin-side
  streaming-interruption seam exists.
- ``policy.strict.provider_override_at_session_start`` — current strict LLM
  behavior refuses; it does not replace the provider.

``policy.strict.unconditional_override`` is also a legacy name, but it remains
live for an unresolved-provider refusal. Its name must not be read as evidence
that an override occurred.
"""

from typing import Literal

ReasonCode = Literal[
    "policy.strict.clearnet",
    "policy.strict.unknown_metadata",
    "policy.strict.unconditional_override",
    "policy.strict.cloud_not_allowlisted",
    "policy.strict.cloud_allowlisted",
    "policy.strict.cloud_endpoint_mismatch",
    "policy.strict.cloud_prompted_allow",
    "policy.strict.cloud_prompted_deny",
    "policy.lenient.unknown_metadata_warning",
    "mordred.degraded.disable_unprotected",
    "mordred.degraded.no_origin_skill",
    "mordred.degraded.no_resolved_provider",
    "policy.strict.local_stream_interrupted",
    "policy.strict.session_refused",
    "policy.strict.provider_override_at_session_start",
    "network.use",
    "network.use_failed",
    "network.bringup_failed",
    "network.path_dropped",
    "network.transport_incompatible",
    "keyvault.recovery_digest_mismatch",
    "keyvault.seed_display_aborted_screenshot",
    "keyvault.unwrap_authorized",
    "keyvault.unwrap_denied",
    "keyvault.init_started",
    "keyvault.init_completed",
    "keyvault.init_denied",
    "keyvault.backup_exported",
    "policy.strict.keyvault_uninitialized",
    "policy.lenient.keyvault_uninitialized_warning",
    "mordred.degraded.audit_encryption_unavailable",
    "policy.egress.tool_blocked",
]
