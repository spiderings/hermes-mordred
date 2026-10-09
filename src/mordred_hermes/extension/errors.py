"""Stable, client-visible error codes for the extension WebSocket API.

Handlers used to place ``str(exc)`` straight into a reply. Most of the
exceptions that reach those handlers are deliberate, reviewed wire codes
(``rpc_endpoint_not_allowed``, ``wallet_signer_changed``, …), but the same
paths also carry text nobody reviewed: OS errors naming ``~/.hermes`` paths, an
injected chat handler's internal message, a proxied RPC failure. The page
principal is a browser document, so anything returned there is one XSS or one
screenshot away from being read by something other than the operator.

This module keeps the useful half and drops the rest: a code is echoed only if
it is on the reviewed allowlist for the CALL SITE that caught it, and the
discarded detail is logged server-side, where diagnosing it belongs.

The allowlist is per-context because the recognizer is a message-prefix match:
without scoping, an exception whose message merely *starts* with an allowlisted
code would be echoed as that code. That matters exactly where the exception text
is not ours — the injected chat handler is an agent, and an agent's message is
influenced by whatever it just read. It leaks nothing (only a code crosses the
wire), but a chat turn should not be able to answer with ``wallet_signer_changed``.
Scoping keeps each site to the codes its own callees actually raise; an unknown
context echoes nothing.
"""

from __future__ import annotations

import logging

_log = logging.getLogger(__name__)

# Deliberate wire codes raised by ``wallet``/``rpc`` and by
# ``keyvault.extension_sign``. Each is the ``<code>`` half of the project's
# ``<code>: <human detail>`` exception convention; the detail half is dropped.
_SIGN_CODES = frozenset(
    {
        # extension.wallet — request preparation
        "invalid_personal_sign_params",
        "invalid_eth_signTypedData_v4_params",
        "personal_sign_account_mismatch",
        "eth_signTypedData_v4_account_mismatch",
        "invalid_chain_id",
        "invalid_transaction_params",
        "transaction_chain_id_not_allowed",
        "transaction_chain_id_mismatch",
        "transaction_from_mismatch",
        "rpc_endpoint_not_allowed",
        "transaction_rpc_required",
        "unsupported_method",
        # extension.wallet — approval-time signing
        "missing_expected_signer",
        "signer_snapshot_mismatch",
        "wallet_signer_changed",
        "signature_signer_verification_failed",
        "transaction_signer_mismatch",
        "transaction_snapshot_not_canonical",
        "broadcast_failed",
        # keyvault.extension_sign — transaction validation
        "invalid_transaction",
        "invalid_transaction_address",
        "invalid_transaction_chain_id",
        "invalid_transaction_data",
        "invalid_transaction_quantity",
        "negative_transaction_quantity",
        "conflicting_transaction_fee_fields",
        "transaction_access_list_requires_type_2",
        "transaction_priority_fee_exceeds_max_fee",
        "unsupported_transaction_access_list",
        "unsupported_transaction_fields",
        "unsupported_transaction_type",
        # extension.rpc
        "invalid_rpc_url",
        "rpc_chain_id_mismatch",
        "rpc_eip1559_unavailable",
        "rpc_error",
        "rpc_http_error",
        "rpc_invalid_response",
        "rpc_redirect_refused",
        "rpc_request_failed",
        "rpc_response_too_large",
        "rpc_routing_unavailable",
    }
)

# ``chat.py`` wraps a failed agent build as ``agent_unavailable: <detail>``;
# nothing else on that path has a reviewed code.
_CHAT_CODES = frozenset({"agent_unavailable"})

# ``accounts_request`` and ``slack_setup`` raise no coded exceptions of their
# own: both are classified by exception TYPE (below) or fall back.
_CODES_BY_CONTEXT = {
    "chat": _CHAT_CODES,
    "sign_request": _SIGN_CODES,
    "sign_approve": _SIGN_CODES,
    "accounts_request": frozenset[str](),
    "slack_setup": frozenset[str](),
}

# Exceptions whose *message* is prose (operator instructions, missing-field
# lists) but whose *type* is a meaningful outcome for the client.
_SAFE_EXCEPTION_CODES = {
    "WalletConfigError": "wallet_config_invalid",
    "WalletNotConfigured": "wallet_not_configured",
    "TransactionFieldsMissing": "transaction_fields_missing",
}


def wire_error_code(exc: BaseException, *, fallback: str, context: str) -> str:
    """Return a reviewed error code for *exc*; log whatever is dropped.

    ``fallback`` is returned for anything unrecognized (and for any context not
    listed in ``_CODES_BY_CONTEXT``), so a new — or injected — exception message
    can never reach a client by default.
    """
    code = str(exc).split(":", 1)[0].strip()
    if code in _CODES_BY_CONTEXT.get(context, frozenset[str]()):
        return code
    for name in _exception_names(exc):
        mapped = _SAFE_EXCEPTION_CODES.get(name)
        if mapped is not None:
            _log.warning("extension %s: %s (reported as %s)", context, name, mapped)
            return mapped
    if _is_replayed_failure(exc):
        # A cached failure replayed inside its cooldown window: the traceback
        # was already logged when the underlying call actually failed. Logging
        # it again per request is how one broken wallet fills a disk.
        _log.warning("extension %s failed again within its cooldown (reported as %r)", context, fallback)
        return fallback
    # exc_info keeps the traceback out of the reply but in the operator's log.
    _log.warning("extension %s failed (reported as %r)", context, fallback, exc_info=exc)
    return fallback


def _is_replayed_failure(exc: BaseException) -> bool:
    """Whether *exc* stands in for an earlier, already-logged failure."""
    return isinstance(getattr(exc, "original_type_name", None), str)


def _exception_names(exc: BaseException) -> list[str]:
    """Class names to classify *exc* by, replayed failures included.

    ``wallet._CachedSnapshotFailure`` stands in for an earlier exception whose
    traceback was deliberately dropped; it carries the original class name so a
    replay inside the cooldown window reports the same code as the first reply.
    """
    original = getattr(exc, "original_type_name", None)
    names = [original] if isinstance(original, str) else []
    names.extend(klass.__name__ for klass in type(exc).__mro__)
    return names
