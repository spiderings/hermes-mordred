"""Secure-Enclave-backed DEK wrap/unwrap.

Phase 4 PR3 step-B. The contract is frozen in SPEC.md §Wrap wire format
& algorithm (2026-05-14):

- 127-byte blob: ``MRKW(4)|version(1)|alg_suite(1)|key_id_hash(16)|
  ephemeral_pub(65)|wrapped_dek(40)`` for ``version=1``.
- ``wrap_dek`` is offline — uses the cached Enclave **public** key plus
  a freshly generated software ephemeral private key. No authorization
  prompt; no audit entry on success.
- ``unwrap_dek`` is authorized — calls ``enclave_ecdh`` which on macOS
  routes to ``SecKeyCopyKeyExchangeResult`` and may prompt the user.
  Emits exactly one of ``keyvault.unwrap_authorized`` /
  ``keyvault.unwrap_denied`` per call.
- HKDF ``info`` binds every non-secret blob field to the KEK, so a
  tampered ``ephemeral_pub`` or ``key_id_hash`` produces a different
  KEK and AES-KW unwrap fails the AIV check — integrity protection
  despite AES-KW lacking AAD (codex review HIGH-2).
- AES-KW is RFC 3394: 32-byte DEK → 40-byte output, including the 8-byte
  fixed AIV. There is NO separate IV field (codex review BLOCKER-2).

The Enclave authorization boundary is abstracted by the
:class:`NativeBackend` ``Protocol``. Production code uses a backend
that lazy-loads pyobjc on first call (lands in step-C); tests inject a
software ``FakeBackend`` that uses ``cryptography`` for a real P-256
keypair so the HKDF / AES-KW / wire-format code paths are exercised
with real crypto — codex review MEDIUM-4 (mocks must not hide format
bugs).

Internal Python surface (PR3 step-0 freeze, consumed by PR4 ``api.py``):

- :func:`generate_wrapping_key` — create + persist a new Enclave key.
- :func:`get_wrapping_key_public` — return SEC1 uncompressed public key.
- :func:`delete_wrapping_key` — remove from Keychain (idempotent).
- :func:`wrap_dek` — produce a 127-byte blob (offline, no audit).
- :func:`unwrap_dek` — verify + decrypt a blob (authorized, emits audit).

Exception taxonomy is in :mod:`mordred_hermes.keyvault._exceptions`.
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Callable
from typing import Any, Literal, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._audit_emit import chain_and_raise, emit_capture
from ._exceptions import (
    WrapAuthCancelled,
    WrapIntegrityError,
    WrapKeyNotFound,
    WrapParseError,
)

AuditSink = Callable[[dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Wire-format constants (SPEC.md §Wrap wire format & algorithm)
# ---------------------------------------------------------------------------

MAGIC: bytes = b"MRKW"
VERSION: int = 1
ALG_SUITE: int = 1  # (P256_ECDH_RAW, HKDF_SHA256, AES256_KW_RFC3394)
DEK_LEN: int = 32
KEY_ID_HASH_LEN: int = 16
EPHEMERAL_PUB_LEN: int = 65  # SEC1 uncompressed P-256: 1 + 32 + 32
WRAPPED_DEK_LEN: int = 40  # RFC 3394 AES-KW for 32-byte input
HEADER_LEN: int = 127

# Offsets (mirror the byte-layout table in SPEC.md):
_OFFSET_MAGIC = 0
_OFFSET_VERSION = 4
_OFFSET_ALG_SUITE = 5
_OFFSET_KEY_ID_HASH = 6
_OFFSET_EPHEMERAL_PUB = 22
_OFFSET_WRAPPED_DEK = 87


# ---------------------------------------------------------------------------
# Backend Protocol
# ---------------------------------------------------------------------------


NativeErrorCode = Literal[
    "user_cancelled",
    "auth_failed",
    "biometry_lockout",
    "passcode_not_set",
    "key_not_found",
]
"""Closed set of translated native-error codes.

Matches POLICY.md code #20 ``native_error_code``. ``key_not_found`` is in
the set because :func:`unwrap_dek` branches on it (raising
:class:`WrapKeyNotFound` with no audit emit per review-fix-1 HIGH-1) —
the check happens BEFORE the audit-emit decision, so the code is still
the right way for a backend to signal "missing Keychain item."
"""

_NATIVE_ERROR_CODES: frozenset[str] = frozenset(
    ("user_cancelled", "auth_failed", "biometry_lockout", "passcode_not_set", "key_not_found")
)
"""Runtime lookup mirror of :data:`NativeErrorCode`.

Mypy-strict catches in-tree typos at the type level via the ``Literal``;
this frozenset catches them at runtime in case a third-party
``NativeBackend`` implementation (e.g. PR4's production ``_SecKeyBackend``)
ever calls ``NativeBackendError("-25293")`` after stringifying a raw
``OSStatus`` — that would leak biometric-attempt state into the audit
log via ``_emit_unwrap_denied`` (codex review-fix-2 MEDIUM-1).
"""


class NativeBackendError(Exception):
    """Raised by :class:`NativeBackend` to signal an authorization failure.

    ``code`` is one of the translated strings documented in POLICY.md
    code #20 (:data:`NativeErrorCode`). The raw ``OSStatus`` from
    pyobjc is **not** stored — it carries biometric-attempt-count state
    that should not cross the audit-log boundary.

    Construction validates ``code`` against :data:`_NATIVE_ERROR_CODES`
    and raises :class:`ValueError` on any value outside the frozen set.
    A backend MUST translate raw ``OSStatus`` ints to one of the closed
    strings before raising — fail-fast at the backend boundary instead
    of leaking through the audit boundary (codex review-fix-2 MEDIUM-1).
    """

    def __init__(self, code: str) -> None:
        if code not in _NATIVE_ERROR_CODES:
            raise ValueError(
                f"NativeBackendError code must be one of "
                f"{sorted(_NATIVE_ERROR_CODES)!r}; got {code!r}. "
                "Production backends MUST translate raw OSStatus values to "
                "one of these strings before raising — the audit log "
                "(POLICY.md #20) must never see raw OS error ints."
            )
        super().__init__(code)
        self.code: str = code


@runtime_checkable
class NativeBackend(Protocol):
    """Narrow Secure-Enclave boundary (codex review MEDIUM-4).

    All four methods are I/O against the Keychain or Enclave. HKDF +
    AES-KW + wire-format parsing live in :mod:`wrap` and are exercised
    with real crypto in the unit tests; only Enclave authorization is
    mocked.

    ``@runtime_checkable`` mirrors the repo convention for structural
    Protocols used as dependency-injection seams (e.g.
    ``wizard/policy_writer.PolicyWriter``, ``credentials_writer.CredentialsWriter``,
    ``env_file_writer.EnvFileWriter``) — review-fix-1 HIGH-3.
    """

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        """Create a new Enclave-backed P-256 keypair tagged with
        ``key_id`` and return the SEC1 uncompressed public key. Raises
        :class:`~mordred_hermes.keyvault._exceptions.WrapKeyAlreadyExists`
        (a :class:`WrapKeyNotFound` subclass) if a key with this id
        already exists (the production backend translates
        ``errSecDuplicateItem``).

        ``unattended`` selects the key's authorization policy:
        ``False`` (or ``None`` → safe default) gates every ``enclave_ecdh``
        behind Touch ID / passcode; ``True`` creates a key usable without
        a prompt (still hardware-bound). ``None`` lets the backend fall
        back to the ``MORDRED_SEKEY_UNATTENDED`` env default."""
        ...

    def get_enclave_public_key(self, key_id: str) -> bytes:
        """Return the SEC1 uncompressed public key for ``key_id``.
        Raises :class:`WrapKeyNotFound` if the Keychain has no item."""
        ...

    def delete_enclave_key(self, key_id: str) -> None:
        """Remove the native item for ``key_id``.

        Confirmed absence is a no-op where the backend can establish it.
        Windows PCP cannot distinguish absence from inaccessible retained keys;
        an unopenable keyset must refuse deletion, including repeated deletes.
        """
        ...

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        """Compute raw ECDH between the Enclave private key for
        ``key_id`` and the supplied ``peer_pub`` (SEC1 uncompressed).

        This is the only authorization boundary in the Protocol — on
        macOS this invokes ``SecKeyCopyKeyExchangeResult`` which may
        prompt for Touch ID / Optic ID / passcode.

        Raises :class:`NativeBackendError` on denial (cancelled, auth
        failed, biometry change locked out, no passcode set). Raises
        :class:`WrapKeyNotFound` if the Keychain item is missing.
        """
        ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _key_id_hash(key_id: str) -> bytes:
    """SHA-256 prefix used both for the on-disk ``key_id_hash`` field and
    the audit-log identifier. 16 bytes for the blob, 8 bytes (hex
    encoded → 16 chars) for the audit log."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:KEY_ID_HASH_LEN]


def _audit_key_id_hex(key_id: str) -> str:
    """16-char hex prefix of ``SHA-256(key_id)`` for audit-log emission.

    Never use the full ``key_id`` in the audit log — POLICY.md code #19
    explicitly forbids it so consumers can rate-limit by hash without
    seeing the cleartext. A prefix of :func:`_key_id_hash` on purpose:
    operators grep audit entries against the blob/Keychain hashes, so the
    two derivations must never diverge.
    """
    return _key_id_hash(key_id)[:8].hex()


def _build_hkdf_info(key_id_hash: bytes, ephemeral_pub: bytes) -> bytes:
    """Construct the HKDF ``info`` parameter that binds non-secret blob
    fields to the derived KEK (codex review HIGH-2).

    Layout: ``MAGIC || version(1) || alg_suite(1) || key_id_hash(16) ||
    ephemeral_pub(65)`` = 87 bytes. A tampered field produces a
    different ``info`` → different KEK → AES-KW unwrap fails the AIV
    check, giving us authenticated integrity despite AES-KW lacking AAD.
    """
    return MAGIC + bytes([VERSION, ALG_SUITE]) + key_id_hash + ephemeral_pub


def _derive_kek(shared_secret: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 with a zero-length salt, 32-byte output (AES-256)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def _decode_sec1_uncompressed_p256(point_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Strict SEC1 uncompressed P-256 decode.

    Rejects compressed (``0x02`` / ``0x03``) and hybrid (``0x06`` /
    ``0x07``) encodings — the wire format pins uncompressed (``0x04``).
    Off-curve points are rejected by ``from_encoded_point`` via the
    underlying OpenSSL EC_POINT validation.
    """
    if len(point_bytes) != EPHEMERAL_PUB_LEN or point_bytes[0] != 0x04:
        raise WrapParseError(
            "ephemeral_pub must be 65-byte SEC1 uncompressed (0x04 prefix); "
            f"got {len(point_bytes)} bytes starting with {point_bytes[:1]!r}"
        )
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point_bytes)
    except ValueError as exc:
        raise WrapParseError(f"ephemeral_pub is not a valid P-256 point: {exc}") from exc


class _ParsedHeader:
    """Holds the parsed-and-validated view of a 127-byte wrap blob.

    Attributes are positional bytes only. Constructed by
    :func:`_parse_header`, which validates every field — callers can
    rely on each attribute being well-formed.
    """

    __slots__ = ("ephemeral_pub", "key_id_hash", "wrapped_dek")

    def __init__(
        self,
        key_id_hash: bytes,
        ephemeral_pub: bytes,
        wrapped_dek: bytes,
    ) -> None:
        self.key_id_hash = key_id_hash
        self.ephemeral_pub = ephemeral_pub
        self.wrapped_dek = wrapped_dek


def _parse_header(blob: bytes, key_id: str) -> _ParsedHeader:
    """Strict structural validation of a wrap blob.

    Every rejection is a :class:`WrapParseError` so callers can treat
    "this blob is invalid" as a single category. The check order is
    cheapest-first: length → magic → version → alg_suite → key_id_hash
    → ephemeral_pub SEC1 decode. This means a tampered byte is reported
    with the most specific failure mode available, but no Enclave call
    has happened yet.
    """
    if len(blob) != HEADER_LEN:
        raise WrapParseError(f"wrap blob must be exactly {HEADER_LEN} bytes for version=1; got {len(blob)}")

    magic = blob[_OFFSET_MAGIC:_OFFSET_VERSION]
    if magic != MAGIC:
        raise WrapParseError(f"bad magic: expected {MAGIC!r}, got {magic!r}")

    version = blob[_OFFSET_VERSION]
    if version != VERSION:
        raise WrapParseError(f"unsupported wrap blob version: {version} (this build expects {VERSION})")

    alg_suite = blob[_OFFSET_ALG_SUITE]
    if alg_suite != ALG_SUITE:
        raise WrapParseError(
            f"unsupported alg_suite: {alg_suite} (this build expects suite 1 = P256_ECDH_RAW + HKDF_SHA256 + AES256_KW)"
        )

    blob_kid_hash = blob[_OFFSET_KEY_ID_HASH:_OFFSET_EPHEMERAL_PUB]
    expected_kid_hash = _key_id_hash(key_id)
    if blob_kid_hash != expected_kid_hash:
        # NOTE: we report mismatch but do NOT include the cleartext
        # ``key_id`` in the message. Leaking it via error text would
        # defeat the POLICY.md #19 "never the cleartext key_id" rule.
        raise WrapParseError("key_id_hash mismatch — blob was wrapped for a different key_id")

    ephemeral_pub = blob[_OFFSET_EPHEMERAL_PUB:_OFFSET_WRAPPED_DEK]
    # Validate the EC point — raises ``WrapParseError`` on a malformed
    # or off-curve point. The decoded ``EllipticCurvePublicKey`` is not
    # retained because :func:`unwrap_dek` passes the raw bytes to
    # ``backend.enclave_ecdh``; storing the decoded form was dead state
    # (security-reviewer NIT-4 / python-reviewer LOW-2).
    _decode_sec1_uncompressed_p256(ephemeral_pub)

    wrapped_dek = blob[_OFFSET_WRAPPED_DEK:]
    if len(wrapped_dek) != WRAPPED_DEK_LEN:
        # Unreachable given the HEADER_LEN check, but defensive.
        raise WrapParseError(f"wrapped_dek must be {WRAPPED_DEK_LEN} bytes; got {len(wrapped_dek)}")

    return _ParsedHeader(blob_kid_hash, ephemeral_pub, wrapped_dek)


def _emit_unwrap_denied(
    audit_sink: AuditSink,
    *,
    key_id: str,
    native_error_code: str,
) -> Exception | None:
    """Best-effort emit of the ``keyvault.unwrap_denied`` audit entry.

    Returns the sink's exception (if any, only :class:`Exception`
    subclasses) so the caller can chain it as ``__context__`` on the
    primary :class:`WrapAuthCancelled`. Mirrors PR2 ``recovery._emit_mismatch``
    (code-reviewer HIGH-1, 2026-05-14); the capture / chaining policy lives
    in :mod:`._audit_emit`.
    """
    return emit_capture(
        audit_sink,
        {
            "event": "keyvault.unwrap_dek",
            "decision": "block",
            "reason": "keyvault.unwrap_denied",
            "key_id_hash": _audit_key_id_hex(key_id),
            "native_error_code": native_error_code,
        },
    )


# ---------------------------------------------------------------------------
# Public surface (PR3 step-0 SPEC freeze)
# ---------------------------------------------------------------------------


def generate_wrapping_key(
    key_id: str,
    *,
    backend: NativeBackend,
    unattended: bool | None = None,
    native_key_id: str | None = None,
) -> bytes:
    """Create + persist a Secure-Enclave-backed P-256 keypair for ``key_id``.

    Returns the SEC1 uncompressed public key (65 bytes) so callers — e.g.
    PR4's ``api.generate`` — can use it directly without a second
    :func:`get_wrapping_key_public` round-trip (review LOW-3).

    The public key remains exportable; the private key never leaves the
    Enclave. Raises
    :class:`~mordred_hermes.keyvault._exceptions.WrapKeyAlreadyExists`
    (a :class:`WrapKeyNotFound` subclass) if a key with this id already
    exists in the Keychain (backend translates ``errSecDuplicateItem``
    to this exception so callers do not need to know the OSStatus).

    ``unattended`` is forwarded to :meth:`NativeBackend.generate_enclave_key`
    to pick the key's authorization policy (interactive vs. prompt-free);
    ``None`` uses the backend default (``MORDRED_SEKEY_UNATTENDED`` env,
    else interactive).
    """
    return backend.generate_enclave_key(native_key_id if native_key_id is not None else key_id, unattended=unattended)


def get_wrapping_key_public(
    key_id: str,
    *,
    backend: NativeBackend,
    native_key_id: str | None = None,
) -> bytes:
    """Return the SEC1 uncompressed P-256 public key (65 bytes) for ``key_id``.

    Raises :class:`WrapKeyNotFound` if the Keychain has no item. No
    Enclave authorization happens — public-key lookup is unprivileged.
    """
    return backend.get_enclave_public_key(native_key_id if native_key_id is not None else key_id)


def delete_wrapping_key(
    key_id: str,
    *,
    backend: NativeBackend,
    native_key_id: str | None = None,
) -> None:
    """Remove the Keychain item for ``key_id``. Idempotent.

    Deleted keys cannot be recovered — any wrap blobs produced under
    ``key_id`` become permanently un-unwrappable. The caller is
    responsible for exporting backups (``api.export_backup``, Phase 4
    PR4) before invoking this.
    """
    backend.delete_enclave_key(native_key_id if native_key_id is not None else key_id)


def wrap_dek(
    dek: bytes,
    key_id: str,
    *,
    backend: NativeBackend,
    native_key_id: str | None = None,
) -> bytes:
    """Wrap a 32-byte DEK under the Enclave-protected wrapping key.

    Offline — does NOT call ``enclave_ecdh`` and never prompts the user
    for authorization. Uses the cached Enclave public key + a freshly
    generated software ephemeral private key. Each call produces a
    different blob even for the same ``(dek, key_id)`` because the
    ephemeral keypair is fresh.

    Returns the 127-byte blob documented in SPEC.md §Wrap wire format.

    Raises :class:`WrapKeyNotFound` if the Keychain has no item for
    ``key_id``. Raises :class:`ValueError` if ``dek`` is not exactly
    ``DEK_LEN`` bytes.
    """
    if len(dek) != DEK_LEN:
        raise ValueError(f"DEK must be exactly {DEK_LEN} bytes; got {len(dek)}")

    enclave_pub_bytes = backend.get_enclave_public_key(native_key_id if native_key_id is not None else key_id)
    enclave_pub = _decode_sec1_uncompressed_p256(enclave_pub_bytes)

    ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    shared_secret = ephemeral_priv.exchange(ec.ECDH(), enclave_pub)

    kid_hash = _key_id_hash(key_id)
    info = _build_hkdf_info(kid_hash, ephemeral_pub_bytes)
    kek = _derive_kek(shared_secret, info)

    wrapped_dek = aes_key_wrap(kek, dek)

    # The 127-byte blob is exactly ``info || wrapped_dek`` — ``info`` spans
    # offsets 0.._OFFSET_WRAPPED_DEK (== 87 == len(MAGIC)+2+KEY_ID_HASH_LEN+
    # EPHEMERAL_PUB_LEN). ``unwrap_dek`` reconstructs ``info`` from the
    # parsed header fields, so re-serializing the same prefix a second time
    # here (rather than reusing ``info``) would risk the two packings
    # silently diverging and deriving a mismatched KEK, breaking unwrap.
    return info + wrapped_dek


def unwrap_dek(
    blob: bytes,
    key_id: str,
    *,
    audit_sink: AuditSink,
    backend: NativeBackend,
    native_key_id: str | None = None,
) -> bytes:
    """Verify the blob and unwrap the DEK using the Enclave key.

    This is the authorization boundary — ``backend.enclave_ecdh`` calls
    ``SecKeyCopyKeyExchangeResult`` which may prompt the user. Emits
    exactly one of:

    - ``keyvault.unwrap_authorized`` (decision ``allow``) on success.
    - ``keyvault.unwrap_denied`` (decision ``block``) on auth failure.

    Raises:
        WrapParseError: blob is structurally invalid. Parse rejections
            happen BEFORE any Enclave call — UX + privacy (no biometric
            prompt for malformed blobs).
        WrapKeyNotFound: Keychain has no item for ``key_id``. Surfaces
            from two paths: (a) a parse-time lookup miss when the
            backend exposes one, and (b) a mid-unwrap
            ``NativeBackendError("key_not_found")`` translated to
            :class:`WrapKeyNotFound` because missing-key is pre-
            authorization per SPEC.md §Wrap wire format & algorithm
            "Algorithm — unwrap_dek" step 2 — NO audit entry is emitted
            in either case (review-fix-1 HIGH-1).
        WrapAuthCancelled: user denied the access-control prompt. The
            underlying :class:`NativeBackendError` is chained via
            ``__cause__``; if ``audit_sink`` itself raised while
            recording the denial, the sink exception is chained via
            ``__context__`` so callers' denial handlers stay correct
            (mirrors PR2 ``recovery.import_backup`` HIGH-1 fix).
        WrapIntegrityError: AES-KW AIV check failed — blob's
            ``ephemeral_pub`` or ``wrapped_dek`` was tampered with.

    The ``audit_sink`` is called at most once per invocation, and only
    for prompt-denied / authorized decisions. Integrity / parse / key-
    not-found failures do NOT emit any audit entry because they happen
    before the authorization decision is reached. If the sink itself
    raises during the success-path emit, the exception is swallowed
    and the DEK is returned anyway (review-fix-1 MEDIUM-1) — the
    asymmetry with the denial path is deliberate: the denial path has
    a primary exception to chain against, but the success path has
    only a return value and must deliver the DEK intact (a lost DEK is
    operationally worse than a missing audit entry, which is
    recoverable).
    """
    parsed = _parse_header(blob, key_id)

    # ``enclave_ecdh`` is the only path that can prompt the user. We
    # capture any ``NativeBackendError`` into ``denied`` and raise the
    # translated exception OUTSIDE the ``except`` handler so Python's
    # implicit ``__context__`` machinery does not overwrite our explicit
    # ``__context__ = sink_exc`` assignment (CPython unconditionally sets
    # ``__context__`` on ``raise`` inside an active exception handler;
    # see ``Python/ceval.c:do_raise`` → ``PyException_SetContext``).
    # PR2 ``recovery._emit_mismatch`` uses the same pattern (HIGH-1, 2026-05-14).
    denied: NativeBackendError | None = None
    shared_secret: bytes | None = None
    try:
        shared_secret = backend.enclave_ecdh(
            native_key_id if native_key_id is not None else key_id,
            parsed.ephemeral_pub,
        )
    except NativeBackendError as exc:
        denied = exc

    if denied is not None:
        # HIGH-1: ``errSecItemNotFound`` mid-unwrap surfaces as
        # :class:`WrapKeyNotFound` (more specific than ``WrapAuthCancelled``)
        # with no audit emit. The docstring in ``_exceptions.py`` already
        # promises this contract; the fix completes the implementation.
        if denied.code == "key_not_found":
            raise WrapKeyNotFound(denied.code) from denied

        # All other native error codes are prompt-denied flows. Emit
        # ``keyvault.unwrap_denied`` and raise ``WrapAuthCancelled``,
        # chaining the native error via ``__cause__`` and any sink
        # failure via ``__context__``. Both attributes are assigned
        # explicitly outside the ``except`` handler (there is no active
        # exception here to auto-fill ``__context__`` with) — the
        # chaining contract is documented once in ``_audit_emit``.
        sink_exc = _emit_unwrap_denied(audit_sink, key_id=key_id, native_error_code=denied.code)
        primary = WrapAuthCancelled(denied.code)
        primary.__cause__ = denied
        chain_and_raise(primary, sink_exc)

    # HIGH-2: ``denied is None`` here means the ``try`` block completed,
    # so ``shared_secret`` is bound. The ``assert`` form would be
    # stripped by ``python -O``; instead we raise a real
    # :class:`RuntimeError` whose message documents the invariant. The
    # guard is unreachable in practice and exists only to narrow
    # ``shared_secret`` from ``bytes | None`` to ``bytes`` for mypy.
    if shared_secret is None:
        raise RuntimeError(
            "unreachable: enclave_ecdh returned without raising NativeBackendError but produced no shared secret"
        )

    info = _build_hkdf_info(parsed.key_id_hash, parsed.ephemeral_pub)
    kek = _derive_kek(shared_secret, info)

    try:
        dek = aes_key_unwrap(kek, parsed.wrapped_dek)
    except InvalidUnwrap as exc:
        raise WrapIntegrityError("AES-KW AIV check failed — wrapped_dek or ephemeral_pub was tampered with") from exc

    # MEDIUM-1: best-effort audit emit on success. The DEK has been
    # computed; if the sink raises, the caller MUST still receive it.
    # Asymmetric with the denial path by design (see docstring).
    # ``contextlib.suppress(Exception)`` (not ``BaseException``) mirrors
    # ``_emit_unwrap_denied``'s policy — Ctrl-C / SystemExit /
    # GeneratorExit propagate untouched so CLI shutdown stays clean.
    with contextlib.suppress(Exception):
        audit_sink(
            {
                "event": "keyvault.unwrap_dek",
                "decision": "allow",
                "reason": "keyvault.unwrap_authorized",
                "key_id_hash": _audit_key_id_hex(key_id),
            }
        )

    return dek
