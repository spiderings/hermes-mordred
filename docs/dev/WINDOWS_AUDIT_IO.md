# Checked audit I/O

The opt-in root `_audit_io` session API implements the shared Windows audit
contract in SPEC and PLAN. Existing POSIX audit functions and all consumers
remain unchanged. `_audit_session` imports only stdlib and `_private_fs`.

`audit_session(path, create=False, blocking=True, transaction=None)` scopes one
exact-private directory transaction. `create=True` admits only a missing final
directory. Checked absence is read-only and becomes a successful result only
when the owning context closes. Borrowed transactions must assert exact-private
admission, lifetime and checked parent identity; their owner controls final
success. Same-directory nesting reuses the explicit active transaction;
different-directory nesting refuses. No global mutex is held while locking.
No callbacks, prompts or key providers may run inside a session.

Sessions expose checked stat, probe, immutable snapshot/snapshot_many, bounded
listing, create-no-replace, identity-bound append/rename/delete and directory
identity. Bounds must be positive integers. Probes only route complete JSON
object first lines: duplicate keys, invalid, incomplete, blank or overlong lines
are unknown; MRAL format markers route to the consumer regardless of version.
Crypto validation and key lifetime remain consumer responsibilities.

`decode_audit_bytes` bounds combined gzip output and validates gzip trailers.
`rotate_audit` and `sweep_audit_retention` accept an already held session. Dated
names match the exact active basename, valid calendar date, optional numeric
suffix and optional gzip extension. Gzip publication is verified before raw
deletion. Known local compression or not-committed I/O/access/busy publication
failures can retain a checked raw identity. Other failures propagate; a fatal
failure after persistent mutation promotes uncertainty with progress notes.
Protect returned raw/gzip names during the immediate retention sweep. Retention
uses checked mtime, while the enumeration API also returns parsed dates.

Initial budgets: 16 MiB per raw/snapshot/output, 64 MiB aggregate snapshots,
4,096 directory entries/first-line bytes, and raw cap plus 64 KiB gzip overhead.
The explicit read/decode budgets permit a later adapter to select larger finite
limits. These helpers never authorize encryption downgrade or automatic retry.

Validation covers actual checked POSIX transactions for portable shared behavior,
Win32 boundary fakes for absence/admission/cleanup, and Windows-only real files,
ACLs, links and process contention. Fault tests exercise identity change,
uncertain mutations, collision limits, verified raw degradation, gzip bounds,
partial retention, scope/thread/process refusal and lock reuse. CI selects the
shared/native tests and exercises the APIs from a wheel outside the checkout.
Host tests do not constitute native Windows validation.
