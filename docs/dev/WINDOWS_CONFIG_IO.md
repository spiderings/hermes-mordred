# Windows canonical configuration API and verification plan

C2 implements the canonical Windows configuration boundary from SPEC and the
C1b/C2 design. POSIX public readers retain their existing behavior. This shared
slice does not claim runtime enforcement readiness: C3 must migrate writers and
C8 must migrate decisions and caches.

## API and lifetime

`CanonicalPaths(home, config_name='config.yaml', mordred_name='mordred',
policy_name='policy.json')` describes one absolute home and direct safe leaves.
`canonical_session(paths, scope='home'|'policy', create=False, blocking=True)`
returns a process/thread/lifetime-bound session. It opens trusted confidential
home before exact-private mordred, and releases in reverse. Same-home nesting
reuses locks; policy scope can extend home scope until the outermost exit.
Different homes and conflicting leaf layouts are refused. Existing lower-level
mordred transactions must never acquire a canonical session. Prompts, provider
calls and long helpers belong outside sessions.

Checked directory identities and checked revalidation admit same-spelling/case
aliases only when they identify the pinned directory. Optional directory openers
must exit successfully before missing-home/mordred observations escape. The
coordinator never interprets arbitrary opener errors as fresh state.

`session.home_directory_identity() -> FileIdentity | None` returns the checked
home binding for a caller-supplied session. It validates the creating session's
process/thread/lifetime and the pinned home identity/security before returning;
`None` represents only the session's already-checked absence. It does not open
raw paths or reacquire a lock. As with all observations, successful outer exit
is required before absence can escape the owning checked context.

`CheckedContents(data, metadata)` records bounded bytes and checked metadata.
`CanonicalSnapshot(config, policy)` uses `None` only for clean checked absence.
`read_canonical_snapshot` uses nonblocking locks; errors remain errors.
`read_home`, `read_policy`, `read_pair` return checked contents/snapshots. Config,
policy and dotenv are limited to 8 MiB; marker reads to 4 KiB. `write_home` and
`delete_home` support dotenv and validated uninstall backup leaves only; config
always uses the pair protocol. Backups are create-no-replace and verified.

`session.policy_update(recover_pending=False)` returns an active `PolicyUpdate`.
Its put/delete methods stage bytes or expected-identity deletions. Context exit
without explicit `commit()` publishes nothing. Commit is attempted once. Existing
members are captured and revalidated, unchanged safe bytes retain identities and
descriptors, and pending recovery still verifies/finalizes a complete pair.
Marker creation/verification precedes any member mutation. Exact intended pair
verification precedes identity-bound marker deletion and checked absence.
Publication errors retain the marker; deletion/cleanup uncertainty can leave a
verified pair marker-free but must raise. Caught uncertain mutation errors remain
on the session: subsequent operations and outer exit re-raise the original
classified failure, even if cleanup also fails. A nested nonblocking reader uses
nonblocking acquisition when extending a home scope to policy scope. There is no rollback, automatic retry,
or finally-block marker deletion. Recovery is available only through the live
owning full policy update. Callers parse and validate whole source documents
before commit: this module deliberately transports bytes without YAML/JSON
transformation policy.

## Reader compatibility audit

Shared JSON callers include `_provider_resolution` reading `auth.json`, which is
not policy. Shared YAML callers are mostly canonical config but expose a generic
file reader and custom config paths. Automatic Windows dispatch applies to
`config.yaml` and `policy.json`; explicit snapshot parsers support custom leaf
names through `CanonicalPaths`. Generic files retain generic semantics and are
not silently classified as canonical configuration. Canonical policy wrappers
require the direct `home/mordred/policy.json` relationship; explicit custom
layouts must use the typed API. No split-root guarantee is provided.

Snapshot parsers raise on malformed whole documents and preserve checked absence.
Policy mode parsing defaults only on checked absence or a valid missing key;
invalid types/values select strict. Presentation mapping wrappers can still
collapse errors to `{}` and must never use that shape to authorize a decision.
Windows `allow_pending_transaction=True` cannot bypass checked coordination.
Marker diagnostics use bounded checked reads and recommend configure/reconciliation,
never unconditional marker removal.

## Verification matrix

Tests use injected foundation openers on non-Windows hosts (without changing
`sys.platform`/`os.name`) and native Windows processes in scoped CI:

- Lock order/reverse release, nested reuse/extension, conflicting home/layout,
  directory identity changes, foreign thread/process and expired session/update.
- Existing/absent home, mordred and pair-member permutations; cleanup failures,
  missing intermediates, busy, unsafe, denied and oversize remain failures.
- Staging and uncommitted exit; exact no-op; puts, identity deletes, backup
  create-no-replace; all marker/member/verification/finalization failure points.
- Stale safe recovery versus unsafe marker refusal, unexpected marker identity
  replacement, no read-through bypass, and lock-held marker ABA exclusion.
- Snapshot YAML/JSON parser behavior, safe bounded diagnostics, custom leaves,
  canonical parent validation and unchanged generic/POSIX wrappers.
- Native ordinary-user process contention and snapshot refusal during partial
  pair publication; controller owns Windows Server/Windows 11 live acceptance.

Run focused tests, repository Ruff/format, strict mypy with only CI extras, then
all-extras full pytest under the isolated Python 3.13 uv environment. Record
native results separately; host doubles do not establish native acceptance.

## Future audit integration

C7a audit sessions can borrow an already-held private transaction only after
`assert_private_admission()` validates the exact-private admission strategy,
then checking `directory_identity()`. Identity alone cannot distinguish a
confidential transaction from a private one. C2 exposes
`session.borrow_mordred_transaction()` as a context-managed protected
`PrivateTransaction` proxy. It may extend home scope to an existing mordred
scope in home-before-mordred order, honoring the current session's blocking
choice. Only an outer `create=True` session authorizes creation. A checked absent
scope cannot be upgraded. The loan never releases the owner's locks and expires
when its own context or creating session closes. Each operation validates owner
process/thread/lifetime, exact-private admission and checked directory identity.
Do not use global lock lookup, retain the proxy, reach into its internals, or
acquire home from an independent mordred/audit transaction.

The proxy refuses the configured policy leaf, canonical `policy.json`, pending
marker, legacy `.policy-write.lock`, their legacy `.tmp`/random `.tmp` staging
names, and foundation lock/staging names. Reads and all mutation operands,
including both rename operands, obey this boundary. Enumeration filters these
names after a bounded underlying scan; protected entries still consume that
scan's budget. Pending policy state refuses borrowing, including from a recovery
update. Successful mutations update the owning session's publication tracking.
Uncertain operations and admission errors poison it with the first classified
failure even if the caller catches the immediate exception. Borrowing does not
create a policy pending marker for unrelated custody/audit mutations.

`session.publication_receipt()` provides a separate lifetime-bound receipt with
`mark_published()` and `mark_uncertain(error: PrivateFSError)` only. It grants no
filesystem authority. A caller holding a separately checked child transaction
must report every successful mutation immediately, and report uncertain
primitive/child-exit errors before suppressing them. Escaping errors also join
the owner outcome; after reported publication they poison the owner. Receipts
validate process/thread/session/receipt lifetime before recording a result,
without parent filesystem revalidation first: such a check could hide an
already-published child. Parent security/identity revalidation and cleanup still
run at the owning boundary. Reports cannot clear publication or the original
failure; wrong-thread/process and expired receipts cannot report.

These APIs establish shared coordination only. Custody enrollment, memory
sealing and production encrypted-audit callers remain separate component work.


## Wizard consumers (C3)

The Windows wizard holds one canonical session across each complete read,
parse, transform and publication. Every public policy writer validates both
whole documents, preserves round-trip YAML and opaque provider overrides, and
stages the complete intended pair before one explicit commit. Only the full
`write` operation requests stale-marker recovery. Standalone section edits,
identity migration and policy emission refuse a pending marker. POSIX behavior
remains on its existing implementation. Unsupported split roots are rejected.

Dotenv updates use the canonical home lock across bounded UTF-8 reads and
transforms. Credentials use home, policy, then the checked private credentials
child, in that order. Cleanup re-reads under its owning session; checked private
create-no-replace backups must be verified before removing source content.
Explicit secret-backup directories retain their published path.

Verification plan: exercise public writers through the real coordinator with
injected checked filesystem capabilities on POSIX, then native Windows fixtures.
Cover YAML preservation, plugin migration, opaque overrides, all standalone
entry points, malformed pair refusal, explicit recovery, unchanged identities,
marker/publication/cleanup faults, dotenv export syntax and invalid UTF-8 or
size, backup collisions, stale cleanup plans and custom canonical leaf names.
Native acceptance additionally runs configure twice in a Hermes-created home,
fresh-process contention, interrupted pair publication, private credential and
backup descriptors, and paths containing spaces and Unicode. Controller records
native acceptance separately from the host unit suite.

`CanonicalSession.create_policy_backup(name, data)` creates only bounded
`env-removed-[safe stamp].env` backup leaves in the live exact-private policy
scope, after the marker guard. It rejects the actual canonical policy name and
marker case-insensitively, even with custom canonical leaves. Creation never
replaces an existing entry; verified reads establish publication and failures
retain classified uncertainty. Explicit different backup directories use a
checked private child capability after the canonical locks. Backup child locks
are always nonblocking: a busy explicit destination raises classified `busy`
without modifying the source, avoiding cross-profile lock cycles while keeping
the requested destination. The component
promotes subsequent cleanup failures to uncertain after child publication.

Generic legacy `_atomic_write_text`, `_read_regular_text` and
`_policy_write_lock` remain explicitly unsupported on Windows: every migrated
consumer uses its complete checked transaction instead. Memory/OpenClaw and
other later lifecycle consumers must migrate their whole read/modify/write
before using Windows storage; this change does not enable them incidentally.
No compatibility guarantee extends to old Windows writers or noncooperating
upstream writers. Flag-only configure resolves its defaults from the checked
pair inside the same update; prompts and upstream setup remain outside locks.

Native consumer selection is `tests/test_wizard_config_native_windows.py`:
configure rerun, credential and backup ACLs, no-overwrite collision, concurrent
fresh-process config/dotenv changes, public-writer crash/recovery and unsafe ACL
refusal. Its profile-style fixture does not establish actual Hermes-generated
home acceptance; the controller's separate installed-runtime run covers that.
