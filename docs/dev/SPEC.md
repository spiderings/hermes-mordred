# Mordred — Specification (Hermes-base)

This document defines the behavior shipped by `hermes-mordred`. It describes
the current contract, not the sequence of pull requests that produced it.
Implementation details may evolve, but security boundaries, persistent wire
formats, and public behavior must stay consistent with this specification or
change here in the same patch.

## Vision

Mordred adds privacy-oriented policy, route selection, local-LLM enforcement,
hardware-backed key handling, at-rest protection, and an end-to-end browser
extension gateway to an ordinary Hermes installation. It is a cooperative
control layer inside the Hermes process, not an operating-system sandbox and
not a claim that every program run by the same user is contained.

The default experience remains usable: an operator can install the package,
run `hermes-mordred setup`, inspect the resulting state, and opt into
stricter controls. When a strict boundary cannot establish the evidence it
needs, it refuses rather than silently claiming protection.

## Project Identity

### Relationship to Hermes

`hermes-mordred` is a standalone MIT-licensed package that depends on
`hermes-agent`. It is not a fork or a copy of the upstream repository. It
ships these six `hermes_agent.plugins` entry points:

- `mordred_network`
- `mordred_privacy_check`
- `mordred_llm_guard`
- `mordred_keyvault`
- `mordred_wizard`
- `mordred_e2e`

Hermes core stays unmodified and Mordred does not submit upstream pull
requests. [`UPSTREAM.md`](./UPSTREAM.md) owns that relationship and the
compatibility policy.

### Platform Support (v1)

- Python 3.11 or newer is required. CI exercises Python 3.11 through 3.13.
- macOS and Linux support the policy, network, CLI, and extension layers.
- On macOS, the preferred native key backend is the installed Secure Enclave
  helper. An entitled in-process Security-framework backend and a
  login-Keychain software P-256 namespace remain ordered compatibility
  fallbacks.
- On Linux, the keyvault requires the installed TPM 2.0 helper and fails
  closed if it is absent or unusable. There is no Linux software-key fallback.
- Transparent `.env` injection, `config.yaml` materialize/reseal, agent-memory
  at-rest encryption, and the encrypted workspace integration are active only
  on macOS. Off macOS they may be enrolled, but status reports them inactive
  and plaintext remains the runtime source.
- Arming those macOS seals is fail-closed on the runtime: before removing a
  plaintext, the CLI probes the interpreter that should run `hermes` and also
  the interpreter of each `hermes gateway run` process it can identify in the
  process table, refusing when either cannot run the startup shim. Identifiable
  means: this user's process whose argv is `<python> -m hermes_cli… gateway
  run`, `<python> <launcher> gateway run`, `<launcher> gateway run`, or
  `<shell> <launcher> gateway run`, with an absolute launcher path. Gateways
  running under another account, or argv shapes outside that set, are not
  probed. A scan that finds nothing is not a refusal, and
  `--force-runtime-unverified` seals without either check.
- The `config` target protects `config.yaml` between managed process runs, not
  throughout a run. Its startup hook materializes a mode-`0600` plaintext file
  for the managed process lifetime and reseals it on clean exit; an unclean
  exit can leave that working copy until the next managed start and exit.
- The `workspace` target protects the `claude-private` encrypted APFS volume
  Mordred wraps, not a Hermes-owned file, and it is macOS-only. `sealed`
  (detached) is the protected state; `open` (mounted) means the contents are
  plaintext to every process running as the operator; `off` means the volume
  is not set up here.
- File-vault `vault recover` is supported only on macOS. The Linux TPM helper
  implements native wrapping, but the file vault has no Linux device-anchor
  store and must not claim a working recovery hot path there.
- Windows and mobile support are deferred. Pure cryptographic and storage
  modules remain testable with injected backends on other platforms.

### License Note

This repository is MIT licensed. Dependencies and optional native tooling keep
their own licenses; release review must preserve attribution and avoid copying
Hermes source into this package.

## Threat Model & Accepted Limitations

Mordred is designed for a cooperative Hermes process on a host whose operator
controls the account. It protects policy decisions and stored material against
common misconfiguration, accidental clearnet use through integrated routes,
and loss of plaintext files at rest. It does not create a hostile-code
security boundary.

Current defenses include:

- policy-gated skill installation through `hermes-mordred install`;
- generic strict runtime blocking for known network tools on clearnet;
- Tor/VPN route lifecycle and provider-transport compatibility checks;
- strict LLM identity and endpoint checks immediately before primary egress,
  plus dedicated guards for Hermes auxiliary LLM clients;
- strict startup refusal when a required Mordred sibling plugin is disabled;
- purpose-bound envelope encryption and native-key authorization;
- encrypted audit records when a keyvault-backed writer is available; and
- loopback-only, paired, encrypted browser-extension transport.

Accepted limitations include:

- a skill can open a direct socket or invoke an unwrapped executable;
- Hermes does not provide trusted `origin_skill` provenance to
  `pre_tool_call`, so runtime policy is tool-based rather than per-skill;
- provider or transport metadata supplied by an untrusted component can lie;
- same-UID malware can inspect process memory, modify local files, or remove
  audit history;
- plaintext necessarily exists while a secret is in use, and screen-capture
  detection cannot defeat a physical camera;
- traffic emitted by a parent harness such as Codex CLI, Claude CLI, Cursor,
  or an ACP client bypasses Hermes plugin hooks;
- if all Mordred plugins and the packaged interpreter-startup guard are
  removed, plugin-only enforcement no longer runs;
- helper discovery through writable PATH locations is not equivalent to
  signed-distribution attestation; and
- wallet signing and payment authorization are not isolated into a separate
  privilege domain.

The remaining hardening work is tracked as release gates in
[`ROADMAP.md`](./ROADMAP.md), especially OS1 and P1. Documentation must not
describe those gates as current protection.

### Newly defended via Hermes plugin hooks (no core seam needed)

Hermes hooks provide useful cooperative boundaries:

- `on_session_start` checks plugin integrity, declared harness state,
  persisted provider state, auxiliary-guard installation, and route startup;
- `pre_tool_call` receives `tool_name` and applies the generic clearnet guard;
- `pre_api_request` receives the resolved `provider` and `base_url` for the
  primary request, allowing endpoint-bound LLM and transport checks;
- `on_session_end` performs best-effort route teardown and secret resealing;
  and
- `pre_gateway_dispatch` receives `event` and `gateway` for the E2E gateway.

[`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) and
`tools/hook_payload_contract.json` own the exact consumed fields.

### Defended via plugin-side strict-mode startup refusal (zero-PR strategy)

Each runtime sibling registers the shared integrity check. In strict mode, a
known Mordred plugin recorded as disabled causes
`MordredIntegrityRefused`, a `BaseException` subclass, at the next session
start. This deliberately escapes Hermes's ordinary hook error wrapper.

The check is a startup boundary, not a live lock on configuration edits.
Changing disable state during an already-running session takes effect on the
next startup. Hard prevention of the disable operation itself is not shipped.

### Plugin-only fallback for missing seams

Where Hermes supplies no trusted skill origin, Mordred records
`mordred.degraded.no_origin_skill` and uses the generic strict tool-name rule.
Where provider identity cannot be resolved, strict mode blocks/refuses and
records the relevant degraded and policy reasons. Mordred never treats missing
evidence as permission and does not claim that these fallbacks contain direct
network access.

## Plugin-Only Architecture (zero Hermes core modifications, zero-PR strategy)

All integration occurs through installed entry points, the standalone
`hermes-mordred` console script, supported Hermes hooks, narrowly targeted
runtime guards, and the packaged `.pth` startup files. The `.pth` guards engage
only for Hermes invocations (or their explicit opt-in environment variables)
and do not turn Mordred into a replacement Python runtime.

`hermes-mordred` is the canonical CLI spelling. The registered Hermes-host
subcommand is a compatibility alias on versions that discover plugin CLI
commands; it is not available before the wizard plugin is loaded on older
supported hosts.

### What Mordred Adds (6 plugins)

The distribution is `hermes-mordred`; imports remain under `mordred_hermes`.

| Entry point | Current responsibility |
|---|---|
| `mordred_network` | Tor/VPN/clearnet route lifecycle, proxy evidence, health checks, transport gating |
| `mordred_privacy_check` | install policy, generic runtime tool policy, audit writer, sibling integrity |
| `mordred_llm_guard` | `mordred-local` registration, strict provider/endpoint refusal, harness and auxiliary-client guards |
| `mordred_keyvault` | native-key envelopes, recovery primitives, audit encryption, macOS runtime secret lifecycle |
| `mordred_wizard` | configuration, migration, status, policy, network, keyvault, vault, encryption, and plugin CLI |
| `mordred_e2e` | gateway-side encrypted extension dispatch and signing integration |

### Conventions (not plugins)

`<home>` means the active profile-aware Hermes home, normally `~/.hermes`.
Policy values, audit reason strings, filesystem ownership, and hook payloads
are shared contracts rather than independent plugins. Their canonical maps
are [`POLICY.md`](./POLICY.md), [`PATHS.md`](./PATHS.md), and
[`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md).

### What Mordred Inherits from Hermes (never modified)

Mordred uses Hermes's agent loop, provider registry, skills, tools, memory,
gateway framework, configuration home, plugin manager, and hook dispatcher.
Compatibility code may read those surfaces and refuse when they drift, but it
does not patch the upstream repository or redistribute a modified Hermes.

### Conditionally inherited (lenient mode only)

Lenient mode permits operation when metadata or protection evidence is
incomplete, while warning and auditing the downgrade. It may therefore inherit
Hermes's ordinary provider, skill, and clearnet behavior. Strict mode must not
be described as providing the same permissive fallback.

### Naming Convention

The canonical distribution name is `hermes-mordred`; `mordred-hermes` is a
metadata-only compatibility shim. Python imports use `mordred_hermes`, Hermes
entry points use `mordred_*`, and audit reasons use stable dotted names. The
browser-facing gateway entry point remains `mordred_e2e`, while its Python
implementation lives under `mordred_hermes.extension`.

## Target User (v1)

The primary user runs Hermes locally, accepts that plugins are cooperative
controls, and wants explicit choices for network paths, cloud LLM use, local
secret storage, and browser-extension access. Strict mode is intended for an
operator willing to resolve missing evidence instead of accepting automatic
fallback.

## User Stories (v1)

### Story 1: Adding the privacy layer for existing Hermes users

An existing Hermes user installs the appropriate extras, runs
`hermes-mordred setup`, reviews `hermes-mordred status`, and continues to run
the upstream agent. Setup is re-runnable and skips completed steps.
Configuration writes preserve unrelated Hermes keys and install Mordred's
six-plugin set without modifying upstream source.

### Story 1.5: Migration from OpenClaw + Mordred-OpenClaw

`hermes-mordred upgrade` detects a legacy `~/.openclaw` tree, applies explicit
row-level conflict policies, and remains idempotent. It never overwrites an
existing conflicting Mordred configuration silently. The exact source,
destination, and conflict ownership are in [`PATHS.md`](./PATHS.md).

### Story 2: New user setup

A new user installs Hermes plus this distribution and runs the Mordred wizard.
The wizard defaults to lenient policy, writes `config.yaml` and the derived
`policy.json` transactionally, and explains which optional backend or route
setup is still required.

### Story 3: Skill execution and automatic path selection

Installation through `hermes-mordred install` evaluates the skill's
`metadata.mordred` declaration before delegating to Hermes. At runtime,
configured Tor/VPN routes are selected before provider-client construction and
kept stable for the session. This story does not imply per-skill runtime
provenance or direct-socket containment.

### Story 4: Local LLM enforcement (strict-mode override)

The heading is retained as a stable documentation anchor; current behavior is
refusal, not override. In strict mode, `mordred-local` is allowed only when its
runtime endpoint exactly matches the pinned loopback endpoint and resolves
only to loopback addresses. A cloud provider is allowed only when cloud use is
enabled, the provider is allowlisted (or interactively granted by
`prompt-once`), and the actual HTTPS endpoint matches that provider's accepted
shape. Otherwise Mordred stops the request before egress.

The primary boundary is `pre_api_request`. Hermes auxiliary clients that do
not emit that hook are guarded at their resolver/client-construction seams.
Mordred does not rewrite an already resolved provider to `mordred-local`.

### Story 5: Key management

The user initializes one profile-scoped keyvault, verifies a digest through an
offline workflow, and stores secret material only in purpose-bound envelopes.
macOS prefers the Secure Enclave helper with compatibility fallbacks; Linux
requires the TPM helper. Seed display is short-lived and capture-aware where
the OS exposes the signal.

The Python API can export and import a recoverable encrypted manifest. The
operator CLI exposes `keyvault export --output` and `recover --blob` for the
corresponding portable snapshot workflow. Exported snapshots are point-in-time
artifacts and must be recreated after Keyvault contents change.

### Story 6: Coexistence with Hermes's existing features

Mordred preserves unrelated Hermes configuration and uses profile-aware paths.
Mordred owns agent-memory at-rest encryption as a runtime wrapper around the
memory tool's read/write seam in `tools/memory_tool.py`: no Hermes release
encrypts memories, and the zero-PR commitment means upstream cannot be asked
to. Hermes still owns the entry format inside the plaintext and the memory
tool itself. Extension state uses Hermes's established `<home>/extension/`
directory rather than the private keyvault tree.

## Scope (In) — what we build in v1

### Plugin: `mordred_network`

The network plugin provides:

- `tor`, `vpn`, and `clearnet` route selection with one process-wide runtime;
- Tor child-process ownership, a profile-scoped data directory, SOCKS5h proxy
  environment, and optional ControlPort liveness through `stem`;
- VPN provider support, including Mullvad account indirection through
  `<home>/.env` and configurable external commands;
- strict-vs-lenient route bring-up behavior and repeated health checks;
- provider transport classification before client construction;
- conservative handling of unknown transport facts, DNS behavior, IPv6, QUIC,
  UDP, gRPC, and WebSocket limitations; and
- audit events for use, failure, drop, bring-up failure, and incompatibility.

Mordred's `disable_ipv6` option configures its Tor client; it does not disable
host IPv6 or prevent an unwrapped process from opening a socket. A transport
refusal does not tear down a shared route merely to fall back another session
to clearnet. [`POLICY.md`](./POLICY.md) owns the matrices and provider evidence.

### Plugin: `mordred_privacy_check`

The privacy plugin parses `SKILL.md` frontmatter for
`metadata.mordred.network_requirements`, `requires_keyvault`, and advisory
`outbound_endpoints`. Its install decision is authoritative only when the user
goes through `hermes-mordred install`; an ordinary Hermes install command does
not traverse this wrapper.

At runtime it checks plugin integrity, writes the one-shot missing-origin
degradation marker, and blocks the default network-tool set on clearnet under
strict policy. Audit records are bounded and must never contain secrets or raw
untrusted documents.

### Plugin: `mordred_llm_guard`

The LLM plugin registers the synthetic `mordred-local` provider, establishes a
loopback proxy bypass, detects declared/known harness primaries, guards Hermes
auxiliary clients, checks persisted provider state at session start, and
checks the resolved primary request at `pre_api_request`.

Strict enforcement is fail-closed and exception-based. `prompt-once` is
process-local, keyed by normalized provider/route, and available only with an
interactive terminal. A missing TTY denies without caching that denial.

### Plugin: `mordred_keyvault`

The keyvault plugin owns native wrapping-key integration, verification
digests, encrypted secret envelopes, recovery manifests, encrypted audit
writers, Ethereum key envelopes, and the macOS startup/reseal integration for
the at-rest vault. Public calls accept an injected backend for deterministic
testing; production entry points resolve a platform backend centrally.

#### Key hierarchy

Each logical key ID identifies a native non-exportable P-256 wrapping key. A
random 32-byte data-encryption key (DEK) encrypts each secret with AES-256-GCM;
the native public key wraps that DEK through P-256 ECDH, HKDF-SHA-256, and
RFC 3394 AES Key Wrap. Only wrapped keys and ciphertext are persisted.

Logical key IDs and purposes are hashed before use as path components. The
profile-scoped native ID binds the logical identity to the keyvault root so
different Hermes homes cannot accidentally share a same-named native key.

The separate at-rest file vault uses a random master key with two recovery
paths: a device-wrapped master and an Argon2id passphrase-wrapped master. It
lives at `<home>/mordred/vault/`, not inside the keyvault envelope tree.

#### Key generation and verification digest

Let `H` be 32-byte BLAKE3, and let `top4` return the first four PoW bytes:

```text
seed_hash      = H(normalized_seed UTF-8)
pass_hash      = H(normalized_passphrase UTF-8)
masked_pass    = (pass_hash[0:4] XOR top4(pow_bytes)) || pass_hash[4:32]
digest         = H(seed_hash || masked_pass)
```

The expected value is exactly 32 bytes and comparison is timing-safe. Recovery
parses the backup header and verifies this digest before running Argon2id or
decrypting ciphertext. The offline tool shipped in the wheel implements the
same algorithm without importing the live keyvault state.

#### Proof-of-Work (PoW) algorithm (Phase 4 PR10 step-0 freeze, 2026-05-16)

The historical heading is retained because tests and external notes cite it.
The current PoW contract is:

```text
prefix     = b"MRPOW\x01"
preimage   = prefix || normalized_seed UTF-8 || nonce.uint64_little_endian
condition  = BLAKE3(preimage) has at least 20 leading zero bits
result     = the digest for the smallest nonce satisfying condition
```

Only the first four result bytes mask the verification digest. Difficulty,
prefix, byte order, and smallest-nonce rule are part of the compatibility
contract.

#### `keyvault init` flow (Phase 4 PR10)

Initialization is an explicit ceremony:

1. Probe the selected native backend and required crypto dependencies.
2. Generate a BIP39 seed and collect a recovery passphrase without placing
   either secret on a command line.
3. Normalize the inputs, compute PoW and the expected digest, and prepare an
   opaque, expiring seed-display handle without mutating durable state.
4. Display the seed through the protected display flow and direct the user to
   reproduce the digest on an offline device.
5. Require the typed digest to match exactly.
6. Only after confirmation, create the native wrapping key, commit metadata
   and the digest, optionally store the seed for HD derivation, and emit the
   completion event.

Any mismatch emits `keyvault.init_denied` and leaves no committed keyvault.
Interrupted native-key creation is reconciled through the lifecycle journal.

#### Seed phrase display security

The display handle has a 60-second monotonic deadline, redacted
representation, no equality/hash/copy/pickle/state export, one-shot consume,
and an in-place wipeable byte buffer. Display attempts a network blackout and,
on macOS, aborts if screen capture is detected. These controls reduce
accidental disclosure; they cannot defeat a physical camera, privileged
capture, terminal scrollback outside the controlled flow, or memory inspection
by the same user.

#### Protection-tier hierarchy (fallback)

Production backend selection is ordered and platform-specific:

1. macOS installed `mordred-hermes-sekey` helper (Secure Enclave);
2. macOS legacy in-process Security-framework namespace when usable;
3. macOS login-Keychain software P-256 namespace for compatibility when the
   interpreter lacks the entitlement needed to persist an Enclave key;
4. Linux installed `mordred-hermes-tpmkey` helper (TPM 2.0), with no software
   fallback.

Installing a helper does not migrate an existing key between namespaces.
Committed metadata keeps enough backend identity to continue finding an older
key. `enable-se` and `enable-tpm` build/install/probe helpers; they do not
convert current key material.

#### Implementation interface

`NativeBackend` exposes generate, public-key lookup, delete, and ECDH
operations. The public `keyvault.api` exposes two-phase generation, digest
verification, `encrypt`, `decrypt`, `export_backup`, and `import_backup`.
Secret encryption requires a non-empty purpose, and decryption requires the
same logical key ID, envelope ID, and purpose.

Exceptions distinguish structural corruption, missing keys, duplicate keys,
native unavailability, authorization cancellation, and verification mismatch.
Callers must not collapse an authorization denial into a corruption message.

#### Backup wire format versioning (Phase 4 PR2 freeze, 2026-05-14)

`MRKV` v1 is a self-describing passphrase-wrapped blob:

```text
magic(4)="MRKV" | version(1)=1 | kdf_id(1)=Argon2id |
m_cost(4 BE)=47104 KiB | t_cost(4 BE)=1 | p_cost(4 BE)=1 |
salt(16) | verification_digest(32) | aes_blob_len(4 BE) |
nonce(12) | ciphertext(N) | tag(16)
```

The first 66 bytes are AES-GCM AAD. Version 1 accepts only the canonical KDF
profile and rejects malformed lengths and unsafe cost values before KDF work.
A breaking layout or KDF-profile change requires a new version and compatible
reader dispatch.

#### Wrap wire format & algorithm (Phase 4 PR3 freeze, 2026-05-14)

`MRKW` v1 is exactly 127 bytes:

```text
"MRKW"(4) | version(1) | suite(1) | key_id_hash(16) |
ephemeral P-256 public key(65) | AES-KW wrapped DEK(40)
```

Wrapping uses the cached native public key and a fresh software ephemeral
P-256 key, derives a 32-byte KEK with HKDF-SHA-256 bound to the non-secret
header fields, and applies RFC 3394 AES Key Wrap to a 32-byte DEK. It requires
no private-key authorization and emits no successful unwrap event.

Unwrapping invokes native ECDH and emits exactly one of
`keyvault.unwrap_authorized` or `keyvault.unwrap_denied`. AES-KW has no
separate IV field; its fixed integrity value is part of the 40-byte result.

#### PR4 API contract & MREN envelope wire format (Phase 4 PR4 step-0 freeze, 2026-05-15)

The historical heading remains the stable anchor for the public keyvault API
and `MREN` v1. Current behavior is defined by the following subsections.

##### Mordred normalization (split: seed phrase vs passphrase, codex HIGH #1)

Seed phrases use Unicode NFKD, remove Unicode format (`Cf`) characters,
case-fold, split on whitespace, and rejoin with one ASCII space. This matches
the tolerance expected for BIP39 words.

Passphrases use Unicode NFKD only. Case, whitespace, and format characters are
significant entropy and are not trimmed, folded, or removed. The two
normalizers must not be merged.

##### Two-phase generate (codex BLOCKER #2)

`prepare_generate(seed, passphrase, pow_bytes)` computes the digest and
returns `(SeedDisplayHandle, expected_digest)` without disk, backend, or audit
mutation. `confirm_generate(...)` consumes the confirmed state and performs
the native/persistent transaction only after a timing-safe digest match.
`generate(...)` is the composed public convenience entry point and preserves
the same fail-before-mutation guarantee.

The default logical key ID is `default`. A successful result reports the
logical key ID, its hashed storage identity, and the committed UTC timestamp.

##### SeedDisplayHandle (opaque, codex BLOCKER #3)

`SeedDisplayHandle` is intentionally not a dataclass or serializable secret
container. Its observable representation is always redacted. It is unhashable,
rejects equality/copy/deepcopy/pickle/state access, serializes consumption with
a lock, and releases the normalized seed at most once. Expiry wipes before
raising `SeedDisplayExpired`.

The non-secret expected digest remains readable after a successful display so
a slow confirmation does not resurrect or retain the seed.

##### MREN envelope (managed storage, decrypt requires purpose)

`MREN` v1 layout is:

```text
"MREN"(4) | version(1) | key_id_hash(16) | purpose_hash(16) |
wrapped_dek/MRKW(127) | aes_blob_len(4 BE) |
nonce(12) | ciphertext(N) | tag(16)
```

The first 164 bytes are AES-GCM AAD; the fixed header including the length is
168 bytes. The parser verifies magic, version, framing, key hash, and purpose
hash before native unwrap. Envelopes are stored beneath hashed key and purpose
directories; clear purpose strings are not recoverable from their path.

##### export_backup / import_backup (ciphertext-rewrap manifest, codex BLOCKER #1)

`keyvault.api.export_backup()` unwraps each stored DEK through the authorized
native boundary, rewraps the manifest under an `MRKV` recovery blob, returns
the bytes in memory, and emits `keyvault.backup_exported`. It does not choose a
destination path or persist a temporary plaintext/export file.

`keyvault.api.import_backup()` accepts an `MRKV` blob, verifies the embedded
digest before KDF/decryption, provisions a fresh native key in an empty target
keyvault, and reconstructs purpose-bound `MREN` envelopes for that device.
Import refuses overwrite/merge conflicts and rolls back provisional state on
failure.

The CLI exposes export through `keyvault export --output <path>`. It selects
the single initialized logical key, collects the init passphrase and any
required paper Seed Phrase through masked prompts, and delegates MRKV creation
to `keyvault.api.export_backup()`. The wizard publishes a complete mode-`0600`
file atomically without replacement. The parent must already be a real
directory, the final path must not exist, and failures leave no partial final
file. Import remains `keyvault recover --blob <path>` into an empty profile.

##### File-safety semantics (step-B foundation, codex HIGH #4)

Security-sensitive state uses profile-scoped validated roots, mode `0700`
directories, mode `0600` regular files, atomic replacement, directory flushes,
and stable lock files. Reads and writes reject unsafe symlinks and special-file
endpoints. Lifecycle lock ordering prevents reset, import, generation, and
envelope mutation from crossing one another.

The exact persistent inventory and journal names are owned by
[`PATHS.md`](./PATHS.md).

##### Audit emissions for PR4 (4 new reason codes #21-24)

The heading is historical; the complete current enum is in
[`POLICY.md`](./POLICY.md). The four format-era events remain:

- `keyvault.recovery_digest_mismatch`
- `keyvault.seed_display_aborted_screenshot`
- `keyvault.unwrap_authorized`
- `keyvault.unwrap_denied`

Initialization and backup export add their own later stable reasons. An event
contains bounded identifiers only, never seed words, passphrases, raw key IDs,
DEKs, or backup bytes.

##### Capability-probe fail-on-skip (codex HIGH #5)

Live backend tests are allowed to skip only when their entire suite was not
requested. Once `MORDRED_KEYVAULT_LIVE=1` requests the live path, missing
hardware capability, helper installation, or authorization is a failure, not
a green skip. CI cannot provide the device interaction; maintainers record the
manual result as required by [`CI.md`](./CI.md).

#### Agent-memory at-rest encryption (sealed memory file format v1)

No Hermes release encrypts `<home>/memories/*.md`, and the `memory`
encryption target previously only provisioned a key without protecting
anything on disk. This runtime makes that protection real, on the same
precedent as the `.env` write guard and the config `.pth` hook: a defensive
wrapper Mordred installs around a private upstream seam, fail-closed on the
read path.

The sealed memory file format is a two-line text container:

```text
line 0: HERMES-MEMORY-ENC-v1
line 1: base64url(nonce[12] || AES-256-GCM(plaintext, aad))
```

The key is `HERMES_MEMORY_KEY`: URL-safe base64 of exactly 32 bytes, with an
optional `base64:` or `hex:` prefix. AAD binds each ciphertext to its file's
basename (`hermes-memory-v1:<file basename>`) so `MEMORY.md` and `USER.md`
ciphertexts cannot be swapped for each other. The format is text-safe on
purpose — an upstream `read_text()` of a sealed file yields a recognisable
magic line instead of a `UnicodeDecodeError`. Every write uses a fresh nonce,
and the plaintext is always the whole file body: Mordred encrypts bytes and
leaves entry parsing to Hermes.

Arming is evaluated per call, from a marker file and the current key, never
cached:

| marker | key | behavior |
|---|---|---|
| absent | any | not armed — plaintext as today |
| present | valid | armed — writes seal; reads unseal sealed files and pass plaintext files through (migration on write) |
| present | missing or invalid | armed, fails closed for memory I/O — every write refuses, and reading a *sealed* file refuses; plaintext files still read |
| present | valid, but ciphertext fails to authenticate | refuses loudly — the read raises, so the affected load or mutation aborts and nothing is overwritten |

`HERMES_SAFE_MODE` disarms the hook outright. An undecryptable sealed file
always refuses loudly rather than reporting an empty memory. The hook never
blocks interpreter start-up; when sealed files exist and the key is missing,
the first memory load fails with the remedy in the message (so agent start-up
stops there) instead of presenting an empty memory, and every memory write
refuses — Mordred never silently writes plaintext while armed.

Seam coverage depends on which shape of the upstream memory tool is
installed. Mordred wraps three call sites per seam shape shipped by
hermes-agent 0.13–0.15, 0.16–0.19, and current main: the read chokepoint, the
write chokepoint, and the drift-backup write. An unrecognised seam is
unsupported: when armed, the process refuses to start (`sys.stderr` plus exit
1, recoverable with `HERMES_SAFE_MODE=1`); when not armed, nothing is wrapped
and memory stays plaintext.

Known out-of-band paths are documented limitations, not silent gaps: `hermes
agent-import` is best-effort patched; raw readers (`hermes doctor` size
reporting, the Desktop learning graph, the Honcho migration upload) see
sealed text and degrade gracefully rather than leak plaintext; an
out-of-process writer produces plaintext that is sealed on its next write and
shown as `exposed` in the meantime; and `memory.write_approval` pending JSON
stays plaintext (`encryption enable memory` warns about it).

`encryption enable memory` requires the runtime probe to pass and the env
target to already be enrolled and not opted out — the key rides on the env
shim. It performs one Touch ID authorization through `set_memory_key`, writes
the marker, eagerly migrates existing plaintext files to sealed, and warns
when a running gateway needs a restart to pick up the change. `encryption
disable memory` decrypts every sealed file back to plaintext, removes the
marker and sets the opt-out marker (paused by operator), and keeps the key.
`encryption purge memory` disables and then strips the key. `encryption
status` reports `on`, `paused`, `off`, or `exposed`. `setup` runs a
`memory-encryption` step right after `env-encryption`: it runs without a
dedicated prompt, exactly like the env step (the opt-out marker is how an
operator declines), resolves `manual` under `--non-interactive`, and honours
the operator opt-out.

The capability probe `runtime_memory_encryption_available` joins the env and
config probes in the same family and appears in `encryption status`'s gateway
lines. A CI canary test runs the round trip against the installed upstream
memory tool so an upstream refactor of the seam trips a red build rather than
a silent regression.

#### Explicitly out of v1

- exporting private native wrapping keys;
- silently downgrading Linux TPM protection to a software key;
- automatic migration of an existing key when `enable-se` or `enable-tpm`
  installs a helper;
- unattended claims for keys created with attended authorization policy;
- same-UID tamper-proof storage; and
- cross-purpose decryption or recovery into a non-empty keyvault.

### Plugin: `mordred_wizard` (CLI Extension)

The standalone CLI exposes these top-level commands:

```text
status
setup
configure
upgrade
install
network     use | status | init
policy      show | explain | dry-run | reload
audit       tail | grep | decrypt | purge
keyvault    init | list | verify-digest | export | recover | reset |
            enable-se | enable-tpm | eth
vault       init | change-passphrase | recover | add | status | cat |
            migrate | set-memory-key | enable-config-decrypt |
            disable-config-decrypt
encryption  status | enable | disable | purge | change-passphrase
plugins     list
extension   pair | serve
```

`status`, `policy show`, keyvault listing, vault status, and encryption status
are non-mutating. `configure`, `keyvault init/reset`, `network init`, vault
mutations, encryption toggles, audit purge, pairing, and serving can touch real
profile or external state; tests and local experiments must isolate
`HERMES_HOME` as described in [`setup.md`](./setup.md).

The wizard is the sole writer of the canonical Mordred policy transaction and
preserves unrelated Hermes configuration. It never accepts the Mullvad account,
seed phrase, or recovery passphrase as a normal command-line flag.

`setup` is a re-runnable first-run orchestrator. It probes upstream Hermes,
configuration, the selected network route, the platform helper, keyvault, and
macOS env and agent-memory encryption, then runs only incomplete steps and
prints status. It never resets or overwrites a blocked/corrupt keyvault.
Non-interactive mode runs only the automatable subset and reports the
interactive commands still needed.

### Plugin: `mordred_e2e`

`mordred_e2e` is the browser-extension gateway plugin and the one
manifest-less entry point: `pyproject.toml` registers it directly against
`mordred_hermes.extension.gateway_plugin` rather than a `plugin.yaml`.
Extension chat runs through the same `AIAgent` class the messaging platforms
use, so it passes through every other Mordred hook instead of acting as a
side channel.

A browser extension pairs to one Hermes profile through a code exchange plus
an ECDH handshake, with an optional WebAuthn credential bound to the pairing;
[`PATHS.md`](./PATHS.md) owns the resulting `<home>/extension/` state files.
The standalone `hermes-mordred extension serve` command starts the localhost
WebSocket server on port 7788 for pairing, chat, signing, and wallet/RPC
requests; it does not start on its own alongside an ordinary Hermes session.

On Slack and Discord, end-to-end encryption is mandatory across all channels:
the `pre_gateway_dispatch` hook hands the agent only a complete, context-bound
`ENC:v3` command, and anything it cannot decrypt is refused with a rate-limited
needs-key notice to the sender instead of being forwarded in cleartext. A reply
into an encrypted conversation is re-encrypted in kind.
[`SLACK_E2E.md`](./SLACK_E2E.md) owns the exact wire grammar. Conversation
history is recorded encrypted at rest under the pairing's shared key so any
paired surface can replay it. The wallet/RPC bridge signs through the keyvault
and broadcasts from the server side, honoring the `mordred_network` route (Tor
when it is active) so RPC egress follows the same path as the rest of the
process; the browser never reaches an RPC node directly.

## Operational Guarantees & Caveats

### Audit log policy

Audit entries are bounded records with `ts`, `event`, `decision`, and
`reason`. Current decisions include `allow`, `block`, `override`, `warn`,
`raise`, and `fallback`. `reason` is one of the 31 stable values in
[`POLICY.md`](./POLICY.md), or `null` where no policy reason applies.

The active log rotates daily or at 10 MiB, retains dated files for 30 days,
and serializes cooperating writers through a stable sidecar lock. Plaintext
NDJSON is the baseline before a keyvault audit key exists. When encrypted
logging was expected but cannot be constructed, the factory falls back to
plaintext and emits `mordred.degraded.audit_encryption_unavailable` when it can
do so safely.

Encryption protects record confidentiality and per-entry integrity at rest.
It does not make the log append-only or prevent a same-UID process from
deleting, truncating, or replacing history.

#### Encrypted audit-log wire format (`MRAL` v1, Phase 4 PR6 freeze)

`MRAL` is line-oriented:

```text
line 0: {"fmt":"MRAL","ver":1,"key_id":...,"wdek":...}
line N: base64(nonce(12) || AES-GCM-ciphertext || tag(16))
```

`wdek` is a base64 `MRKW` blob. The in-memory 32-byte log DEK is wiped when the
writer closes. Every entry is encrypted independently and bound by AAD to its
file header. Cooperating append/rotate/rollback operations share the audit lock
and detect inode/header ownership changes before reusing a cached DEK.

Historical plaintext logs are not rewritten in place. The audit CLI can tail,
search, decrypt dated encrypted files, and purge confirmed old rotations.

### Plugin-disable protection (plugin-side only, zero-PR strategy)

The required sibling set is a fixed six-entry constant, not dynamically
expanded from manifests. Strict startup aborts when any sibling is recorded as
disabled. Lenient/off operation may continue with a degradation record.

The packaged interpreter-startup integrity guard provides an earlier
defense-in-depth check for normal Hermes console starts, but it remains local
code under the same user account. Neither layer prevents an operator or
same-UID attacker from uninstalling the package or launching a different
interpreter.

### Policy file caching

Readers cache a validated policy snapshot within a process. `policy reload`
clears that in-process cache; there is no filesystem watcher. The wizard uses a
lock and pending marker across `config.yaml` plus `policy.json`, and readers
that observe an incomplete transaction fail closed instead of combining two
generations.

### Plugin Versioning & Compatibility

All plugins ship in the `hermes-mordred` distribution and share one version.
The package version in `src/mordred_hermes/__about__.py` is the release source
of truth and is updated through `tools/bump_version.py`. The minimum supported
Hermes version is declared in `pyproject.toml`; CI checks both the floor and a
current release. Private upstream seams used by compatibility guards must be
validated in tests and cause an explicit refusal or diagnostic on drift.

Persistent `MRKV`, `MRKW`, `MREN`, and `MRAL` layouts require versioned readers.
Stable audit reason strings and documented policy fields are compatibility
surfaces and are not renamed casually.

### Observability

Operators use `hermes-mordred status`, focused `network`/`policy`/`keyvault`/
`vault`/`encryption` status commands, and the audit CLI. Status output must
distinguish configured, initialized, protected, exposed, paused/inactive, and
unavailable states instead of reducing them to one boolean.

Sensitive values are redacted. JSON output is available where documented for
automation, while destructive or secret-bearing ceremonies remain explicit
and interactive unless a narrowly scoped confirmation flag exists.

## Scope (Out) — explicitly deferred

- modifying or submitting pull requests to Hermes upstream;
- a general sandbox for arbitrary Python, shell, or direct socket activity;
- automatic rerouting of a resolved cloud LLM request to a local provider;
- trusted per-skill runtime provenance without a new host seam;
- hard prevention of plugin disable/uninstall by the local user;
- Windows/mobile product support and a supported Windows helper workflow;
- transparent env/config/memory/workspace lifecycle outside macOS;
- audit hash chains, external anchoring, or same-UID tamper resistance;
- isolated signer/payment authorization;
- automatic migration of native-key protection tiers.

Future candidates and their release gates live in
[`ROADMAP.md`](./ROADMAP.md); actionable unfinished work lives in
[`TODO.md`](./TODO.md).

## MVP Phasing

The original phase headings and pull-request notes have been removed from the
current specification. All six entry points, the policy/network/LLM layers,
keyvault formats, CLI, at-rest vault, and extension surface described above are
shipped behavior. A feature is current only when implementation, tests, and
the canonical documents agree; a roadmap item is not part of the MVP merely
because code scaffolding exists.

## Operational Setup (one-time)

Use [`setup.md`](./setup.md) for the development environment and
[`../user/QUICKSTART.md`](../user/QUICKSTART.md) for operator setup. Always run
repository commands through `uv run` or `.venv/bin/...`, and isolate
`HERMES_HOME` before testing a mutating ceremony. On macOS, build/probe the
Secure Enclave helper before relying on that protection tier; on Linux,
build/probe the TPM helper before keyvault initialization. Reserve extension
port 7788 for the production gateway and use another port for local tests.

Operators should start with `hermes-mordred setup`; developers should follow
[`setup.md`](./setup.md). Before a release, run the automated quality gates in
[`CI.md`](./CI.md) and record the applicable manual live-device validations.
Do not substitute version strings for checking which environment/import path
is actually under test.
