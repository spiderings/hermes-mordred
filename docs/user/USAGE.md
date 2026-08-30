# Mordred — usage guide

> **Audience**: operators running Mordred locally. For the current design and
> boundaries see [`SPEC.md`](../dev/SPEC.md), [`POLICY.md`](../dev/POLICY.md),
> and [`PATHS.md`](../dev/PATHS.md). For developer environment setup see
> [`setup.md`](../dev/setup.md).
>
> **Scope**: the `mordred_wizard` CLI surface exposed today through the standalone `hermes-mordred …` command.

---

## 1. How to invoke

Requires Python 3.11 or newer and `hermes-agent>=0.13.0` on macOS or Linux;
see the [README](../../README.md#requirements) for the platform matrix.

Use `hermes-mordred <cmd>` for every Mordred operation. This works on every
supported Hermes version and stays available before Mordred is configured and
whenever its configuration needs recovery. Newer Hermes versions also expose
the same command tree as a registered subcommand of the Hermes host once the
plugins are enabled — see the compatibility note in the
[project README](../../README.md#use-it).

> **Where `hermes-mordred` actually lives.** The console script itself is
> installed alongside the interpreter, at
> `~/.hermes/hermes-agent/venv/bin/hermes-mordred` for a Hermes-managed
> install. `scripts/install.sh` additionally writes a launcher next to
> `hermes`, so the bare command works from any directory. From a development
> checkout, use `.venv/bin/hermes-mordred` or activate the venv.

Check the installation with:

```sh
hermes-mordred status
```

In this development checkout the fully-wired venv is `.venv`:

```sh
cd <repo-root>            # the hermes-mordred checkout
.venv/bin/hermes-mordred status
```

### Enabling all Mordred plugins

`hermes-mordred configure` manages this automatically. The resulting
`~/.hermes/config.yaml` includes:

```yaml
plugins:
  enabled:
    - mordred_privacy_check
    - mordred_wizard
    - mordred_llm_guard
    - mordred_network
    - mordred_keyvault
    - mordred_e2e
```

Use `hermes-mordred` for commands. (`hermes plugins list` does not surface
entry-point plugins; use `hermes-mordred plugins list`.)

---

## 2. First-run quickstart

New here? Run `hermes-mordred setup` — the guided, re-runnable orchestrator
that probes each step below and only runs what is still incomplete. The full
walkthrough (Purpose / Do / Result, plus what to expect from the interactive
prompts) lives in **[`QUICKSTART.md`](./QUICKSTART.md)**. In brief, `setup`
runs these in order (every step is idempotent and safe to re-run):

```sh
hermes-mordred configure              # interactive setup → writes config.yaml + policy.json
hermes-mordred network init           # OPTIONAL — Tor / VPN / clearnet privacy path
hermes-mordred keyvault enable-se     # build the platform key helper (Linux: enable-tpm)
hermes-mordred keyvault init          # create the hardware-backed keyvault
hermes-mordred encryption enable env  # macOS only: turn on transparent at-rest encryption
hermes-mordred encryption enable memory  # macOS only: seal agent-memory files
hermes-mordred status                 # verify the result at a glance
```

On Linux, the supported operator path stops after keyvault setup and status.
The TPM-backed keyvault is supported, but transparent env/config runtime
loading is inactive, `vault recover` lacks a Linux device-anchor store, and
plaintext remains the runtime source.

`status` prints a single-screen summary (`policy` / `network` / `keyvault` /
per-target `encryption`); see
[`QUICKSTART.md` §2](./QUICKSTART.md#2-first-run-in-order) for the annotated
output and the `workspace` `sealed` / `open` / `off` axis. Add `--json` for
machine-readable output.

---

## 3. Command reference

### `status` — state at a glance
```sh
hermes-mordred status            # human-readable
hermes-mordred status --json     # machine-readable
```

### `setup` — resumable first-run orchestrator

Runs the upstream-Hermes check, Mordred configuration, network selection,
platform helper, keyvault ceremony, macOS env and agent-memory encryption, and
final status in order. Completed steps are skipped on a rerun. A blocked or
corrupt keyvault stops with repair guidance; setup never resets it
automatically.

On `setup`, `--with-hermes-setup` / `--skip-hermes-setup` force or skip the
upstream `hermes setup` step for this run; the same-named flag means something
different on `configure` (see below), where it is a deprecated no-op.

```sh
hermes-mordred setup
hermes-mordred setup --non-interactive
hermes-mordred setup --with-hermes-setup --unattended-keys
hermes-mordred setup --skip-hermes-setup --paper-only
```

`--non-interactive` runs only steps that need no decisions and reports the
remaining manual commands. Key policy flags affect newly created keys only;
`--store-seed-for-hd` is the default and `--paper-only` opts out of storing the
seed for later HD-wallet derivation.

### `configure` — interactive setup
Writes `config.yaml` + `policy.json`. Interactive by default; scriptable with
`--non-interactive` (unspecified flags keep existing values).

By default `configure` collects only the Mordred-specific prompts and does
**not** run the upstream `hermes setup` wizard. Pass `--with-hermes-setup` to
delegate to it first — useful on a fresh machine where Hermes itself is not
configured yet (Hermes pre-fills each prompt so pressing Enter keeps existing
values). On `configure`, the old `--skip-hermes-setup` flag is now the
default behavior and is accepted as a deprecated no-op.
```sh
hermes-mordred configure                                           # Mordred prompts only (default)
hermes-mordred configure --with-hermes-setup                       # run `hermes setup` first, then Mordred prompts
hermes-mordred configure --non-interactive --policy strict --no-allow-cloud-llm
hermes-mordred configure --non-interactive --policy lenient
```
Key flags: `--with-hermes-setup`, `--policy {strict,lenient,off}`,
`--allow-cloud-llm/--no-allow-cloud-llm`,
`--cloud-allowlist <csv>`, `--local-llm-endpoint <url>`, `--local-llm-model-id <id>`,
`--cloud-attempt-action {always-block,prompt-once}`,
`--harness {none,codex,claude-cli,cursor,acp-claude,acp-cline}`.

### `upgrade` — migrate an existing install
Idempotent migration of an existing Hermes / OpenClaw setup to Mordred
(auto-detects `~/.openclaw`). Safe to re-run.
```sh
hermes-mordred upgrade
hermes-mordred upgrade --non-interactive --policy-conflict keep-existing
```
Key flags: `--reset`, `--non-interactive`, `--audit-merge {skip,append-all,abort}`,
`--policy-conflict {keep-existing,overwrite,abort}`.

### `policy` — inspect the active policy
```sh
hermes-mordred policy show                  # print resolved policy.json
hermes-mordred policy explain <skill-id>    # explain an install decision (exit 2 = block)
hermes-mordred policy dry-run <SKILL.md>    # evaluate a SKILL.md without installing
hermes-mordred policy reload                # re-read policy from config.yaml
```

### `network` — privacy path control
```sh
hermes-mordred network init                 # set up Tor / VPN / clearnet (Mullvad account)
hermes-mordred network use tor              # or: vpn, clearnet
hermes-mordred network status               # active path + liveness
```

### `install` — policy-gated skill install
```sh
hermes-mordred install <skill-name>         # or a path to a dir containing SKILL.md
```

### `audit` — the audit log
```sh
hermes-mordred audit tail                        # most recent entries
hermes-mordred audit grep <regex>                # line-wise regex search
hermes-mordred audit decrypt --date YYYY-MM-DD   # decrypt that day's encrypted entries
hermes-mordred audit purge --before YYYY-MM-DD --yes  # delete dated rotated logs before a date
```

### `encryption` — the recommended on/off switch
At-rest encryption per target: `env`, `config`, `memory`, `workspace` — or `all`
to apply the verb to every target at once. The transparent runtime lifecycle is
currently macOS-only. Off macOS, enrollment can exist but `status` reports the
target inactive and plaintext remains authoritative; `workspace` is skipped
when its macOS tooling is unavailable and never fails an `all` batch.
```sh
hermes-mordred encryption status                        # all targets (non-prompting)
hermes-mordred encryption enable  TARGET                # TARGET: env, config, memory, workspace, or all
hermes-mordred encryption disable TARGET                # reversible; keeps vault copy
hermes-mordred encryption purge   TARGET --yes          # destructive
hermes-mordred encryption change-passphrase             # rotate the recovery passphrase (alias of `vault change-passphrase`)
```

`on` means that the target's protection lifecycle is active, not that its
plaintext never exists while in use. Most importantly, `config [on]` writes a
mode-`0600` plaintext `config.yaml` to disk for the lifetime of each managed
Hermes process. It reseals that file on a clean exit. An unclean exit can
leave the plaintext copy in place until the next managed start-and-exit
cycle. The concise target-by-target plaintext and restart matrix is in
[`QUICKSTART.md` §What the protected states mean](./QUICKSTART.md#what-the-protected-states-mean).

Immediately after the first `encryption enable config`, the current plaintext
`config.yaml` remains on disk because the command creates the opt-in marker
after its startup hook has already made the decision for that process. Run
`hermes-mordred encryption status` once. When the status command exits cleanly,
the hook reseals the current config and removes the plaintext. Do not re-run
`encryption enable config` to perform this first seal, and do not delete
`config.yaml` manually.

> **Memory target.** No Hermes release to date (verified through hermes-agent 0.20.0 and GitHub HEAD)
> encrypts `~/.hermes/memories/*.md`, so Mordred owns this one end to end: a
> runtime hook seals every memory write and opens every sealed read, keyed by
> `HERMES_MEMORY_KEY` from the vault `.env`.
>
> **Preconditions** (`enable memory` refuses, exit 1, writing nothing, unless
> all hold): the `env` target is enabled and injecting — that shim is how the
> key reaches the runtime; the platform is macOS; and the interpreter that runs
> `hermes` (plus any gateway running right now) proves it can open a sealed
> file. The last check is the same runtime guard the `.env` seal uses, and
> `--force-runtime-unverified` bypasses it at your own risk.
>
> **What the verbs do.** `enable` stores the key (one Touch ID), writes the
> opt-in marker, and migrates every plaintext `*.md` (and `*.md.bak.*`
> snapshot) already on disk to sealed. `disable` decrypts them all back to
> plaintext, keeps the key, and writes an opt-out marker (`paused`); it
> *refuses* rather than proceed if a sealed file cannot be decrypted, so you
> never end up with unreadable blobs. `purge` runs that same `disable` first
> and only then strips the key.
>
> **Status marks.** `on` = armed and everything on disk is sealed; `paused` =
> opt-out marker (or off macOS); `off` = never enabled; `exposed` = armed but a
> plaintext memory file is on disk — re-run `encryption enable memory` to seal
> it.
>
> **Restart a running gateway** after enabling or disabling. After `enable`,
> the running process still lacks the freshly-minted key, so — fail-closed,
> not plaintext — its memory reads/writes are refused until you restart it,
> and a session may see an empty memory. After `disable`, it still has the
> hook armed in-process; the marker being gone only stops it sealing new
> writes starting at the next memory call. `enable` warns and names the pid
> when it sees one.
>
> **Recovery.** `HERMES_SAFE_MODE=1` disarms the hook for one run (memories are
> then read as-is, sealed ones unreadable) — the escape hatch if a memory
> problem blocks start-up. The key itself lives in the vault `.env`; without
> it, sealed memories cannot be recovered.
>
> **Known limitations** (see SPEC.md's
> [agent-memory section](../dev/SPEC.md#agent-memory-at-rest-encryption-sealed-memory-file-format-v1)
> for the readers and pending-write path named below). Readers that bypass the
> memory tool see the sealed text rather than plaintext (`hermes doctor`'s size
> report, the Desktop learning graph, the Honcho migration upload) — degraded
> display, never a leak. A writer in a process without the hook (a migration
> script) leaves plaintext, which `status` shows as `exposed` and the next
> in-process write seals. `memory.write_approval` stages pending writes as
> plaintext JSON under
> `~/.hermes/pending/memory/` until they are applied (`enable` warns when the
> flag is on). Run `hermes agent-import` from an interpreter that has the hook.
> Drift backups (`*.md.bak.<ts>`) are sealed too. Upstream's own drift error
> tells you to open the `.bak` file directly — with memory encryption on, that
> file is sealed, so decrypt it first with `encryption disable memory` (which
> unseals every `.bak` snapshot alongside the live files) before following
> that advice.

> **Workspace target.** This one is a *container*, not a file set. `enable`
> drives the external `claude-private` tool to create an encrypted APFS
> sparsebundle (`~/Private/claude-private.sparsebundle`) whose passphrase is
> Secure Enclave-wrapped (`~/.config/claude-private/passphrase.wrapped`), and
> whatever you write under the mountpoint (`~/.claude-private-mnt`) lives
> inside it. `CLAUDE_PRIVATE_IMAGE` / `CLAUDE_PRIVATE_KEYDIR` /
> `CLAUDE_PRIVATE_MOUNT` relocate those three paths. Mordred creates, seals,
> and destroys that container and reports its state; it never moves a file
> into it and never reads what is inside. Putting files in is not what
> encrypts them — the volume is encrypted from the moment it is created.
>
> **When the protection is actually on.** `sealed` (detached) is the protected
> state and `open` (mounted) is not: while the volume is mounted its contents
> are plaintext to every process running as you, so protection begins when you
> detach, not when you write. Mount it yourself by running `claude-private` —
> `enable` creates the volume but deliberately never mounts it, which keeps the
> lifecycle and destructive paths free of an untestable auto-unlock. The Secure
> Enclave wrapping binds the volume to this machine: a copied sparsebundle plus
> its wrapped passphrase is useless on another Mac, and unrecoverable if this
> one is lost.
>
> **Putting a Claude Code session inside it.** Claude Code writes transcripts to
> `<config home>/projects/<slug>/*.jsonl`, and `CLAUDE_CONFIG_DIR` names that
> home — an absolute path, set in the shell rather than in a settings file, and
> read at start-up. Do not point your everyday `~/.claude` into the volume:
> sealing it then takes the config home away too, and Claude Code starts
> without your settings, plugins, or history. Use a second config home inside
> the volume and reach for it only while the volume is mounted:
>
> ```sh
> hermes-mordred encryption enable workspace     # create the volume (once)
> claude-private                                 # mount it — Mordred never does this
> CLAUDE_CONFIG_DIR="$HOME/.claude-private-mnt/claude" claude
> hermes-mordred encryption disable workspace    # detach = sealed = protected
> ```
>
> Nothing is migrated by any of this: transcripts already under
> `~/.claude/projects/` stay plaintext where they are. The target covers only
> the volume's contents, so it does not reach Hermes's own session storage
> (`<home>/state.db`, `<home>/sessions/*.jsonl`), which no encryption target
> covers.

> **Runtime guard before a seal (macOS).** `enable env` and `enable config`
> remove the plaintext, so both first prove the file can be unsealed again at
> startup. Two interpreters are probed. The first is the one that *should* run
> `hermes`: `MORDRED_HERMES_RUNTIME_PYTHON` if set, else
> `~/.hermes/hermes-agent/venv`, else the `hermes` launcher on `$PATH`. The
> second is the interpreter of each `hermes … gateway run` process running
> **right now** under your account — read from the process table, because a
> gateway started from some other virtualenv is what actually has to unseal the
> file, and its recorded `gateway_state.json` argv can name a different
> interpreter than the one the kernel exec'd. Four argv shapes are recognised
> (the launcher path must be absolute in each):
>
> - `<python> -m hermes_cli… gateway run`
> - `<python> <launcher> gateway run` (how a console script appears once the
>   kernel rewrites the `#!` exec)
> - `<launcher> gateway run`
> - `<shell> <launcher> gateway run`
>
> A gateway running under another account (or a shape outside that set) is not
> seen, and therefore not probed. If a running gateway cannot load the shim, the
> command refuses and touches nothing (excerpt):
>
> ```text
> error: refusing to vault-seal .env — a hermes gateway is RUNNING from a different
>   interpreter that cannot handle the seal: /path/to/repo/.venv/bin/python (pid 4242).
>   probe: the hermes runtime (/path/to/repo/.venv/bin/python) cannot decrypt a sealed
>   .env: ModuleNotFoundError("No module named 'mordred_hermes'")
>   …
> ```
>
> Fix it by installing the package into that interpreter
> (`uv pip install --python <that-python> 'hermes-mordred[macos]'`) or by stopping
> that gateway and restarting it from the expected runtime, then re-run the
> command. `--force-runtime-unverified` skips both checks and seals anyway
> (advanced — the file stays unreadable until that runtime has Mordred). When no
> gateway is running, or the process table cannot be read, the extra check is
> skipped silently: it never blocks a seal on an inconclusive scan.
>
> `encryption status` reports the same discovery on macOS, one line per running
> gateway: `gateway runtime: <python> (pid N) — env shim: ok | config hook:
> MISSING`. `--json` output is unchanged (and skips the probes).

> **Changing the recovery passphrase.** `change-passphrase` rewraps the vault
> under a new passphrase and leaves the master key, the device key, and every
> enrolled file untouched — nothing is re-encrypted, and day-to-day automatic
> opening is unaffected. It tries this device's key first (so you can rotate even
> if you forgot the old passphrase, as long as the machine still works) and falls
> back to asking for the current passphrase when the device key is unavailable
> (non-macOS, or a vault copied to another machine).

### `keyvault` — hardware-backed key management
```sh
hermes-mordred keyvault init                # initialise the keyvault
hermes-mordred keyvault list                # list key IDs
hermes-mordred keyvault verify-digest       # integrity check
hermes-mordred keyvault export --output <path>  # create a new mode-0600 MRKV snapshot
hermes-mordred keyvault recover --blob <path>   # restore from a backup blob
hermes-mordred keyvault reset               # DESTROY profile-owned key material + remove the keyvault (irreversible; --yes to skip the prompt)
hermes-mordred keyvault enable-se           # macOS: build+install Secure Enclave helper (ad-hoc signed, no Apple Developer account)
                                # safe to refresh; key policy is selected only by fresh init/recovery — see §4.3
hermes-mordred keyvault enable-tpm          # Linux: build+install TPM 2.0 helper (machine-bound, Tier 2)
hermes-mordred keyvault eth <sub>           # Ethereum keys — see below
```

`keyvault export` refuses an existing output path and requires its immediate
parent to be a real directory. It prompts for the Keyvault init passphrase and,
for a paper-only Keyvault, the 24-word Seed Phrase; neither belongs in argv.
The snapshot is point-in-time, so export again after every Keyvault content
change. If the command exits non-zero but reports that the backup *was*
published and only a post-publication durability or cleanup step failed, the
file at `--output` is complete (mode `0600`); verify it and remove the private
`.<name>.mordred-materialize-*` staging copy if one was left beside it before
relying on it. Never run `reset` unless an isolated recovery test has verified the
latest blob or every dependency on the source has been removed.

#### `keyvault eth` — Ethereum keys (HD wallet)

`keyvault init` stores your 24-word seed encrypted by default
(`--store-seed-for-hd`), so accounts can be derived later without re-entering
it. **The raw private key never leaves the keyvault** — these commands return
only the EIP-55 address and an opaque `envelope_id` handle.

```sh
hermes-mordred keyvault eth new                          # generate a new random key
hermes-mordred keyvault eth derive --index 0             # derive BIP-44 account #0 from the seed
hermes-mordred keyvault eth address --envelope-id <id>   # show the address for a stored key
```

| Command | Key flags |
|---|---|
| `new` | `--key-id <id>` (default `default`), `--json` |
| `derive` | `--index N` / `--account N` / `--change N` (all default `0`), `--seed-envelope-id <id>`, `--key-id`, `--json` |
| `address` | `--envelope-id <id>` **(required)**, `--key-id`, `--json` |

- `derive` walks `m/44'/60'/account'/change/index`. The BIP-39 passphrase (the
  "25th word") is **not** supported — derivation always uses an empty passphrase.
- `--seed-envelope-id` is needed only when several seeds are stored.
- `derive` and `address` decrypt key material, so they trigger a Touch ID /
  passcode prompt unless the wrapping key is unattended (§4.3).
- Requires the `ethereum` extra; rerun the installer with `--extras ethereum`.

#### Legacy vaults and cross-profile migration

*Skip this unless you are carrying a vault created before profile-scoped native
key IDs, or moving one between `HERMES_HOME` profiles.*

Keys created by current releases are isolated per `HERMES_HOME`. A legacy
keyvault remains readable, but `keyvault reset` intentionally retains its
machine-global legacy Keychain tag because another profile may share it.
Create an
[`MRKV`](../dev/SPEC.md#backup-wire-format-versioning-phase-4-pr2-freeze-2026-05-14)
snapshot (the passphrase-protected keyvault backup format) with
`keyvault export --output <path>`, then import it into a fresh profile with
`recover --blob <path>`. Keep the original profile
and native helper store intact until the destination has been verified; export
does not make reset or source removal safe by itself.

Current profiles also record the profile-scoped audit wrapping key separately
from the main key. If audit-key generation or its durability check is
interrupted, Mordred will not use the uncertain key: auditing continues in
plaintext with a downgrade marker until the incomplete keyvault is reset and
recovered. A partially committed audit key is not treated as authoritative
merely because its native blob is visible.

### `vault` — the underlying encrypted store (advanced)
Normally driven by `encryption`; rarely used directly.
```sh
hermes-mordred vault init                   # new vault sealed under a recovery passphrase
hermes-mordred vault add <name> <file>      # encrypt a file under a logical name
hermes-mordred vault status                 # generation + enrolled file names (non-prompting)
hermes-mordred vault cat <name>             # decrypt one entry to stdout
hermes-mordred vault migrate                # import plaintext .env + config.yaml
hermes-mordred vault recover                # macOS only: re-key a copied vault onto this Mac
hermes-mordred vault change-passphrase      # rotate the recovery passphrase (also exposed as `encryption change-passphrase`)
hermes-mordred vault set-memory-key         # store/rotate HERMES_MEMORY_KEY (the agent-memory key; `encryption enable memory` turns sealing on)
hermes-mordred vault enable-config-decrypt  # put config.yaml under transparent at-rest decrypt
hermes-mordred vault disable-config-decrypt # stop managing config.yaml; restore plaintext
```

#### Migrate to a new machine

The vault is sealed two ways: this device's key (the everyday hot path) and a
recovery passphrase (the cold path). The supported recovery workflow currently
requires macOS on the destination. When you move to a new Mac, copy the vault
directory across and then re-key it onto the new device:

```sh
# on the old machine — the vault lives under <hermes home>/mordred/vault
cp -a ~/.hermes/mordred/vault /path/to/transfer/   # then move it to the new machine

# on the new machine, after restoring the directory to the same location
hermes-mordred vault recover                # prompts for the recovery passphrase and re-keys onto this device
```

`vault recover` cold-opens the copied vault with the recovery passphrase and
re-wraps the **same** master key under a fresh wrapping key in this Mac's Secure
Enclave, so the everyday automatic (writable) hot path works locally again —
the master key and every enrolled file are unchanged, and your recovery
passphrase stays the same for the next Mac. It is the encryption-vault
counterpart to `keyvault recover` (which restores keyvault key material from a
backup blob). Until you run it, a copied vault opens read-only (`vault cat`
works via the passphrase; `vault status` works with no passphrase at all, since
it only reads the on-disk manifest — but enrolling does not).

Do not run `vault recover` on Linux. The TPM helper supplies the wrapping
backend, but the current production path still resolves the device anchor
through the macOS Keychain store. Linux recovery requires a native anchor-store
implementation first and can otherwise fail after staging recovery files.

### `plugins`
```sh
hermes-mordred plugins list                 # discovered Mordred plugins
```

### `extension` — browser-extension pairing and server (preview)
```sh
hermes-mordred extension pair               # print a MORT-… code (+ QR with messaging), then wait
hermes-mordred extension pair --timeout 300 # seconds to wait for the extension to pair (default 600)
hermes-mordred extension serve              # run the extension WebSocket server in the foreground
hermes-mordred extension serve --port 7799  # bind a non-default port (default: 127.0.0.1:7788)
```
> `pair` prints a code and waits for a running extension WebSocket server to
> consume it — either this plugin's `extension serve` or a compatible
> legacy/custom gateway. After the normal platform install, the pairing path
> does not need the server's `extension` extra; `messaging` adds only the QR
> render. A `gateway.extension_pairing` fallback remains for compatible older
> custom checkouts. When no pairing backend is available, the command fails
> closed with a clear install hint.
>
> `serve` runs the plugin's own ported server (`mordred_hermes.extension`)
> standalone. Install the `extension` extra to guarantee its dependencies.
> Pairing, crypto, history, keyvault signing, and agent chat all work: the chat
> handler binds the
> Hermes runtime shipped with `hermes-agent`, so E2E-encrypted messages get
> real agent replies (a stub reply appears only if that runtime is missing);
> see [`EXTENSION.md`](./EXTENSION.md) for the security model and deployment
> options.
> Ctrl+C stops it; a bound port exits with a one-line error. Stock Hermes does
> not start this API, so inspect the owner rather than assuming an occupied
> port is reusable. The published Chromium bundle supports port 7788; port
> 7799 is for the localhost page, tests, or a suitably configured custom
> extension build. Non-loopback `--host` values are refused. To open the
> localhost web app, copy the complete private `Web page:` URL printed at
> startup, including its `#token=…` fragment.

---

## 4. Interactive command walkthroughs

The reference above (§3) is terse on purpose. The three commands that run an
**interactive flow** — `keyvault init`, `network init`, and `configure` — are
walked through in full here. [`QUICKSTART.md`](./QUICKSTART.md) keeps the short
path and points back to these sections for detail.

### 4.1 `keyvault init` — the interactive ceremony

`keyvault init` is not a one-shot key generation: it is an **interactive security
ceremony that needs a real terminal**. In a pipe or non-interactive context it
aborts cleanly with a non-interactive error (and a redirected stdout is refused
separately) instead of raising a raw error — always run it in your own terminal.
Three steps, in order:

1. **Choose a Passphrase** (hidden input). It is never stored. Together with
   the Seed Phrase and an exported backup blob, it is required for
   cross-device keyvault recovery.
2. **A 24-word Seed Phrase is shown** (auto-clears after 60s) — write it down.
3. **Offline verification digest.** In a second tab/device, run the command below,
   then re-enter the 64-char digest it prints at the `Verification digest …`
   prompt on the primary machine:

   ```sh
   python3 scripts/keyvault_offline_digest.py
   ```

   > On this dev checkout, plain `python3` works — the script auto-re-runs under
   > the bundled venv that has `blake3`. On a bare air-gapped device, first run
   > `python3 -m pip install blake3`.

   It asks for three values in order: ① the 24-word Seed Phrase, ② the Passphrase,
   ③ the
   [top4(PoW)](../dev/SPEC.md#proof-of-work-pow-algorithm-phase-4-pr10-step-0-freeze-2026-05-16)
   hex (shown on the init screen).

> On macOS, `keyvault init` can degrade to a software P-256 key in the login
> Keychain when Secure Enclave access is unavailable. Linux has no software
> floor: install the TPM helper with `keyvault enable-tpm`, or initialization
> fails closed. The ceremony itself is otherwise unchanged.

> The **first** `encryption enable` creates the underlying vault and asks once
> for a recovery passphrase (keep it safe — it is the cold-path recovery if the
> device key is ever lost). Later enables reuse it silently. You *can* pre-create
> the vault with `vault init`, but you don't need to — `encryption` drives it.

> **On ordering**: `keyvault init` and `encryption enable env` create different
> stores and different native keys. Run `keyvault init` when you need keyvault
> envelopes or HD-wallet derivation. Run `encryption enable env` to create the
> at-rest file vault. The 24-word keyvault seed does not replace the file
> vault's recovery passphrase and does not reconstruct its encrypted files.
> After Keyvault initialization, create and separately store a portable
> snapshot with `keyvault export`; it does not back up the at-rest file vault.

### 4.2 The device key and the recovery passphrase are different things

For the at-rest file vault, the **device key** and the **recovery passphrase**
are two different ways to open the same random master key. Both are created by
the first `encryption enable` (or an explicit `vault init`). They are separate
from the main `default` key and seed ceremony created by `keyvault init`.

| | ① Device key | ② Recovery passphrase |
|---|---|---|
| Created by | First `encryption enable` or `vault init` | First `encryption enable` or `vault init` |
| What it is | a Secure Enclave / TPM hardware key | a string you remember |
| Where it lives | native device/helper storage; it is non-exportable | with the operator, ideally in a password manager |
| When it's used | Normal device-backed vault opens | Cold recovery or migration to another device |
| Weakness | Lost with an unavailable device/helper store | Must be stored and entered securely |

Both seal the same master key:

```
.env secrets ──encrypt── master key ┬─ sealed by ① device key   (hot path, automatic)
                                     └─ sealed by ② passphrase   (cold path, recovery)
```

**Why not collapse them into one?**

- **Only ①** → lose the device and the vault is **unrecoverable forever**.
- **Only ②** → every normal open needs operator input and loses the
  device-backed hot path.

① cannot be exported; ② can be carried. They are alternative wrappers around
one master key, not two factors that must both be presented for each open.

### 4.3 Touch ID prompts — why several per command, and how to silence them

On macOS the device key (①) lives in the **Secure Enclave**, and by default it is
created in **attended** mode: macOS asks for **Touch ID every time the vault is
unwrapped**. Each component that opens the vault prompts independently, so a
*single* `hermes-mordred …` run can unlock the vault more than once:

- the `config` decrypt hook at interpreter startup (after `encryption enable config`),
- the `.env` injection when the plugin loads (after `encryption enable env`),
- plus whatever the command itself touches (e.g. `encryption enable memory`
  re-enrolls `.env` once to store the memory key).

So with `env` + `config` on you will typically see **2–3 Touch ID prompts per
command** — expected, not a bug.

**Recommended: create the SE key in unattended mode** — especially if anything
starts Hermes in the **background** (a launchd-started gateway, `extension
serve`). An attended key blocks a background process on a Touch ID prompt it can
never answer: after the 120 s helper timeout the process starts **without** the
vault-managed secrets (e.g. a Slack bot token sealed in `.env` silently drops
that platform, with only a `Failed to load plugin 'mordred_keyvault':
auth_failed` warning in the logs). To make the hot path **silent** (no Touch ID
while the Mac is unlocked), install the helper and select **unattended** policy
on a later fresh device-key creation command:

```sh
hermes-mordred keyvault enable-se                # build + install/probe the SE helper
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred keyvault init
                                     # optional main keyvault key, unattended
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred encryption enable env
                                     # file-vault device key, unattended
```

The environment variable applies only to the command it prefixes. After the
file-vault key is created unattended, its normal opens do not require Touch ID
while your login session is unlocked.

`keyvault enable-se` may install or refresh the helper with an existing
keyvault, but never creates, promotes, or migrates a wrapping key. Existing
helper-store, legacy PyObjC-Keychain, and software keys remain in their original
namespace and continue through ordered backend fallback. The same
`MORDRED_SEKEY_UNATTENDED=1` policy can prefix a recovery command when that
command creates a genuinely fresh device key.

> **Trade-off**: an unattended SE key (access control `.privateKeyUsage` only) can
> be unwrapped by any process running as you while the Mac is unlocked — you trade
> per-use biometric confirmation for convenience. Ciphertext-at-rest and the
> recovery passphrase (②) are unaffected.

> **Already created an attended key?** The attended/unattended choice is fixed
> when the key is created. Re-running `enable-se` safely refreshes the helper
> but cannot convert that key. For the file vault, keep the complete vault
> directory and recovery passphrase; `vault recover` can re-key a copied vault
> on a genuinely fresh device/profile, but it is not an in-place policy toggle.
> For the main keyvault, export a fresh portable blob and verify recovery into
> a fresh profile before considering an attended-to-unattended replacement.
> Never reset either store while secrets or wallets still depend on it.

### 4.4 `network init` — the dialog and prompts

`network init` is interactive. The first thing it shows is the radio dialog —
**Network privacy path**:

```
   ┌─| Network privacy path |──────────┐
   │  ( ) tor                          │
   │  ( ) vpn                          │
   │  (*) clearnet                     │
   │                                   │
   │     < Ok >      < Cancel >        │
   └───────────────────────────────────┘
```

It picks the **default** route written to config — `(*)` marks the current
choice (`clearnet` on a fresh setup). `network use` can change that saved
choice later; restart Hermes to activate the route before provider clients are
built. A running Hermes process never switches its frozen route live.

**How to operate it**: **↑ / ↓** move the highlight, **Space** selects (moves
the `*`), **Tab** jumps to the `< Ok >` / `< Cancel >` buttons, **Enter**
activates the focused button.

**What each route is** — what the setting actually does, and what it needs:

- **`tor` — anonymity, slowest.** Mordred launches the official `tor` daemon as a
  child process and routes traffic through a local SOCKS proxy (port `9050` by
  default); your traffic hops through the Tor network and your source IP is
  hidden. *Needs:* `tor` installed (`brew install tor` / `apt-get install tor`).
  *Note:* bridges / obfs4 / Snowflake (for censored networks) aren't supported in
  v1. Pick this when anonymity matters most and you can accept the speed cost.
- **`vpn` — IP privacy with speed (any VPN; Mullvad recommended).** The `vpn`
  route can drive any VPN — Mullvad is the recommended default, but `wireguard`
  / `custom` providers let you use Proton VPN, IVPN, ExpressVPN, and others (see
  *Using a different VPN* below). With Mullvad, Mordred drives the official
  `mullvad` CLI to connect; your real IP is hidden behind the VPN exit, and it
  judges liveness by handshake age. The *killswitch* prompt blocks all traffic
  if the VPN drops. *Needs (Mullvad):* the Mullvad app/CLI installed,
  `mullvad account login`, and a Mullvad account (a paid service). macOS (Apple
  Silicon) and Ubuntu/Debian only; Windows is out of scope in v1. Pick this for a
  hidden IP without Tor's slowdown.
- **`clearnet` — direct, no privacy (default).** A genuine no-op: no proxy, no
  daemon, no traffic rewriting — your connection goes straight out as usual.
  *Needs:* nothing. Fastest and simplest, but your source IP is fully visible.
  Pick this if you don't need anonymity or just want things working.

After the path, `network init` asks **only the prompts the route you picked
needs** (UX request 2026-08-12): pick `clearnet` and the wizard is done right
there — no further prompts. Pick `tor` and it asks the **Tor prompts** below.
Pick `vpn` and it asks a **VPN provider** question, then the prompts for
whichever provider you picked. A route you didn't pick is never asked about
and its previously saved settings are left exactly as they were on disk —
switching routes on a re-run never wipes another route's configuration.

**Tor route only** (asked only if you picked **tor**) — defaults are usually fine:

| Prompt | Default | What it means |
|---|---|---|
| Tor binary path | `tor` | Where the `tor` program is. Leave as `tor` if it's on your PATH. |
| Tor SOCKS port | `9050` | Local port Tor's SOCKS proxy listens on. Standard is 9050; rarely changed. |

**VPN route only** (asked only if you picked **vpn**) — `network init` asks **which
VPN provider** to use *first*, and only then that provider's prompts:

| Provider | Use it for | What `network init` then asks |
|---|---|---|
| `mullvad` *(default)* | Mullvad — the only provider allowed in **strict** mode. | The 3 Mullvad prompts below. |
| `wireguard` | Any VPN that exports a WireGuard `.conf` (Proton VPN, IVPN, Windscribe, self-hosted). | **WireGuard config path** — the `.conf` file. Mordred runs `wg-quick up/down` on it. |
| `custom` | Any VPN with only its own CLI (ExpressVPN, NordVPN, Surfshark). | **up / down / health** commands. The health command must exit `0` only while the tunnel is connected; see the guidance below. |

The **Mullvad prompts** appear *only if you keep the `mullvad` provider* — pick
`wireguard` or `custom` and you're never asked for a Mullvad account number:

| Prompt | Default | What it means |
|---|---|---|
| Mullvad account number | (keep current) | Your Mullvad account number. Blank keeps the saved one; saved to `~/.hermes/.env`. |
| Mullvad relay country | `auto` | `auto`, or a 2-letter code (e.g. `se`) to pin the VPN exit country. |
| Mullvad killswitch | `no` | Lockdown mode — block all traffic if the VPN drops, so your real IP can't leak. |

> **In short:** the route you pick decides everything else you're asked.
> Want **clearnet** (the default)? Answer the one path question and you're
> done. Pick **tor** → also answer the 2 Tor prompts (defaults usually fine).
> Pick **vpn** → also choose a provider, then answer its prompts (3 for
> Mullvad).
>
> Prefer no dialog? Set everything from flags in one shot:
> `hermes-mordred network init --non-interactive --path tor` (see `network init --help`).

#### Using a different VPN (not just Mullvad)

Mullvad is the **recommended default**, but the `vpn` route can drive any VPN —
the **VPN provider** question above is where you choose, and the Mullvad prompts
are skipped entirely when you don't pick Mullvad. So **Proton VPN** →
`wireguard` (download its `.conf` from the Proton portal); **ExpressVPN** →
`custom` (`expressvpnctl connect` …). You can also set these directly in
`~/.hermes/config.yaml` under `plugins.mordred_network`: `vpn_provider`,
`wireguard_config_path`, and `custom_up_cmd` / `custom_down_cmd` /
`custom_health_cmd` (each a YAML list, e.g. `[expressvpnctl, connect]`).

Choosing a custom health command requires checking the behavior of the VPN CLI
version installed on your machine. Mordred ignores the command's printed output:
exit status `0` means healthy, and any non-zero status means unhealthy. A command
that prints `Disconnected` but still exits `0` is therefore not a valid probe. If
you leave the health command blank, setup can continue, but Mordred cannot detect
a dropped tunnel and always reports this provider as healthy.

For example, on a Mac where `command -v expressvpnctl` prints
`/usr/local/bin/expressvpnctl`, enter:

```text
VPN up command: expressvpnctl connect
VPN down command: expressvpnctl disconnect
VPN health command: /bin/sh -c 'test "$(/usr/local/bin/expressvpnctl get connectionstate)" = Connected'
```

Replace `/usr/local/bin/expressvpnctl` with the path reported on your machine.
The explicit `/bin/sh -c` wrapper converts ExpressVPN's `Connected` /
`Disconnected` output into the exit status Mordred needs. A plain
`expressvpnctl status` is unsuitable if that version exits `0` in both states.

If these commands are difficult to determine or enter, keep the wizard open and
consult a local coding assistant such as Claude Code or Codex. Ask it to inspect
the installed CLI rather than guess. This prompt is suitable to copy and paste:

> Inspect the VPN CLI installed on this machine. Tell me exactly what to enter for
> Mordred's VPN up, down, and health prompts. The health command must return exit
> status 0 only while connected and non-zero while disconnected; Mordred ignores
> printed status. Use `command -v` to find the exact executable path. Do not
> change the VPN connection state or expose credentials without asking me.

> **Strict mode is Mullvad-only.** Mordred can verify a kill-switch / DNS-leak
> protection only for Mullvad (it drives `mullvad lockdown-mode` directly), so
> under **strict** policy a `wireguard` / `custom` provider is **refused**
> (fail-closed). Use them under **lenient** / **off** policy — fine for everyday
> IP privacy. Mordred runs custom commands directly as argv; a shell is involved
> only when you explicitly configure one, as in the `/bin/sh -c` example above.
> Commands are read only from your config. Platform: macOS + Linux.

### 4.5 `configure` — policy mode and the agent harness in detail

`hermes-mordred configure` walks through a short list of Mordred questions. It
does not run upstream `hermes setup` unless you pass `--with-hermes-setup`.
**If in doubt, press Enter through the Mordred prompts** to keep their defaults.
After you select `lenient`, the wizard also explains that the remaining settings
only affect strict mode and that accepting their defaults is safe.

| # | Question | Default | What it means | Do |
|---|---|---|---|---|
| 1 | Mordred policy mode | `lenient` | How strictly rules are enforced (detail below). | Enter |
| 2 | Allow cloud LLM providers? | `N` | Permit cloud LLMs at all. | Enter |
| 3 | Cloud provider allowlist | (hidden) | Only shown if you answered `y` above. Pick providers from a checkbox list (Space to toggle, Enter to confirm). | Skipped on `N` |
| 4 | Local LLM endpoint URL | `http://localhost:1234/v1` | Where your local LLM is reached. Under strict mode this must be loopback HTTP(S). | Enter |
| 5 | Local LLM model id | empty | Local LLM model name. | Enter |
| 6 | On cloud LLM attempt under strict mode | `always-block` | What to do when a cloud LLM is attempted under strict. | Enter |
| 7 | Agent harness | `none` | Which agent tool drives Hermes (Claude CLI / Codex / Cursor / …). | Enter |

> - Questions 2–7 only change runtime behaviour under **strict** mode; with the
>   default `lenient`, nothing is blocked.
> - Under `strict`, `mordred-local` accepts only the exact HTTP(S) loopback IP
>   `127.0.0.1` / `::1`, or `localhost` whose DNS results are all loopback.
>   URLs containing credentials are refused. This check applies equally to the
>   configured endpoint and Hermes's resolved runtime URL, before any health
>   probe or model request. Active process proxies are bypassed for these exact
>   hosts, and the health probe never trusts ambient proxy variables.
>   Non-strict modes keep their existing behaviour.
> - `prompt-once` (Q6) asks once per provider whether to allow that provider for
>   the remainder of the current Hermes process under strict mode — but only at an
>   interactive terminal. Headless / harness / CI sessions have no TTY, so it
>   fails closed to `always-block` there. The decision is cached for the session
>   and audited as `policy.strict.cloud_prompted_allow` / `_deny`.
> - Q7 (agent harness): pick the tool you actually drive Hermes with (Codex /
>   Claude CLI / Cursor / …) for accurate auditing, or `none` if unsure. Under
>   strict mode a declared harness refuses the session — by design, because
>   Mordred cannot observe that tool's LLM traffic.
> - `configure` only writes `config.yaml` + `policy.json`. It does **not** create
>   keys or encrypt anything — that is `keyvault init` → `encryption enable`.

#### Policy mode (Q1) in detail

| Mode | What it means | Who it's for |
|---|---|---|
| `strict` | The strictest. Refuses unapproved cloud LLMs, disables IPv6 use by Mordred's Tor client, and refuses a declared/known AI harness. | Advanced users who want fail-closed behavior. |
| `lenient` (**default / recommended**) | Standard. Guards are active but stay out of your way — the built-in default. | Most people, and anyone who just wants it working. |
| `off` | Disables all guards entirely. | Anyone who wants no restrictions at all. |

> Only `strict` can actually stop you (refuse a session or block an install).
> `lenient` just records audit warnings; `off` does nothing.

#### Agent harness (Q7) in detail

This setting declares **which tool you run Hermes through**. It is not a switch that
raises or lowers security — think of it as an honesty field that tells Mordred exactly
what it can and cannot police.

**Premise — how Mordred guards you:**
For the primary Hermes request, Mordred checks the resolved provider and actual
endpoint at `pre_api_request`, immediately before egress. Hermes auxiliary LLM
clients do not all emit that hook, so Mordred also guards their resolver and
client-construction seams.

```
[Hermes provider] → [pre_api_request check] → [LLM endpoint]
                              ↑ allow or refuse here
```

**Problem — external tools (harnesses) take a side road:**
Codex / Claude CLI / Cursor / ACP clients carry their own line to the AI. They
call the LLM *without going through Hermes*, so neither the primary hook nor
the auxiliary guards see it — the traffic is invisible to Mordred.

```
[Codex / Claude CLI / …] ──direct──→ [cloud LLM]   ← bypasses the hook = invisible to Mordred
```

**So strict refuses:**
`strict` mode guarantees the policy can be *fully* enforced. If invisible traffic exists it
cannot guarantee that, so it would rather stop than let it half-through (fail-closed).

| Mode | When a known harness is detected |
|---|---|
| `strict` | **Refuses** the session (can't guarantee enforcement → stop) |
| `lenient` | **Warns + audits** and continues |
| `off` | Does nothing (the check is disabled) |

**How to pick:** running `hermes` directly in your terminal → `none`. Running it inside
Codex / Claude CLI / Cursor / Zed (ACP) → pick that tool. `acp-claude` / `acp-cline` apply
only when you reach Claude / Cline **via ACP (Agent Client Protocol)** (e.g. the Zed editor).
If none of this rings a bell, `none` is correct.

#### Inspect or change it later

| Do (command) | Purpose | Result |
|---|---|---|
| `hermes-mordred policy show` | Print the resolved policy currently in force. | Outputs `policy.json`. |
| `hermes-mordred configure --non-interactive --policy strict` | Switch to strict mode without prompts. | Policy mode set to `strict`. |
| `hermes-mordred policy explain <skill-id>` | Explain whether a skill would be allowed to install. | Prints the decision (exit 2 = block). |

---

## 5. The three storage layers

The three command families are related, but they are not one nested store:

```text
native device backend (Secure Enclave or TPM)
├── keyvault   purpose-bound MREN envelopes and wallet/seed material
└── vault      encrypted file container with its own device key + passphrase
    └── encryption   macOS-oriented env/config/memory/workspace facade
```

- **`keyvault`** manages the main logical key, purpose-bound secret envelopes,
  recovery-digest ceremony, and wallet material.
- **`vault`** is a separate encrypted file container under
  `<home>/mordred/vault/`. Use its commands for migration, cold recovery, or
  low-level inspection.
- **`encryption`** drives the vault for common targets. Its transparent runtime
  lifecycle is macOS-only; Linux keyvault/TPM support does not make these
  targets active.

See [`SPEC.md`](../dev/SPEC.md) for the security contract and
[`PATHS.md`](../dev/PATHS.md) for the complete storage inventory.

---

## 6. Conversational read-only access (`mordred-status` skill)

Mordred's runtime plugins register no mutation-capable agent tools. An agent
must not be able to loosen its own constraints, and secrets must not flow
through a recorded transcript. The repository does include one optional,
read-only observation skill so you can ask the Hermes agent "what's my mordred
status?" in chat. The trust boundary is documented in
[`SPEC.md`](../dev/SPEC.md) §Threat Model & Accepted Limitations.

The skill ships in this repo at `skills/mordred-status/SKILL.md`.
Install = copy it into the Hermes skills directory:

```sh
mkdir -p ~/.hermes/skills/mordred-status
cp skills/mordred-status/SKILL.md ~/.hermes/skills/mordred-status/
```

What it allows the agent to run — metadata-only, no secrets:
`status [--json]`, `policy show`, `policy explain <id>`, `network status`,
`plugins list`. Everything else (any mutation, `audit decrypt`, `vault cat`,
even `audit tail|grep`) is explicitly forbidden inside the skill: the agent must
print the command for you to run yourself in your shell.

The skill declares `metadata.mordred: {network_requirements: local-only,
requires_keyvault: false}` and passes the policy gate cleanly
(`hermes-mordred policy dry-run skills/mordred-status` → allow,
including under strict mode).

> **Residual risk**: the FORBIDDEN list is a prompt-level instruction, not an
> enforcement mechanism. Hard enforcement of what the agent may execute belongs
> to the Hermes exec-tool approval settings, not to this skill.

---

## 7. Platform notes

- **macOS Apple Silicon**: Secure Enclave is the production key backend. The
  helper is ad-hoc codesigned (free — no Apple Developer account). Build/install
  via `keyvault enable-se`. The `workspace` encryption target is "sealed when
  idle" only (not while mounted under the same user).
- **Linux**: TPM 2.0 is the key backend (`keyvault enable-tpm`). MVP binding is
  machine-only (Tier 2 — no per-use PIN/PCR prompt). Transparent `.env` and
  `config.yaml` loading/resealing, agent-memory sealing, and workspace
  encryption are inactive; plaintext stays the runtime source and status
  reports the limitation.
- **Fallback behavior**: macOS can use a software P-256 key in the login
  Keychain when Secure Enclave access is unavailable. Linux deliberately has no
  software fallback and fails closed without the TPM helper.

---

## 8. Troubleshooting

- For keyvault, Touch ID, and recovery issues, start with
  [§4](#4-interactive-command-walkthroughs). File-vault recovery is currently
  macOS-only; encrypted data cannot be recovered if both its device key and
  recovery passphrase are lost. Keep Keyvault snapshots, the init passphrase,
  and the Seed Phrase separate.
- For browser-extension, gateway, pairing, or port 7788 issues, use the
  [`EXTENSION.md` troubleshooting table](./EXTENSION.md#troubleshooting).
- For Tor or VPN issues, run `hermes-mordred network status`, select the
  intended route with `hermes-mordred network use tor` (or `vpn` / `clearnet`),
  and restart Hermes if the route changed.
- If the audit log falls back to plaintext with
  `mordred.degraded.audit_encryption_unavailable`, restart from a context that
  can access the device key. Recovery is automatic.
- Audit entries are plaintext until `keyvault init` creates the material needed
  by the encrypted writer. `hermes-mordred status` reports the active audit-log
  state.

---

## 9. Package upgrades and removal

### Upgrade the installed package

Re-run the installer with the same `--extras`, `--all-extras`, or
`--with-extension` flags used for the original installation, then restart the
Hermes gateway or standalone Extension server:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
```

A Hermes self-update can recreate `~/.hermes/hermes-agent/venv`. Repeat the
same feature flags whenever you reinstall or upgrade so optional dependencies
such as `extension`, `ethereum`, `messaging`, and `tor-control` are installed
and re-resolved in the new environment.

To install an exact release, replace `VERSION` with its PEP 440 version and
retain any required feature flags:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --version VERSION
```

For an Extension installation, add `--with-extension` before `--version`.
Custom installations should likewise repeat their original `--extras ...` or
`--all-extras` selection.

### Migrate existing configuration

`hermes-mordred upgrade` migrates an existing Hermes or OpenClaw configuration;
it does not install a newer package:

```sh
hermes-mordred upgrade
```

The migration is safe to repeat. Fresh installations should use `configure`
instead.

### Uninstall safely

Decrypt protected data before removing the package or native keys:

```sh
hermes-mordred encryption disable all
hermes-mordred vault disable-config-decrypt
hermes-mordred encryption status          # verify every target is off
```

After verifying the plaintext data, you may explicitly destroy profile-owned
keys. This command is irreversible:

```sh
hermes-mordred keyvault reset --yes
```

Remove the six `mordred_*` entries from `plugins.enabled`, then uninstall both
the canonical distribution and the legacy compatibility name:

```sh
uv pip uninstall --python ~/.hermes/hermes-agent/venv/bin/python3 \
  mordred-hermes hermes-mordred
rm -f "$(dirname "$(command -v hermes)")/hermes-mordred"
```

State under `~/.hermes/mordred/` and installed native helpers are intentionally
left behind. Remove them manually only after confirming that no encrypted data
or backup still depends on them.
