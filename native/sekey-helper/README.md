# mordred-hermes-sekey

A small, signed Swift CLI that performs Secure Enclave (SE) P-256 operations on
behalf of the (unsigned) Python `hermes-mordred` keyvault.

## Why this exists

An unsigned / ad-hoc-signed Python interpreter cannot carry the
`keychain-access-groups` entitlement, so persisting SE keys *in the Keychain*
fails with `errSecMissingEntitlement (-34018)`. The usual fix
(`keychain-access-groups` + a provisioning profile + a `.app` bundle) requires
a **paid Apple Developer Program** membership — and a bare Developer-ID CLI
that requests the entitlement without a profile is SIGKILLed by AMFI.

This helper sidesteps all of that with **CryptoKit**
(`SecureEnclave.P256.KeyAgreement.PrivateKey`): it never touches the Keychain.
The private key lives in the Secure Enclave; its `dataRepresentation` — an
opaque blob that *only this device's Enclave* can decrypt and use — is written
to an ordinary file. A leaked blob is useless on any other machine, so no
entitlement, no provisioning profile, no `.app` bundle, and **no paid Developer
account** are needed. An **ad-hoc codesign** (`codesign --sign -`) is enough.

```
Python (unsigned)
  └─ subprocess ──▶ mordred-hermes-sekey (ad-hoc signed)
                       └─ CryptoKit SecureEnclave key
                            • private key: in the Secure Enclave
                            • dataRepresentation blob: <store>/<tag_hex>.bin
```

### Key blob store

`<store>` is resolved in this order:

1. `MORDRED_SEKEY_STORE` — explicit directory (authoritative).
2. `$HERMES_HOME/mordred/keyvault/sekey`
3. `~/.hermes/mordred/keyvault/sekey`

This mirrors `mordred_hermes._home.hermes_home`. The directory is created
`0700` and each `<tag_hex>.bin` blob is written `0600`. A blob is completed,
chmodded, and synced under a private staging name before an atomic no-replace
hard link publishes it, so neither a short write nor a concurrent generator can
leave a partial or silently replaced authoritative key. The helper rejects a
symlinked/non-directory/loose-mode store and reads blobs with no-follow,
regular-file, and exact-mode checks. Publication is reported successful only
after the store directory syncs; a sync failure is indeterminate and leaves the
visible orphan for explicit reset/remediation rather than letting Python commit
ciphertext against a non-durable key name.

## Protocol (one process invocation = one operation)

Send a single JSON object on stdin; read a single JSON object on stdout.

| Request | Success response |
|---|---|
| `{"cmd":"generate","tag_hex":"..","label":".."}` | `{"public_key_hex":"04.."}` |
| `{"cmd":"public_key","tag_hex":".."}` | `{"public_key_hex":"04.."}` |
| `{"cmd":"delete","tag_hex":".."}` | `{"ok":true}` |
| `{"cmd":"ecdh","tag_hex":"..","peer_pub_hex":".."}` | `{"shared_hex":".."}` |
| `{"cmd":"probe"}` | `{"ok":true}` |
| `{"cmd":"anchor_get","account":".."}` | `{"value_hex":".."}` |
| `{"cmd":"anchor_add","account":"..","value_hex":".."}` | `{"ok":true}` (fails with `-25299` if present) |
| `{"cmd":"anchor_set","account":"..","value_hex":".."}` | `{"ok":true}` (update, else add) |
| `{"cmd":"anchor_delete","account":".."}` | `{"ok":true}` (idempotent) |

Failure (any command), exit code 1:

```json
{"error":{"domain":"OSStatus","status":-25300,"message":".."}}
```

`tag_hex` is derived from `key_id` as a SHA-256 prefix by the Python side.
The cleartext `key_id` is never sent across the subprocess boundary.

### Authorization policy (per key)

`generate` takes an optional `"unattended"` boolean (default `false`):

- **`false` (interactive, default):** the key is gated by Touch ID / passcode, so every `ecdh` prompts. Use for a human-approved vault.
- **`true` (unattended):** the key carries only `.privateKeyUsage` — still Enclave-bound (cannot be copied to another machine) but `ecdh` runs **without a prompt** while the session is unlocked. Use for autonomous encrypt+decrypt (e.g. hermes / Claude Code).

The choice is baked into the key's `dataRepresentation` at generation time and cannot change afterward. Encryption (`wrap_dek`) never needs the private key, so it is always prompt-free regardless of this flag — only decryption (`unwrap_dek` → `ecdh`) is affected.

On the Python side this is `unattended=` on `api.generate` / `wrap.generate_wrapping_key` / `backend.generate_enclave_key`; when unspecified, the default comes from the `MORDRED_SEKEY_UNATTENDED=1` env var, else interactive.

Generation and deletion are serialized with a private store-wide `.lock` file.
For generation, the lock spans the existence check, Secure Enclave key creation,
and atomic blob publication. Concurrent helpers therefore cannot both pass the
duplicate check and replace one another's key; exactly one request wins and
later requests return `errSecDuplicateItem`. A concurrent delete likewise
cannot remove a newly generated blob between that check and publication.

When **interactive**, `ecdh` triggers a system prompt because the
key is created with the access control
`[.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]` — Touch ID
preferred, with a **device-passcode fallback**. The fallback matters: with
`.biometryCurrentSet` alone, a biometry lockout (e.g. repeated failed Touch ID
reads, which happen with an ad-hoc-signed CLI) would make the wrapping key
unusable until a screen unlock. `.biometryCurrentSet` still invalidates the key
if the enrolled fingerprint set changes.

Error status ints mirror the legacy Keychain path so the Python
`_translate_error` table is unchanged: duplicate → `-25299`
(`errSecDuplicateItem`), missing → `-25300` (`errSecItemNotFound`), any auth /
generic failure → `-25293` (`errSecAuthFailed`), all with `domain:"OSStatus"`.

## Build, sign, install

The easiest way is the Mordred CLI — it locates these sources (in a source
checkout or a `pip install`-ed wheel), builds + ad-hoc-signs + installs the
helper, then verifies the Secure Enclave probe:

```bash
hermes-mordred keyvault enable-se
# Authorization policy is selected when the key is created, not at install:
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred keyvault init
```

The installer may also refresh the helper with an existing vault. It never
promotes or migrates an existing wrapping key: helper-store, legacy
PyObjC-Keychain, and software keys stay in their original namespace and remain
reachable through the Python backend's ordered fallback.

Or run the build script directly:

```bash
./build.sh
```

Both run `swift build -c release`, codesign ad-hoc (no Developer ID, no
provisioning profile, no paid Apple Developer account required), and install to
`~/.local/bin/mordred-hermes-sekey`. Installation copies and syncs to a private
file in the destination directory, verifies that staged signature, then
atomically renames it over the old helper; an interrupted copy leaves the
previous executable intact. The destination directory sync is required before
the installer reports success. Key-blob publication and deletion inside the
helper use macOS `F_FULLFSYNC` for the blob/store directory (falling back to
`fsync` only when the filesystem reports that full sync is unsupported).

Overrides via env: `MORDRED_SEKEY_INSTALL_DIR` (install target),
`MORDRED_SEKEY_STORE` (key blob directory).

Smoke test:

```bash
echo '{"cmd":"probe"}' | ~/.local/bin/mordred-hermes-sekey
```

## How Python finds it

`mordred_hermes.keyvault._seckey_helper._find_helper()` looks, in order:

1. `MORDRED_SEKEY_HELPER` env var (absolute path)
2. `~/.local/bin/mordred-hermes-sekey`
3. `mordred-hermes-sekey` on `PATH`

When found, it becomes the SE backend; otherwise the keyvault falls back to
pyobjc and then a software P-256 key (see `_seckey_backend.py`).

## Vault anchor items (`anchor_*`)

The at-rest vault pins a small non-secret freshness anchor (`SHA-256(wmk)` and
the manifest generation) in a login-keychain generic-password item. Items in
the legacy login keychain trust only the binary that created them (by code
hash, plus a `cdhash:` partition id for ad-hoc-signed code); any other binary
that reads, updates or deletes the item makes macOS ask for the login password
("... wants to use your confidential information stored in ... in your
keychain"). When Python wrote the item in-process, every other interpreter -- a
development venv, Hermes's managed Python, an upgraded Python -- triggered that
dialog on each access, several times per setup flow.

The `anchor_*` commands move the item behind this helper: the helper creates
and reads it, so every Python process on the machine goes through one binary
whose code hash the item trusts. Details:

- **Fixed service.** The helper only ever addresses service
  `mordred-hermes.vault.anchor.sekey`; Python passes the account (the vault's
  anchor label) and the value. It cannot be used to read arbitrary keychain
  items. `MORDRED_SEKEY_ANCHOR_NAMESPACE` (lowercase letters, digits, `-`; live
  tests only) appends `.<namespace>` to that service.
- **Same protection as before.** `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
  legacy login keychain (the data-protection keychain needs the
  `keychain-access-groups` entitlement, which ad-hoc-signed code cannot hold),
  default ACL = this binary only. No "allow all applications".
- **Migration.** When the helper item is absent, Python reads the old
  in-process item (`mordred-hermes.vault.anchor`) once -- the one access that
  may still ask for the password, when the running interpreter did not write
  it -- copies it with `anchor_add` (add-only: a concurrent newer pin is never
  overwritten), and tries to delete the old item without prompting.
- **Older helpers** answer `unknown cmd`; Python then keeps using the
  in-process item for that process, as before.
- **Reproducible build.** `build.sh` links with `-Xlinker -S` so the binary (and
  its ad-hoc code hash) does not depend on the source path or build time.
  Rebuilding the same source with the same toolchain keeps the item trusted; a
  helper built from changed source asks once per anchor item -- answer
  **Always Allow** so the new binary is added to the item's ACL.
