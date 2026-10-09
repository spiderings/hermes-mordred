# Windows TPM helper

`mordred-hermes-winkey.exe` provides user-scoped P-256 ECDH through the explicit
Microsoft Platform Crypto Provider. It requires a usable TPM and credentialed
Windows logon. It never falls back to software, exports a private key, captures
a password, or impersonates a user. This helper does **not** establish complete
Windows support for Mordred's filesystem, memory, network, wizard, or Desktop.

## Build and install

Install Rust MSVC (minimum 1.85), Visual Studio C++ Build Tools and a Windows
SDK. The source directory must be writable for Cargo build artifacts (use a
user-owned Hermes virtual environment for bundled sources). From PowerShell,
with the intended Hermes Python environment available:

```powershell
.\build.ps1 -Python C:\path\to\venv\Scripts\python.exe
# Or select an explicit absolute installation directory:
.\build.ps1 -InstallDir 'C:\Users\alice\Hermes home\bin'
```

The default destination is `bin` under the profile-aware Hermes home resolved by
that Python. The script builds locked sources, verifies the copied executable
hash, and atomically replaces an existing helper. A failed build or an in-use
destination retains the old binary. Installation does not create a key or prove
TPM readiness. Stop active helper processes before updating.

Python discovers an explicit `MORDRED_WINKEY_HELPER` first, then the selected
Hermes home's `bin/mordred-hermes-winkey.exe`, then absolute PATH directories.
An invalid explicit override fails closed. Trust the selected directories;
this is an unsigned local build, not publisher-signature verification.

## Protocol and custody

One UTF-8 JSON request (maximum 4096 bytes) on stdin, followed by EOF; one JSON
response plus newline on stdout. Failures return a nonzero exit and
`error: {domain, status, message, reason}`. Neutral reasons are `NOT_FOUND`,
`EXISTS`, `UNAVAILABLE`, and `AUTH_DENIED`. Native numeric statuses are retained.

Commands: `generate`, `public_key`, `ecdh`, `delete`, `probe`. Tagged commands
require `tag_hex` encoding 1–256 bytes. `ecdh` additionally requires
`peer_pub_hex`, an uncompressed SEC1 P-256 point. Generation/public lookup return
`public_key_hex`; ECDH returns a 32-byte big-endian `shared_hex`; deletion/probe
return `ok: true`. Existing `label`/`unattended` fields are accepted, but this
hardware tier does not offer biometric authorization.

Persisted names are `mordred-hermes:<sha256(decoded_tag)>`. A SID-scoped Global
Windows mutex serializes operations on a key across helper processes and logon
sessions (30-second timeout, no unlocked fallback). The tested TPM's native
create/finalize pair alone allowed competing creations despite no overwrite
flag. Probe uses its own random key, performs ECDH and requires successful
cleanup. `NOT_FOUND` can also mean an inaccessible keyset under the current
token; it is never permission to automatically regenerate a key. Deletion must
open and delete the exact key. An unopenable keyset returns `UNAVAILABLE` with
the original status, including repeat deletion after successful removal. PCP
enumeration omitted inaccessible retained keys in the actual cloned-disk test;
neither enumeration nor a successful fresh-key probe can establish absence.
Windows therefore does not promise success-on-missing deletion idempotency.

Windows CNG `TRUNCATE` raw ECDH is little-endian: the helper reverses all 32 bytes,
preserving leading zeros for the existing MRKW format. Private export policy
must be zero. The generated key is bound to the originating TPM and user;
copying a disk is not a recovery mechanism.

## Verification

```powershell
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo +1.85.0 test --locked
# Disposable keys, isolated ordinary test account, actual hardware only:
$env:MORDRED_WINKEY_TEST='1'
cargo test --locked --test live_cng -- --ignored --test-threads=1
```

Live tests cover independent P-256 parity including a leading-zero secret,
private-export refusal, duplicate preservation, concurrent operations and probe
cleanup. Without the explicit gate the hardware cases remain ignored. The
Python production MRKW gate is `tests/integration/test_keyvault_windows.py`;
set `MORDRED_WINKEY_HELPER` to the compiled executable and use `pytest -m integration`.
Build/install tests use `MORDRED_WINKEY_BUILD_TEST=1` and `tests/test_winkey_build.py`.
Use an isolated Hermes home for every test. Actual AWS validation and remaining
Windows limits are recorded in `docs/dev/CI.md` and `WINDOWS_FEASIBILITY.md`.

Wizard-owned builds read Cargo's release image through the shared bounded
public-source capability, which permits Cargo hardlinks while rejecting reparse
paths and foreign mutation rights. The source is unchanged. Its SHA256 must
match the build script's digest before publication; installed helpers and their
ownership receipts keep the stricter single-link destination policy. Standalone
builds with an explicit install directory retain their existing publication
behavior without requiring an installed wizard package.
