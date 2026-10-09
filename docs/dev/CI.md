# Mordred — CI Policy (Hermes-base)

> **Status**: current operational policy for this standalone repository. Workflow
> YAML is authoritative for mechanics; this document owns intent, release order,
> branching, and manual validation requirements.

## Why it got simpler

Mordred is a plugin package, not a Hermes fork. CI is responsible for Mordred's
source, package, native helpers, compatibility floor, and declared integration
boundaries. Hermes tests and releases remain upstream responsibilities.

## Standalone-repo adaptations (2026-07-01)

The standalone repository resolves `hermes-agent` from PyPI, ships its own five
workflows, and has no inherited upstream workflows. The initial repository-split
repair is complete; historical restoration details remain in Git.

## Active workflows

| Workflow | Purpose | Trigger |
|---|---|---|
| `ci.yml` | Test matrix, extras, wheel smoke, Tor/TPM, native helper builds | PR and pushes to `dev`/`main` |
| `upstream-check.yml` | Hermes hook-name and consumed-payload drift | Weekly and manual |
| `labeler.yml` | Path-based PR labels | `pull_request_target` |
| `integration-vpn.yml` | Live Mullvad validation | Manual only |
| `release.yml` | TestPyPI/PyPI build and publish | Manual only |

## `ci.yml` details

The workflow has nine job definitions:

1. **`test`** — Python/OS matrix; Ruff, shellcheck (one Linux cell), strict
   mypy, pytest, coverage, and the status-skill drift guard.
2. **`feature-extras`** — installs `ethereum`, `messaging`, and `tor-control`
   and runs their focused tests so optional coverage cannot disappear behind
   import skips.
3. **`package-smoke`** — builds sdist then wheel, installs outside the checkout,
   loads six plugin entry points plus the console script, and checks shipped
   native/offline/web/bootstrap assets.
4. **`hermes-floor`** — pins `hermes-agent==0.13.0`, verifies the resolver kept
   the pin, and runs the compatible default suite.
5. **`integration-tor`** — Docker-based Tor, SOCKS5h, and provider-transport
   integration tests. Tor bootstrap runs against the live Tor network; the
   harness waits up to 240s per attempt and recreates the container once
   before failing (`tests/integration/_docker.py`). A `BootstrapTimeout`
   that survives both attempts is a network flake — re-run the job rather
   than bypassing the CI gate.
6. **`sekey-helper`** — compiles the Secure Enclave Swift helper on macOS.
7. **`tpmkey-helper`** — checks the Rust crate, locked dependencies, MSRV, and
   `tss-esapi` build.
8. **`tpmkey-helper-tpm`** — runs the TPM backend against `swtpm` on Linux.
9. **`windows-private-fs`** — scoped native ACL/path/publication/process tests on
   Server 2022 with Python 3.11–3.13, plus an sdist-derived wheel smoke outside
   the checkout. This is foundation coverage, not whole-Windows product support.

Key policy:

- The test matrix covers Ubuntu and macOS with Python 3.11–3.13.
- CI installs `.[dev,keyvault,extension]`; macOS adds `macos`. Do not assume
  `ethereum` or `tor-control` imports are available in the main typing job.
- Run `mypy --strict src tools scripts/keyvault_offline_digest.py`; a narrower
  CLI target silently stops checking `tools/` or the shipped digest script.
- GitHub Actions use immutable commit SHAs. Cargo commands use `--locked`.
- The default pytest configuration excludes `integration` tests.
- Required branch checks are the Ubuntu and macOS Python 3.12 `test` cells;
  helper and integration jobs remain additional signals.
- Live LLM and Secure Enclave tests have no automated workflow. VPN is the only
  live-gated suite with a manual workflow.

## `integration-vpn.yml` details

This workflow requires the `MORDRED_MULLVAD_ACCOUNT` repository secret and a
manual `mullvad_version` input. It installs the official daemon, runs
`tests/integration/test_vpn.py` with `MORDRED_LIVE_VPN_TEST=1`, then always
disconnects and logs out in teardown. It never runs automatically because it
uses a paid account and mutates runner network state.

## Windows dedicated custody validation

The scoped Windows job includes `test_windows_custody_profile.py` and
`test_windows_custody.py`. These use real checked files and real MRKW crypto
with an injected native P-256 boundary; they do not prove TPM availability.
POSIX primitive fault-injection cases are skipped on Windows, where the
foundation's native fault suite remains required.

Real CNG validation is explicit: set `MORDRED_TEST_WINDOWS_CUSTODY_LIVE=1` and
`MORDRED_WINDOWS_CUSTODY_TEST_ROOT` to an existing isolated retained task root,
then run `uv run pytest -q -o addopts= -m integration
 tests/test_windows_custody_live.py` (one command line). Use the installed
wheel venv's Python for the corresponding out-of-checkout run. Each run creates
a UUID profile, reports only its path, enrolls new independent memory/audit
keys and deletes only those keys after checked verification. A failed run
preserves its profile/journals for explicit reconciliation; never remove that
fixture first or blindly regenerate after a native missing result. The real
known-stopped gateway gate must pass before the live test creates keys.

This slice does not arm memory, run an installed Hermes hook, exercise Telegram,
provide excluded file-vault features, or establish Windows 11/product readiness.
Record native results separately under the existing validation log.

## Manual live-device validation log

- **2026-10-08 — Windows dedicated custody checked-file candidate (C5a).**
  Revision `b4793e7d3` passed **51 tests with 11 POSIX-only fault-injection
  skips** in both ordinary-user Server 2025 / Python 3.11.17 source and fresh
  sdist-derived wheel environments. Selectors:
  `tests/test_windows_custody.py tests/test_windows_custody_profile.py`.
  These runs use real Windows checked files and real MRKW cryptography with
  an injected native-key backend; they do **not** establish actual CNG enrollment
  or deletion. All profiles are disposable and imported origins were checked.
  Wheel SHA-256: `32298344357c81e279a0d66668b4f392170f6e583613feb7379949fae98345be`.

  Core and scoped R1 independent reviews approved. Host full regression before
  the narrow R1 correction: 6,060 passed, 126 skipped, 38 excluded. Final focused
  checks: 62 passed, one native-only skip; reduced-extras types, lint/format,
  shellcheck and docs passed. R1 validates malformed journal field types and
  prevents pytest from rendering native key operands in live-test failures.

  Real CNG validation is pending the C5c ordinary-user process-inventory gate:
  protected foreign process token access is denied on this machine. The gate
  remains strict; no native-key live test or fixture was run as a workaround.
  The managed installation image prerequisite and supported-runtime boundary
  are tracked in shared contract PR #195. Memory hooks, installed-runtime proof,
  encrypted audit/Telegram consumers, wizard flows and Windows 11 are separate
  unfinished gates. The component PR remains a draft until native custody
  acceptance is complete.

- **2026-10-08 — First keyvault Windows caller: wallet selection storage.**
  Component contract PR #193 follows the shared contract/foundation PRs
  #191/#192. The implementation at `e05034f63` migrates only the keyvault-owned
  wallet selection document; `be87acf06` fixes Windows pytest IDs and extends
  cleanup-error coverage. Signing, key custody, memory/reset/purge, audit,
  installer and Desktop support remain separate, incomplete gates.

  Reused `i-00f4db5c3a204906b` in `ap-southeast-1`; verified it stopped before
  startup and armed a two-hour controller stop deadline plus a Windows scheduled
  shutdown. Tests ran as the credentialed, non-administrator `mordred` user on
  Server 2025, Python 3.11.17, fixed local NTFS, using new synthetic paths.
  Neither TPM fixtures nor Linux validation resources were changed.

  Final source and out-of-checkout wheel suites each produced **121 passed,
  2 POSIX-fork skips** across the wallet suite and four shared filesystem/process
  test modules (the POSIX-only module was not selected). The wheel was built
  from the sdist and installed without dependencies into a fresh venv, with
  pytest installed separately. Its imported module was under
  `C:\Users\mordred.000\wallet-wheel-20261008\venv\Lib\site-packages`;
  SHA-256: `6871af48f413c7270962705b3127e5c0138d1bd90f2d63a166b5cae4f5ee5b3e`.
  The source run used the separate `wallet-validation-20261008` tree.

  Native cases prove ACL/junction/hard-link refusal without repair, read/write
  process exclusion, bounded file reads, and pre/post-publication error handling.
  Synthetic selection survived a fresh process and a Windows reboot with SHA-256
  `34fee0fee72b07ef4640a7638737e5d20c72aa7bd74d6ee688aa23f9e6a8ea5f`.
  A separate ordinary account was denied access; its temporary account, task and
  logon rights were removed. This slice did not repeat EC2 stop/start persistence,
  sudden power-loss testing, TPM operations, Windows 11 or whole-product flows.

  The initial source/wheel runs each had **117 passed, 2 skips, 2 setup/teardown
  errors**: pytest expanded a 1 MiB parameter into `PYTEST_CURRENT_TEST`, exceeding
  Windows' 32767-character environment limit. Short explicit parameter IDs fixed
  the harness; no product-code change was needed. Independent review found no
  product defect, confirmed that harness issue and suggested the additional
  absent-wallet transaction-cleanup regression, which now passes.
  Final local Python 3.13 full regression: **5,362 passed, 45 skipped,
  34 integration deselected; 88.48% coverage**. Five warnings came from the
  existing FastAPI/Starlette, Hermes escape-sequence and POSIX fork checks.
  Ruff/format, reduced-extras strict mypy (206 files), shellcheck and all
  12 documentation-link tests passed. The final hosted CI results are tracked
  on the component PR; local/native acceptance does not replace that matrix.
  The host was verified stopped after acceptance; both task-specific automatic
  stop mechanisms were disarmed. Its retained disk and synthetic wallet remain.
  Evidence is retained under `~/.codex/artifacts/mordred-windows-wallet-20261008/`.
- **2026-10-08 — Checked Windows audit sessions (C7a).**
  Shared implementation `b39a064379038bcce99fb021fe7418f326c1d105`, with the
  already-reviewed elevated-owner fixture correction at `b9332e64d`, passed
  ordinary-user Server 2025 source and isolated sdist-derived wheel suites:
  **356 passed, 54 skipped** each. Native checks include process serialization,
  hostile ACL/hardlink/junction refusal and case aliases. Wheel origin was
  verified inside a fresh test-only environment. Host all-extras regression:
  5,603 passed, 63 skipped, 35 deselected; independent reviewer focused run:
  165 passed, four native skips. Ruff/format, reduced-extras strict mypy and
  shellcheck passed; independent review found no actionable issues.
  An intentionally broader Windows diagnostic also selected legacy POSIX
  `test_log_rotation.py`: 373 passed, 54 skipped, one existing fchmod-path
  failure. Legacy audit APIs remain POSIX; C7a's new explicit session APIs do
  not migrate production consumers. That diagnostic exclusion is not a waiver
  for the later C5/C7b consumer and whole-product gates.
  Evidence: `~/.codex/artifacts/mordred-windows-completion-20261008/c7a-*`.
  Windows 11, encrypted-writer key leases, CLI and production caller adoption
  remain separate gates.

- **2026-10-08 — Windows confidential-file and coordinator identity capabilities.**
  Code `fc5db88455592badb638ca400507866b53328450` passed ordinary-user
  Windows Server 2025 source and isolated sdist-derived wheel runs: **279 passed,
  53 POSIX-only skips** each, including the explicitly enabled inherited-ACL
  live roundtrip. Wheel SHA-256: `d55a4ee4aba92a146387f5aedaf1b9fe0b227d0c59498db5d11e1e278eb5c648`. Module origin was checked inside the
  fresh wheel environment. The preceding `4f3f4377e` implementation also passed
  actual Hermes-created `config.yaml`/`.env` read and replacement with unchanged
  parent ACLs; replacements became exact-private. Local Python 3.13 all-extras
  regression at `4f3f4377e`: 5,493 passed, 59 skipped, 35 integration deselected;
  final identity-seam focused suite: 277 passed, 54 skipped, one live deselected.
  Strict reduced-extras mypy, Ruff and formatting passed. Independent original
  and identity-seam reviews found no actionable issues. Evidence is retained
  under `~/.codex/artifacts/mordred-windows-completion-20261008/` (C1b logs).
  These are shared-boundary checks; production caller migration, full product,
  Windows 11 and new reboot/TPM validation are not established by this entry.

- **2026-10-08 — Canonical Windows configuration coordination (C2).**
  Code `c5d4e871c9b9b1846c95b1c22a2876179fa7f47e` passed ordinary-user
  Server 2025 source and fresh sdist-derived wheel suites: **357 passed,
  54 skipped** each. Skips are POSIX-specific or require an elevated owner
  fixture. The wheel environment installed only pytest and ruamel.yaml for
  these shared-boundary tests; this is not a full product dependency smoke.
  Native cases include inherited-descriptor no-op preservation, case aliases,
  fresh-process busy refusal, and a killed writer between config/policy members
  retaining a pending marker until explicit reconciliation. Wheel import origin
  was verified inside its new virtual environment.
  Independent review findings on caught uncertainty, nested nonblocking scope
  extension and custom config-name bypass were fixed and scoped re-review passed.
  Full host regression before the final narrow nested-cleanup guard: 5,603 passed,
  63 skipped, 35 deselected; final complete focused suite: 111 passed, three
  native skips. Ruff/format, reduced-extras strict mypy, shellcheck and docs checks
  passed. Evidence: `~/.codex/artifacts/mordred-windows-completion-20261008/c2-*`.
  Canonical wizard writer adoption, enforcement decisions/caches, Windows 11 and
  installation-to-normal-use remain separate component gates.

- **2026-10-08 — Private filesystem review fixes on macOS.**
  Review reproduced inherited extended-ACL grants despite mode 0700/0600 and
  stale exception text after promotion to an uncertain commit. Before the fix,
  six native ACL regressions and one exception-message regression failed.
  Product revision `e6efd9dfc` checks macOS ACLs through validated descriptors,
  accepts only absent/empty/deny-only ACLs and refuses all allow/unknown entries
  or query failures without repairing permissions. Even owner-only, read-only
  and inherit-only allow entries are intentionally refused; the normal profile
  deny-delete ACL remains accepted. Exception `args` and text now follow the
  current `commit_state` while preserving the original exception.

  Native macOS tests cover inherited grants, existing directory/file/lock ACLs,
  ACL changes during a transaction and injected native-query/free failures with
  resource cleanup. The five filesystem test files produced **85 passed,
  34 platform skips**. The full default suite produced **5,250 passed, 49 skipped,
  34 integration deselected; 87.42% coverage**. Ruff/format, strict mypy (205
  files), shellcheck and an independent read-only review passed. Hosted Windows
  cleanup tests also assert that rendered errors match uncertain commit state;
  current-head CI results are tracked on PR #192. AWS was not started for these
  fixes, and Linux validation resources were untouched. The actual Windows
  wheel/restart evidence below predates these fixes and is not a fresh host run.
  Local evidence is retained under
  `~/.codex/artifacts/mordred-filesystem-review-fixes-20261008/`.

- **2026-10-08 — Shared private filesystem foundation (WF1–WF5).**
  Independent foundation PR #192 follows contract PR #191; neither includes the
  pending CNG helper implementation or migrates component callers. The product
  source at `cb266a5` was built as an sdist and then wheel, installed in a fresh
  out-of-checkout `wf-wheel-final\venv` under the credentialed ordinary `mordred`
  user on retained Server 2025 build 26100, fixed local NTFS. Python was 3.11.17
  AMD64; the imported module was under that venv's
  `Lib\site-packages\mordred_hermes`. Wheel SHA-256:
  `BFBC6419B245DE7026F43699CD623F70269F37B74E16F130313DC8069C12FEB4`.

  Running `python -m pytest -q` against the five `test_private_fs*.py` files
  produced **91 passed, 13 POSIX-only skips** from both source and installed
  wheel. Native checks cover create-time/existing ACLs, normal profile ancestors,
  junctions/hard links, >260-character paths, an actual 8.3 sidecar alias,
  concurrent process/thread transactions, crash release, interrupted writes and
  held-target refusal. Fault-injection tests separately cover short/zero writes,
  ambiguous publication, flush/close/unlock failures and uncertain commit state;
  they are not physical disk-failure tests. Independent review found two issues:
  case-sensitive POSIX reserved names and cleanup misclassifying completed
  publication. Both reproduced before fixes and passed afterward, including
  preservation of the original exception when cleanup also fails.

  With `MORDRED_WINDOWS_FS_LIVE=1`, a synthetic
  `MORDRED_WINDOWS_FS_TEST_ROOT` and provision/reopen phases,
  `python -m pytest -q -s -m integration tests/integration/test_private_fs_windows.py`
  passed under a non-administrator token. A separately credentialed disposable
  ordinary user was denied access to the wheel-created file. Only its temporary
  batch-logon right was granted; that right, account and scheduled task were
  removed after the assertion. Existing accounts, TPM fixtures and Linux
  validation resources were unchanged. No inbound network rules were added.

  Fresh-process, final-wheel Windows reboot and EC2 stop/start reopen each passed. Synthetic
  fixture SHA-256 remained
  `5aa341081d33ad1cfdbb608258d9f0a4078e54f7458a6133011837e96eef33de`.
  This is retention evidence, not sudden power-loss durability.

  On the clean dev-based foundation branch, the full default suite with coverage
  produced **5,235 passed, 49 skipped, 34 integration deselected; 87.38% coverage**.
  The earlier branch including pending helper changes passed 5,269 tests; the
  differing count reflects PR isolation, not removed foundation assertions.
  Ruff/format, shellcheck and reduced-extras strict mypy (204 source files) passed.
  Hosted CI gates are tracked on PR #192 (three Windows cells plus existing
  Linux/macOS checks); early failures and their resolutions follow. Final host
  state was independently verified **stopped** after acceptance. The retained
  development instance has one encrypted 50 GiB gp3 volume
  (`vol-08b0b74e57e899ad0`), existing TPM fixtures and synthetic filesystem evidence.
  Storage remains billable; no new volume, snapshot or instance was created. The initial hosted native run passed 90 checks and failed
  only the independent Get-Acl subprocess: inherited PowerShell 7 module paths
  prevented Windows PowerShell from loading its security module. The test child
  now reconstructs the default PSModulePath without weakening ACL assertions.
  The next hosted run passed all native tests but correctly refused the broadly
  writable ancestor on the RUNNER_TEMP data volume. The out-of-checkout wheel
  smoke now uses the runner's ordinary profile; the product trust policy and
  system ACLs are unchanged.
  Sanitized run evidence is retained privately under
  `~/.codex/artifacts/mordred-windows-filesystem-20261008/`.

- **2026-10-07 — Windows CNG helper implementation (W1–W4).**
  The dedicated Phase 0 Windows Server 2025/NitroTPM host was reused under the
  ordinary `mordred` account with password-authenticated SSH through SSM. MSVC
  Build Tools `17.14.37710.0`, toolset `14.44.35207`, Windows SDK 26100, Rust
  `1.99.0` and MSRV `1.85.0` built the actual executable. The Rust protocol/unit
  suite passed **12 tests**; the separately gated real CNG suite passed **3 tests**.
  It verified P-256 ECDH against an independent implementation, a leading-zero
  secret, duplicate preservation, malformed-point refusal, private-export
  rejection with export policy zero, deletion, and concurrent probe cleanup.

  **Actual-device corrections:** the provider rejected the silent flag on
  deletion (`0x80090009`), while zero flags succeeded. Two parallel native
  create/finalize operations returned distinct successful keys for one name
  despite no overwrite flag; a user-SID/key-scoped Global Windows mutex now
  serializes helper operations across processes and sessions. The same live
  concurrency regression then passed. Public-key-only SSH still correctly
  refused the compiled helper's probe with `AUTH_DENIED` (`0x80090010`). No
  password capture, impersonation or software provider exists in the product.

  **Python/build boundary:** actual Windows production MRKW wrap/unwrap through
  the compiled helper passed, including a Unicode/space-containing installation
  path, duplicate refusal, wrong-profile/corrupt-ciphertext rejection, missing
  helper, valid-data retention and refusal after deletion. The installer passed
  **4 actual Windows tests** covering replacement, failed-build retention,
  an in-use executable and a Japanese default home under a cp1252 Python pipe.
  ASCII JSON transports the default path without code-page corruption.
  The hosted Windows CI initially reproduced a PowerShell 7 -> Python -> 5.1
  module-path inheritance failure (`Get-FileHash` unavailable). The installer
  explicitly loads Utility/Management manifests from its own `$PSHOME`;
  the existing build tests cover that actual runner invocation. Windows PowerShell 5.1 requires `[NullString]::Value`
  for the nullable `File.Replace` backup argument. A real sdist-to-wheel build
  passed **6 packaging checks**. The wheel installed outside the checkout;
  `build.ps1` compiled bundled sources under `site-packages` and installed into
  the selected Hermes home's `bin`. The resulting executable SHA256 was
  `c3da84b5ab0a2e2171ce0f9663af2322fb811bc19b781418cb8c25a3f02e6255`
  after the review corrections.

  **Persistence:** a retained synthetic MRKW fixture (SHA256
  `e80184560cc28a8342e745c34c43c90c8f673e072b8ff89eda9ee88f12404e81`) reopened
  through the installed wheel/helper in a fresh process, after Windows reboot,
  and after actual EC2 stop/start. Each check verified the same public key and
  plaintext digest; SID, fixture, executable and PCP key-file hashes were
  retained. The final helper also reopened this unchanged fixture after upgrade and a
  second Windows reboot and EC2 stop/start.
  The same final executable on a cloned disk refused the retained key on the
  second TPM, while fresh production MRKW operations worked. Both clone
  integration tests passed; SID, credential-file and retained PCP-file hashes
  matched the source host.

  **Review/regressions:** one independent whole-branch review identified
  malformed helper acknowledgement/status handling and a possible false-success
  deletion of a retained inaccessible key. The bridge regression failed in 18
  cases before correction; the focused local suite then passed **218 tests**,
  and Windows passed **101 tests** with one explicitly clone-gated skip. The
  inaccessible-key deletion regression failed on the real clone before the fix,
  then passed with the final executable. A new-key probe succeeded and CNG
  enumeration omitted the inaccessible retained key, so neither proved absence.
  Windows deletion now refuses an unopenable keyset with the original status
  and `UNAVAILABLE`, including repeat deletion; exact-key deletion still passes.
  After the review fixes, the full local suite passed **5,158 tests**, with
  **88.62% coverage**. Reduced-extras strict mypy, Ruff and
  ShellCheck passed. A scoped Windows helper CI job is added; hosted runners do
  not substitute for hardware acceptance. Full Windows private filesystem,
  runtime, wizard, network, Desktop and Windows 11 acceptance remain separate
  dependent plans.

  **Cleanup:** second instance `i-0d0f2c45787bedcee` terminated; AMI
  `ami-0d58a6979d00b69ff` deregistered and snapshot `snap-0cff25fd395bda4c2`
  deleted. Primary `i-00f4db5c3a204906b` is retained for subsequent porting,
  with CPU credits restored to standard and compute stopped after validation.
  Its encrypted 50 GiB gp3 volume remains (approximately USD 4.80/month at
  the recorded regional storage rate); the task-only SSM role/security group
  remain, with no inbound rules. Previous Linux validation resources were
  untouched. No production profiles or live Telegram/LLM accounts were used.

- **2026-10-07 — Windows native feasibility on actual EC2 NitroTPM (Phase 0).**
  Unchanged Mordred `f14c1edce23f88c4a2cb6f8bfd3c1454ed0a59ce` / `0.2.0a1`,
  installed as a locally built wheel with `keyvault,extension` extras, was tested
  on Windows Server 2025 build 26100, x86_64, `t3.large` in `ap-southeast-1`.
  The TPM-enabled image was `ami-05171b2d13ab22cba` (2026-09-17); primary
  instance `i-00f4db5c3a204906b`, encrypted 50 GiB gp3, UEFI/NitroTPM 2.0.
  The older Linux validation instance remained stopped and untouched.

  **Host baseline:** pinned upstream Hermes `v2026.9.24`, commit
  `f97608f178d1ffeca59860195ab7da295f7c8e5f`; Agent `0.21.5`, Desktop `0.17.6`,
  Electron `40.10.2`, Python `3.11.17`, Node `22.23.3` / npm `10.9.9`.
  The plugin loaded from the wheel in
  `C:\Users\mordred.000\hermes-source\venv\Lib\site-packages`, not the checkout.
  `hermes --help`, `hermes-mordred --help`, and isolated
  `hermes-mordred status --json` exited zero. `hermes desktop --build-only`
  produced the real `win-unpacked/Hermes.exe`. Playwright launched that binary
  under the ordinary user and captured screenshots: with Mordred disabled in
  a separate baseline home, Desktop reached provider onboarding; with Mordred
  enabled, backend startup refused at `_audit_io.py`'s unavailable `os.fchmod`
  during the network plugin's audit initialization. No security checks were
  bypassed and no upstream application source was patched. No model provider
  or messaging account was configured, so onboarding is not a chat/E2E pass.

  The upstream installer needed a clean checkout of its exact release in the
  disposable source directory (initial checkout refused generated/line-ending
  changes), then its official individual dependency stages after an existing-
  venv cleanup failed under the ordinary user. npm completed, though the wrapper
  emitted empty-exit-code failures; Desktop used the official CLI build. These
  workarounds do not establish one-command Windows installation support.
  An initial gateway harness timed out while collecting inherited output pipes.
  A repeat with file output reached the Gateway Starting banner and remained
  alive at 20 seconds; ordinary-user `taskkill /T /F` returned Access denied,
  and the harness also hit cp1252 output encoding. Thus clean shutdown, channel
  readiness and scheduled gateway support are not established; the later SYSTEM
  cleanup found that PID already gone.

  **Unmodified test baseline:**
  `python -m pytest -q -o addopts= --tb=short tests/test_keyvault_wrap.py tests/test_file_lock.py`
  returned **71 passed, 6 skipped, 12 failed**. All failures were in the file-lock
  suite: both POSIX-mode assumptions and Windows-path regex assumptions occur.
  These are recorded failures, not a passing Windows suite. The independent
  wire probe used Python `3.12.15` / cryptography `50.0.2` and the unchanged
  production `wrap.py` (SHA-256
  `a043eb7dbc1c04ad0d80f849a588748ca50fb1b7d3b536b7b4fb4c097c2dfe6c`).

  **Hardware custody:** `Get-Tpm` reported present/ready, manufacturer `AMZN`.
  The explicit Microsoft Platform Crypto Provider reported implementation flag
  `1` (hardware). Direct CNG user-scoped persisted `ECDH_P256` worked without
  setting KeyAgreement usage; explicitly setting that property returned
  `0x80090029`. `NCryptSecretAgreement` and `NCryptDeriveKey(TRUNCATE)` yielded
  32 little-endian bytes, reversed for Mordred. Nine comparisons with independent
  Python/OpenSSL ECDH passed, including leading-zero scalar `189`. The unchanged
  127-byte MRKW wrapper round-tripped. Corrupt ciphertext, wrong profile,
  malformed points and an invalid native peer were refused; valid ciphertext
  remained usable. Private export failed with `0x8009000A`.

  The same proof passed in a separate password-authenticated non-administrator
  SSH process, without impersonation. Public-key-only SSH could not access the
  persisted key (`0x80090016`); this token distinction must be diagnosed by the
  actual product process. SYSTEM-only or impersonated results are not presented
  as desktop/service identity proof. No Windows password capture or impersonation
  is proposed for the product helper. Fresh-process reopen, Windows reboot and EC2 stop/start
  retained public-key fingerprint
  `7a573e66759b1ae7a4fa2715985d2ffa4d597eeab63978581170b0fe9c7f8e27`
  and the valid synthetic wrapped DEK. The reboot repeat used a credentialed
  user token from the SSM harness. The stop/start repeat also passed under the
  actual password-authenticated ordinary-user SSH process. A separate disposable
  key was created/reopened/deleted, and its subsequent open returned
  `0x80090016`; the retained original fixture still decrypted afterward.
  Scheduled gateway acceptance remains open.

  **Device binding:** a cleanly stopped disk was imaged and launched on
  second NitroTPM instance `i-08c6ec3e52adac82a`. Local SID, encrypted DPAPI test
  credential, PCP key metadata and wrapped-fixture hashes matched the source.
  DPAPI unprotect and credentialed logon succeeded, but the copied persisted key
  could not open (`0x80090016`). A new, uniquely named key under the same user on
  the second TPM completed ECDH with independent software parity and refused
  private export; it was deleted afterward. This controls for unavailable TPM,
  wrong SID and inability to authenticate. The test used synthetic data only.

  **Phase 0 resources:** primary Windows and prior Linux instances were verified
  stopped at the investigation boundary. Clone `i-08c6ec3e52adac82a` was
  terminated; AMI `ami-021065c89d82a9745` was deregistered and snapshot
  `snap-0b8b5d7ed23d25d0d` deleted. The task's TCP/22 ingress was revoked; all
  working access uses SSM. The dedicated SSM role/profile and primary encrypted
  50 GiB gp3 volume remain for implementation ($4.80/month storage at the
  queried regional rate). The primary was then resumed for the approved helper
  implementation with a new bounded shutdown deadline. Windows instance rate
  was $0.1332/hour, excluding IPv4, surplus CPU credits and other usage.

  **Scope and evidence:** disposable scripts, JSON results, baseline failure
  logs, build logs and actual application screenshots are retained privately at
  `~/.codex/artifacts/mordred-windows-validation-20261007/`; do not publish its
  test credentials or private SSH key. The checked-in change is documentation
  only. It proves feasibility of this device's CNG/wire boundary, not a shipped
  helper, secure Windows file storage, Windows 11/MSIX, consumer TPMs, scheduled
  gateway custody, Private Telegram or full Windows support. See
  [Windows feasibility](WINDOWS_FEASIBILITY.md) and the Windows sections of
  [SPEC](SPEC.md#windows-native-support-proposal-2026-10-07) and
  [PLAN](PLAN.md#windows-cng-helper-implementation-plan).


- **2026-10-07 — Real Telegram login, sync, and questions on EC2 NitroTPM.**
  Installed the wheel built from `52e69d7fc` in the actual Hermes Desktop
  interpreter on the isolated Ubuntu 24.04 EC2 NitroTPM host. The CLI login
  completed against the user's real Telegram account with exit code 0.
  A separate process successfully unsealed the saved session through the TPM;
  metadata reported `logged_in=true` and `api_configured=true`, the sealed
  file had the `MTC1` header and mode `0600`, and memory encryption was active.
  Credential values and the decrypted session were not included in evidence.
  Subsequent operator-authorized sync imported three messages across two
  dialogs; a later incremental sync imported one new message into a third
  dialog, while an unchanged sync imported zero duplicates. With a
  TPM-sealed Venice key, `deepseek-v4-flash` passed the live private-model
  catalog check and answered questions through the production service path.
  The final period query considered all four imported messages without
  truncation. No message content, account identifiers, or model answers are
  recorded here. This validates the CLI/service path, not a live Hermes agent
  conversation or the Desktop question UI. Live-account cancellation and
  logout remain untested; the operator retained the encrypted session.
  Login evidence:
  `mordred-linux-telegram-20261007/live-login-success.png` and
  `mordred-linux-telegram-20261007/live-login-verification.json`.

- **2026-10-07 — Follow-up review and Linux TPM custody fixes.**
  Tested commit `1e64c8d85` on the same isolated Ubuntu 24.04 EC2 NitroTPM
  environment. An independent review reproduced two data-loss paths: keyvault
  reset recursively deleting the native memory key, and inaccessible memory
  directories being mistaken for empty during purge. The reset bug was also
  reproduced against the prior code on actual NitroTPM using a disposable
  profile; the new integration assertion failed before the fix (reset returned
  success), then passed after it. The actual-device suite passed **2 tests in
  8.29s**, including reset refusal, failed-scan key/ciphertext retention and
  subsequent successful reads, plus synthetic Telegram sync/list/ask/cancel.
  Added regression coverage for inaccessible directories and individual files,
  concurrent provisioning/reset, uninstall purge ordering, ordinary Linux
  plaintext reads/writes, and malformed ambient keys during re-enable.
  Linux full suite: **5,118 passed, 21 skipped, 0 failures/errors** (172.375s).
  macOS full suite: **5,212 passed, 5 skipped, 0 failures/errors** (160.681s).
  A macOS symlink-handling regression found during remediation was fixed by
  selecting the strict scanner only for Linux/TPM custody; its existing test
  and the final full suite passed. Metadata-only Linux status now refuses
  unreadable memory trees instead of reporting them ready. Ruff, format,
  shellcheck, JavaScript syntax, and strict mypy passed; reduced-extras Linux
  mypy checked 195 files. Coverage and the full CI interpreter matrix were not
  repeated for this follow-up. Evidence: `mordred-linux-telegram-20261007/review-*`.
  All three validation instances were verified stopped after this run; existing
  EBS/AMI/snapshot resources were retained. No live account/model was used;
  that acceptance gate remains pending.

- **2026-10-07 — Linux Private Telegram implemented and validated on EC2.**
  Tested feature code through commit `8b37984d3` on the existing Ubuntu
  24.04.5 x86_64 `t3.medium` NitroTPM instance in `ap-southeast-1`, using isolated
  source, memory, and Desktop homes. Python 3.12.3; production helper and
  `/dev/tpmrm0`; no `TCTI` or native-test override for actual-device acceptance.
  The explicit `MORDRED_LINUX_TELEGRAM_TEST=1` suite passed **2 tests** against
  real NitroTPM (7.95s). It exercised fresh Hermes startup hooks, sealed memory
  read/write, corrupt wrapped-key and unavailable-device refusal without ambient
  key fallback, ciphertext preservation, disable/re-enable with the same key,
  and purge. A synthetic Telegram client and local model drove real
  `TelegramService` sync/list/ask/cancel, encrypted archive storage and fresh
  process credential access through the real TPM. A separate swtpm run passed
  the same **2 tests** (44.88s); it is recorded separately from hardware proof.
  The complete Linux suite passed **5,103 tests, 21 skipped, 0 failures/errors**,
  with **87.99% coverage**. macOS/Python 3.14.7 regression passed **5,197 tests,
  5 skipped, 0 failures/errors**. Ruff, format, shellcheck, JavaScript syntax,
  documentation links, and strict mypy passed; Linux mypy used a fresh venv
  with only `dev,keyvault,extension` extras (195 files). The full CI Python
  matrix was not rerun locally. The four post-review regression tests first
  failed, then passed: runtime write/purge serialization, stale-profile path
  refusal, re-enable authentication of existing seals, and old Desktop client
  rejection. No Secure Enclave helper behavior changed; its live-device gate
  was not rerun.
  Installed the final wheel into the actual Python interpreter used by packaged
  Hermes Desktop `v2026.9.24` (Agent 0.21.5 / Desktop 0.17.6 / Electron 40.10.2),
  verified installed source/asset SHA-256 hashes against this checkout, and
  observed the TPM 2.0 label, absence of per-use presence/recovery promises,
  and successful memory enable through the page. The actual Desktop API
  hardware build/probe and idempotent memory enable also passed. Screenshots
  and sanitized logs are in `mordred-linux-telegram-20261007`.
  Stopped and started the instance, verified the pinned SSH host key at its
  new IP, and read the same sealed memory using Desktop's actual interpreter
  through the Hermes startup path. Wrapped-key and ciphertext SHA-256 hashes
  were unchanged. All three validation instances were stopped after testing;
  prior encrypted EBS volumes, the private AMI, and snapshots remain retained.
  **Limits:** no real Telegram login, live MTProto server, or live model was
  exercised; operator-assisted login/sync/question/cancel/logout remains pending.
  Linux memory is bound to its original TPM and has no portable recovery key.
  The unchanged baseline's cross-instance rejection remains separate evidence.

- **2026-10-07 — Current TPM implementation validated on actual EC2 NitroTPM.**
  Tested unchanged Mordred commit `f3211c6fb20b42d610feb00cfd6ed8d20681c888`
  on two `t3.medium` instances in `ap-southeast-1`, using a private,
  NitroTPM-enabled UEFI AMI cloned from the previous stopped Ubuntu validation
  disk. Ubuntu 24.04.5 x86_64, kernel `7.0.0-1014-aws`, Python 3.12.3,
  Rust/Cargo 1.85.0. AWS reported `TpmSupport=v2.0`; `/dev/tpmrm0` reported
  manufacturer `AMZN`, vendor `NitroTPM`, TPM 2.0, and NIST P-256 support.
  No TPM emulator was running. Used separate source and `HERMES_HOME` paths;
  the original validation instance remained stopped.
  Native tests ran with `MORDRED_TPM_TEST=1` and
  `TCTI=device:/dev/tpmrm0`: **64 passed, 0 failed, 0 ignored**, including
  actual key creation, ECDH parity, encrypted-session attributes, substitution
  rejection, and deletion. The existing focused Python suites passed
  **172 tests**. Built and installed the release helper, then separately
  verified production Python `wrap_dek`/`unwrap_dek` and `TeeSecretStore`
  using synthetic secrets, with `TCTI` and `MORDRED_TPM_TEST` unset.
  Verified fresh-process access, mode-`0600` key/ciphertext files, corrupt wrap
  and credential rejection, wrong-profile refusal, unavailable-device refusal
  without software fallback, and preservation of valid ciphertext after errors.
  Copied both opaque native key blobs to the second NitroTPM instance: its
  helper probe succeeded, but both copied blobs were rejected by that TPM.
  Stopped and started the original test instance, verified its pinned SSH host
  key at its new IP, and successfully unwrapped the original data and Telegram
  credentials without regenerating keys. The actual `keyvault enable-tpm`
  CLI also built, installed, and passed its hardware probe; original keys still
  worked after installation. Finally verified idempotent key deletion and
  refusal to unseal credentials after deletion of the synthetic test key.
  Evidence bundle: `mordred-nitrotpm-validation-20261007` (source/helper hashes,
  device properties, native/Python logs, and per-case results).
  **Scope:** this validates the existing TPM backend and credential custody,
  not Linux private Telegram as a complete feature. `telegram doctor` confirmed
  the hardware check passed while agent-memory encryption remained inactive.
  No real Telegram account, live model, memory-encryption implementation, or
  full Telegram/Desktop workflow was exercised in this run.
- **2026-10-07 — Packaged Hermes Desktop validated on Ubuntu EC2.**
  Built the official Hermes release `v2026.9.24` (`f97608f178d1`, Agent
  0.21.5 / Desktop 0.17.6 / Electron 40.10.2) with `hermes desktop
  --build-only` on the same Ubuntu 24.04.5 x86_64 instance. Installed Mordred
  commit `2c7073576` into the Python environment used by Desktop, with a
  separate `HERMES_HOME` and Desktop user-data directory. Ran the packaged
  Electron application under Xvfb/Openbox and inspected it through VNC over
  an SSH tunnel. The app mounted `/api/plugins/mordred/`, loaded the Mordred
  sidebar page, and displayed "Private Telegram requires macOS" without
  Secure Enclave or memory-encryption setup buttons or an Xcode error.
  The same page and platform guard remained visible after restarting the app
  and its backend. The installed page's SHA-256 matched the source asset.
  The virtual display produced a GPU command-buffer error during initial startup; the test used
  `desktop.electron_flags: ["--disable-gpu"]` for software rendering.
  No model credentials, Telegram login, or hardware-key operations were used.
- **2026-10-07 — Desktop Telegram platform guard validated on Ubuntu EC2.**
  Ubuntu 24.04.5 x86_64, Python 3.12.3, in `ap-southeast-1`, with an isolated
  `HERMES_HOME`. Before the fix, `/enclave/build` returned a job that failed
  with `enclave_build_failed`; the native command rejected Linux before
  checking the build tools. The actual Desktop plugin rendered in a temporary
  React/SDK harness against the EC2 API reproduced the misleading Xcode toast.
  After the fix, `/status` reported `platform=linux` and
  `telegram_supported=false`; the page displayed the macOS requirement with
  no Secure Enclave or memory-encryption setup buttons. Direct HTTP requests
  to both setup endpoints returned `telegram_platform_unsupported` without
  starting a job. The 12 platform tests had 10 expected failures before the
  fix; all 115 platform, Desktop API, and native-helper CLI tests passed after
  it. The full unit suite passed on Ubuntu (5,079 passed, 21 skipped) and
  macOS (5,173 passed, 5 skipped), with 31 integration tests deselected on
  each. Ruff, formatting, strict mypy with the Linux extras, and shellcheck
  passed. This checks the Ubuntu runtime and plugin UI, not a full Hermes
  Desktop installation, a live Telegram account, or TPM hardware operations.
- **2026-05-25 — passed on real devices**:
  - `MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py -v`
  - `MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=... pytest -m integration tests/integration/test_vpn.py -v`
- **2026-08-21 — Slack E2E outbound channel-key binding passed on live Slack.**
  In an externally shared channel with a bound `K_chan`, an encrypted command
  reached the gateway, was released as `/version`, and received an encrypted
  reply that the browser extension rendered as the Hermes version with no
  decrypt failure. An agent-initiated top-level send also arrived as `ENC:v3`
  and decrypted, a plaintext post received the readable needs-key notice, and
  an unbound channel remained unchanged. The same end-user round-trip passed
  when the sender was an external Slack Connect member. The successful
  `app_mention` was stamped with the installing workspace; an earlier generic
  message supplied the external workspace scope and reproduced
  `key_not_bound_to_channel`. The captured generic-event shape now has strict
  regression coverage for the authenticated installing-team fallback,
  including stale-scope and forged-raw-team rejection.
- **2026-08-21 — isolated Slack `/hermes` slash-command dispatch passed on live
  Slack.** The app-level token was rotated to stop the competing Socket Mode
  client, and a fresh foreground gateway then received a Slack hello reporting
  one connection. In the installing workspace, `/hermes` carried a bare
  `ENC:v3` argument: the plaintext `/version`, Unicode lock, and Slack `:lock:`
  alias were absent from the wire value. The foreground gateway authenticated
  and released `/version`, and the bot posted a top-level encrypted reply. A
  Web API read confirmed that the reply was from the bot, decrypted under the
  bound channel key to `Hermes Agent v0.19.0`, and did not expose the version in
  plaintext. The gateway recorded no invalid-envelope, replay, encrypted-send,
  or Slack-send failure for the round trip.
- **2026-08-20 — agent-memory encryption passed on Apple Silicon with a running
  gateway.** Enabling memory encryption sealed the existing memory file and
  emitted the restart warning. After restarting the gateway, the Hermes memory
  seam read both existing entries, added and reloaded a temporary fact, and
  removed it again while the on-disk file remained mode `0600` with the
  `HERMES-MEMORY-ENC-v1` header; `encryption status` reported `memory [on]`.
  Disabling memory encryption restored the whole file to plaintext, the same
  two entries remained readable through Hermes, and the temporary fact was
  absent. The pre-test gateway and encryption states were restored afterward.

After changing a live-gated path, rerun the relevant command and append a dated
result here. Do not replace the previous result without recording the new date.
Tor and TPM use hermetic CI coverage and do not belong in this manual log.

## `upstream-check.yml` details

- Runs Monday at 03:00 UTC and by manual dispatch.
- Checks both the latest PyPI `hermes-agent` and a shallow clone of upstream
  `main`.
- `tools/check_hook_payload_drift.py` statically verifies `VALID_HOOKS` and the
  fields in literal `invoke_hook(...)` dispatches against
  `tools/hook_payload_contract.json`.
- A mismatch opens or updates an `actionable` + `upstream-drift` issue. It never
  patches Hermes or opens an upstream PR.
- `tests/test_hook_payload_drift.py` runs the same contract against the locally
  installed package and ensures contract keys match Mordred registrations.

## `labeler.yml` details

`.github/labeler.yml` maps repository paths to labels; the workflow applies
them with `contents: read` and `pull-requests: write`. Because it uses
`pull_request_target`, it must never check out or execute the PR head.

Required labels:

- `plugins/mordred-network`
- `plugins/mordred-privacy-check`
- `plugins/mordred-llm-guard`
- `plugins/mordred-keyvault`
- `plugins/mordred-wizard`
- `plugins/mordred-extension`
- `actionable`, `upstream-drift`, `docs`, and `ci`

## `dependabot.yml` details

`.github/dependabot.yml` keeps the SHA-pinned GitHub Actions current: weekly,
with all action bumps grouped into one `ci`-labelled PR against `dev`. Scope is
deliberately actions-only — Python dependencies are governed by
`pyproject.toml` floors plus `uv.lock` and the `hermes-floor` job, so pip/uv
update PRs would add review noise without a matching safety gain. It is not a
workflow, so the expected-path list in [Auditing](#auditing) is unchanged.

## `release.yml` details

Publishing is `workflow_dispatch` only and uses PyPI Trusted Publishing (OIDC),
not stored API tokens.

- `target`: `testpypi` or `pypi`.
- `mode=reserve`: the already-published permanent `mordred-hermes==0.0.0.dev0`
  name-reservation stub.
- `mode=reserve-rename`: the separate permanent
  `hermes-mordred==0.0.0.dev0` reservation required before the distribution
  rename.
- `mode=release`: the real package.
- `mode=compat`: the metadata-only legacy-name shim. The workflow refuses this
  mode unless the matching `hermes-mordred` version already exists on the
  selected index.
- `expected-version`: exact PEP 440 version required in source, wheel metadata,
  and sdist metadata.
- Production publishing accepts only `main` and never permits a CI-gate bypass.
- The build must produce exactly one wheel and one sdist with matching name and
  version.

### Initial setup (one-time, manual by the operator)

Completed 2026-07-07: TestPyPI/PyPI trusted publishers, GitHub environments,
and the `0.0.0.dev0` reservation are in place. The current private-repository
billing plan does not permit required reviewers on the `pypi` environment;
manual dispatch plus the production branch/CI gates are the compensating
controls until that setting becomes available.

Completed 2026-08-12 for the `hermes-mordred` rename: pending publishers were
created on both indexes with owner `InternetMaximalism`, repository
`mordred-hermes`, workflow `release.yml`, and environments `testpypi` / `pypi`.
`reserve-rename` published `0.0.0.dev0` from main SHA `504e1b7ab` after exact-SHA
CI succeeded. Fresh installs from both indexes confirmed a dependency-free,
entry-point-free reservation with no `mordred_hermes` runtime package. The
historical `reserve` mode remains immutable and must not be dispatched again.

On 2026-08-12, after both `0.1.0a16` projects passed TestPyPI and production
verification, the repository was renamed to `mordredagent/hermes-mordred`.
All four publisher claims (two projects on both indexes) were replaced
add-first with the new repository claim while preserving `release.yml` and the
`testpypi` / `pypi` environments.

### Normal release (runbook)

1. Run `python tools/bump_version.py <version>`; never reuse a published PyPI
   version or edit version surfaces separately.
2. Run the full local checks and merge the version bump to `dev` through a PR.
3. Open the release PR from `dev` to `main`, aggregate the included PRs'
   Changes/Fixes entries, confirm CI, and merge.
4. Dispatch TestPyPI from `main` with `mode=release` and the exact expected
   version.
5. In a fresh venv, install `hermes-mordred` from TestPyPI (using PyPI as the
   dependency index) and verify the single `mordred` plugin entry point plus
   `hermes-mordred --version`.
6. Dispatch TestPyPI with `mode=compat`; install `mordred-hermes` in another
   fresh venv, verify that it resolves the matching canonical package, then
   uninstall only the shim and confirm the runtime package and CLI remain.
7. Repeat steps 4–6 against production PyPI, preserving the same canonical-first
   order.
8. After the production compatibility upload succeeds, `release.yml` creates
   annotated tag `v<version>` on that run's exact release commit and publishes
   the GitHub Release. Its notes and tag annotation come from the matching
   merged `dev` → `main` PR; include nonempty `### Changes` and/or `### Fixes`
   entries before publishing. Alpha, beta, RC, and development versions are
   automatically marked as prereleases. Confirm the `github-release` job is
   green and inspect the resulting Release.

The finalizer runs only after a successful production `compat` publish, never
for TestPyPI or reservation modes. Only this job receives `contents: write`
and `pull-requests: read`; package publication retains its OIDC-only grant.
It checks that both distributions have an unyanked wheel and sdist on PyPI.
For all four files, PyPI's HTTPS Integrity API must report publishing
provenance for this repository's `release.yml` on `main`, the production
environment, the matching file digest, and the exact release SHA. This trusts
PyPI's validated attestations; it is not independent offline signature
verification. If `main` advances between the canonical and compatibility
publishes, mismatched provenance stops tag creation even if versions match.
Existing tags must resolve to the exact release SHA; they are never moved.
Existing published Releases with the correct prerelease status are preserved,
including any human edits to their notes.

If finalization fails after upload (for example, an API outage), fix the cause
and **re-run failed jobs** on the same workflow run. Do not dispatch a new
publish or re-run all jobs: PyPI versions cannot be uploaded twice. A tag
created before a Release API failure is reused safely. A mismatched tag,
draft Release, or incorrect prerelease flag requires operator investigation;
the finalizer fails rather than overwriting it. For read-only diagnosis, run
`uv run python tools/finalize_release.py --repo mordredagent/hermes-mordred
--sha <release-merge-sha> --version <version> --dry-run` from the matching
version checkout with `GH_TOKEN` set. This verifies PyPI and GitHub state
without creating tags or Releases.

## Changelog convention

There is no `CHANGELOG.md`. Every PR description carries one entry per line
under `### Changes` and/or `### Fixes`; external contributions append
`Thanks @<author>`. A release PR aggregates those lines into its description,
tag annotation, and GitHub Release notes.

There is currently no PR template, so authors add the headings manually.

## Branching model (dev / main, introduced 2026-07-07)

- `dev` is the default integration branch. Feature PRs target `dev`.
- `main` is release-only and changes through `dev` → `main` PRs.
- CI runs for PRs and post-merge pushes to both branches.
- Scheduled workflows use the definition on the default `dev` branch.
- Release dispatches use the `main` ref.

## Branch protection (one-time setup)

The current private-repository billing plan does not expose branch protection
or rulesets. When available, protect both `dev` and `main`, require the Ubuntu
and macOS Python 3.12 test cells, require branches to be current, and keep
direct pushes to `main` disabled. Until then, the branching convention above is
the operational control.

## Auditing

List active workflows with:

```sh
gh api -X GET /repos/mordredagent/hermes-mordred/actions/workflows \
  --paginate --jq '.workflows[] | select(.state=="active") | .path' | sort
```

Expected paths are the five workflows in [Active workflows](#active-workflows).
Any additional workflow requires an explicit policy update and review.

## Future expansion

Add a documentation publishing workflow only when the project has a hosted docs
site. Add broader E2E automation only when it can run without production
credentials or state. Until then, keep the current workflows small and
purpose-specific.
# Windows completion acceptance matrix

Windows completion is tracked by SPEC.md §Windows product completion contract
and PLAN.md §Windows product completion execution. This matrix is a release
gate, not a new claim that the existing platform jobs test the entire product.

| Evidence layer | Environment | Required evidence |
| --- | --- | --- |
| Regression | supported local Python and existing POSIX CI | component tests, formatting, reduced-extras strict typing, packaging and integrated coverage |
| Native portable behavior | Windows CI, supported Python matrix | real Win32 filesystem calls, PowerShell installer, process locks, unsafe object refusal and non-hardware flows |
| TPM and persistence | ordinary-user Windows Server 2025 on existing AWS host | compiled production CNG helper, source and fresh wheel, separate-user denial, process restart/reboot/stop-start retention |
| Client product workflow | Windows 11 x64 VM/Cloud PC or physical PC | native install through normal use, Desktop and gateway, lifecycle/backup/upgrade/uninstall, actual runtime paths and token/provider |
| External integrations | explicitly available route/account/model services | real applicable VPN/Tor transport and authenticated flows; synthetic fixtures recorded separately |

Physical Windows hardware is not required. Windows 365 provides a virtual TPM
([Microsoft security documentation](https://learn.microsoft.com/windows-365/enterprise/security));
Azure Windows 11 VM use requires eligible licenses
([Microsoft deployment guidance](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/windows-desktop-multitenant-hosting-deployment)).
These are environment options, not evidence that Mordred's CNG provider or
product flow has passed there. Test the actual provider/token and record any
refusal. ARM virtualization does not replace x64 helper acceptance.

For each component record commit, command, interpreter/module path, OS/CPU,
ordinary/admin user status, result and exclusions. Report implementation,
unit tests, native Server checks, Windows 11 checks and live-service checks
separately. Keep unchecked gates visible; never count a skipped hardware or
account-dependent test as a pass. No Windows-ready release claim follows from
green foundation/helper/wallet jobs alone.


### C1a lifecycle validation (2026-10-08)

The checked lifecycle slice extends the scoped `windows-private-fs` invocation
with `tests/test_private_fs_lifecycle.py` and
`tests/test_private_fs_lifecycle_faults.py`. Existing native Windows tests now
also cover lifecycle ACL/junction refusal and exclusive-handle sharing failures;
process tests include concurrent checked append with every record retained.

Local macOS Python 3.13.12 validation: the focused shared-filesystem suite has
**184 passed, 47 platform-specific skips**. Ruff check/format passed. Strict mypy
passed for 205 source files in a separate `.venv-ci` installed with only
`dev,keyvault,extension,macos` extras. Native Windows execution belongs to the
controller's final-commit acceptance run, not these local results.

Regression development observed 43 lifecycle cases fail on missing APIs, then
13 portable Windows cases fail on missing backend methods. Three native ABI
cases failed before adding time/seek/truncation/enumeration bindings. Subsequent
RED/GREEN cases caught prevalidation metadata access, unbounded reserved staging
scans and replaced exceptions after Windows publication. Fault seams exercise
partial append/rollback, partial POSIX rename, native deletion/rename ambiguity,
close/unlock/directory cleanup and original-error preservation. These are
injected failures, not physical disk-failure or power-loss durability evidence.

The full default `uv run pytest -q` run exited 0: **5,425 passed, 52 skipped,
34 integration deselected** (counts from progress output and collection).
Twelve final cleanup regressions added while that run was active were verified
by the subsequent focused run above; product code was unchanged. Warnings were
upstream Starlette/httpx deprecation, an installed Hermes invalid-escape warning,
and existing Python multi-threaded-fork deprecations. No test failed.

C1a review follow-up: ordinary `OSError` bodies after successful deletion exposed
uncertainty loss when POSIX unlock or lock-close also failed. Regression RED was
**2 failed, 4 passed**; retaining the transaction mutation state during error
classification gave **6 passed**. The analogous directory-close case already
preserved uncertainty and remains covered. Final focused suite: **190 passed,
47 skipped**; Ruff check/format and reduced-extras strict mypy (205 files) passed.
The full suite was not repeated for this bounded review fix.

Actual Windows Server 2025 ordinary-user validation on 2026-10-08 used Python
3.11.17, a disposable home and separate source/wheel directories on the retained
AWS host. Source commit `15ccec45b` passed **193 tests, 38 platform skips**.
An sdist-derived wheel from reviewed commit `d2db7b5d3`, installed with no package
dependencies in a fresh venv (plus pytest), passed **193 tests, 44 platform
skips**. The six additional skips are the new POSIX-only raw-error regressions;
the review fix did not change Windows product code. Module paths were verified
inside the new wheel venv, with no source path injection. Wheel SHA-256:
`02c57837fc35d6aa9476d4bcafc01d3defedef0453ace6b34ccde0696ae6245e`.

The actual native cases cover metadata/prefix/enumeration, checked deletion,
no-replace rename, append, hostile ACLs/junctions/hard links, held handles and
cross-process append contention. Injected cleanup failures are separately
identified in test names. Independent review found one POSIX classification
defect, fixed and re-reviewed with no remaining important findings. Shellcheck
also passed. This slice did not repeat reboot/stop-start or TPM custody tests;
it adds no Windows 11 or whole-product acceptance claim. Host shutdown remains
the responsibility of the ongoing completion task's bounded auto-stop controls.

### C5 custody foundation validation (2026-10-08)

The shared prerequisite exposes validated Windows principal identity,
confidential bounded inventory, protected canonical transaction loans and
monotonic child publication receipts. It does not enable production custody,
memory or encrypted audit callers. Scoped Windows CI additionally selects
`tests/test_private_fs_principal.py` and `tests/test_config_io_custody.py`;
existing native confidential/coordinator suites now include inherited inventory,
fresh-process SID comparison, borrowed audit and child receipt cases.

Local macOS Python 3.13.12 all-extras verification at code `c6d2e8ab7`:
**5,895 passed, 106 skipped, 37 integration cases deselected**. Five warnings are
existing dependency/fork deprecations and an upstream-source escape warning. Focused shared capabilities/readers and
docs: **281 passed, 16 skipped** with default marker filtering disabled; the
native/integration skips are not Windows execution evidence. Ruff check/format,
ShellCheck and strict mypy for 210 source files passed; mypy used an isolated
reduced-extras environment (`dev,keyvault,extension,macos`).

Regression development caught missing interfaces, nested nonblocking loan
acquisition, caught uncertain admission failures and child outcome loss when
parent security revalidation happened before receipt reporting. Native Server
source/wheel validation, independent review, Windows 11 and production caller
adoption remain separate gates controlled by the completion run.
