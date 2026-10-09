# Windows support feasibility and proposed validation plan

Date: 2026-10-07.
Status: Phase 0 and the W1–W4 CNG helper slice are implemented and validated
on actual AWS Windows/NitroTPM. Full Windows product support remains incomplete.
This document proposes work, not an approved support contract. SPEC.md, PLAN.md,
TODO.md, and CI.md remain the source of truth for implemented behavior.

## Intended outcome

Run Mordred natively on Windows and validate it progressively on actual AWS
Windows instances, following the earlier Linux validation approach. The assumed
target includes CLI, policy enforcement, networking, extension/ Desktop, and
TPM-backed Private Telegram credentials and agent memory. WSL alone does not
establish native Windows support. Feature scope remains subject to review.

The initial investigation was read-only. After the user approved proceeding,
Phase 0 provisioned an isolated AWS Windows host and exercised disposable
probes against unchanged Mordred code. Product implementation and live-account
tests are separate gates.

## Findings and confidence

Native Windows CNG custody is experimentally feasible: an ordinary credentialed
user performed hardware P-256 ECDH and decrypted the unchanged MRKW format on
actual AWS NitroTPM. Full product support requires the implementation slices
below. Importing the package or opening its UI does not establish full support.

The original local checkout is at `f3211c6fb` and contains existing uncommitted
Linux documentation work. The planning baseline is remote `dev`, verified with
`git ls-remote`: `f14c1edce23f88c4a2cb6f8bfd3c1454ed0a59ce` (0.2.0a1).
Its CI log records Linux TPM memory, Private Telegram, and Desktop validation.
The isolated `docs/windows-feasibility` worktree branches from that baseline;
the existing local changes remain untouched.

| Area | Evidence | Remaining work |
| --- | --- | --- |
| Hermes host | Pinned v2026.9.24 CLI and source-built Desktop run; enabling Mordred reveals an `os.fchmod` startup refusal | Port audit/filesystem behavior and verify full gateway lifecycle and plugin hooks |
| AWS environment | Dedicated Windows Server 2025 NitroTPM host provisioned and exercised | Retain only identified development resources; stop compute between runs |
| Key backend | `_seckey_backend.py` selects `find_winkey_helper()` on `win32` | Native CNG helper and production MRKW integration validated; port runtime/storage callers next |
| Encryption contract | `keyvault/wrap.py` requires P-256 ECDH, HKDF, AES-KW and the existing MRKW format | Helper parity, persistence and second-TPM refusal proved; validate full product custody after filesystem port |
| Files and locks | `_file_lock.py` depends on POSIX mode checks and `flock`; `_audit_io.py` calls `os.fchmod` | Provide equivalent Windows ACL, handle, reparse-point, and process-lock behavior |
| Memory and setup | Linux support exists, but platform branches admit macOS/Linux | Extend custody, bootstrap, reset/purge protection, CLI setup and status |
| Desktop | API capability responses and setup routes currently exclude Windows | Add accurate capabilities, setup actions and actual packaged/source-built app verification |
| Network | Existing lifecycle and process inspection include POSIX assumptions | Inventory Tor/VPN executable discovery, subprocess shutdown, DNS/proxy behavior and failure refusal |

Relevant upstream facts:

- Hermes documents native Windows 10/11, but its bundled MSIX Desktop requires
  Windows 11 22H2 or later. Source installation and MSIX are distinct validation
  targets. Documentation for current upstream is not proof that an older pinned
  release has the same support.
  [Hermes native Windows guide](https://hermes-agent.nousresearch.com/docs/user-guide/windows-native).
- AWS supports preconfigured Windows NitroTPM AMIs with UEFI. NitroTPM state is
  not included in EBS snapshots; snapshots are not TPM-key recovery.
  [AWS NitroTPM requirements](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html).
- Windows exposes TPM-backed keys through Microsoft Platform Crypto Provider.
  The Phase 0 experiment established this device/provider supports Mordred's
  ECDH and raw-secret requirements; other TPM devices remain acceptance targets.
  [Microsoft CNG providers](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers),
  [NCryptSecretAgreement](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsecretagreement).

## Phase 0 decision

**Go for the standalone CNG helper and Python bridge.** Actual hardware ECDH,
wire compatibility, private-export refusal, retained data after reboot and
stop/start, deletion refusal, and the same-disk/second-TPM negative control have
been observed. The host-only Desktop reaches onboarding. Existing Mordred startup
and file-lock failures are explicit porting work, not waived acceptance gates.
The subsequent W1–W4 implementation proved the production helper (see the
CI manual validation log). Scheduled gateway lifecycle, consumer Windows 11/MSIX
and end-to-end Private Telegram remain unproven. The user approved continuing
with in-session implementation after reviewing the proposed plan.

## Approaches considered

1. **Native Windows with a CNG TPM helper (recommended).** Fits the existing
   helper-selection and JSON protocol boundaries and preserves the hardware-key
   floor. Requires Windows filesystem and lifecycle work as well as a helper.
2. **WSL2 deployment.** Reuses more Linux code, but does not prove native Windows
   compatibility or provide evidence of Windows CNG custody. TPM availability
   inside WSL is a separate question. This does not meet the assumed target.
3. **DPAPI/software-only initial custody.** May simplify development, but is a
   different security guarantee. Do not silently substitute it for TPM support.
   A deliberately weaker product tier would need a separate explicit decision.

## Phase 0: decisive feasibility experiment

Use `intmax-developer` in `ap-southeast-1`, matching the earlier validation.
The previous Linux NitroTPM instance was verified stopped and must remain intact.
No retained Linux credentials or live-account fixtures should be copied.

Candidate discovered through EC2 on 2026-10-07:

- `TPM-Windows_Server-2025-English-Full-Base-2026.09.17`,
  `ami-05171b2d13ab22cba`, `BootMode=uefi`, `TpmSupport=v2.0`.
- Compatibility follow-up: Server 2022 image `ami-0f8128438045a25dd`.

Start with one x86_64 `t3.large` candidate (8 GiB RAM for Python/native/Desktop
builds); verify regional availability and current price before provisioning.
Use a second temporary matching instance only for the device-binding test.
Use encrypted EBS, task tags and isolated source/test homes. Prefer Systems
Manager for commands and port forwarding. The actual source-built Electron
application can be driven through Playwright under a credentialed ordinary user;
a separate interactive Windows 11 acceptance run still covers consumer installs.
Never infer user-session custody from a SYSTEM-run probe.
If SSM is unavailable, constrain management access to the operator's address.

The experiment must answer these questions in order:

1. Does an unmodified, pinned Hermes release install and run CLI, gateway and
   source-built Desktop on this Windows Server? Which interpreter loads plugins?
2. Is the actual AWS NitroTPM visible to Windows, and can the intended ordinary
   application user create, reopen and delete a non-exportable P-256 key using
   the Platform Crypto Provider? Record provider and device properties.
3. Can that key perform ECDH with an independent software ephemeral key and
   provide the exact normalized secret required by the existing HKDF/AES-KW
   code? Check byte order, leading-zero padding, malformed peer-key rejection,
   and existing MRKW format round trips.
4. Do keys survive a fresh process, OS reboot and EC2 stop/start? Does copying
   ciphertext/key metadata to the second instance fail to decrypt? Distinguish
   account-access refusal from evidence of device binding.
5. Does helper/provider failure refuse decryption without generating a new key
   or switching to software? Are valid ciphertext and keys preserved on errors?

**Go:** the host integration and complete key protocol succeed through the
intended application user. Then finalize the product contract and task plan.
**Replan:** Hermes public hooks are insufficient, or the CNG provider cannot
implement the required ECDH contract. Evaluate a Windows TPM Base Services
backend or an explicitly versioned wrapping suite separately. Do not rewrite the
wire format or weaken key custody as an incidental compatibility fix.

## Proposed implementation order after the experiment

Follow the cross-component docs-first convention. Submit SPEC/PLAN/TODO/CI
contracts to `dev` first, then keep component changes in separate PRs.

| Order | Slice | Acceptance criterion |
| --- | --- | --- |
| 1 | Keyvault Windows helper | Native executable, bounded JSON protocol, scoped key names, provider verification, full ECDH parity and actual-device negative tests |
| 2 | Shared Windows platform primitives | Restrictive ACLs at creation; safe handle-based access; reparse-point refusal; interprocess exclusion; atomic replace and crash tests; POSIX regressions pass |
| 3 | Keyvault runtime and memory | Fresh-process bootstrap, encrypted credential/memory reads and writes, profile isolation, concurrent reset/purge refusal, no plaintext/software fallback |
| 4 | Wizard and installation | PowerShell-compatible build/install/probe; correct `.exe` discovery and `Scripts` interpreter paths; idempotent setup/disable/re-enable/purge and useful Windows errors |
| 5 | Network | Windows Tor/VPN discovery and lifecycle; DNS/proxy enforcement; outages and shutdown; each unsupported route fails explicitly |
| 6 | Policy, LLM guard, privacy and audit callers | Each component adopts verified Windows storage/process behavior separately and preserves strict-mode enforcement |
| 7 | Extension and Desktop | Gateway start/stop and pairing work; actual app reports TPM capabilities correctly; setup and synthetic Telegram workflow succeed |
| 8 | Packaging and CI | Wheel/sdist install outside checkout; Windows Python matrix; helper build; focused component and full suite checks; reproducible manual-device gate |

Shared primitives span component consumers: the contract PR must specify their
boundary and migration order. Split caller changes by component, retaining the
current macOS/Linux behavior. Reuse the single `mordred` entry point and existing
public Hermes integration; no upstream PRs or fork modifications.

Windows file protection must replace POSIX security properties, not merely skip
`chmod`/`fcntl` errors. Candidate primitives include Windows security descriptors
and `LockFileEx`; verify ownership, ACL inheritance, parent-directory trust,
sharing modes, junction/symlink races and handle lifetime.
[Microsoft LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).

Preserve the Linux-style machine-bound tier: do not promise Touch ID-equivalent
presence or automatic recovery. Full macOS `.env`/config/workspace seal parity,
Windows Hello, ARM64 and a new recovery mechanism are separate scope decisions.
Do not advertise them as part of an initial Windows port.

## Follow-on change inventory

This inventory names the inspected seams for the dependent plans; it is not a
proposal to modify all components in the helper PR. Platform branches must be
read before changing a match: a POSIX call inside a guarded Linux function is
not itself a Windows defect.

| Slice | Concrete seams | Required review |
| --- | --- | --- |
| Shared storage | `_file_lock.py`, `_audit_io.py` | Replace mode-bit and optional-`fcntl` behavior with real Windows ACL/handle/lock guarantees; audit startup currently fails at `os.fchmod` |
| Keyvault persistence | `keyvault/_storage.py`, `_plaintext_capture.py`, `_memory_key.py`, `_config_bootstrap.py` | Secure creation and replacement, private temporary files, retained encrypted data and lifecycle locks |
| Runtime discovery | `keyvault/_runtime_probe.py`, `_runtime_env.py`, `_pth_bootstrap.py` | User identity, Windows process/interpreter paths, isolated home and actual Desktop runtime |
| Wizard | `wizard/openclaw_migration.py`, `_keyvault_init.py`, `_runtime_gate.py`, `uninstall_cli.py`, encryption/memory/Telegram setup CLIs | PowerShell builds, file protection, supported capability gates, idempotent setup and guarded purge |
| Extension | `extension/pairing.py`, `extension/telegram/store.py`, `memory_guard.py`, `hardening.py`, `tee.py` | Private session/archive files, process locks and existing Linux-style wrapped-DEK custody |
| Audit/policy consumers | `privacy_check/audit.py`, `wizard/policy_writer.py`, network registration | Adopt shared primitives per component; preserve startup refusal and strict route enforcement |
| Desktop and process lifecycle | `desktop/api.py`, `extension/__main__.py`, upstream public gateway hooks | Accurate Windows capabilities, token-specific custody, process-tree cleanup, startup/stop/restart under ordinary and scheduled identities |

## Validation and release gates

- Run relevant tests on the Windows instance after every slice, not only at the
  end. Use synthetic secrets/messages and a stub model for repeatable tests.
- Validate `HERMES_HOME`, upstream native home resolution, user/profile changes,
  paths with spaces/non-ASCII, helper location and the actual Desktop interpreter.
- Exercise encrypted archive sync/list/ask/cancel, restart, enable/disable,
  corruption, missing TPM/helper, wrong profile, key deletion and concurrent
  writers. Unavailable security must block the operation and preserve data.
- Test normal-user execution and the scheduled gateway account separately.
  A CNG key available to an administrator/SYSTEM session does not establish
  availability to Desktop or a scheduled task under another identity.
- Run macOS/Linux regressions, reduced-extras strict mypy, Ruff, package checks
  and the existing coverage floor. Skip only genuinely platform-specific tests;
  replace POSIX assertions with meaningful Windows security assertions.
- Windows CI proves portable behavior with injected backends; it does not
  substitute for actual NitroTPM acceptance. Record exact commits, versions,
  commands, test counts, screenshots and sanitized failures in the CI manual log.
- Real Telegram login and live model queries are a later interactive gate with
  separately supplied credentials. Do not reuse the existing Linux account state.
- Windows Server EC2 validates the server runtime and source-built Desktop path.
  It does not establish Windows 11 MSIX installation, package permissions,
  self-update or consumer TPM compatibility. Require a separate Windows 11
  desktop session for that release claim; choose a suitable Windows 11 cloud
  desktop or user device after confirming availability and terms.

## Cost and completion policy

Initial planning made no billable changes. The approved experiment uses
Windows `t3.large` in Singapore: the current AWS price query returned
$0.1332/hour, plus EBS, public IPv4, transfer and any surplus CPU credits.
The 50 GiB gp3 volume is $0.096/GB-month ($4.80/month if retained). Unlimited
CPU credits were enabled for the build; Windows surplus credits are
$0.096/vCPU-hour. A four-hour auto-stop is a backstop, not a substitute for
explicit stop/verification. These are rate estimates, not a billing statement.

Track task-owned resources, stop compute after testing, and report retained
storage and recurring charges. Do not terminate an instance retaining the only
TPM key for data the operator wants to keep. Use disposable synthetic fixtures
for destructive/key-deletion experiments.

The Phase 0 evidence is recorded in [CI.md](CI.md#manual-live-device-validation-log).
The immediate implementation deliverable is the independent CNG helper and its
Python bridge ([PLAN W1–W4](PLAN.md#windows-cng-helper-implementation-plan));
full Windows product readiness depends on the later component gates. No reliable
end-to-end schedule is claimed from the successful CNG experiment alone.
