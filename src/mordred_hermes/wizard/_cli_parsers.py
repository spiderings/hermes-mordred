"""argparse subparser tree for ``hermes mordred ...`` + the per-command handlers.

Builds the full command surface so ``--help`` lists every subcommand, and
holds the thin ``_handle_*`` handlers that each delegate to their own module
and return an exit code. Extracted from :mod:`.cli` (which keeps the ``main`` /
``dispatch`` entry points and re-exports the names below) to keep each module
under the size guideline. All subcommands below are implemented.

Subcommand tree (SPEC.md §Plugin: ``mordred_wizard``):

- ``configure``                                  — interactive Mordred setup (policy / LLM / harness)
- ``upgrade [--reset|--non-interactive|...]``    — idempotent migration (detects ~/.openclaw)
- ``install <skill>``                            — install a skill through the policy gate
- ``network {use,status,init}``                  — network-privacy path control + on-demand setup
- ``policy {show,explain,dry-run,reload}``       — inspect / explain the active policy
- ``audit {tail,grep,decrypt,purge}``            — read / maintain the audit log
- ``keyvault {init,list,verify-digest,export,recover,reset,enable-se,enable-tpm,eth}`` — keyvault management
- ``vault {init,add,status,cat,migrate,...}``    — at-rest secrets/env vault
- ``plugins list``                               — show the Mordred plugin and its components
- ``plugins migrate``                            — switch config.yaml to the single ``mordred`` plugin
- ``uninstall [--dry-run|--yes|--purge-data|--remove-helper]`` — remove Mordred, restore Hermes's files
"""

from __future__ import annotations

import argparse

from .._policy_types import ACTIVE_PATHS, POLICY_MODES


def _setup_subparser(parser: argparse.ArgumentParser, *, required: bool = True) -> None:
    """Build the full ``hermes mordred`` subcommand tree.

    Hermes calls this once at CLI initialisation with the top-level
    ``mordred`` subparser. We add ``mordred_command`` dest and per-command
    sub-subparsers, each wired via ``set_defaults(func=<handler>)``.

    ``required`` defaults to ``True`` (Hermes' contract: a subcommand must be
    given). The standalone ``main`` passes ``required=False`` so a bare
    ``hermes-mordred`` can greet with the quickstart help instead of erroring.
    """
    sub = parser.add_subparsers(dest="mordred_command", required=required, metavar="COMMAND")

    _add_status(sub)
    _add_setup(sub)
    _add_configure(sub)
    _add_upgrade(sub)
    _add_install(sub)
    _add_network(sub)
    _add_policy(sub)
    _add_audit(sub)
    _add_keyvault(sub)
    _add_vault(sub)
    _add_encryption(sub)
    _add_plugins(sub)
    _add_extension(sub)
    _add_telegram(sub)
    _add_egress(sub)
    _add_desktop(sub)
    _add_uninstall(sub)


# -----------------------------------------------------------------------------
# Subcommand parsers — each calls set_defaults(func=...) wiring its handler.
# -----------------------------------------------------------------------------


def _add_desktop(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("desktop", help="Hermes Desktop setup page (install / uninstall / status)")
    dsub = p.add_subparsers(dest="desktop_command", required=True, metavar="COMMAND")
    for name, text in (
        ("install", "Place the Mordred setup page and its local API in Hermes"),
        ("uninstall", "Remove the Mordred setup page"),
        ("status", "Show whether the setup page is installed"),
    ):
        dsub.add_parser(name, help=text).set_defaults(func=_handle_desktop)


def _add_uninstall(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "uninstall",
        help="Remove Mordred and restore Hermes's files (decrypts what Mordred encrypted first)",
        description=(
            "Turn off every at-rest encryption target (restoring plaintext .env / config.yaml / memories), "
            "remove Mordred's entries from config.yaml and .env, the Hermes Desktop page and the installer's "
            "launcher, then uninstall the package from Hermes's environment. Mordred's data (vault, keyvault, "
            "Telegram archive, audit log) is kept unless --purge-data is given."
        ),
    )
    p.add_argument("--dry-run", action="store_true", help="Print the plan and change nothing")
    p.add_argument("--yes", action="store_true", help="Do not ask for confirmation (not for --purge-data)")
    p.add_argument(
        "--purge-data",
        action="store_true",
        help="Also permanently delete Mordred's data and device keys (asks you to type a confirmation)",
    )
    p.add_argument(
        "--erase-encrypted",
        action="store_true",
        help="Do not decrypt: delete encrypted data (sealed memories, vault copies of .env / config.yaml) "
        "together with all Mordred data. Implies --purge-data; asks you to type a confirmation",
    )
    p.add_argument(
        "--remove-helper",
        action="store_true",
        help="Also remove the Mordred-built native helper in ~/.local/bin (mordred-hermes-sekey / -tpmkey)",
    )
    p.set_defaults(func=_handle_uninstall)


def _add_egress(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("egress", help="Tool-egress level: stop the agent's tools from sending data out")
    esub = p.add_subparsers(dest="egress_command", required=True, metavar="COMMAND")
    esub.add_parser("status", help="Show the level, taint setting and blocklists").set_defaults(func=_handle_egress)
    p_set = esub.add_parser("set", help="Set the level: lockdown | search | blocklist | off")
    p_set.add_argument("level", choices=["lockdown", "search", "blocklist", "off"])
    p_set.set_defaults(func=_handle_egress)
    for name, arg, text in (
        ("block", "domain", "Add a domain to the blocklist"),
        ("unblock", "domain", "Remove a domain from the blocklist"),
        ("block-tool", "tool", "Block a tool at every level except off"),
        ("unblock-tool", "tool", "Unblock a tool"),
    ):
        p_item = esub.add_parser(name, help=text)
        p_item.add_argument(arg)
        p_item.set_defaults(func=_handle_egress)
    p_taint = esub.add_parser("taint", help="Lock a session down after it reads private data (on|off)")
    p_taint.add_argument("state", choices=["on", "off"])
    p_taint.set_defaults(func=_handle_egress)


def _add_telegram(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("telegram", help="Read-only import of your own Telegram account (optional extra)")
    tsub = p.add_subparsers(dest="telegram_command", required=True, metavar="COMMAND")
    p_setup = tsub.add_parser("setup", help="Guided first-time setup (Enclave, login, privacy LLM, first import)")
    p_setup.add_argument(
        "--no-touch-id",
        action="store_true",
        help="Create the Enclave key without a per-use Touch ID / passcode requirement",
    )
    p_setup.set_defaults(func=_handle_telegram)
    p_doctor = tsub.add_parser("doctor", help="Health check from metadata only (no Touch ID, no content)")
    p_doctor.add_argument("--json", action="store_true", help="Machine-readable output")
    p_doctor.set_defaults(func=_handle_telegram)
    p_login = tsub.add_parser("login", help="Create a session, sealed by the Secure Enclave")
    p_login.add_argument(
        "--no-touch-id",
        action="store_true",
        help="Create the Enclave key without a per-use Touch ID / passcode requirement",
    )
    p_login.set_defaults(func=_handle_telegram)
    p_sync = tsub.add_parser("sync", help="Import new messages from every dialog into the encrypted archive")
    p_sync.add_argument(
        "--all",
        action="store_true",
        help="Import everything: all history, channels, archived chats and large groups (slow)",
    )
    p_sync.add_argument(
        "--days",
        type=int,
        default=None,
        metavar="N",
        help="Only chats active in the last N days, and only their last N days of messages "
        "(default: 3; 0 = all history)",
    )
    p_sync.add_argument(
        "--include-large-groups",
        action="store_true",
        help="Also import groups with more than --large-group-size members (skipped by default)",
    )
    p_sync.add_argument(
        "--large-group-size",
        type=int,
        default=None,
        metavar="N",
        help="Member count above which a group is skipped (default: 100)",
    )
    p_sync.add_argument("--skip-channels", action="store_true", help="Skip broadcast channels")
    p_sync.add_argument("--include-archived", action="store_true", help="Also import the Archived Chats folder")
    p_sync.add_argument("--skip-archived", action="store_true", help="Skip the Archived Chats folder (the default)")
    p_sync.add_argument(
        "--limit-per-dialog",
        type=int,
        default=None,
        metavar="N",
        help="First import only: keep the newest N messages per dialog (default: all)",
    )
    p_sync.set_defaults(func=_handle_telegram)
    p_status = tsub.add_parser("status", help="Show login state and archive counts")
    p_status.add_argument("--show-account", action="store_true", help="Also print the account display name")
    p_status.set_defaults(func=_handle_telegram)
    p_logout = tsub.add_parser("logout", help="Revoke the session at Telegram and remove it from the vault")
    p_logout.add_argument(
        "--forget",
        action="store_true",
        help="Also delete the API credentials, the archive key and the local archive",
    )
    p_logout.set_defaults(func=_handle_telegram)
    p_venice = tsub.add_parser("venice", help="Store the Venice.ai API key and model used for questions")
    p_venice.add_argument("--model", default=None, help="Venice model id (must be labelled 'private')")
    p_venice.set_defaults(func=_handle_telegram)
    p_local = tsub.add_parser("local-llm", help="Send questions to a model on this machine (loopback only)")
    p_local.add_argument("--endpoint", required=True, help="e.g. http://127.0.0.1:11434/v1")
    p_local.add_argument("--model", required=True, help="Model name served by that endpoint")
    p_local.set_defaults(func=_handle_telegram)
    p_migrate = tsub.add_parser("migrate-tee", help="Move vault-stored credentials into the Secure Enclave seal")
    p_migrate.add_argument(
        "--no-touch-id",
        action="store_true",
        help="Create the Enclave key without a per-use Touch ID / passcode requirement",
    )
    p_migrate.set_defaults(func=_handle_telegram)


def _add_extension(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("extension", help="Browser extension: pairing and bridge")
    esub = p.add_subparsers(dest="extension_command", required=True, metavar="COMMAND")
    p_pair = esub.add_parser("pair", help="Generate a pairing code and wait for the extension")
    p_pair.add_argument("--timeout", type=float, default=600.0, help="Seconds to wait for pairing (default: 600)")
    p_pair.set_defaults(func=_handle_extension_pair)
    p_serve = esub.add_parser(
        "serve",
        help="Run the extension WebSocket server (ws://127.0.0.1:7788/ext) in the foreground",
    )
    p_serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="Loopback bind host (default: 127.0.0.1; non-loopback values are refused)",
    )
    p_serve.add_argument("--port", type=int, default=7788, help="Bind port (default: 7788)")
    p_serve.set_defaults(func=_handle_extension_serve)


def _add_status(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "status",
        help="Show Mordred state at a glance (policy / network / keyvault / encryption)",
    )
    p.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p.set_defaults(func=_handle_status)


def _add_setup(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "setup",
        help="Run every setup step in order (hermes / configure / network / hardware helper / "
        "keyvault / encryption); safe to re-run, resumes where it left off",
    )
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; any step that still needs a decision is reported as needing a manual follow-up",
    )
    hermes_group = p.add_mutually_exclusive_group()
    hermes_group.add_argument(
        "--with-hermes-setup",
        action="store_true",
        help="Force-run the upstream `hermes setup` wizard even if it already looks complete",
    )
    hermes_group.add_argument(
        "--skip-hermes-setup",
        action="store_true",
        help="Skip the upstream `hermes setup` step even if it looks incomplete",
    )
    keys_group = p.add_mutually_exclusive_group()
    keys_group.add_argument(
        "--unattended-keys",
        dest="unattended_keys",
        action="store_true",
        default=None,
        help="New keyvault keys skip the per-use Touch ID / passcode prompt (for background callers "
        "like the extension Gateway)",
    )
    keys_group.add_argument(
        "--attended-keys",
        dest="unattended_keys",
        action="store_false",
        default=None,
        help="New keyvault keys require a per-use Touch ID / passcode prompt (default)",
    )
    p.set_defaults(store_seed_for_hd=True)
    seed_storage = p.add_mutually_exclusive_group()
    seed_storage.add_argument(
        "--store-seed-for-hd",
        dest="store_seed_for_hd",
        action="store_true",
        help="SE-encrypt the generated keyvault seed so HD Ethereum accounts can be derived later (default).",
    )
    seed_storage.add_argument(
        "--paper-only",
        dest="store_seed_for_hd",
        action="store_false",
        help="Do not store the generated keyvault seed at rest; require the paper seed for later recovery/import.",
    )
    p.set_defaults(func=_handle_setup)


def _add_configure(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "configure",
        help="Run interactive Mordred setup (writes config.yaml + policy.json)",
    )
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Apply from flags without prompting (CI / scripted use); unspecified flags keep existing settings",
    )
    p.set_defaults(with_hermes_setup=False)
    setup_group = p.add_mutually_exclusive_group()
    setup_group.add_argument(
        "--with-hermes-setup",
        action="store_true",
        help="Also run the upstream `hermes setup` wizard before the Mordred prompts (skipped by default)",
    )
    # Deprecated no-op: skipping `hermes setup` became the default (2026-07-16).
    # Kept so existing documented/scripted invocations keep parsing; hidden from
    # --help. Shares the dest (store_false) so no vestigial attribute hangs off
    # the Namespace — mirrors keyvault init's seed_storage group — while the
    # mutually exclusive group still errors when both flags are passed.
    setup_group.add_argument(
        "--skip-hermes-setup",
        dest="with_hermes_setup",
        action="store_false",
        help=argparse.SUPPRESS,
    )
    p.add_argument("--policy", choices=POLICY_MODES, help="Mordred policy mode")
    p.add_argument(
        "--allow-cloud-llm",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Allow cloud LLM providers (passes through provider override)",
    )
    p.add_argument("--cloud-allowlist", help="Cloud provider allowlist (comma-separated; empty = none)")
    p.add_argument("--local-llm-endpoint", help="Local LLM endpoint URL")
    p.add_argument("--local-llm-model-id", help="Local LLM model id")
    p.add_argument(
        "--cloud-attempt-action",
        choices=["always-block", "prompt-once"],
        help="On a cloud LLM attempt under strict mode",
    )
    p.add_argument(
        "--harness",
        choices=["none", "codex", "claude-cli", "cursor", "acp-claude", "acp-cline"],
        help="Agent harness (strict mode refuses if a known harness is detected)",
    )
    p.set_defaults(func=_handle_configure)


def _add_upgrade(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "upgrade",
        help="Migrate an existing Hermes / OpenClaw install to Mordred (idempotent; detects ~/.openclaw)",
    )
    p.add_argument("--reset", action="store_true", help="Force overwrite on every conflict")
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail fast when a conflict policy was not pre-specified",
    )
    p.add_argument(
        "--audit-merge",
        choices=["skip", "append-all", "abort"],
        help="OpenClaw audit-log merge policy when overlap is detected",
    )
    p.add_argument(
        "--policy-conflict",
        choices=["keep-existing", "overwrite", "abort"],
        help="Behaviour when ~/.hermes/config.yaml plugins.mordred_* already differs",
    )
    p.set_defaults(func=_handle_upgrade)


def _add_install(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "install",
        help="Install a skill through the Mordred policy gate (delegates to privacy_check)",
    )
    p.add_argument("skill", help="Skill name or path to a directory containing SKILL.md")
    p.set_defaults(func=_handle_install)


def _add_network(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("network", help="Network privacy path control (Tor / VPN / clearnet)")
    nsub = p.add_subparsers(dest="network_command", required=True, metavar="COMMAND")

    p_use = nsub.add_parser("use", help="Switch active network path")
    p_use.add_argument("path", choices=ACTIVE_PATHS, help="Network path to use (tor, vpn, or clearnet)")
    p_use.set_defaults(func=_handle_network_use)

    p_status = nsub.add_parser("status", help="Show active path and liveness")
    p_status.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_status.set_defaults(func=_handle_network_status)

    p_init = nsub.add_parser(
        "init",
        help="Set up network privacy on demand (Tor / VPN / clearnet, Mullvad account)",
    )
    p_init.add_argument(
        "--non-interactive",
        action="store_true",
        help="Apply from flags without prompting (CI / scripted use); keeps the existing Mullvad secret",
    )
    p_init.add_argument("--path", choices=ACTIVE_PATHS, help="Default network path")
    p_init.add_argument("--tor-binary", help="Tor binary path (filesystem path or shell-resolvable name)")
    p_init.add_argument("--tor-socks-port", type=int, help="Tor SOCKS port")
    p_init.add_argument("--mullvad-relay", help="Mullvad relay country ('auto' or a 2-letter code)")
    p_init.add_argument(
        "--mullvad-killswitch",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable the Mullvad killswitch (lockdown-mode)",
    )
    p_init.add_argument(
        "--clear-mullvad",
        action="store_true",
        help="Remove the stored Mullvad account secret from ~/.hermes/.env",
    )
    p_init.set_defaults(func=_handle_network_init)


def _add_policy(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("policy", help="Inspect and explain the active Mordred policy")
    psub = p.add_subparsers(dest="policy_command", required=True, metavar="COMMAND")

    p_show = psub.add_parser("show", help="Print resolved policy.json")
    p_show.set_defaults(func=_handle_policy_show)

    p_explain = psub.add_parser(
        "explain",
        help="Explain the install decision for a known skill id (exit code 2 when the decision is block)",
    )
    p_explain.add_argument("skill_id", help="Skill id to explain")
    p_explain.set_defaults(func=_handle_policy_explain)

    p_dry = psub.add_parser(
        "dry-run",
        help="Evaluate install policy against a SKILL.md path without installing (exit code 2 = would block)",
    )
    p_dry.add_argument("skill_path", help="Path to SKILL.md file to evaluate")
    p_dry.set_defaults(func=_handle_policy_dry_run)

    p_reload = psub.add_parser("reload", help="Re-read policy from config.yaml (in-process state reset)")
    p_reload.set_defaults(func=_handle_policy_reload)


def _add_audit(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("audit", help="Tail / grep / decrypt / purge the Mordred audit log")
    asub = p.add_subparsers(dest="audit_command", required=True, metavar="COMMAND")

    p_tail = asub.add_parser("tail", help="Tail the most recent audit entries")
    p_tail.add_argument("-n", "--lines", type=int, default=20, help="Number of recent entries to show (default: 20)")
    p_tail.set_defaults(func=_handle_audit_tail)

    p_grep = asub.add_parser("grep", help="Grep audit entries (line-wise regex)")
    p_grep.add_argument("pattern", help="Regex pattern to match against audit entries")
    p_grep.set_defaults(func=_handle_audit_grep)

    p_decrypt = asub.add_parser("decrypt", help="Decrypt encrypted audit entries")
    p_decrypt.add_argument("--date", required=True, help="YYYY-MM-DD")
    p_decrypt.set_defaults(func=_handle_audit_decrypt)

    p_purge = asub.add_parser("purge", help="Delete dated rotated audit logs (destructive; needs --yes)")
    p_purge.add_argument("--before", required=True, help="YYYY-MM-DD")
    p_purge.add_argument("-y", "--yes", action="store_true", help="Confirm the destructive purge")
    p_purge.set_defaults(func=_handle_audit_purge)


def _add_keyvault(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("keyvault", help="Mordred keyvault management")
    ksub = p.add_subparsers(dest="keyvault_command", required=True, metavar="COMMAND")

    p_init = ksub.add_parser("init", help="Initialise the keyvault")
    p_init.set_defaults(store_seed_for_hd=True)
    seed_storage = p_init.add_mutually_exclusive_group()
    seed_storage.add_argument(
        "--store-seed-for-hd",
        dest="store_seed_for_hd",
        action="store_true",
        help="SE-encrypt the generated seed so HD Ethereum accounts can be derived later (default).",
    )
    seed_storage.add_argument(
        "--paper-only",
        dest="store_seed_for_hd",
        action="store_false",
        help="Do not store the generated seed at rest; require the paper seed for later recovery/import.",
    )
    p_init.set_defaults(func=_handle_keyvault_init)
    p_list = ksub.add_parser("list", help="List key IDs")
    p_list.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_list.set_defaults(func=_handle_keyvault_list)
    ksub.add_parser("verify-digest", help="Verify the keyvault digest").set_defaults(
        func=_handle_keyvault_verify_digest
    )
    p_export = ksub.add_parser("export", help="Create a portable, passphrase-protected Keyvault backup snapshot")
    p_export.add_argument("--output", required=True, help="New output file (must not already exist; written mode 0600)")
    p_export.set_defaults(func=_handle_keyvault_export)
    p_recover = ksub.add_parser("recover", help="Restore from a backup blob")
    p_recover.add_argument("--blob", required=True, help="Path to the backup blob file")
    p_recover.set_defaults(func=_handle_keyvault_recover)
    p_reset = ksub.add_parser(
        "reset",
        help="Destroy all key material and remove the keyvault (irreversible)",
    )
    p_reset.add_argument(
        "-y",
        "--yes",
        dest="assume_yes",
        action="store_true",
        help="Skip the interactive confirmation (for scripted / non-interactive use).",
    )
    p_reset.set_defaults(func=_handle_keyvault_reset)
    p_enable_se = ksub.add_parser(
        "enable-se",
        help="Build + install the hardware Secure Enclave helper (ad-hoc signed; no Apple Developer account)",
    )
    p_enable_se.add_argument("--install-dir", help="Install directory for the helper (default: ~/.local/bin)")
    p_enable_se.set_defaults(func=_handle_keyvault_enable_se)
    p_enable_tpm = ksub.add_parser(
        "enable-tpm",
        help="Build + install the Linux TPM 2.0 helper (machine-bound; Tier 2, no per-use prompt)",
    )
    p_enable_tpm.add_argument("--install-dir", help="Install directory for the helper (default: ~/.local/bin)")
    p_enable_tpm.set_defaults(func=_handle_keyvault_enable_tpm)
    p_enable_win = ksub.add_parser("enable-winkey", help="Build and probe the Windows CNG TPM helper")
    p_enable_win.add_argument("--install-dir", help="Helper directory (default: <HERMES_HOME>/bin)")
    p_enable_win.set_defaults(func=_handle_keyvault_enable_winkey)

    from . import keyvault_eth_cli

    keyvault_eth_cli.add_eth_subparsers(ksub)


def _add_vault(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("vault", help="At-rest secrets/env vault")
    vsub = p.add_subparsers(dest="vault_command", required=True, metavar="COMMAND")

    p_init = vsub.add_parser(
        "init",
        help="Create a new encrypted vault sealed under a recovery passphrase",
    )
    p_init.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_init.set_defaults(func=_handle_vault_init)

    p_change_pp = vsub.add_parser(
        "change-passphrase",
        help="Change the vault's recovery passphrase (master key and enrolled files unchanged)",
    )
    p_change_pp.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_change_pp.set_defaults(func=_handle_vault_change_passphrase)

    p_recover = vsub.add_parser(
        "recover",
        help="Re-key a vault copied to this machine onto its Secure Enclave (restores the writable hot path)",
    )
    p_recover.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_recover.set_defaults(func=_handle_vault_recover)

    p_add = vsub.add_parser(
        "add",
        help="Encrypt a file into the vault under a logical name",
    )
    p_add.add_argument("name", help="Logical name to store the file under (e.g. .env)")
    p_add.add_argument("source", help="Path to the plaintext file to encrypt into the vault")
    p_add.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_add.set_defaults(func=_handle_vault_add)

    p_status = vsub.add_parser(
        "status",
        help="Show a vault's generation and enrolled file names (never prompts; reads the manifest unverified)",
    )
    p_status.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_status.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_status.set_defaults(func=_handle_vault_status)

    p_cat = vsub.add_parser(
        "cat",
        help="Print one enrolled file's decrypted bytes to stdout (opens read-only via passphrase recovery)",
    )
    p_cat.add_argument("name", help="Enrolled file name to decrypt and print")
    p_cat.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_cat.set_defaults(func=_handle_vault_cat)

    p_migrate = vsub.add_parser(
        "migrate",
        help="Import existing plaintext files into the vault (default: .env + config.yaml under the Hermes home)",
    )
    p_migrate.add_argument(
        "source",
        nargs="*",
        help="Plaintext file(s) to import, each enrolled under its basename "
        "(default: .env and config.yaml under the Hermes home)",
    )
    p_migrate.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_migrate.set_defaults(func=_handle_vault_migrate)

    p_set_memory_key = vsub.add_parser(
        "set-memory-key",
        help="Store/rotate HERMES_MEMORY_KEY in the vault .env (the agent-memory encryption key; "
        "`encryption enable memory` is what turns sealing on)",
    )
    p_set_memory_key.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_set_memory_key.add_argument(
        "--rotate",
        action="store_true",
        help="Replace an existing key with a fresh one (default: leave an existing key unchanged)",
    )
    p_set_memory_key.set_defaults(func=_handle_vault_set_memory_key)

    p_enable_cfg = vsub.add_parser(
        "enable-config-decrypt",
        help="Put config.yaml under the at-rest vault (transparent decrypt at Hermes startup)",
    )
    p_enable_cfg.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_enable_cfg.set_defaults(func=_handle_vault_enable_config_decrypt)

    p_disable_cfg = vsub.add_parser(
        "disable-config-decrypt",
        help="Stop managing config.yaml in the vault and restore a plaintext copy (recovery)",
    )
    p_disable_cfg.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_disable_cfg.set_defaults(func=_handle_vault_disable_config_decrypt)


def _add_encryption(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "encryption",
        help="Unified at-rest encryption toggle (env / config / memory / workspace / all)",
    )
    esub = p.add_subparsers(dest="encryption_command", required=True, metavar="COMMAND")

    p_status = esub.add_parser("status", help="Show encryption state of all targets (non-prompting)")
    p_status.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_status.set_defaults(func=_handle_encryption_status)

    # enable / disable / purge over all four targets (workspace is macOS-only and
    # gated at runtime; status reports all four). The `all` pseudo-target fans the
    # verb out over every target, best-effort (workspace skipped when ineligible).
    _toggle_targets = ["env", "config", "memory", "workspace", "all"]

    p_enable = esub.add_parser("enable", help="Turn on at-rest encryption for a target")
    p_enable.add_argument(
        "target", choices=_toggle_targets, help="Encryption target (env, config, memory, workspace, or all)"
    )
    p_enable.add_argument("--non-interactive", action="store_true", help="Apply without prompting (CI / scripted use)")
    p_enable.add_argument(
        "--force-runtime-unverified",
        action="store_true",
        help="(env/config, macOS) seal .env / config.yaml even when the `hermes` runtime "
        "can't be verified to decrypt it — advanced; data stays unreadable until that "
        "runtime has mordred",
    )
    p_enable.set_defaults(func=_handle_encryption_enable)

    p_disable = esub.add_parser("disable", help="Turn off encryption for a target (reversible; keeps the vault copy)")
    p_disable.add_argument(
        "target", choices=_toggle_targets, help="Encryption target (env, config, memory, workspace, or all)"
    )
    p_disable.add_argument("--non-interactive", action="store_true", help="Apply without prompting (CI / scripted use)")
    p_disable.set_defaults(func=_handle_encryption_disable)

    p_purge = esub.add_parser("purge", help="Remove the encrypted copy for a target (destructive; needs --yes)")
    p_purge.add_argument(
        "target", choices=_toggle_targets, help="Encryption target (env, config, memory, workspace, or all)"
    )
    p_purge.add_argument("-y", "--yes", action="store_true", help="Confirm the destructive purge")
    p_purge.set_defaults(func=_handle_encryption_purge)

    # The recovery passphrase is born during `encryption enable`, so users look
    # for its rotation here too. Alias the vault-level command for discoverability.
    p_change_pp = esub.add_parser(
        "change-passphrase",
        help="Change the vault's recovery passphrase (alias of `vault change-passphrase`)",
    )
    p_change_pp.add_argument(
        "--root",
        help="Vault root directory (default: <hermes home>/mordred/vault)",
    )
    p_change_pp.set_defaults(func=_handle_vault_change_passphrase)


def _add_plugins(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "plugins",
        help="Show or migrate the Mordred Hermes plugin",
    )
    psub = p.add_subparsers(dest="plugins_command", required=True, metavar="COMMAND")
    psub.add_parser("list", help="Show the Mordred plugin and its components").set_defaults(func=_handle_plugins_list)
    p_migrate = psub.add_parser(
        "migrate",
        help="Replace the old per-component plugin names in config.yaml with the single 'mordred' plugin",
    )
    p_migrate.add_argument(
        "--only-legacy",
        action="store_true",
        help="Do nothing unless config.yaml still lists an old per-component name (used by install.sh)",
    )
    p_migrate.set_defaults(func=_handle_plugins_migrate)


# -----------------------------------------------------------------------------
# Handlers — each delegates to its module (lazy-imported to keep CLI start fast).
# Each handler accepts ``argparse.Namespace`` and returns an exit code (int).
# -----------------------------------------------------------------------------


def _handle_status(args: argparse.Namespace) -> int:
    from . import status_cli

    return status_cli.cli_status(args)


def _handle_setup(args: argparse.Namespace) -> int:
    from . import setup_cli

    return setup_cli.cli_setup(args)


def _handle_configure(args: argparse.Namespace) -> int:
    from . import configure

    return configure.cli_handler(args)


def _handle_upgrade(args: argparse.Namespace) -> int:
    from . import upgrade
    from .policy_writer import PolicyWriter

    options = upgrade.UpgradeOptions(
        reset=bool(getattr(args, "reset", False)),
        non_interactive=bool(getattr(args, "non_interactive", False)),
        audit_merge=getattr(args, "audit_merge", None),
        policy_conflict=getattr(args, "policy_conflict", None),
    )
    report = upgrade.run(options=options, policy_writer=PolicyWriter())
    print(upgrade.render_report(report))
    return 0


def _handle_install(args: argparse.Namespace) -> int:
    from . import install_dispatch

    return install_dispatch.cli_handler(args)


def _handle_network_use(args: argparse.Namespace) -> int:
    from . import network_cli

    return network_cli.handle_use(args)


def _handle_network_status(args: argparse.Namespace) -> int:
    from . import network_cli

    return network_cli.handle_status(args)


def _handle_network_init(args: argparse.Namespace) -> int:
    from . import network_cli

    return network_cli.handle_init(args)


def _handle_policy_show(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_show(args)


def _handle_policy_explain(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_explain(args)


def _handle_policy_dry_run(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_dry_run(args)


def _handle_policy_reload(args: argparse.Namespace) -> int:
    from . import policy_explainer

    return policy_explainer.cli_reload(args)


def _handle_audit_tail(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_tail(args)


def _handle_audit_grep(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_grep(args)


def _handle_audit_decrypt(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_decrypt(args)


def _handle_audit_purge(args: argparse.Namespace) -> int:
    from . import audit_cli

    return audit_cli.cli_purge(args)


def _handle_keyvault_init(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_init(args)


def _handle_keyvault_list(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_list(args)


def _handle_keyvault_verify_digest(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_verify_digest(args)


def _handle_keyvault_export(args: argparse.Namespace) -> int:
    from . import keyvault_export_cli

    return keyvault_export_cli.cli_export(args)


def _handle_keyvault_recover(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_recover(args)


def _handle_keyvault_reset(args: argparse.Namespace) -> int:
    from . import keyvault_cli

    return keyvault_cli.cli_reset(args)


def _handle_keyvault_enable_se(args: argparse.Namespace) -> int:
    from . import keyvault_native_cli

    return keyvault_native_cli.cli_enable_se(args)


def _handle_keyvault_enable_tpm(args: argparse.Namespace) -> int:
    from . import keyvault_native_cli

    return keyvault_native_cli.cli_enable_tpm(args)


def _handle_vault_init(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_init(args)


def _handle_vault_change_passphrase(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_change_passphrase(args)


def _handle_vault_recover(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_recover(args)


def _handle_vault_add(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_add(args)


def _handle_vault_status(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_status(args)


def _handle_vault_cat(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_cat(args)


def _handle_vault_migrate(args: argparse.Namespace) -> int:
    from . import vault_cli

    return vault_cli.cli_migrate(args)


def _handle_vault_set_memory_key(args: argparse.Namespace) -> int:
    from . import vault_memory_key

    return vault_memory_key.cli_set_memory_key(args)


def _handle_vault_enable_config_decrypt(args: argparse.Namespace) -> int:
    from . import config_decrypt_cli

    return config_decrypt_cli.cli_enable(args)


def _handle_vault_disable_config_decrypt(args: argparse.Namespace) -> int:
    from . import config_decrypt_cli

    return config_decrypt_cli.cli_disable(args)


def _handle_encryption_status(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_status(args)


def _handle_encryption_enable(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_enable(args)


def _handle_encryption_disable(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_disable(args)


def _handle_encryption_purge(args: argparse.Namespace) -> int:
    from . import encryption_cli

    return encryption_cli.cli_purge(args)


def _handle_plugins_list(args: argparse.Namespace) -> int:
    from . import plugins_list

    return plugins_list.cli_handler(args)


def _handle_plugins_migrate(args: argparse.Namespace) -> int:
    from . import plugins_list

    return plugins_list.migrate_cli_handler(args)


def _handle_extension_pair(args: argparse.Namespace) -> int:
    from . import extension_pair_cli

    return extension_pair_cli.cli_extension_pair(args)


def _handle_desktop(args: argparse.Namespace) -> int:
    from ..desktop import install

    return install.cli_desktop(args)


def _handle_uninstall(args: argparse.Namespace) -> int:
    from . import uninstall_cli

    return uninstall_cli.cli_uninstall(args)


def _handle_egress(args: argparse.Namespace) -> int:
    from . import egress_cli

    return egress_cli.cli_egress(args)


def _handle_telegram(args: argparse.Namespace) -> int:
    from . import telegram_cli

    return telegram_cli.cli_telegram(args)


def _handle_extension_serve(args: argparse.Namespace) -> int:
    # The extension package and launcher are dependency-light. ``serve`` owns
    # the optional aiohttp check so unrelated import bugs are never relabelled
    # as a missing ``extension`` extra here.
    from mordred_hermes.extension.__main__ import serve

    return serve(host=args.host, port=args.port)


def _handle_keyvault_enable_winkey(args: argparse.Namespace) -> int:
    from . import keyvault_native_cli

    return keyvault_native_cli.cli_enable_winkey(args)
