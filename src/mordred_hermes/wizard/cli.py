"""Console-script entry points for ``hermes mordred ...`` / ``hermes-mordred ...``.

The argparse subcommand tree and its per-command handlers live in
:mod:`._cli_parsers` (extracted to keep this module small). This module holds
the two entry points — :func:`main` (the ``hermes-mordred`` console script,
wired in ``pyproject.toml`` ``[project.scripts]``) and :func:`dispatch` (the
handler-invocation helper Hermes / tests call) — and re-exports
``_setup_subparser`` plus the ``_handle_*`` handlers so existing import paths
are unchanged (``wizard/__init__.py`` registers ``cli._setup_subparser`` with
Hermes; tests import ``cli._setup_subparser`` / ``cli.dispatch`` / ``cli.main``
and reference ``cli._handle_*`` directly).

Subcommand tree (SPEC.md §Plugin: ``mordred_wizard``, now the ``mordred`` plugin's wizard component):

- ``setup``                                      — one-command orchestrator: runs every step below in
  order, resuming where it left off (never destroys state; never auto-resets the keyvault)
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
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from . import _term

# The subcommand tree + handlers live in ``_cli_parsers``; re-export them so
# ``cli._setup_subparser`` (Hermes registration in ``wizard/__init__.py``) and
# ``cli._handle_*`` (tests) keep resolving here. See ``__all__``.
from ._cli_parsers import (
    _add_audit,
    _add_configure,
    _add_desktop,
    _add_egress,
    _add_encryption,
    _add_extension,
    _add_install,
    _add_keyvault,
    _add_network,
    _add_plugins,
    _add_policy,
    _add_setup,
    _add_status,
    _add_telegram,
    _add_uninstall,
    _add_upgrade,
    _add_vault,
    _handle_audit_decrypt,
    _handle_audit_grep,
    _handle_audit_purge,
    _handle_audit_tail,
    _handle_configure,
    _handle_desktop,
    _handle_egress,
    _handle_encryption_disable,
    _handle_encryption_enable,
    _handle_encryption_purge,
    _handle_encryption_status,
    _handle_extension_pair,
    _handle_extension_serve,
    _handle_install,
    _handle_keyvault_enable_se,
    _handle_keyvault_enable_tpm,
    _handle_keyvault_export,
    _handle_keyvault_init,
    _handle_keyvault_list,
    _handle_keyvault_recover,
    _handle_keyvault_reset,
    _handle_keyvault_verify_digest,
    _handle_network_init,
    _handle_network_status,
    _handle_network_use,
    _handle_plugins_list,
    _handle_plugins_migrate,
    _handle_policy_dry_run,
    _handle_policy_explain,
    _handle_policy_reload,
    _handle_policy_show,
    _handle_setup,
    _handle_status,
    _handle_telegram,
    _handle_uninstall,
    _handle_upgrade,
    _handle_vault_add,
    _handle_vault_cat,
    _handle_vault_change_passphrase,
    _handle_vault_disable_config_decrypt,
    _handle_vault_enable_config_decrypt,
    _handle_vault_init,
    _handle_vault_migrate,
    _handle_vault_recover,
    _handle_vault_set_memory_key,
    _handle_vault_status,
    _setup_subparser,
)
from ._defaults import is_missing_keyvault_stack
from ._prompt_io import NonInteractiveAbort

__all__ = [
    "_add_audit",
    "_add_configure",
    "_add_desktop",
    "_add_egress",
    "_add_encryption",
    "_add_extension",
    "_add_install",
    "_add_keyvault",
    "_add_network",
    "_add_plugins",
    "_add_policy",
    "_add_setup",
    "_add_status",
    "_add_telegram",
    "_add_uninstall",
    "_add_upgrade",
    "_add_vault",
    "_handle_audit_decrypt",
    "_handle_audit_grep",
    "_handle_audit_purge",
    "_handle_audit_tail",
    "_handle_configure",
    "_handle_desktop",
    "_handle_egress",
    "_handle_encryption_disable",
    "_handle_encryption_enable",
    "_handle_encryption_purge",
    "_handle_encryption_status",
    "_handle_extension_pair",
    "_handle_extension_serve",
    "_handle_install",
    "_handle_keyvault_enable_se",
    "_handle_keyvault_enable_tpm",
    "_handle_keyvault_export",
    "_handle_keyvault_init",
    "_handle_keyvault_list",
    "_handle_keyvault_recover",
    "_handle_keyvault_reset",
    "_handle_keyvault_verify_digest",
    "_handle_network_init",
    "_handle_network_status",
    "_handle_network_use",
    "_handle_plugins_list",
    "_handle_plugins_migrate",
    "_handle_policy_dry_run",
    "_handle_policy_explain",
    "_handle_policy_reload",
    "_handle_policy_show",
    "_handle_setup",
    "_handle_status",
    "_handle_telegram",
    "_handle_uninstall",
    "_handle_upgrade",
    "_handle_vault_add",
    "_handle_vault_cat",
    "_handle_vault_change_passphrase",
    "_handle_vault_disable_config_decrypt",
    "_handle_vault_enable_config_decrypt",
    "_handle_vault_init",
    "_handle_vault_migrate",
    "_handle_vault_recover",
    "_handle_vault_set_memory_key",
    "_handle_vault_status",
    "_setup_subparser",
    "dispatch",
    "main",
]


def dispatch(args: argparse.Namespace) -> int:
    """Top-level dispatch helper.

    Hermes calls the handler set via ``set_defaults(func=...)`` directly,
    so this helper is mainly for tests that build a Namespace by hand.
    Returns the handler's exit code (0 = success).

    A ``KeyboardInterrupt`` from any handler — the prompt layer re-raises it
    on Ctrl-C by design (see ``_prompt_io``) — becomes a clean ``Aborted.``
    on stderr with exit code 130 (128 + SIGINT), not a traceback. An
    ``EOFError`` (Ctrl-D at a prompt_toolkit prompt) is treated the same way.
    Likewise :class:`NonInteractiveAbort` becomes an ``error:`` line with exit
    code 2 (the usage-error convention shared with ``encryption purge`` /
    ``audit``).

    This guard protects the standalone ``hermes-mordred`` entry because
    :func:`main` routes through here. A host that exposes the registered plugin
    command tree and invokes ``args.func(args)`` directly must provide the same
    guard at its registration boundary or route through :func:`dispatch`.
    """
    func = getattr(args, "func", None)
    if func is None:
        raise SystemExit("usage: hermes-mordred <COMMAND> ... (no subcommand provided)")
    try:
        result: Any = func(args)
    except KeyboardInterrupt:
        # The leading newline moves past the ``^C`` the terminal echoes onto
        # the prompt line, so ``Aborted.`` starts on its own line.
        print("\nAborted.", file=sys.stderr)
        return 130
    except EOFError:
        # Ctrl-D at a prompt: the operator declined to answer, same as Ctrl-C.
        print("\nAborted.", file=sys.stderr)
        return 130
    except NonInteractiveAbort as exc:
        _term.emit_error(str(exc))
        return 2
    except ModuleNotFoundError as exc:
        # Only the known optional crypto stack is translated; any other
        # missing module is a real bug and must keep its traceback.
        if not is_missing_keyvault_stack(exc):
            raise
        _term.emit_error(
            f"this command needs the keyvault crypto stack (missing: {(exc.name or '').partition('.')[0]}) — "
            "install with: pip install 'hermes-mordred[keyvault]' "
            "(on macOS use '[macos]' to also enable Secure Enclave support)"
        )
        return 1
    return int(result) if isinstance(result, int) else 0


def main(argv: list[str] | None = None) -> int:
    """Standalone ``hermes-mordred`` console-script entry.

    This is the dependable bootstrap and recovery CLI. Hermes 0.19 exposes the
    registered ``hermes mordred`` tree only after the ``mordred`` plugin is
    enabled; ``hermes-mordred`` invokes the same handlers directly before or
    after plugin configuration and remains compatible with the supported
    Hermes version floor.

    Wired in ``pyproject.toml`` ``[project.scripts]`` as
    ``hermes-mordred = "mordred_hermes.wizard.cli:main"``.
    """
    from ..__about__ import __version__

    parser = argparse.ArgumentParser(
        prog="hermes-mordred",
        description="Mordred privacy layer (standalone CLI).",
        epilog=(
            "Quickstart (first run):\n"
            "  hermes-mordred setup    first checks that upstream Hermes itself is set up (offering\n"
            "                          `hermes setup` if not), then runs every step below in order --\n"
            "                          it is safe to re-run: it resumes from wherever it left off and\n"
            "                          never destroys existing state (never auto-resets the keyvault)\n"
            "\n"
            "The individual steps `setup` drives, useful on their own for troubleshooting or\n"
            "redoing a single one:\n"
            "  hermes-mordred configure              interactive setup (policy / LLM / harness)\n"
            "  hermes-mordred network init           optional: Tor / VPN / clearnet privacy path\n"
            "  hermes-mordred keyvault enable-se      (macOS) / enable-tpm (Linux): hardware helper\n"
            "  hermes-mordred keyvault init          create the hardware-backed keyvault\n"
            "  hermes-mordred encryption enable env  turn on at-rest encryption (first run creates the vault)\n"
            "  hermes-mordred status                 check the result at a glance\n"
            "\n"
            "Wallet / advanced Keyvault recovery material:\n"
            "  hermes-mordred keyvault init\n"
            "  hermes-mordred keyvault export --output /secure/path/keyvault-backup.mrkv\n"
            "\n"
            "Storage command families:\n"
            "  encryption  recommended facade over the Vault for env / config / memory / workspace\n"
            "  vault       underlying encrypted file store (advanced; separate recovery passphrase)\n"
            "  keyvault    separate wallet / API envelope store (portable backup recovery)\n"
            "\n"
            "Remove Mordred (restores plaintext .env / config.yaml / memories first):\n"
            "  hermes-mordred uninstall --dry-run    show the plan\n"
            "  hermes-mordred uninstall              run it (data is kept unless --purge-data)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured output (equivalent to setting NO_COLOR=1)",
    )
    # Standalone: a bare `hermes-mordred` is a discovery moment, so the subcommand
    # is optional here and we print the quickstart help below. Hermes keeps it
    # required via the default.
    _setup_subparser(parser, required=False)
    ns = parser.parse_args(argv)
    if getattr(ns, "no_color", False):
        # Flip the env var the shared `_term.should_color()` gate already honours,
        # so the flag reaches every command's renderer without threading a param.
        os.environ["NO_COLOR"] = "1"
    if getattr(ns, "mordred_command", None) is None:
        parser.print_help()
        return 0
    return dispatch(ns)
