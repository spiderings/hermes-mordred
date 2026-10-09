# hermes-mordred

[![PyPI](https://img.shields.io/pypi/v/hermes-mordred)](https://pypi.org/project/hermes-mordred/)
[![CI](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml/badge.svg)](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml)

Privacy-preserving plugins for the
[Hermes agent](https://github.com/NousResearch/hermes-agent): hardware-backed
keys, Tor/VPN routing, local-LLM policy enforcement, encrypted audit data,
end-to-end gateway messages, and macOS-integrated at-rest encryption.

Mordred is a cooperative control layer inside Hermes, not an operating-system
sandbox. See the
[specification](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/SPEC.md#threat-model--accepted-limitations)
for the security boundary and accepted limitations.

**Status: active alpha.** New users should start with the
**[Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md)**.

## The plugin

The package registers one Hermes plugin, `mordred` (a single
`hermes_agent.plugins` entry point), made of these components:

| Component | Purpose |
|---|---|
| `keyvault` | Secure Enclave / TPM-backed key management and at-rest secrets |
| `llm_guard` | Strict-mode local-LLM enforcement |
| `network` | Tor, VPN, and clearnet path management |
| `privacy_check` | Skill-metadata policy enforcement and audit logging |
| `e2e` | Encrypted Slack and Discord gateway commands and replies |
| `wizard` | The `hermes-mordred` CLI |

Hermes (and Hermes Desktop) lists it as one plugin, `mordred`; enabling or
disabling it turns every component on or off together. Releases up to
0.1.0a20 registered six plugins instead (`mordred_network`,
`mordred_privacy_check`, ...). `hermes-mordred plugins migrate` (also run by
`install.sh`, `configure`, and `upgrade`) replaces those names in
`plugins.enabled` / `plugins.disabled` with `mordred`. The `plugins.mordred_*`
settings sections in `config.yaml` keep their names.

## Requirements

- Python 3.11 or newer and `hermes-agent>=0.13.0`.
- macOS or Linux. Windows and mobile support are deferred.
- Transparent at-rest encryption of `.env`, configuration, memory, and the
  workspace is macOS-only. On Linux the TPM-backed keyvault works, but those
  encryption targets stay inactive.

## Install (users, from PyPI)

Start with an installed Hermes Agent, then run the Mordred installer:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
hermes-mordred setup
hermes-mordred status
```

`install.sh` only installs the package; `hermes-mordred setup` is what
configures Mordred and creates keys. It runs `configure`, which enables the
`mordred` plugin. Manual configuration is covered by the
[usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md#2-first-run-quickstart).
Version pins, optional features, inspect-before-running steps, platform
commands, and expected output are documented in the
[Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md).

### Use it

Use `hermes-mordred status` for the overall state. On macOS, guided setup also
offers agent-memory protection through `hermes-mordred encryption enable memory`.
The complete command reference and security ceremonies live in the
[usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md).

Once Hermes 0.19.0+ is configured and the plugins are enabled,
`hermes mordred <command>` exposes the same command tree. On older Hermes
versions, or before the first `configure`, keep using `hermes-mordred`.

### Verify discovery

```sh
hermes-mordred plugins list
```

It shows the `mordred` plugin and whether each component registered. Some
Hermes versions omit package entry points from `hermes plugins list`.

## Documentation

Detailed setup, operations, and troubleshooting are maintained in the dedicated
guides:

| Audience | Guide | Covers |
|---|---|---|
| Users | [Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md) | Install and first protected setup |
| Users | [Usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md) | Commands, ceremonies, troubleshooting, upgrades, removal |
| Users | [Extension guide (preview)](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md) | Optional browser extension, E2E messaging, wallet bridge |
| Users | [Telegram guide (preview)](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/TELEGRAM.md) | Ask Hermes about your own Telegram messages: read-only, Secure Enclave sealed, Venice/local only |
| Developers | [Development setup](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/setup.md) | Editable `.venv`, `HERMES_HOME` isolation, validation |
| Developers | [Development index](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/README.md) | Maintained sources of truth |

## License

MIT
