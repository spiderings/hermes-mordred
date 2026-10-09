---
name: mordred-status
description: "Read-only inspection of the Mordred privacy layer (status, policy, network path, plugins). Observe only — never mutate or read secrets."
version: 1.0.0
metadata:
  hermes:
    tags: [mordred, privacy, status, policy, network, keyvault, encryption]
    related_skills: []
  mordred:
    network_requirements: local-only
    requires_keyvault: false
---

# Mordred status (read-only)

Inspect the local Mordred privacy layer when the user asks things like
"what's my Mordred status?", "what policy is active?", "which network route
is selected?", or "which Mordred plugins are loaded?".

## CRITICAL — read-only boundary

Mordred's job is to **constrain and audit** this agent. You may **observe** its
state but you must **never change it or read its secrets** from a conversation.

**ALLOWED** (metadata only — no secrets):

| Intent | Command |
|--------|---------|
| Overall state | `MORDRED status` |
| Machine-readable state | `MORDRED status --json` |
| Active policy | `MORDRED policy show` |
| Explain a skill's install decision | `MORDRED policy explain <skill-id>` |
| Network path + liveness | `MORDRED network status` |
| Discovered Mordred plugins | `MORDRED plugins list` |

where `MORDRED` is resolved by trying, in order (the CLI's real location is
environment-specific — never hardcode one developer's machine path):

1. `command -v hermes-mordred` — use it if it resolves on `PATH`.
2. Otherwise try the Hermes-managed venv, the documented install target per
   this repo's `README.md` ("Install (users, from PyPI)" section):
   `~/.hermes/hermes-agent/venv/bin/hermes-mordred`.
3. Otherwise **ask the operator** for the path to their `hermes-mordred` venv
   (e.g. "I can't find `hermes-mordred` on PATH or at the default Hermes venv
   location — what path did you install it to?"). Only conclude "not
   installed" (see below) once the operator confirms there is no such install.

Run these via the code-execution / shell tool and report the output.

**FORBIDDEN** — never run from this skill. If the user wants any of these, print
the exact command and tell them to run it themselves in their shell:

- Any mutation: `configure`, `upgrade`, `keyvault init|recover|reset|enable-se|enable-tpm`,
  `encryption enable|disable|purge`, `network init|use`, `vault *`, `install`.
- Any secret read-out: `audit decrypt`, `vault cat`.
- Even read-only `audit tail|grep` — it can surface install decisions into the
  transcript. Do not run it; hand the command to the user instead.

## Why

These rules preserve the domain separation in `docs/dev/SPEC.md` §Threat Model
& Accepted Limitations: a recording agent may observe Mordred's state, but
secrets (recovery passphrase, `.env` contents, decrypted audit) and control
actions stay in the operator's shell, outside the transcript.

> **Residual risk**: the FORBIDDEN list above is a prompt-level instruction,
> not an enforcement mechanism — it does not technically prevent this agent
> from running a mutating command. Hard enforcement of what the agent may
> execute belongs to the Hermes exec-tool approval settings, not to this
> skill (see `README.md` § "Conversational read-only access").

## If the CLI is missing

If none of the three resolution steps above find `hermes-mordred` —
including after asking the operator — tell the user no Mordred install was
found and stop. Do not try to install or build anything.
