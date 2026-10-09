// Mordred setup for Hermes Desktop.
//
// Secrets typed here (Telegram api_hash, login code, 2FA password, a Venice
// key) go from these masked inputs straight to Mordred's local API through
// ctx.rest(): never into the chat, the model, the agent's tools, plugin
// storage, notifications or logs. Inputs are cleared after each submit.
import {
  host,
  Button,
  Checkbox,
  Input,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  PALETTE_AREA,
} from '@hermes/plugin-sdk'
import { jsx, jsxs, Fragment } from 'react/jsx-runtime'
import { useCallback, useEffect, useState } from 'react'

let rest = null
// The SDK checkbox's default border is a pale theme colour that disappears on
// a white card; draw it in the text colour (CanvasText follows light/dark).
const CHECKBOX_STYLE = { borderColor: 'CanvasText', borderWidth: 1.5, borderStyle: 'solid' }
// Pages listening for background-job events (Enclave build, import).
const jobListeners = new Set()

const MESSAGES = {
  telegram_platform_unsupported: 'Private Telegram requires macOS Secure Enclave or Linux TPM 2.0, with memory encryption enabled. Update both Mordred and its Desktop assets if platform metadata is missing.',
  memory_encryption_required: 'Turn on memory encryption first (step 2).',
  memory_encryption_failed: 'Memory encryption could not be turned on. Check hardware access and the Hermes runtime, then try again.',
  telegram_already_logged_in: 'Telegram is already connected.',
  invalid_api_credentials: 'api_id must be a number and api_hash 32 hex characters (my.telegram.org → API development tools).',
  invalid_phone: 'Enter the phone number in international format, e.g. +819012345678.',
  login_code_invalid: 'That login code is not correct.',
  login_code_expired: 'The login code expired. Start again.',
  uninstall_confirm_mismatch: 'Type delete my data exactly to also delete your data.',
  uninstall_failed: 'Uninstall stopped before removing anything it could not restore. See the report below.',
  login_password_invalid: 'That Telegram two-step verification password is not correct.',
  login_flow_expired: 'This login attempt expired. Start again.',
  telegram_rate_limited: 'Telegram asked to wait before trying again.',
  hermes_venice_key_missing: 'No Venice key is set in Hermes. Enter one below.',
  local_endpoint_invalid: 'Use http://127.0.0.1:<port>/… (this host only).',
  tee_unavailable: 'The hardware key helper is unavailable (step 1).',
  tee_auth_cancelled: 'Touch ID was cancelled.',
  tpm_build_failed: 'Building or probing the TPM helper failed. Install Rust, pkg-config and libtss2-dev; ensure this user can access /dev/tpmrm0.',
  enclave_build_failed: 'Building the Secure Enclave helper failed. Install the Xcode command-line tools and retry.',
  sync_in_progress: 'An import is already running.',
  telegram_not_configured: 'Set the question model first (step 3).',
  hermes_model_not_private: 'Hermes itself must use a Venice private model or a local model first (step 0).',
}

function explain(code) {
  return MESSAGES[code] || `Failed (${code || 'unknown'})`
}

async function call(path, body) {
  try {
    const res = await rest(path, body === undefined ? {} : { method: 'POST', body })
    if (res && res.ok === false) throw new Error(res.error)
    return res
  } catch (err) {
    const code = (err && (err.body && err.body.error)) || (err && err.message) || 'unknown'
    throw new Error(explain(String(code).replace(/^.*"error":"([^"]+)".*$/, '$1')))
  }
}

function Step({ n, title, done, children }) {
  return jsxs('section', {
    style: { border: '1px solid var(--border, #333)', borderRadius: 10, padding: 16, marginBottom: 12 },
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: `${done ? '✓' : n}  ${title}` }),
      done ? null : children,
    ],
  })
}

function Row({ children }) {
  return jsx('div', { style: { display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }, children })
}

function HermesModelStep({ check, refresh }) {
  const ok = Boolean(check && check.ok)
  const verifying = check && check.kind === 'venice' && check.private === null
  return jsxs('section', {
    style: { border: '1px solid var(--border, #333)', borderRadius: 10, padding: 16, marginBottom: 12 },
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: `${ok ? '✓' : '0'}  Hermes chat model` }),
      ok
        ? jsx('p', { children: `${check.model} (${check.kind === 'local' ? 'local, this host only' : 'Venice private, no retention'})` })
        : jsxs(Fragment, {
            children: [
              jsx('p', {
                children: verifying
                  ? `Could not verify ${check.model} with Venice right now (offline?).`
                  : `Everything Hermes reads goes to its chat model${check && check.model ? ` (now: ${check.model})` : ''}. For Telegram it must be a Venice private model or a model on this host.`,
              }),
              verifying
                ? null
                : jsx('ol', {
                    children: [
                      jsx('li', { key: 1, children: 'Open Settings → Providers → “Local / custom endpoint”.' }),
                      jsx('li', { key: 2, children: 'Venice: base URL https://api.venice.ai/api/v1, your Venice API key, and a private model such as e2ee-deepseek-v4-flash or deepseek-v4-flash.' }),
                      jsx('li', { key: 3, children: 'Or a local server (Ollama / LM Studio) at http://127.0.0.1:<port>/v1.' }),
                      jsx('li', { key: 4, children: 'Select that model for chats, then press Check again.' }),
                    ],
                  }),
              jsx(Button, { onClick: refresh, children: 'Check again' }),
            ],
          }),
    ],
  })
}

function EnclaveStep({ done, refresh, hardwareKind }) {
  const linux = hardwareKind === "tpm"
  const label = linux ? "TPM 2.0" : "Secure Enclave"
  const [busy, setBusy] = useState(false)
  const build = async () => {
    setBusy(true)
    try {
      await call('/hardware/build', {})
      host.notify({ kind: 'info', message: `Building the ${label} helper… this takes a few minutes.` })
      refresh()
    } catch (e) {
      host.notifyError(e, 'Build failed')
      setBusy(false)
    }
  }
  useEffect(() => {
    if (done) setBusy(false)
  }, [done])
  useEffect(() => {
    // A failed build ends the job without `done`; let the user retry.
    const reset = () => setBusy(false)
    jobListeners.add(reset)
    return () => jobListeners.delete(reset)
  }, [])
  return jsx(Step, {
    n: 1,
    title: label,
    done,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: linux ? 'Telegram keys are bound to this TPM. There is no per-use user-presence prompt or portable recovery. Losing TPM state loses access.' : 'Your Telegram keys are sealed by a key that never leaves this device’s Secure Enclave.' }),
        jsx(Button, { disabled: busy, onClick: build, children: busy ? 'Building…' : `Set up ${label}` }),
      ],
    }),
  })
}

function MemoryStep({ done, refresh, hardwareKind }) {
  const [busy, setBusy] = useState(false)
  const [phrase, setPhrase] = useState(null)
  const [saved, setSaved] = useState(false)
  const enable = async () => {
    setBusy(true)
    try {
      const r = await call('/memory/enable', { acknowledge_tpm_no_recovery: hardwareKind === 'tpm' })
      if (r.recovery_passphrase) setPhrase(r.recovery_passphrase)
      else refresh()
    } catch (e) {
      host.notifyError(e, 'Memory encryption failed')
    } finally {
      setBusy(false)
    }
  }
  if (phrase) {
    return jsx(Step, {
      n: 2,
      title: 'Save your recovery passphrase',
      done: false,
      children: jsxs(Fragment, {
        children: [
          jsx('p', { children: 'Write this down and keep it safe. It is shown only once and is the only way to recover your encrypted data if this Mac is lost.' }),
          jsx('pre', { style: { fontSize: 18, padding: 12, userSelect: 'all', whiteSpace: 'pre-wrap' }, children: phrase }),
          jsxs('label', {
            style: { display: 'flex', gap: 8, alignItems: 'center' },
            children: [jsx(Checkbox, { checked: saved, onCheckedChange: (v) => setSaved(v === true), style: CHECKBOX_STYLE }), 'I have written it down'],
          }),
          jsx(Row, {
            children: jsx(Button, {
              disabled: !saved,
              onClick: () => {
                setPhrase(null)
                host.notify({ kind: 'success', message: 'Memory encryption is on. Restart Hermes to finish.' })
                refresh()
              },
              children: 'Continue',
            }),
          }),
        ],
      }),
    })
  }
  return jsx(Step, {
    n: 2,
    title: 'Encrypt Hermes memory',
    done,
    children: jsxs(Fragment, {
      children: [
        jsx('p', { children: hardwareKind === 'tpm' ? 'Memory is encrypted with a TPM-bound key, without per-use user presence or a recovery passphrase. Disable encryption before moving hosts to restore plaintext while the original TPM works. Restart Hermes after setup.' : 'Telegram requires everything Hermes remembers to be encrypted. Hardware approval may be requested.' }),
        jsx(Button, { disabled: busy, onClick: enable, children: busy ? 'Encrypting…' : 'Turn on memory encryption' }),
      ],
    }),
  })
}

function TelegramStep({ done, needsApi, refresh }) {
  const [apiId, setApiId] = useState('')
  const [apiHash, setApiHash] = useState('')
  const [phone, setPhone] = useState('')
  const [secret, setSecret] = useState('')
  const [flow, setFlow] = useState(null)
  const [step, setStep] = useState('phone')
  const [busy, setBusy] = useState(false)
  const reset = () => {
    setFlow(null)
    setStep('phone')
    setSecret('')
  }
  const submit = async () => {
    setBusy(true)
    try {
      if (step === 'phone') {
        const body = { phone }
        if (needsApi) Object.assign(body, { api_id: apiId, api_hash: apiHash })
        const r = await call('/telegram/login/start', body)
        setApiHash('')
        setFlow(r.flow_id)
        setStep(r.step)
      } else {
        const path = `/telegram/login/${flow}/${step === 'code' ? 'code' : 'password'}`
        const r = await call(path, step === 'code' ? { code: secret } : { password: secret })
        setSecret('')
        if (r.step === 'done') {
          host.notify({ kind: 'success', message: 'Telegram connected (read-only).' })
          reset()
          refresh()
        } else setStep(r.step)
      }
    } catch (e) {
      setSecret('')
      host.notifyError(e, 'Telegram login failed')
      if (/expired/.test(String(e && e.message))) reset()
    } finally {
      setBusy(false)
    }
  }
  const field = (props) => jsx(Input, { autoComplete: 'off', ...props })
  return jsx(Step, {
    n: 4,
    title: 'Connect Telegram (read-only)',
    done,
    children: jsxs(Fragment, {
      children: [
        step === 'phone' && needsApi
          ? jsxs(Fragment, {
              children: [
                jsxs('p', {
                  children: [
                    'Create an app at ',
                    jsx('code', { style: { userSelect: 'all' }, children: 'https://my.telegram.org/apps' }),
                    ' (API development tools) and paste its api_id and api_hash.',
                  ],
                }),
                jsx(Row, { children: field({ placeholder: 'api_id', value: apiId, onChange: (e) => setApiId(e.target.value) }) }),
                jsx(Row, { children: field({ type: 'password', placeholder: 'api_hash', value: apiHash, onChange: (e) => setApiHash(e.target.value) }) }),
              ],
            })
          : null,
        step === 'phone'
          ? jsx(Row, { children: field({ placeholder: 'Phone number, e.g. +819012345678', value: phone, onChange: (e) => setPhone(e.target.value) }) })
          : jsxs(Fragment, {
              children: [
                jsx('p', {
                  children:
                    step === 'code'
                      ? 'Enter the login code Telegram just sent to your Telegram app.'
                      : 'Enter your Telegram two-step verification password (the "Cloud Password" you set in Telegram → Settings → Privacy and Security). This is not your computer password or a Mordred passphrase. It is not stored.',
                }),
                jsx(Row, { children: field({ type: 'password', placeholder: step === 'code' ? 'Telegram login code' : 'Telegram password', value: secret, onChange: (e) => setSecret(e.target.value) }) }),
              ],
            }),
        jsxs(Row, {
          children: [
            jsx(Button, { disabled: busy, onClick: submit, children: busy ? 'Working…' : step === 'phone' ? 'Send login code' : 'Continue' }),
            flow ? jsx(Button, { variant: 'ghost', onClick: () => { call(`/telegram/login/${flow}/cancel`, {}).catch(() => {}); reset() }, children: 'Cancel' }) : null,
          ],
        }),
      ],
    }),
  })
}

function LlmStep({ done, hermesKey, refresh }) {
  const [key, setKey] = useState('')
  const [endpoint, setEndpoint] = useState('http://127.0.0.1:11434/v1')
  const [model, setModel] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (path, body) => {
    setBusy(true)
    try {
      await call(path, body)
      setKey('')
      host.notify({ kind: 'success', message: 'Question model set.' })
      refresh()
    } catch (e) {
      host.notifyError(e, 'Could not set the model')
    } finally {
      setBusy(false)
    }
  }
  return jsx(Step, {
    n: 3,
    title: 'Question model (Venice private or local)',
    done,
    children: jsxs(Fragment, {
      children: [
        hermesKey
          ? jsx(Row, { children: jsx(Button, { disabled: busy, onClick: () => run('/llm/venice', { use_hermes_key: true }), children: 'Use the Venice key Hermes already has' }) })
          : null,
        jsx(Row, {
          children: [
            jsx(Input, { key: 'k', type: 'password', autoComplete: 'off', placeholder: 'Or paste a Venice API key', value: key, onChange: (e) => setKey(e.target.value) }),
            jsx(Button, { key: 'b', disabled: busy || !key, onClick: () => run('/llm/venice', { api_key: key }), children: 'Use this key' }),
          ],
        }),
        jsx(Row, {
          children: [
            jsx(Input, { key: 'e', placeholder: 'Local endpoint', value: endpoint, onChange: (e) => setEndpoint(e.target.value) }),
            jsx(Input, { key: 'm', placeholder: 'Local model name', value: model, onChange: (e) => setModel(e.target.value) }),
            jsx(Button, { key: 'l', disabled: busy || !model, onClick: () => run('/llm/local', { endpoint, model }), children: 'Use local model' }),
          ],
        }),
      ],
    }),
  })
}

function ImportStep({ ready, refresh }) {
  const [days, setDays] = useState(3)
  const [sync, setSync] = useState(null)
  const poll = useCallback(async () => {
    try {
      setSync(await call('/sync'))
    } catch (_) {
      /* ignore */
    }
  }, [])
  useEffect(() => {
    if (!ready) return undefined
    poll()
    const t = setInterval(poll, 3000)
    return () => clearInterval(t)
  }, [ready, poll])
  const start = async () => {
    try {
      await call('/sync', { days: Number(days) || 3, include_archived: false })
      host.notify({ kind: 'info', message: 'Import started. Approve a hardware prompt if asked.' })
      poll()
    } catch (e) {
      host.notifyError(e, 'Import failed')
    }
  }
  const progress = sync && sync.progress
  return jsx(Step, {
    n: 5,
    title: 'Import messages',
    done: false,
    children: ready
      ? jsxs(Fragment, {
          children: [
            jsx('p', { children: 'Pinned chats first. Large groups and archived chats are skipped. Nothing is downloaded twice.' }),
            jsxs(Row, {
              children: [
                'Last',
                jsx(Input, { style: { width: 70 }, type: 'number', min: 1, value: days, onChange: (e) => setDays(e.target.value) }),
                'days',
                jsx(Button, { disabled: sync && sync.syncing, onClick: start, children: sync && sync.syncing ? 'Importing…' : 'Import' }),
              ],
            }),
            sync
              ? jsx('p', {
                  children: sync.syncing && progress
                    ? `Chats ${progress.dialogs_done}/${progress.dialogs_total}, ${progress.messages_imported} new messages`
                    : sync.last_error
                      ? explain(sync.last_error)
                      : 'Ready. Ask Hermes about your Telegram messages in any chat.',
                })
              : null,
          ],
        })
      : jsx('p', { children: 'Finish the steps above first.' }),
  })
}

const PURGE_PHRASE = 'delete my data'

function UninstallSection() {
  const [open, setOpen] = useState(false)
  const [plan, setPlan] = useState(null)
  // decrypt: back to normal files (data kept unless `purge`); erase: delete encrypted data without decrypting.
  const [mode, setMode] = useState('decrypt')
  const [purge, setPurge] = useState(false)
  const [phrase, setPhrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState(null)
  const deleting = mode === 'erase' || purge
  const show = async () => {
    setOpen(true)
    try {
      setPlan(await call('/uninstall/plan'))
    } catch (e) {
      host.notifyError(e, 'Could not read the uninstall plan')
    }
  }
  const reset = () => {
    setOpen(false)
    setMode('decrypt')
    setPurge(false)
    setPhrase('')
  }
  const run = async () => {
    setBusy(true)
    try {
      const body = { mode, purge_data: mode === 'decrypt' && purge }
      if (deleting) body.confirm = phrase
      const job = await call('/uninstall', body)
      // Poll the job: the report is on it, and the page may go away after Mordred is removed.
      for (;;) {
        await new Promise((r) => setTimeout(r, 2000))
        const j = await call(`/jobs/${job.job_id}`)
        if (j.state !== 'running') {
          setReport({ ok: j.state === 'done', text: (j.progress && j.progress.summary) || '' })
          break
        }
      }
    } catch (e) {
      host.notifyError(e, 'Uninstall failed')
    } finally {
      setBusy(false)
      setPhrase('')
    }
  }
  const box = { border: '1px solid #b91c1c', borderRadius: 10, padding: 16, margin: '32px 0 12px' }
  const pre = { whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 280, overflow: 'auto', background: 'rgba(127,127,127,0.08)', padding: 8, borderRadius: 6 }
  const radio = { accentColor: 'CanvasText', width: 16, height: 16, marginTop: 3, flexShrink: 0 }
  const choice = (value, title, detail) =>
    jsxs('label', {
      key: value,
      style: { display: 'flex', gap: 8, alignItems: 'flex-start', marginTop: 10, cursor: 'pointer' },
      children: [
        jsx('input', { type: 'radio', name: 'mordred-uninstall-mode', checked: mode === value, onChange: () => setMode(value), style: radio }),
        jsxs('span', { children: [jsx('strong', { children: title }), jsx('br', {}), detail] }),
      ],
    })
  if (report) {
    return jsxs('section', {
      style: box,
      children: [
        jsx('h3', { style: { margin: '0 0 8px' }, children: report.ok ? 'Mordred was uninstalled' : 'Uninstall stopped' }),
        jsx('p', { children: report.ok ? 'Quit Hermes Desktop (⌘Q) and open it again to finish.' : 'Nothing that could not be restored was removed.' }),
        jsx('pre', { style: pre, children: report.text }),
      ],
    })
  }
  const shownPlan = plan && (mode === 'erase' ? plan.plan_erase : purge ? plan.plan_purge : plan.plan)
  return jsxs('section', {
    style: box,
    children: [
      jsx('h3', { style: { margin: '0 0 8px' }, children: 'Uninstall Mordred' }),
      jsx('p', { children: 'Removes Mordred from Hermes and restores Hermes to how it was before. Choose what happens to your encrypted data.' }),
      open
        ? jsxs(Fragment, {
            children: [
              choice('decrypt', 'Decrypt, then uninstall', 'Encrypted files (Hermes memory, .env, config) become normal files again, so Hermes keeps everything. Hardware approval may be requested.'),
              mode === 'decrypt'
                ? jsxs('label', {
                    style: { display: 'flex', gap: 8, alignItems: 'center', margin: '8px 0 0 24px' },
                    children: [
                      jsx(Checkbox, { checked: purge, onCheckedChange: (v) => setPurge(v === true), style: CHECKBOX_STYLE }),
                      'Also delete Mordred’s own data and keys (Telegram archive and login, vault, keyvault).',
                    ],
                  })
                : null,
              choice('erase', 'Erase encrypted data without decrypting, then uninstall', 'Nothing is decrypted. Encrypted Hermes memory, the vault copies of .env / config and all Mordred data and keys are deleted. Anything that exists only in encrypted form is lost for good.'),
              shownPlan ? jsx('pre', { style: { ...pre, marginTop: 12 }, children: shownPlan }) : jsx('p', { children: 'Loading…' }),
              deleting
                ? jsxs(Fragment, {
                    children: [
                      jsx('p', { children: `This deletes data and cannot be undone. Type “${PURGE_PHRASE}” to confirm.` }),
                      jsx(Row, { children: jsx(Input, { value: phrase, autoComplete: 'off', placeholder: PURGE_PHRASE, onChange: (e) => setPhrase(e.target.value) }) }),
                    ],
                  })
                : null,
              jsx(Row, {
                children: [
                  jsx(Button, {
                    key: 'go',
                    variant: 'destructive',
                    disabled: busy || !plan || (deleting && phrase.trim() !== PURGE_PHRASE),
                    onClick: run,
                    children: busy
                      ? 'Uninstalling… (approve a hardware prompt if asked)'
                      : mode === 'erase'
                        ? 'Erase and uninstall'
                        : purge
                          ? 'Decrypt, uninstall and delete Mordred data'
                          : 'Decrypt and uninstall',
                  }),
                  jsx(Button, { key: 'cancel', variant: 'outline', disabled: busy, onClick: reset, children: 'Cancel' }),
                ],
              }),
            ],
          })
        : jsx(Row, { children: jsx(Button, { variant: 'outline', onClick: show, children: 'Uninstall Mordred…' }) }),
    ],
  })
}

function SetupPage() {
  const [status, setStatus] = useState(null)
  const refresh = useCallback(async () => {
    try {
      setStatus(await call('/status?client_version=2'))
    } catch (e) {
      host.notifyError(e, 'Mordred is not reachable. Restart Hermes after installing Mordred.')
    }
  }, [])
  useEffect(() => {
    refresh()
  }, [refresh])
  // Re-read the status when a background job ends, and poll while one runs in
  // case the event was missed (e.g. the page was reopened mid-job).
  useEffect(() => {
    jobListeners.add(refresh)
    return () => jobListeners.delete(refresh)
  }, [refresh])
  const running = Boolean(status && status.jobs && status.jobs.length)
  useEffect(() => {
    if (!running) return undefined
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [running, refresh])
  const c = (status && status.checks) || {}
  const ok = (name) => Boolean(c[name] && c[name].ok)
  const loggedIn = ok('login')
  const modelOk = Boolean(status && status.hermes_model && status.hermes_model.ok)
  return jsxs('div', {
    style: { maxWidth: 720, margin: '24px auto', padding: '0 16px' },
    children: [
      jsx('h2', { children: 'Mordred setup' }),
      jsx('p', { children: 'Private, read-only Telegram for Hermes.' }),
      status
        ? status.telegram_supported && ["secure_enclave", "tpm"].includes(status.hardware_kind)
          ? jsxs(Fragment, {
              children: [
                jsx('p', { children: 'Secrets entered here go only to Mordred on this host and are sealed by its hardware key.' }),
                jsx(HermesModelStep, { check: status.hermes_model, refresh }),
                modelOk
                  ? jsxs(Fragment, {
                      children: [
                        jsx(EnclaveStep, { done: c.hardware?.ok === true, refresh, hardwareKind: status.hardware_kind }),
                        jsx(MemoryStep, { done: ok('memory_encryption'), refresh, hardwareKind: status.hardware_kind }),
                        jsx(LlmStep, { done: ok('privacy_llm'), hermesKey: status.hermes_venice_key, refresh }),
                        ok('privacy_llm')
                          ? jsx(TelegramStep, { done: loggedIn, needsApi: !status.telegram_api, refresh })
                          : jsx(Step, { n: 4, title: 'Connect Telegram (read-only)', done: false, children: jsx('p', { children: 'Set the question model first (step 3).' }) }),
                        jsx(ImportStep, { ready: loggedIn && ok('privacy_llm') && ok('memory_encryption'), refresh }),
                      ],
                    })
                  : jsx('p', { children: 'The remaining steps unlock once Hermes uses a private or local model.' }),
              ],
            })
          : jsxs('section', {
              role: 'status',
              children: [
                jsx('h3', { children: 'Private Telegram setup unavailable' }),
                jsx('p', { children: MESSAGES.telegram_platform_unsupported }),
              ],
            })
        : jsx('p', { children: 'Loading…' }),
      jsx(UninstallSection, {}),
    ],
  })
}

export default {
  id: 'mordred',
  name: 'Mordred',
  register(ctx) {
    rest = ctx.rest
    ctx.register({ id: 'setup-route', area: ROUTES_AREA, data: { path: '/mordred' }, render: () => jsx(SetupPage, {}) })
    ctx.register({ id: 'setup-nav', area: SIDEBAR_NAV_AREA, data: { path: '/mordred', label: 'Mordred', codicon: 'shield' } })
    ctx.register({
      id: 'setup-palette',
      area: PALETTE_AREA,
      data: { id: 'mordred.setup', label: 'Mordred: Set up private Telegram', keywords: ['telegram', 'privacy', 'mordred'], run: () => host.navigate('/mordred') },
    })
    ctx.onEvent('plugin.mordred.job', (e) => {
      const p = e && e.payload
      if (!p) return
      if (p.state === 'done') host.notify({ kind: 'success', message: `Mordred: ${p.kind} finished.` })
      if (p.state === 'failed') host.notify({ kind: 'error', message: `Mordred: ${explain(p.error)}` })
      if (p.state === 'done' || p.state === 'failed') jobListeners.forEach((fn) => fn())
    })
  },
}
