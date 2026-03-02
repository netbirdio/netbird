import { useState, useEffect } from 'react'
import { Call } from '@wailsio/runtime'
import type { ConfigInfo } from '../bindings'

async function getConfig(): Promise<ConfigInfo | null> {
  try {
    console.log('[Settings] calling services.SettingsService.GetConfig')
    const result = await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.SettingsService.GetConfig')
    console.log('[Settings] GetConfig result:', JSON.stringify(result))
    return result as ConfigInfo
  } catch (e) {
    console.error('[Settings] GetConfig error:', e)
    return null
  }
}

async function setConfig(cfg: ConfigInfo): Promise<void> {
  console.log('[Settings] calling services.SettingsService.SetConfig')
  await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.SettingsService.SetConfig', cfg)
}

type Tab = 'connection' | 'network' | 'security'

export default function Settings() {
  const [config, setConfigState] = useState<ConfigInfo | null>(null)
  const [tab, setTab] = useState<Tab>('connection')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getConfig().then(c => { if (c) setConfigState(c) })
  }, [])

  function update<K extends keyof ConfigInfo>(key: K, value: ConfigInfo[K]) {
    setConfigState(prev => prev ? { ...prev, [key]: value } : prev)
  }

  async function handleSave() {
    if (!config) return
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      await setConfig(config)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  if (!config) {
    return <div className="text-nb-gray-400">Loading settings…</div>
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Settings</h1>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-nb-gray-920 p-1 rounded-lg border border-nb-gray-900">
        {(['connection', 'network', 'security'] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`flex-1 py-2 rounded text-sm font-medium capitalize transition-colors ${
              tab === t ? 'bg-netbird text-white' : 'text-nb-gray-400 hover:text-white'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="bg-nb-gray-920 rounded-xl p-6 border border-nb-gray-900 space-y-5">

        {tab === 'connection' && (
          <>
            <Field label="Management URL">
              <input
                className="input"
                value={config.managementUrl}
                onChange={e => update('managementUrl', e.target.value)}
                placeholder="https://api.netbird.io:443"
              />
            </Field>
            <Field label="Admin URL">
              <input
                className="input"
                value={config.adminUrl}
                onChange={e => update('adminUrl', e.target.value)}
              />
            </Field>
            <Field label="Pre-shared Key">
              <input
                className="input"
                type="password"
                value={config.preSharedKey}
                onChange={e => update('preSharedKey', e.target.value)}
                placeholder="Leave empty to clear"
              />
            </Field>
            <Toggle
              label="Connect automatically when service starts"
              checked={!config.disableAutoConnect}
              onChange={v => update('disableAutoConnect', !v)}
            />
            <Toggle
              label="Enable notifications"
              checked={!config.disableNotifications}
              onChange={v => update('disableNotifications', !v)}
            />
          </>
        )}

        {tab === 'network' && (
          <>
            <Field label="Interface Name">
              <input
                className="input"
                value={config.interfaceName}
                onChange={e => update('interfaceName', e.target.value)}
                placeholder="netbird0"
              />
            </Field>
            <Field label="WireGuard Port">
              <input
                className="input"
                type="number"
                min={1}
                max={65535}
                value={config.wireguardPort}
                onChange={e => update('wireguardPort', parseInt(e.target.value) || 0)}
                placeholder="51820"
              />
            </Field>
            <Toggle
              label="Enable lazy connections (experimental)"
              checked={config.lazyConnectionEnabled}
              onChange={v => update('lazyConnectionEnabled', v)}
            />
            <Toggle
              label="Block inbound connections"
              checked={config.blockInbound}
              onChange={v => update('blockInbound', v)}
            />
          </>
        )}

        {tab === 'security' && (
          <>
            <Toggle
              label="Allow SSH connections"
              checked={config.serverSshAllowed}
              onChange={v => update('serverSshAllowed', v)}
            />
            <Toggle
              label="Enable post-quantum security via Rosenpass"
              checked={config.rosenpassEnabled}
              onChange={v => update('rosenpassEnabled', v)}
            />
            <Toggle
              label="Rosenpass permissive mode"
              checked={config.rosenpassPermissive}
              onChange={v => update('rosenpassPermissive', v)}
            />
          </>
        )}
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-6 py-2.5 bg-netbird hover:bg-netbird-500 disabled:opacity-50 rounded-lg font-medium transition-colors"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
        {saved && <span className="text-green-400 text-sm">Saved!</span>}
        {error && <span className="text-red-400 text-sm">{error}</span>}
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-sm text-nb-gray-400 mb-1.5">{label}</label>
      {children}
    </div>
  )
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer">
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className="toggle-track"
      >
        <span className="toggle-thumb" />
      </button>
      <span className="text-sm">{label}</span>
    </label>
  )
}
