import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import type { ConfigInfo } from '../bindings'
import Card from '../components/ui/Card'
import CardRow from '../components/ui/CardRow'
import Toggle from '../components/ui/Toggle'
import Input from '../components/ui/Input'
import Button from '../components/ui/Button'
import SegmentedControl from '../components/ui/SegmentedControl'

async function getConfig(): Promise<ConfigInfo | null> {
  try {
    return await invoke<ConfigInfo>('get_config')
  } catch (e) {
    console.error('[Settings] GetConfig error:', e)
    return null
  }
}

async function setConfig(cfg: ConfigInfo): Promise<void> {
  await invoke('set_config', { cfg })
}

type Tab = 'connection' | 'network' | 'security'

const tabOptions: { value: Tab; label: string }[] = [
  { value: 'connection', label: 'Connection' },
  { value: 'network', label: 'Network' },
  { value: 'security', label: 'Security' },
]

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
    return <div style={{ color: 'var(--color-text-secondary)' }}>Loading settings\u2026</div>
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-xl font-semibold mb-6" style={{ color: 'var(--color-text-primary)' }}>Settings</h1>

      <SegmentedControl options={tabOptions} value={tab} onChange={setTab} className="mb-6" />

      {tab === 'connection' && (
        <>
          <Card label="SERVER CONFIGURATION" className="mb-5">
            <CardRow label="Management URL">
              <Input
                value={config.managementUrl}
                onChange={e => update('managementUrl', e.target.value)}
                placeholder="https://api.netbird.io:443"
                style={{ width: 240 }}
              />
            </CardRow>
            <CardRow label="Admin URL">
              <Input
                value={config.adminUrl}
                onChange={e => update('adminUrl', e.target.value)}
                style={{ width: 240 }}
              />
            </CardRow>
            <CardRow label="Pre-shared Key">
              <Input
                type="password"
                value={config.preSharedKey}
                onChange={e => update('preSharedKey', e.target.value)}
                placeholder="Leave empty to clear"
                style={{ width: 240 }}
              />
            </CardRow>
          </Card>

          <Card label="BEHAVIOR" className="mb-5">
            <CardRow label="Connect automatically">
              <Toggle checked={!config.disableAutoConnect} onChange={v => update('disableAutoConnect', !v)} />
            </CardRow>
            <CardRow label="Enable notifications">
              <Toggle checked={!config.disableNotifications} onChange={v => update('disableNotifications', !v)} />
            </CardRow>
          </Card>
        </>
      )}

      {tab === 'network' && (
        <>
          <Card label="INTERFACE" className="mb-5">
            <CardRow label="Interface Name">
              <Input
                value={config.interfaceName}
                onChange={e => update('interfaceName', e.target.value)}
                placeholder="netbird0"
                style={{ width: 180 }}
              />
            </CardRow>
            <CardRow label="WireGuard Port">
              <Input
                type="number"
                min={1}
                max={65535}
                value={config.wireguardPort}
                onChange={e => update('wireguardPort', parseInt(e.target.value) || 0)}
                placeholder="51820"
                style={{ width: 100 }}
              />
            </CardRow>
          </Card>

          <Card label="OPTIONS" className="mb-5">
            <CardRow label="Lazy connections" description="Experimental">
              <Toggle checked={config.lazyConnectionEnabled} onChange={v => update('lazyConnectionEnabled', v)} />
            </CardRow>
            <CardRow label="Block inbound connections">
              <Toggle checked={config.blockInbound} onChange={v => update('blockInbound', v)} />
            </CardRow>
          </Card>
        </>
      )}

      {tab === 'security' && (
        <Card label="SECURITY" className="mb-5">
          <CardRow label="Allow SSH connections">
            <Toggle checked={config.serverSshAllowed} onChange={v => update('serverSshAllowed', v)} />
          </CardRow>
          <CardRow label="Rosenpass post-quantum security">
            <Toggle checked={config.rosenpassEnabled} onChange={v => update('rosenpassEnabled', v)} />
          </CardRow>
          <CardRow label="Rosenpass permissive mode">
            <Toggle checked={config.rosenpassPermissive} onChange={v => update('rosenpassPermissive', v)} />
          </CardRow>
        </Card>
      )}

      <div className="flex items-center gap-3">
        <Button onClick={handleSave} disabled={saving}>
          {saving ? 'Saving\u2026' : 'Save'}
        </Button>
        {saved && <span className="text-[13px]" style={{ color: 'var(--color-status-green)' }}>Saved!</span>}
        {error && <span className="text-[13px]" style={{ color: 'var(--color-status-red)' }}>{error}</span>}
      </div>
    </div>
  )
}
