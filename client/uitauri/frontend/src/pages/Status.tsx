import { useState, useEffect, useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import type { StatusInfo } from '../bindings'
import Card from '../components/ui/Card'
import CardRow from '../components/ui/CardRow'
import Button from '../components/ui/Button'

async function getStatus(): Promise<StatusInfo | null> {
  try {
    return await invoke<StatusInfo>('get_status')
  } catch (e) {
    console.error('[Dashboard] GetStatus error:', e)
    return null
  }
}

function statusDotColor(status: string): string {
  switch (status) {
    case 'Connected': return 'var(--color-status-green)'
    case 'Connecting': return 'var(--color-status-yellow)'
    case 'Disconnected': return 'var(--color-status-gray)'
    default: return 'var(--color-status-red)'
  }
}

function statusTextColor(status: string): string {
  switch (status) {
    case 'Connected': return 'var(--color-status-green)'
    case 'Connecting': return 'var(--color-status-yellow)'
    case 'Disconnected': return 'var(--color-text-secondary)'
    default: return 'var(--color-status-red)'
  }
}

export default function Status() {
  const [status, setStatus] = useState<StatusInfo | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    const s = await getStatus()
    if (s) setStatus(s)
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 10000)
    const unlisten = listen<StatusInfo>('status-changed', (event) => {
      if (event.payload) setStatus(event.payload)
    })
    return () => {
      clearInterval(id)
      unlisten.then(fn => fn())
    }
  }, [refresh])

  async function handleConnect() {
    setBusy(true)
    setError(null)
    try {
      await invoke('connect')
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function handleDisconnect() {
    setBusy(true)
    setError(null)
    try {
      await invoke('disconnect')
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const isConnected = status?.status === 'Connected'
  const isConnecting = status?.status === 'Connecting'

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-xl font-semibold mb-6" style={{ color: 'var(--color-text-primary)' }}>Status</h1>

      {/* Status hero */}
      <Card className="mb-6">
        <div className="px-4 py-5">
          <div className="flex items-center gap-3 mb-4">
            <span
              className={`w-3 h-3 rounded-full ${status?.status === 'Connecting' ? 'animate-pulse' : ''}`}
              style={{ backgroundColor: status ? statusDotColor(status.status) : 'var(--color-status-gray)' }}
            />
            <span
              className="text-xl font-semibold"
              style={{ color: status ? statusTextColor(status.status) : 'var(--color-text-secondary)' }}
            >
              {status?.status ?? 'Loading\u2026'}
            </span>
          </div>
        </div>

        {status?.ip && (
          <CardRow label="IP Address">
            <span className="font-mono text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>{status.ip}</span>
          </CardRow>
        )}
        {status?.fqdn && (
          <CardRow label="Hostname">
            <span className="font-mono text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>{status.fqdn}</span>
          </CardRow>
        )}
        {status && status.connectedPeers > 0 && (
          <CardRow label="Connected Peers">
            <span style={{ color: 'var(--color-text-secondary)' }}>{status.connectedPeers}</span>
          </CardRow>
        )}
      </Card>

      {/* Actions */}
      <div className="flex gap-3">
        {!isConnected && !isConnecting && (
          <Button onClick={handleConnect} disabled={busy}>
            {busy ? 'Connecting\u2026' : 'Connect'}
          </Button>
        )}
        {(isConnected || isConnecting) && (
          <Button variant="secondary" onClick={handleDisconnect} disabled={busy}>
            {busy ? 'Disconnecting\u2026' : 'Disconnect'}
          </Button>
        )}
      </div>

      {error && (
        <div
          className="mt-4 p-3 rounded-[var(--radius-control)] text-[13px]"
          style={{
            backgroundColor: 'var(--color-status-red-bg)',
            color: 'var(--color-status-red)',
          }}
        >
          {error}
        </div>
      )}
    </div>
  )
}
