import { useState, useEffect, useCallback } from 'react'
import { Events, Call } from '@wailsio/runtime'
import type { StatusInfo } from '../bindings'

async function getStatus(): Promise<StatusInfo | null> {
  try {
    console.log('[Dashboard] calling services.ConnectionService.GetStatus')
    const result = await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ConnectionService.GetStatus')
    console.log('[Dashboard] GetStatus result:', JSON.stringify(result))
    return result as StatusInfo
  } catch (e) {
    console.error('[Dashboard] GetStatus error:', e)
    return null
  }
}

async function connect(): Promise<void> {
  console.log('[Dashboard] calling services.ConnectionService.Connect')
  await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ConnectionService.Connect')
}

async function disconnect(): Promise<void> {
  console.log('[Dashboard] calling services.ConnectionService.Disconnect')
  await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ConnectionService.Disconnect')
}

function statusColor(status: string): string {
  switch (status) {
    case 'Connected': return 'text-green-400'
    case 'Connecting': return 'text-yellow-400'
    case 'Disconnected': return 'text-nb-gray-400'
    default: return 'text-red-400'
  }
}

function statusDot(status: string): string {
  switch (status) {
    case 'Connected': return 'bg-green-400'
    case 'Connecting': return 'bg-yellow-400 animate-pulse'
    case 'Disconnected': return 'bg-nb-gray-600'
    default: return 'bg-red-400'
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
    // Poll every 10 seconds as fallback (push events handle real-time updates)
    const id = setInterval(refresh, 10000)
    // Also listen for push events from the tray
    const unsub = Events.On('status-changed', (event: { data: StatusInfo[] }) => {
      if (event.data[0]) setStatus(event.data[0])
    })
    return () => {
      clearInterval(id)
      if (typeof unsub === 'function') unsub()
    }
  }, [refresh])

  async function handleConnect() {
    setBusy(true)
    setError(null)
    try {
      await connect()
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
      await disconnect()
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
      <h1 className="text-2xl font-bold mb-6">Status</h1>

      {/* Status card */}
      <div className="bg-nb-gray-920 rounded-xl p-6 mb-6 border border-nb-gray-900">
        <div className="flex items-center gap-3 mb-4">
          <span className={`w-3 h-3 rounded-full ${status ? statusDot(status.status) : 'bg-nb-gray-600'}`} />
          <span className={`text-xl font-semibold ${status ? statusColor(status.status) : 'text-nb-gray-400'}`}>
            {status?.status ?? 'Loading…'}
          </span>
        </div>

        {status && (
          <div className="grid grid-cols-2 gap-3 text-sm">
            {status.ip && (
              <>
                <span className="text-nb-gray-400">IP Address</span>
                <span className="font-mono">{status.ip}</span>
              </>
            )}
            {status.fqdn && (
              <>
                <span className="text-nb-gray-400">Hostname</span>
                <span className="font-mono">{status.fqdn}</span>
              </>
            )}
            {status.connectedPeers > 0 && (
              <>
                <span className="text-nb-gray-400">Connected Peers</span>
                <span>{status.connectedPeers}</span>
              </>
            )}
          </div>
        )}
      </div>

      {/* Action button */}
      <div className="flex gap-3">
        {!isConnected && !isConnecting && (
          <button
            onClick={handleConnect}
            disabled={busy}
            className="px-6 py-2.5 bg-netbird hover:bg-netbird-500 disabled:opacity-50 rounded-lg font-medium transition-colors"
          >
            {busy ? 'Connecting…' : 'Connect'}
          </button>
        )}
        {(isConnected || isConnecting) && (
          <button
            onClick={handleDisconnect}
            disabled={busy}
            className="px-6 py-2.5 bg-nb-gray-800 hover:bg-nb-gray-600 disabled:opacity-50 rounded-lg font-medium transition-colors"
          >
            {busy ? 'Disconnecting…' : 'Disconnect'}
          </button>
        )}
      </div>

      {error && (
        <div className="mt-4 p-3 bg-red-900/50 border border-red-700 rounded-lg text-red-300 text-sm">
          {error}
        </div>
      )}
    </div>
  )
}
