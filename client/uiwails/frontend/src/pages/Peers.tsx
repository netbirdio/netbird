import { useState, useEffect, useCallback, useMemo } from 'react'
import { Call } from '@wailsio/runtime'
import type { PeerInfo } from '../bindings'

const SVC = 'github.com/netbirdio/netbird/client/uiwails/services.PeersService'

type SortKey = 'fqdn' | 'ip' | 'status' | 'latency'
type SortDir = 'asc' | 'desc'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function formatLatency(ms: number): string {
  if (ms <= 0) return '—'
  if (ms < 1) return '<1 ms'
  return `${ms.toFixed(1)} ms`
}

function peerName(p: PeerInfo): string {
  if (p.fqdn) return p.fqdn.replace(/\.netbird\.cloud\.?$/, '')
  return p.ip || p.pubKey.substring(0, 8)
}

export default function Peers() {
  const [peers, setPeers] = useState<PeerInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('fqdn')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await Call.ByName(`${SVC}.GetPeers`) as PeerInfo[]
      setPeers(data ?? [])
    } catch (e) {
      console.error('[Peers] load error:', e)
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  const connectedCount = useMemo(() => peers.filter(p => p.connStatus === 'Connected').length, [peers])

  const filtered = useMemo(() => {
    let list = peers
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(p =>
        peerName(p).toLowerCase().includes(q) ||
        p.ip?.toLowerCase().includes(q) ||
        p.connStatus?.toLowerCase().includes(q) ||
        p.fqdn?.toLowerCase().includes(q)
      )
    }
    return [...list].sort((a, b) => {
      let cmp = 0
      switch (sortKey) {
        case 'fqdn': cmp = peerName(a).localeCompare(peerName(b)); break
        case 'ip': cmp = (a.ip ?? '').localeCompare(b.ip ?? ''); break
        case 'status': cmp = (a.connStatus ?? '').localeCompare(b.connStatus ?? ''); break
        case 'latency': cmp = (a.latencyMs ?? 0) - (b.latencyMs ?? 0); break
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [peers, search, sortKey, sortDir])

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  return (
    <div className="max-w-5xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Peers</h1>

      {/* Toolbar */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex-1 max-w-sm">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-nb-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <circle cx={11} cy={11} r={8} /><path d="m21 21-4.3-4.3" />
          </svg>
          <input
            className="w-full pl-9 pr-3 py-2 bg-nb-gray-920 border border-nb-gray-800/40 rounded-md text-sm text-nb-gray-100 placeholder-nb-gray-500 focus:outline-none focus:border-nb-gray-600 transition-colors"
            placeholder="Search by name, IP or status..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="flex gap-2 ml-auto">
          <ActionButton onClick={load}>
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </ActionButton>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-950/40 border border-red-500 rounded-md text-red-400 text-xs">
          {error}
        </div>
      )}

      {/* Summary */}
      {peers.length > 0 && (
        <div className="mb-3 text-xs text-nb-gray-400">
          {connectedCount} of {peers.length} peer{peers.length !== 1 ? 's' : ''} connected
        </div>
      )}

      {/* Table */}
      {loading && peers.length === 0 ? (
        <TableSkeleton />
      ) : peers.length === 0 ? (
        <EmptyState />
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-nb-gray-400 text-sm">
          No peers match your search.
          <button onClick={() => setSearch('')} className="ml-2 text-netbird hover:underline">Clear search</button>
        </div>
      ) : (
        <div className="rounded-md border border-nb-gray-900/60 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-nb-gray-900 border-b border-nb-gray-900/60">
                <SortableHeader label="Peer" sortKey="fqdn" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
                <SortableHeader label="IP" sortKey="ip" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Status" sortKey="status" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
                <th className="px-4 py-3 text-left text-xs font-medium text-nb-gray-400 uppercase tracking-wide">Connection</th>
                <SortableHeader label="Latency" sortKey="latency" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
                <th className="px-4 py-3 text-left text-xs font-medium text-nb-gray-400 uppercase tracking-wide">Transfer</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(p => (
                <PeerRow key={p.pubKey} peer={p} />
              ))}
            </tbody>
          </table>

          <div className="px-4 py-2.5 bg-nb-gray-940 border-t border-nb-gray-900/60 text-xs text-nb-gray-400">
            Showing {filtered.length} of {peers.length} peer{peers.length !== 1 ? 's' : ''}
          </div>
        </div>
      )}
    </div>
  )
}

/* ---- Row ---- */

function PeerRow({ peer }: { peer: PeerInfo }) {
  const name = peerName(peer)
  const connected = peer.connStatus === 'Connected'

  return (
    <tr className="border-b border-nb-gray-900/40 hover:bg-nb-gray-940 transition-colors group/row">
      {/* Peer name */}
      <td className="px-4 py-3 align-middle">
        <div className="flex items-center gap-3 min-w-[160px]">
          <PeerSquare name={name} connected={connected} />
          <div className="flex flex-col">
            <span className="font-medium text-sm text-nb-gray-100 truncate max-w-[200px]" title={peer.fqdn}>{name}</span>
            {peer.networks && peer.networks.length > 0 && (
              <span className="text-xs text-nb-gray-500 mt-0.5">{peer.networks.length} network{peer.networks.length !== 1 ? 's' : ''}</span>
            )}
          </div>
        </div>
      </td>

      {/* IP */}
      <td className="px-4 py-3 align-middle">
        <span className="font-mono text-[0.82rem] text-nb-gray-300">{peer.ip || '—'}</span>
      </td>

      {/* Status */}
      <td className="px-4 py-3 align-middle">
        <StatusBadge status={peer.connStatus} />
      </td>

      {/* Connection type */}
      <td className="px-4 py-3 align-middle">
        <div className="flex flex-col gap-0.5">
          {connected ? (
            <>
              <span className="text-xs text-nb-gray-300">
                {peer.relayed ? 'Relayed' : 'Direct'}{' '}
                {peer.rosenpassEnabled && (
                  <span className="text-green-400" title="Rosenpass post-quantum security enabled">PQ</span>
                )}
              </span>
              {peer.relayed && peer.relayAddress && (
                <span className="text-xs text-nb-gray-500 font-mono" title={peer.relayAddress}>
                  via {peer.relayAddress.length > 24 ? peer.relayAddress.substring(0, 24) + '...' : peer.relayAddress}
                </span>
              )}
              {!peer.relayed && peer.localIceType && (
                <span className="text-xs text-nb-gray-500">{peer.localIceType} / {peer.remoteIceType}</span>
              )}
            </>
          ) : (
            <span className="text-nb-gray-600">—</span>
          )}
        </div>
      </td>

      {/* Latency */}
      <td className="px-4 py-3 align-middle">
        <span className={`text-sm ${peer.latencyMs > 0 ? 'text-nb-gray-300' : 'text-nb-gray-600'}`}>
          {formatLatency(peer.latencyMs)}
        </span>
      </td>

      {/* Transfer */}
      <td className="px-4 py-3 align-middle">
        {(peer.bytesRx > 0 || peer.bytesTx > 0) ? (
          <div className="flex flex-col gap-0.5 text-xs">
            <span className="text-nb-gray-400">
              <span className="text-green-400/70" title="Received">&#8595;</span> {formatBytes(peer.bytesRx)}
            </span>
            <span className="text-nb-gray-400">
              <span className="text-blue-400/70" title="Sent">&#8593;</span> {formatBytes(peer.bytesTx)}
            </span>
          </div>
        ) : (
          <span className="text-nb-gray-600">—</span>
        )}
      </td>
    </tr>
  )
}

/* ---- Peer Icon Square ---- */

function PeerSquare({ name, connected }: { name: string; connected: boolean }) {
  const initials = name.substring(0, 2).toUpperCase()
  return (
    <div className="relative h-10 w-10 shrink-0 rounded-md bg-nb-gray-800 flex items-center justify-center text-sm font-medium text-nb-gray-100 uppercase">
      {initials}
      <div className={`absolute bottom-0 right-0 h-2 w-2 rounded-full z-10 ${connected ? 'bg-green-500' : 'bg-nb-gray-700'}`} />
      <div className="absolute bottom-0 right-0 h-3 w-3 bg-nb-gray-950 rounded-tl-[8px] rounded-br group-hover/row:bg-nb-gray-940 transition-colors" />
    </div>
  )
}

/* ---- Status Badge ---- */

function StatusBadge({ status }: { status: string }) {
  const connected = status === 'Connected'
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
      connected
        ? 'bg-green-500/10 text-green-400 border border-green-500/20'
        : 'bg-nb-gray-800/50 text-nb-gray-400 border border-nb-gray-800'
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500' : 'bg-nb-gray-600'}`} />
      {status || 'Unknown'}
    </span>
  )
}

/* ---- Sortable Header ---- */

function SortableHeader({ label, sortKey, currentKey, dir, onSort }: {
  label: string; sortKey: SortKey; currentKey: SortKey; dir: SortDir; onSort: (k: SortKey) => void
}) {
  const isActive = currentKey === sortKey
  return (
    <th
      className="px-4 py-3 text-left text-xs font-medium text-nb-gray-400 uppercase tracking-wide cursor-pointer select-none hover:text-nb-gray-300 transition-colors"
      onClick={() => onSort(sortKey)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {isActive && (
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            {dir === 'asc' ? <path d="M5 15l7-7 7 7" /> : <path d="M19 9l-7 7-7-7" />}
          </svg>
        )}
      </span>
    </th>
  )
}

/* ---- Action Button ---- */

function ActionButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-nb-gray-920 border border-nb-gray-800/40 text-nb-gray-300 hover:bg-nb-gray-910 hover:text-nb-gray-100 rounded-md transition-colors"
    >
      {children}
    </button>
  )
}

/* ---- Empty State ---- */

function EmptyState() {
  return (
    <div className="rounded-md border border-nb-gray-900/60 bg-nb-gray-920 py-16 flex flex-col items-center gap-3">
      <div className="h-12 w-12 rounded-lg bg-nb-gray-800 flex items-center justify-center">
        <svg className="w-6 h-6 text-nb-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
        </svg>
      </div>
      <p className="text-sm text-nb-gray-400">No peers found. Connect to a network to see peers.</p>
    </div>
  )
}

/* ---- Loading Skeleton ---- */

function TableSkeleton() {
  return (
    <div className="rounded-md border border-nb-gray-900/60 overflow-hidden">
      <div className="bg-nb-gray-900 h-11" />
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-4 py-4 border-b border-nb-gray-900/40 animate-pulse">
          <div className="flex items-center gap-3 flex-1">
            <div className="w-10 h-10 rounded-md bg-nb-gray-800" />
            <div className="h-4 w-28 rounded bg-nb-gray-800" />
          </div>
          <div className="h-4 w-24 rounded bg-nb-gray-800" />
          <div className="h-5 w-20 rounded-full bg-nb-gray-800" />
          <div className="h-4 w-16 rounded bg-nb-gray-800" />
          <div className="h-4 w-14 rounded bg-nb-gray-800" />
          <div className="h-4 w-16 rounded bg-nb-gray-800" />
        </div>
      ))}
    </div>
  )
}
