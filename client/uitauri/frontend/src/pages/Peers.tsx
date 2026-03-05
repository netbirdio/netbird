import { useState, useEffect, useCallback, useMemo } from 'react'
import { invoke } from '@tauri-apps/api/core'
import type { PeerInfo } from '../bindings'
import SearchInput from '../components/ui/SearchInput'
import Button from '../components/ui/Button'
import StatusBadge from '../components/ui/StatusBadge'
import { TableContainer, TableHeader, TableHeaderCell, TableRow, TableCell, TableFooter } from '../components/ui/Table'

type SortKey = 'fqdn' | 'ip' | 'status' | 'latency'
type SortDir = 'asc' | 'desc'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function formatLatency(ms: number): string {
  if (ms <= 0) return '\u2014'
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
      const data = await invoke<PeerInfo[]>('get_peers')
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
      <h1 className="text-xl font-semibold mb-6" style={{ color: 'var(--color-text-primary)' }}>Peers</h1>

      {/* Toolbar */}
      <div className="flex items-center gap-3 mb-4">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search by name, IP or status..."
          className="flex-1 max-w-sm"
        />
        <div className="flex gap-2 ml-auto">
          <Button variant="secondary" size="sm" onClick={load}>Refresh</Button>
        </div>
      </div>

      {error && (
        <div
          className="mb-4 p-3 rounded-[var(--radius-control)] text-[12px]"
          style={{ backgroundColor: 'var(--color-status-red-bg)', color: 'var(--color-status-red)' }}
        >
          {error}
        </div>
      )}

      {peers.length > 0 && (
        <div className="mb-3 text-[12px]" style={{ color: 'var(--color-text-tertiary)' }}>
          {connectedCount} of {peers.length} peer{peers.length !== 1 ? 's' : ''} connected
        </div>
      )}

      {loading && peers.length === 0 ? (
        <TableSkeleton />
      ) : peers.length === 0 ? (
        <EmptyState />
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
          No peers match your search.
          <button onClick={() => setSearch('')} className="ml-2 hover:underline" style={{ color: 'var(--color-accent)' }}>Clear search</button>
        </div>
      ) : (
        <TableContainer>
          <table className="w-full text-[13px]">
            <TableHeader>
              <SortableHeader label="Peer" sortKey="fqdn" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortableHeader label="IP" sortKey="ip" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortableHeader label="Status" sortKey="status" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <TableHeaderCell>Connection</TableHeaderCell>
              <SortableHeader label="Latency" sortKey="latency" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <TableHeaderCell>Transfer</TableHeaderCell>
            </TableHeader>
            <tbody>
              {filtered.map(p => (
                <PeerRow key={p.pubKey} peer={p} />
              ))}
            </tbody>
          </table>
          <TableFooter>
            Showing {filtered.length} of {peers.length} peer{peers.length !== 1 ? 's' : ''}
          </TableFooter>
        </TableContainer>
      )}
    </div>
  )
}

/* ---- Row ---- */

function PeerRow({ peer }: { peer: PeerInfo }) {
  const name = peerName(peer)
  const connected = peer.connStatus === 'Connected'

  return (
    <TableRow>
      <TableCell>
        <div className="flex items-center gap-3 min-w-[160px]">
          <PeerSquare name={name} connected={connected} />
          <div className="flex flex-col">
            <span className="font-medium text-[13px] truncate max-w-[200px]" style={{ color: 'var(--color-text-primary)' }} title={peer.fqdn}>{name}</span>
            {peer.networks && peer.networks.length > 0 && (
              <span className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>{peer.networks.length} network{peer.networks.length !== 1 ? 's' : ''}</span>
            )}
          </div>
        </div>
      </TableCell>

      <TableCell>
        <span className="font-mono text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>{peer.ip || '\u2014'}</span>
      </TableCell>

      <TableCell>
        <StatusBadge status={peer.connStatus} />
      </TableCell>

      <TableCell>
        <div className="flex flex-col gap-0.5">
          {connected ? (
            <>
              <span className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
                {peer.relayed ? 'Relayed' : 'Direct'}{' '}
                {peer.rosenpassEnabled && (
                  <span style={{ color: 'var(--color-status-green)' }} title="Rosenpass post-quantum security enabled">PQ</span>
                )}
              </span>
              {peer.relayed && peer.relayAddress && (
                <span className="text-[11px] font-mono" style={{ color: 'var(--color-text-tertiary)' }} title={peer.relayAddress}>
                  via {peer.relayAddress.length > 24 ? peer.relayAddress.substring(0, 24) + '...' : peer.relayAddress}
                </span>
              )}
              {!peer.relayed && peer.localIceType && (
                <span className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>{peer.localIceType} / {peer.remoteIceType}</span>
              )}
            </>
          ) : (
            <span style={{ color: 'var(--color-text-quaternary)' }}>{'\u2014'}</span>
          )}
        </div>
      </TableCell>

      <TableCell>
        <span className="text-[13px]" style={{ color: peer.latencyMs > 0 ? 'var(--color-text-secondary)' : 'var(--color-text-quaternary)' }}>
          {formatLatency(peer.latencyMs)}
        </span>
      </TableCell>

      <TableCell>
        {(peer.bytesRx > 0 || peer.bytesTx > 0) ? (
          <div className="flex flex-col gap-0.5 text-[11px]">
            <span style={{ color: 'var(--color-text-tertiary)' }}>
              <span style={{ color: 'var(--color-status-green)' }} title="Received">&#8595;</span> {formatBytes(peer.bytesRx)}
            </span>
            <span style={{ color: 'var(--color-text-tertiary)' }}>
              <span style={{ color: 'var(--color-accent)' }} title="Sent">&#8593;</span> {formatBytes(peer.bytesTx)}
            </span>
          </div>
        ) : (
          <span style={{ color: 'var(--color-text-quaternary)' }}>{'\u2014'}</span>
        )}
      </TableCell>
    </TableRow>
  )
}

/* ---- Peer Icon Square ---- */

function PeerSquare({ name, connected }: { name: string; connected: boolean }) {
  const initials = name.substring(0, 2).toUpperCase()
  return (
    <div
      className="relative h-10 w-10 shrink-0 rounded-[var(--radius-control)] flex items-center justify-center text-[13px] font-medium uppercase"
      style={{
        backgroundColor: 'var(--color-bg-tertiary)',
        color: 'var(--color-text-primary)',
      }}
    >
      {initials}
      <span
        className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full"
        style={{
          backgroundColor: connected ? 'var(--color-status-green)' : 'var(--color-status-gray)',
          border: '2px solid var(--color-bg-secondary)',
        }}
      />
    </div>
  )
}

/* ---- Sortable Header ---- */

function SortableHeader({ label, sortKey, currentKey, dir, onSort }: {
  label: string; sortKey: SortKey; currentKey: SortKey; dir: SortDir; onSort: (k: SortKey) => void
}) {
  const isActive = currentKey === sortKey
  return (
    <TableHeaderCell onClick={() => onSort(sortKey)}>
      <span className="inline-flex items-center gap-1">
        {label}
        {isActive && (
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            {dir === 'asc' ? <path d="M5 15l7-7 7 7" /> : <path d="M19 9l-7 7-7-7" />}
          </svg>
        )}
      </span>
    </TableHeaderCell>
  )
}

/* ---- Empty State ---- */

function EmptyState() {
  return (
    <div
      className="rounded-[var(--radius-card)] py-16 flex flex-col items-center gap-3"
      style={{
        backgroundColor: 'var(--color-bg-secondary)',
        boxShadow: 'var(--shadow-card)',
      }}
    >
      <div
        className="h-12 w-12 rounded-[var(--radius-card)] flex items-center justify-center"
        style={{ backgroundColor: 'var(--color-bg-tertiary)' }}
      >
        <svg className="w-6 h-6" style={{ color: 'var(--color-text-tertiary)' }} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
        </svg>
      </div>
      <p className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>No peers found. Connect to a network to see peers.</p>
    </div>
  )
}

/* ---- Loading Skeleton ---- */

function TableSkeleton() {
  return (
    <div
      className="rounded-[var(--radius-card)] overflow-hidden"
      style={{ backgroundColor: 'var(--color-bg-secondary)', boxShadow: 'var(--shadow-card)' }}
    >
      <div className="h-11" style={{ backgroundColor: 'var(--color-bg-tertiary)', opacity: 0.5 }} />
      {Array.from({ length: 5 }).map((_, i) => (
        <div
          key={i}
          className="flex items-center gap-4 px-4 py-4 animate-pulse"
          style={{ borderBottom: '0.5px solid var(--color-separator)' }}
        >
          <div className="flex items-center gap-3 flex-1">
            <div className="w-10 h-10 rounded-[var(--radius-control)]" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
            <div className="h-4 w-28 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          </div>
          <div className="h-4 w-24 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          <div className="h-5 w-20 rounded-full" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          <div className="h-4 w-16 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          <div className="h-4 w-14 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          <div className="h-4 w-16 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
        </div>
      ))}
    </div>
  )
}
