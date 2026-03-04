import { useState, useEffect, useCallback, useMemo } from 'react'
import { Call } from '@wailsio/runtime'
import type { NetworkInfo } from '../bindings'
import SearchInput from '../components/ui/SearchInput'
import Button from '../components/ui/Button'
import Toggle from '../components/ui/Toggle'
import SegmentedControl from '../components/ui/SegmentedControl'
import { TableContainer, TableHeader, TableHeaderCell, TableRow, TableCell, TableFooter } from '../components/ui/Table'

const SVC = 'github.com/netbirdio/netbird/client/uiwails/services.NetworkService'

type Tab = 'all' | 'overlapping' | 'exit-node'
type SortKey = 'id' | 'range'
type SortDir = 'asc' | 'desc'

const tabOptions: { value: Tab; label: string }[] = [
  { value: 'all', label: 'All Networks' },
  { value: 'overlapping', label: 'Overlapping' },
  { value: 'exit-node', label: 'Exit Nodes' },
]

export default function Networks() {
  const [networks, setNetworks] = useState<NetworkInfo[]>([])
  const [tab, setTab] = useState<Tab>('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('id')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      let method: string
      if (tab === 'all') method = 'ListNetworks'
      else if (tab === 'overlapping') method = 'ListOverlappingNetworks'
      else method = 'ListExitNodes'
      const data = await Call.ByName(`${SVC}.${method}`) as NetworkInfo[]
      setNetworks(data ?? [])
    } catch (e) {
      console.error('[Networks] load error:', e)
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [tab])

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  const filtered = useMemo(() => {
    let list = networks
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(n =>
        n.id.toLowerCase().includes(q) ||
        n.range?.toLowerCase().includes(q) ||
        n.domains?.some(d => d.toLowerCase().includes(q))
      )
    }
    return [...list].sort((a, b) => {
      const aVal = sortKey === 'id' ? a.id : (a.range ?? '')
      const bVal = sortKey === 'id' ? b.id : (b.range ?? '')
      const cmp = aVal.localeCompare(bVal)
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [networks, search, sortKey, sortDir])

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  async function toggle(id: string, selected: boolean) {
    try {
      if (selected) await Call.ByName(`${SVC}.DeselectNetwork`, id)
      else await Call.ByName(`${SVC}.SelectNetwork`, id)
      await load()
    } catch (e) {
      setError(String(e))
    }
  }

  async function selectAll() {
    try {
      await Call.ByName(`${SVC}.SelectAllNetworks`)
      await load()
    } catch (e) { setError(String(e)) }
  }

  async function deselectAll() {
    try {
      await Call.ByName(`${SVC}.DeselectAllNetworks`)
      await load()
    } catch (e) { setError(String(e)) }
  }

  const selectedCount = networks.filter(n => n.selected).length

  return (
    <div className="max-w-5xl mx-auto">
      <h1 className="text-xl font-semibold mb-6" style={{ color: 'var(--color-text-primary)' }}>Networks</h1>

      <SegmentedControl options={tabOptions} value={tab} onChange={setTab} className="mb-5" />

      {/* Toolbar */}
      <div className="flex items-center gap-3 mb-4">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search by name, range or domain..."
          className="flex-1 max-w-sm"
        />
        <div className="flex gap-2 ml-auto">
          <Button variant="secondary" size="sm" onClick={selectAll}>Select All</Button>
          <Button variant="secondary" size="sm" onClick={deselectAll}>Deselect All</Button>
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

      {selectedCount > 0 && (
        <div className="mb-3 text-[12px]" style={{ color: 'var(--color-text-tertiary)' }}>
          {selectedCount} of {networks.length} network{networks.length !== 1 ? 's' : ''} selected
        </div>
      )}

      {loading && networks.length === 0 ? (
        <TableSkeleton />
      ) : filtered.length === 0 && networks.length === 0 ? (
        <EmptyState tab={tab} />
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
          No networks match your search.
          <button onClick={() => setSearch('')} className="ml-2 hover:underline" style={{ color: 'var(--color-accent)' }}>Clear search</button>
        </div>
      ) : (
        <TableContainer>
          <table className="w-full text-[13px]">
            <TableHeader>
              <SortableHeader label="Network" sortKey="id" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortableHeader label="Range / Domains" sortKey="range" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <TableHeaderCell>Resolved IPs</TableHeaderCell>
              <TableHeaderCell className="w-20">Active</TableHeaderCell>
            </TableHeader>
            <tbody>
              {filtered.map(n => (
                <NetworkRow key={n.id} network={n} onToggle={() => toggle(n.id, n.selected)} />
              ))}
            </tbody>
          </table>
          <TableFooter>
            Showing {filtered.length} of {networks.length} network{networks.length !== 1 ? 's' : ''}
          </TableFooter>
        </TableContainer>
      )}
    </div>
  )
}

/* ---- Row ---- */

function NetworkRow({ network, onToggle }: { network: NetworkInfo; onToggle: () => void }) {
  const domains = network.domains ?? []
  const resolvedEntries = Object.entries(network.resolvedIPs ?? {})
  const hasDomains = domains.length > 0

  return (
    <TableRow>
      <TableCell>
        <div className="flex items-center gap-3 min-w-[180px]">
          <NetworkSquare name={network.id} active={network.selected} />
          <div className="flex flex-col">
            <span className="font-medium text-[13px]" style={{ color: 'var(--color-text-primary)' }}>{network.id}</span>
            {hasDomains && domains.length > 1 && (
              <span className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>{domains.length} domains</span>
            )}
          </div>
        </div>
      </TableCell>

      <TableCell>
        {hasDomains ? (
          <div className="flex flex-col gap-1">
            {domains.slice(0, 2).map(d => (
              <span key={d} className="font-mono text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>{d}</span>
            ))}
            {domains.length > 2 && (
              <span className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }} title={domains.join(', ')}>+{domains.length - 2} more</span>
            )}
          </div>
        ) : (
          <span className="font-mono text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>{network.range}</span>
        )}
      </TableCell>

      <TableCell>
        {resolvedEntries.length > 0 ? (
          <div className="flex flex-col gap-1">
            {resolvedEntries.slice(0, 2).map(([domain, ips]) => (
              <span key={domain} className="font-mono text-[11px]" style={{ color: 'var(--color-text-tertiary)' }} title={`${domain}: ${ips.join(', ')}`}>
                {ips[0]}{ips.length > 1 && <span style={{ color: 'var(--color-text-quaternary)' }}> +{ips.length - 1}</span>}
              </span>
            ))}
            {resolvedEntries.length > 2 && (
              <span className="text-[11px]" style={{ color: 'var(--color-text-quaternary)' }}>+{resolvedEntries.length - 2} more</span>
            )}
          </div>
        ) : (
          <span style={{ color: 'var(--color-text-quaternary)' }}>{'\u2014'}</span>
        )}
      </TableCell>

      <TableCell>
        <Toggle checked={network.selected} onChange={onToggle} small />
      </TableCell>
    </TableRow>
  )
}

/* ---- Network Icon Square ---- */

function NetworkSquare({ name, active }: { name: string; active: boolean }) {
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
          backgroundColor: active ? 'var(--color-status-green)' : 'var(--color-status-gray)',
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

function EmptyState({ tab }: { tab: Tab }) {
  const msg = tab === 'exit-node'
    ? 'No exit nodes configured.'
    : tab === 'overlapping'
    ? 'No overlapping networks detected.'
    : 'No networks found.'

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
          <path d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A8.966 8.966 0 013 12c0-1.777.514-3.434 1.4-4.832" />
        </svg>
      </div>
      <p className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>{msg}</p>
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
            <div className="h-4 w-24 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          </div>
          <div className="h-4 w-32 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          <div className="h-4 w-20 rounded" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
          <div className="h-6 w-12 rounded-full" style={{ backgroundColor: 'var(--color-bg-tertiary)' }} />
        </div>
      ))}
    </div>
  )
}
