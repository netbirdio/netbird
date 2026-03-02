import { useState, useEffect, useCallback, useMemo } from 'react'
import { Call } from '@wailsio/runtime'
import type { NetworkInfo } from '../bindings'

const SVC = 'github.com/netbirdio/netbird/client/uiwails/services.NetworkService'

type Tab = 'all' | 'overlapping' | 'exit-node'
type SortKey = 'id' | 'range'
type SortDir = 'asc' | 'desc'

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
      <h1 className="text-2xl font-bold mb-6">Networks</h1>

      {/* Tabs */}
      <div className="flex gap-1 mb-5 bg-nb-gray-920 p-1 rounded-lg border border-nb-gray-900 max-w-md">
        {([['all', 'All Networks'], ['overlapping', 'Overlapping'], ['exit-node', 'Exit Nodes']] as [Tab, string][]).map(([t, label]) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`flex-1 py-1.5 rounded text-xs font-medium transition-colors ${
              tab === t ? 'bg-netbird text-white' : 'text-nb-gray-400 hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Toolbar: search + actions */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex-1 max-w-sm">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-nb-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <circle cx={11} cy={11} r={8} /><path d="m21 21-4.3-4.3" />
          </svg>
          <input
            className="w-full pl-9 pr-3 py-2 bg-nb-gray-920 border border-nb-gray-800/40 rounded-md text-sm text-nb-gray-100 placeholder-nb-gray-500 focus:outline-none focus:border-nb-gray-600 transition-colors"
            placeholder="Search by name, range or domain..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="flex gap-2 ml-auto">
          <ActionButton onClick={selectAll}>Select All</ActionButton>
          <ActionButton onClick={deselectAll}>Deselect All</ActionButton>
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

      {/* Selection summary */}
      {selectedCount > 0 && (
        <div className="mb-3 text-xs text-nb-gray-400">
          {selectedCount} of {networks.length} network{networks.length !== 1 ? 's' : ''} selected
        </div>
      )}

      {/* Table */}
      {loading && networks.length === 0 ? (
        <TableSkeleton />
      ) : filtered.length === 0 && networks.length === 0 ? (
        <EmptyState tab={tab} />
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-nb-gray-400 text-sm">
          No networks match your search.
          <button onClick={() => setSearch('')} className="ml-2 text-netbird hover:underline">Clear search</button>
        </div>
      ) : (
        <div className="rounded-md border border-nb-gray-900/60 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-nb-gray-900 border-b border-nb-gray-900/60">
                <SortableHeader label="Network" sortKey="id" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Range / Domains" sortKey="range" currentKey={sortKey} dir={sortDir} onSort={toggleSort} />
                <th className="px-4 py-3 text-left text-xs font-medium text-nb-gray-400 uppercase tracking-wide">Resolved IPs</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-nb-gray-400 uppercase tracking-wide w-20">Active</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(n => (
                <NetworkRow key={n.id} network={n} onToggle={() => toggle(n.id, n.selected)} />
              ))}
            </tbody>
          </table>

          {/* Pagination footer */}
          <div className="px-4 py-2.5 bg-nb-gray-940 border-t border-nb-gray-900/60 text-xs text-nb-gray-400">
            Showing {filtered.length} of {networks.length} network{networks.length !== 1 ? 's' : ''}
          </div>
        </div>
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
    <tr className="border-b border-nb-gray-900/40 hover:bg-nb-gray-940 transition-colors group/row">
      {/* Network name cell (dashboard-style icon square + name) */}
      <td className="px-4 py-3 align-middle">
        <div className="flex items-center gap-3 min-w-[180px]">
          <NetworkSquare name={network.id} active={network.selected} />
          <div className="flex flex-col">
            <span className="font-medium text-sm text-nb-gray-100">{network.id}</span>
            {hasDomains && domains.length > 1 && (
              <span className="text-xs text-nb-gray-500 mt-0.5">{domains.length} domains</span>
            )}
          </div>
        </div>
      </td>

      {/* Range / Domains */}
      <td className="px-4 py-3 align-middle">
        {hasDomains ? (
          <div className="flex flex-col gap-1">
            {domains.slice(0, 2).map(d => (
              <span key={d} className="font-mono text-[0.82rem] text-nb-gray-300">{d}</span>
            ))}
            {domains.length > 2 && (
              <span className="text-xs text-nb-gray-500" title={domains.join(', ')}>+{domains.length - 2} more</span>
            )}
          </div>
        ) : (
          <span className="font-mono text-[0.82rem] text-nb-gray-300">{network.range}</span>
        )}
      </td>

      {/* Resolved IPs */}
      <td className="px-4 py-3 align-middle">
        {resolvedEntries.length > 0 ? (
          <div className="flex flex-col gap-1">
            {resolvedEntries.slice(0, 2).map(([domain, ips]) => (
              <span key={domain} className="font-mono text-xs text-nb-gray-400" title={`${domain}: ${ips.join(', ')}`}>
                {ips[0]}{ips.length > 1 && <span className="text-nb-gray-600"> +{ips.length - 1}</span>}
              </span>
            ))}
            {resolvedEntries.length > 2 && (
              <span className="text-xs text-nb-gray-600">+{resolvedEntries.length - 2} more</span>
            )}
          </div>
        ) : (
          <span className="text-nb-gray-600">—</span>
        )}
      </td>

      {/* Active toggle */}
      <td className="px-4 py-3 align-middle">
        <button
          role="switch"
          aria-checked={network.selected}
          onClick={onToggle}
          className="toggle-track-sm"
        >
          <span className="toggle-thumb-sm" />
        </button>
      </td>
    </tr>
  )
}

/* ---- Network Icon Square (matches dashboard NetworkInformationSquare) ---- */

function NetworkSquare({ name, active }: { name: string; active: boolean }) {
  const initials = name.substring(0, 2).toUpperCase()
  return (
    <div className="relative h-10 w-10 shrink-0 rounded-md bg-nb-gray-800 flex items-center justify-center text-sm font-medium text-nb-gray-100 uppercase">
      {initials}
      {/* Status dot */}
      <div className={`absolute bottom-0 right-0 h-2 w-2 rounded-full z-10 ${active ? 'bg-green-500' : 'bg-nb-gray-700'}`} />
      {/* Corner mask for rounded dot cutout */}
      <div className="absolute bottom-0 right-0 h-3 w-3 bg-nb-gray-950 rounded-tl-[8px] rounded-br group-hover/row:bg-nb-gray-940 transition-colors" />
    </div>
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

function EmptyState({ tab }: { tab: Tab }) {
  const msg = tab === 'exit-node'
    ? 'No exit nodes configured.'
    : tab === 'overlapping'
    ? 'No overlapping networks detected.'
    : 'No networks found.'

  return (
    <div className="rounded-md border border-nb-gray-900/60 bg-nb-gray-920 py-16 flex flex-col items-center gap-3">
      <div className="h-12 w-12 rounded-lg bg-nb-gray-800 flex items-center justify-center">
        <svg className="w-6 h-6 text-nb-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.92 17.92 0 01-8.716-2.247m0 0A8.966 8.966 0 013 12c0-1.777.514-3.434 1.4-4.832" />
        </svg>
      </div>
      <p className="text-sm text-nb-gray-400">{msg}</p>
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
          <div className="w-4 h-4 rounded bg-nb-gray-800" />
          <div className="flex items-center gap-3 flex-1">
            <div className="w-10 h-10 rounded-md bg-nb-gray-800" />
            <div className="h-4 w-24 rounded bg-nb-gray-800" />
          </div>
          <div className="h-4 w-32 rounded bg-nb-gray-800" />
          <div className="h-4 w-20 rounded bg-nb-gray-800" />
          <div className="h-6 w-16 rounded-md bg-nb-gray-800" />
        </div>
      ))}
    </div>
  )
}
