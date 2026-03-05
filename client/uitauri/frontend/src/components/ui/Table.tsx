/* Table primitives for macOS System Settings style tables */

export function TableContainer({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="rounded-[var(--radius-card)] overflow-hidden"
      style={{
        backgroundColor: 'var(--color-bg-secondary)',
        boxShadow: 'var(--shadow-card)',
      }}
    >
      {children}
    </div>
  )
}

export function TableHeader({ children }: { children: React.ReactNode }) {
  return (
    <thead>
      <tr style={{ borderBottom: '0.5px solid var(--color-separator)' }}>
        {children}
      </tr>
    </thead>
  )
}

export function TableHeaderCell({ children, onClick, className }: { children: React.ReactNode; onClick?: () => void; className?: string }) {
  return (
    <th
      className={`px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide ${onClick ? 'cursor-pointer select-none' : ''} ${className ?? ''}`}
      style={{ color: 'var(--color-text-tertiary)' }}
      onClick={onClick}
    >
      {children}
    </th>
  )
}

export function TableRow({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <tr
      className={`transition-colors group/row ${className ?? ''}`}
      style={{ borderBottom: '0.5px solid var(--color-separator)' }}
      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'var(--color-sidebar-hover)')}
      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
    >
      {children}
    </tr>
  )
}

export function TableCell({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <td className={`px-4 py-3 align-middle ${className ?? ''}`}>
      {children}
    </td>
  )
}

export function TableFooter({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="px-4 py-2 text-[11px]"
      style={{
        borderTop: '0.5px solid var(--color-separator)',
        color: 'var(--color-text-tertiary)',
      }}
    >
      {children}
    </div>
  )
}
