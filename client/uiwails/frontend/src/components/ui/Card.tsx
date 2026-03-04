interface CardProps {
  label?: string
  children: React.ReactNode
  className?: string
}

export default function Card({ label, children, className }: CardProps) {
  return (
    <div className={className}>
      {label && (
        <h3 className="text-[11px] font-semibold uppercase tracking-wide px-4 mb-1.5" style={{ color: 'var(--color-text-tertiary)' }}>
          {label}
        </h3>
      )}
      <div
        className="rounded-[var(--radius-card)] overflow-hidden"
        style={{
          backgroundColor: 'var(--color-bg-secondary)',
          boxShadow: 'var(--shadow-card)',
        }}
      >
        {children}
      </div>
    </div>
  )
}
