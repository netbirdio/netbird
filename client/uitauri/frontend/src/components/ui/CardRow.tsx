interface CardRowProps {
  label?: string
  description?: string
  children?: React.ReactNode
  className?: string
  onClick?: () => void
}

export default function CardRow({ label, description, children, className, onClick }: CardRowProps) {
  return (
    <div
      className={`flex items-center justify-between gap-4 px-4 py-3 min-h-[44px] ${onClick ? 'cursor-pointer' : ''} ${className ?? ''}`}
      style={{ borderBottom: '0.5px solid var(--color-separator)' }}
      onClick={onClick}
    >
      <div className="flex flex-col min-w-0 flex-1">
        {label && (
          <span className="text-[13px]" style={{ color: 'var(--color-text-primary)' }}>
            {label}
          </span>
        )}
        {description && (
          <span className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>
            {description}
          </span>
        )}
      </div>
      {children && <div className="shrink-0 flex items-center">{children}</div>}
    </div>
  )
}
