interface SegmentedControlProps<T extends string> {
  options: { value: T; label: string }[]
  value: T
  onChange: (value: T) => void
  className?: string
}

export default function SegmentedControl<T extends string>({ options, value, onChange, className }: SegmentedControlProps<T>) {
  return (
    <div
      className={`inline-flex rounded-[8px] p-[3px] ${className ?? ''}`}
      style={{ backgroundColor: 'var(--color-control-bg)' }}
    >
      {options.map(opt => {
        const active = opt.value === value
        return (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            className="relative px-3 py-1 text-[12px] font-medium rounded-[6px] transition-all duration-200"
            style={{
              backgroundColor: active ? 'var(--color-bg-elevated)' : 'transparent',
              color: active ? 'var(--color-text-primary)' : 'var(--color-text-secondary)',
              boxShadow: active ? 'var(--shadow-segment)' : 'none',
              minWidth: 64,
            }}
          >
            {opt.label}
          </button>
        )
      })}
    </div>
  )
}
