interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
}

export default function SearchInput({ value, onChange, placeholder = 'Search...', className }: SearchInputProps) {
  return (
    <div className={`relative ${className ?? ''}`}>
      <svg
        className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5"
        style={{ color: 'var(--color-text-tertiary)' }}
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={2}
      >
        <circle cx={11} cy={11} r={8} />
        <path d="m21 21-4.3-4.3" />
      </svg>
      <input
        className="w-full text-[13px] outline-none transition-shadow"
        style={{
          height: 28,
          paddingLeft: 28,
          paddingRight: 8,
          backgroundColor: 'var(--color-control-bg)',
          border: '0.5px solid transparent',
          borderRadius: 999,
          color: 'var(--color-text-primary)',
        }}
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
        onFocus={e => {
          e.currentTarget.style.boxShadow = '0 0 0 3px rgba(246,131,48,0.3)'
          e.currentTarget.style.borderColor = 'var(--color-accent)'
        }}
        onBlur={e => {
          e.currentTarget.style.boxShadow = 'none'
          e.currentTarget.style.borderColor = 'transparent'
        }}
      />
    </div>
  )
}
