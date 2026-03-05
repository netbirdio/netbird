interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
}

export default function Input({ label, className, style, ...props }: InputProps) {
  const input = (
    <input
      className={`w-full rounded-[var(--radius-control)] text-[13px] outline-none transition-shadow ${className ?? ''}`}
      style={{
        height: 28,
        padding: '0 8px',
        backgroundColor: 'var(--color-input-bg)',
        border: '0.5px solid var(--color-input-border)',
        color: 'var(--color-text-primary)',
        boxShadow: 'none',
        ...style,
      }}
      onFocus={e => {
        e.currentTarget.style.boxShadow = '0 0 0 3px rgba(246,131,48,0.3)'
        e.currentTarget.style.borderColor = 'var(--color-accent)'
      }}
      onBlur={e => {
        e.currentTarget.style.boxShadow = 'none'
        e.currentTarget.style.borderColor = 'var(--color-input-border)'
      }}
      {...props}
    />
  )

  if (!label) return input

  return (
    <div>
      <label className="block text-[11px] font-medium mb-1" style={{ color: 'var(--color-text-secondary)' }}>
        {label}
      </label>
      {input}
    </div>
  )
}
