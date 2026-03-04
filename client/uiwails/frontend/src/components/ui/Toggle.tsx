interface ToggleProps {
  checked: boolean
  onChange: (value: boolean) => void
  small?: boolean
  disabled?: boolean
}

export default function Toggle({ checked, onChange, small, disabled }: ToggleProps) {
  const w = small ? 30 : 38
  const h = small ? 18 : 22
  const thumb = small ? 14 : 18
  const travel = w - thumb - 4

  return (
    <button
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="relative inline-flex shrink-0 cursor-pointer items-center rounded-full transition-colors duration-200 disabled:cursor-not-allowed disabled:opacity-50"
      style={{
        width: w,
        height: h,
        backgroundColor: checked ? 'var(--color-accent)' : 'var(--color-control-bg)',
        padding: 2,
      }}
    >
      <span
        className="block rounded-full bg-white transition-transform duration-200"
        style={{
          width: thumb,
          height: thumb,
          transform: `translateX(${checked ? travel : 0}px)`,
          boxShadow: '0 1px 3px rgba(0,0,0,0.15), 0 0.5px 1px rgba(0,0,0,0.1)',
        }}
      />
    </button>
  )
}
