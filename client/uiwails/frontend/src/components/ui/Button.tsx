interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'destructive'
  size?: 'sm' | 'md'
}

const styles: Record<string, React.CSSProperties> = {
  primary: {
    backgroundColor: 'var(--color-accent)',
    color: '#ffffff',
  },
  secondary: {
    backgroundColor: 'var(--color-control-bg)',
    color: 'var(--color-text-primary)',
  },
  destructive: {
    backgroundColor: 'var(--color-status-red-bg)',
    color: 'var(--color-status-red)',
  },
}

export default function Button({ variant = 'primary', size = 'md', className, style, children, ...props }: ButtonProps) {
  const variantStyle = styles[variant]
  const pad = size === 'sm' ? '4px 12px' : '6px 20px'
  const fontSize = size === 'sm' ? 12 : 13

  return (
    <button
      className={`inline-flex items-center justify-center gap-1.5 font-medium rounded-[8px] transition-opacity hover:opacity-85 active:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed ${className ?? ''}`}
      style={{ padding: pad, fontSize, ...variantStyle, ...style }}
      {...props}
    >
      {children}
    </button>
  )
}
