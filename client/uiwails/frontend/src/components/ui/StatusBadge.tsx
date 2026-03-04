interface StatusBadgeProps {
  status: 'connected' | 'disconnected' | 'connecting' | string
  label?: string
}

function getStatusColors(status: string): { dot: string; text: string; bg: string } {
  switch (status.toLowerCase()) {
    case 'connected':
      return { dot: 'var(--color-status-green)', text: 'var(--color-status-green)', bg: 'var(--color-status-green-bg)' }
    case 'connecting':
      return { dot: 'var(--color-status-yellow)', text: 'var(--color-status-yellow)', bg: 'var(--color-status-yellow-bg)' }
    case 'disconnected':
      return { dot: 'var(--color-status-gray)', text: 'var(--color-text-secondary)', bg: 'var(--color-status-gray-bg)' }
    default:
      return { dot: 'var(--color-status-red)', text: 'var(--color-status-red)', bg: 'var(--color-status-red-bg)' }
  }
}

export default function StatusBadge({ status, label }: StatusBadgeProps) {
  const colors = getStatusColors(status)

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium"
      style={{ backgroundColor: colors.bg, color: colors.text }}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${status.toLowerCase() === 'connecting' ? 'animate-pulse' : ''}`}
        style={{ backgroundColor: colors.dot }}
      />
      {label ?? status}
    </span>
  )
}
