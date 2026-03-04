import Button from './Button'

interface ModalProps {
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  destructive?: boolean
  loading?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export default function Modal({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', destructive, loading, onConfirm, onCancel }: ModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'rgba(0,0,0,0.4)' }}>
      <div
        className="max-w-sm w-full mx-4 p-5 rounded-[12px]"
        style={{
          backgroundColor: 'var(--color-bg-elevated)',
          boxShadow: 'var(--shadow-elevated)',
        }}
      >
        <h2 className="text-[15px] font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>
          {title}
        </h2>
        <p className="text-[13px] mb-5" style={{ color: 'var(--color-text-secondary)' }}>
          {message}
        </p>
        <div className="flex gap-2 justify-end">
          <Button variant="secondary" size="sm" onClick={onCancel}>
            {cancelLabel}
          </Button>
          <Button
            variant={destructive ? 'destructive' : 'primary'}
            size="sm"
            onClick={onConfirm}
            disabled={loading}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  )
}
