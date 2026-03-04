import { useState, useEffect, useRef } from 'react'
import { Call } from '@wailsio/runtime'
import type { InstallerResult } from '../bindings'
import Card from '../components/ui/Card'
import Button from '../components/ui/Button'

type UpdateState = 'idle' | 'triggering' | 'polling' | 'success' | 'failed' | 'timeout'

export default function Update() {
  const [state, setState] = useState<UpdateState>('idle')
  const [dots, setDots] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    if (state !== 'polling') return
    let count = 0
    const id = setInterval(() => {
      count = (count + 1) % 4
      setDots('.'.repeat(count))
    }, 500)
    return () => clearInterval(id)
  }, [state])

  async function handleTriggerUpdate() {
    abortRef.current?.abort()
    abortRef.current = new AbortController()

    setState('triggering')
    setErrorMsg('')

    try {
      console.log('[Update] calling services.UpdateService.TriggerUpdate')
      await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.UpdateService.TriggerUpdate')
    } catch (e) {
      console.error('[Update] TriggerUpdate error:', e)
      setErrorMsg(String(e))
      setState('failed')
      return
    }

    setState('polling')

    try {
      console.log('[Update] calling services.UpdateService.GetInstallerResult')
      const result = await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.UpdateService.GetInstallerResult') as InstallerResult
      console.log('[Update] GetInstallerResult:', JSON.stringify(result))
      if (result?.success) {
        setState('success')
      } else {
        setErrorMsg(result?.errorMsg ?? 'Update failed')
        setState('failed')
      }
    } catch {
      setState('success')
    }
  }

  return (
    <div className="max-w-lg mx-auto">
      <h1 className="text-xl font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>Update</h1>
      <p className="text-[13px] mb-8" style={{ color: 'var(--color-text-secondary)' }}>
        Trigger an automatic client update managed by the NetBird daemon.
      </p>

      <Card>
        <div className="px-6 py-8 text-center">
          {state === 'idle' && (
            <>
              <p className="text-[13px] mb-5" style={{ color: 'var(--color-text-secondary)' }}>Click below to trigger a daemon-managed update.</p>
              <Button onClick={handleTriggerUpdate}>Trigger Update</Button>
            </>
          )}

          {state === 'triggering' && (
            <p className="animate-pulse text-[15px]" style={{ color: 'var(--color-status-yellow)' }}>Triggering update\u2026</p>
          )}

          {state === 'polling' && (
            <div>
              <p className="text-[17px] mb-2" style={{ color: 'var(--color-status-yellow)' }}>Updating{dots}</p>
              <p className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>The daemon is installing the update. Please wait.</p>
            </div>
          )}

          {state === 'success' && (
            <div>
              <p className="text-[17px] font-semibold mb-2" style={{ color: 'var(--color-status-green)' }}>Update Successful!</p>
              <p className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>The client has been updated. You may need to restart.</p>
            </div>
          )}

          {state === 'failed' && (
            <div>
              <p className="text-[17px] font-semibold mb-2" style={{ color: 'var(--color-status-red)' }}>Update Failed</p>
              {errorMsg && <p className="text-[13px] mb-4" style={{ color: 'var(--color-text-secondary)' }}>{errorMsg}</p>}
              <Button variant="secondary" onClick={() => { setState('idle'); setErrorMsg('') }}>
                Try Again
              </Button>
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}
