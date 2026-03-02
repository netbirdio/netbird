import { useState, useEffect, useRef } from 'react'
import { Call } from '@wailsio/runtime'
import type { InstallerResult } from '../bindings'

type UpdateState = 'idle' | 'triggering' | 'polling' | 'success' | 'failed' | 'timeout'

export default function Update() {
  const [state, setState] = useState<UpdateState>('idle')
  const [dots, setDots] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const abortRef = useRef<AbortController | null>(null)

  // Animate dots when polling
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

    // Poll for installer result (up to 15 minutes handled server-side)
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
    } catch (e) {
      // If the daemon restarts, the gRPC call may fail — treat as success
      setState('success')
    }
  }

  return (
    <div className="max-w-lg mx-auto">
      <h1 className="text-2xl font-bold mb-2">Update</h1>
      <p className="text-nb-gray-400 text-sm mb-8">
        Trigger an automatic client update managed by the NetBird daemon.
      </p>

      <div className="bg-nb-gray-920 rounded-xl p-6 border border-nb-gray-900 text-center">
        {state === 'idle' && (
          <>
            <p className="text-nb-gray-300 mb-5">Click below to trigger a daemon-managed update.</p>
            <button
              onClick={handleTriggerUpdate}
              className="px-6 py-2.5 bg-netbird hover:bg-netbird-500 rounded-lg font-medium transition-colors"
            >
              Trigger Update
            </button>
          </>
        )}

        {state === 'triggering' && (
          <p className="text-yellow-300 animate-pulse">Triggering update…</p>
        )}

        {state === 'polling' && (
          <div>
            <p className="text-yellow-300 text-lg mb-2">Updating{dots}</p>
            <p className="text-nb-gray-400 text-sm">The daemon is installing the update. Please wait.</p>
          </div>
        )}

        {state === 'success' && (
          <div>
            <p className="text-green-400 text-lg font-semibold mb-2">Update Successful!</p>
            <p className="text-nb-gray-300 text-sm">The client has been updated. You may need to restart.</p>
          </div>
        )}

        {state === 'failed' && (
          <div>
            <p className="text-red-400 text-lg font-semibold mb-2">Update Failed</p>
            {errorMsg && <p className="text-nb-gray-300 text-sm mb-4">{errorMsg}</p>}
            <button
              onClick={() => { setState('idle'); setErrorMsg('') }}
              className="px-4 py-2 text-sm bg-nb-gray-900 hover:bg-nb-gray-800 rounded-lg transition-colors"
            >
              Try Again
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
