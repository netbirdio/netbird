import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import type { DebugBundleParams, DebugBundleResult } from '../bindings'
import Card from '../components/ui/Card'
import CardRow from '../components/ui/CardRow'
import Toggle from '../components/ui/Toggle'
import Input from '../components/ui/Input'
import Button from '../components/ui/Button'

const DEFAULT_UPLOAD_URL = 'https://upload.netbird.io'

export default function Debug() {
  const [anonymize, setAnonymize] = useState(false)
  const [systemInfo, setSystemInfo] = useState(true)
  const [upload, setUpload] = useState(true)
  const [uploadUrl, setUploadUrl] = useState(DEFAULT_UPLOAD_URL)
  const [runForDuration, setRunForDuration] = useState(true)
  const [durationMins, setDurationMins] = useState(1)

  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState('')
  const [result, setResult] = useState<DebugBundleResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleCreate() {
    if (upload && !uploadUrl) {
      setError('Upload URL is required when upload is enabled')
      return
    }

    setRunning(true)
    setError(null)
    setResult(null)
    setProgress(runForDuration ? `Running with trace logs for ${durationMins} minute(s)\u2026` : 'Creating debug bundle\u2026')

    const params: DebugBundleParams = {
      anonymize,
      systemInfo,
      upload,
      uploadUrl: upload ? uploadUrl : '',
      runDurationMins: runForDuration ? durationMins : 0,
      enablePersistence: true,
    }

    try {
      const res = await invoke<DebugBundleResult>('create_debug_bundle', { params })
      if (res) {
        setResult(res)
        setProgress('Bundle created successfully')
      }
    } catch (e) {
      console.error('[Debug] CreateDebugBundle error:', e)
      setError(String(e))
      setProgress('')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-xl font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>Debug</h1>
      <p className="text-[13px] mb-6" style={{ color: 'var(--color-text-secondary)' }}>
        Create a debug bundle to help troubleshoot issues with NetBird.
      </p>

      <Card label="OPTIONS" className="mb-5">
        <CardRow label="Anonymize sensitive information">
          <Toggle checked={anonymize} onChange={setAnonymize} />
        </CardRow>
        <CardRow label="Include system information">
          <Toggle checked={systemInfo} onChange={setSystemInfo} />
        </CardRow>
        <CardRow label="Upload bundle automatically">
          <Toggle checked={upload} onChange={setUpload} />
        </CardRow>
      </Card>

      {upload && (
        <Card label="UPLOAD" className="mb-5">
          <CardRow label="Upload URL">
            <Input
              value={uploadUrl}
              onChange={e => setUploadUrl(e.target.value)}
              disabled={running}
              style={{ width: 240 }}
            />
          </CardRow>
        </Card>
      )}

      <Card label="TRACE LOGGING" className="mb-5">
        <CardRow label="Run with trace logs before creating bundle">
          <Toggle checked={runForDuration} onChange={setRunForDuration} />
        </CardRow>
        {runForDuration && (
          <CardRow label="Duration">
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={1}
                max={60}
                value={durationMins}
                onChange={e => setDurationMins(Math.max(1, parseInt(e.target.value) || 1))}
                disabled={running}
                style={{ width: 64, textAlign: 'center' }}
              />
              <span className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
                {durationMins === 1 ? 'minute' : 'minutes'}
              </span>
            </div>
          </CardRow>
        )}
        {runForDuration && (
          <div className="px-4 py-2 text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
            Note: NetBird will be brought up and down during collection.
          </div>
        )}
      </Card>

      {error && (
        <div
          className="mb-4 p-3 rounded-[var(--radius-control)] text-[13px]"
          style={{ backgroundColor: 'var(--color-status-red-bg)', color: 'var(--color-status-red)' }}
        >
          {error}
        </div>
      )}

      {progress && (
        <div
          className="mb-4 p-3 rounded-[var(--radius-control)] text-[13px]"
          style={{
            backgroundColor: 'var(--color-bg-secondary)',
            boxShadow: 'var(--shadow-card)',
            color: running ? 'var(--color-status-yellow)' : 'var(--color-status-green)',
          }}
        >
          <span className={running ? 'animate-pulse' : ''}>{progress}</span>
        </div>
      )}

      {result && (
        <Card className="mb-4">
          <div className="px-4 py-3 space-y-2 text-[13px]">
            {result.uploadedKey ? (
              <>
                <p style={{ color: 'var(--color-status-green)' }} className="font-medium">Bundle uploaded successfully!</p>
                <div className="flex items-center gap-2">
                  <span style={{ color: 'var(--color-text-secondary)' }}>Upload key:</span>
                  <code
                    className="px-2 py-0.5 rounded text-[12px] font-mono"
                    style={{ backgroundColor: 'var(--color-bg-tertiary)' }}
                  >
                    {result.uploadedKey}
                  </code>
                </div>
              </>
            ) : result.uploadFailureReason ? (
              <p style={{ color: 'var(--color-status-yellow)' }}>Upload failed: {result.uploadFailureReason}</p>
            ) : null}
            <div className="flex items-center gap-2">
              <span style={{ color: 'var(--color-text-secondary)' }}>Local path:</span>
              <code
                className="px-2 py-0.5 rounded text-[12px] font-mono break-all"
                style={{ backgroundColor: 'var(--color-bg-tertiary)' }}
              >
                {result.localPath}
              </code>
            </div>
          </div>
        </Card>
      )}

      <Button onClick={handleCreate} disabled={running}>
        {running ? 'Running\u2026' : 'Create Debug Bundle'}
      </Button>
    </div>
  )
}
