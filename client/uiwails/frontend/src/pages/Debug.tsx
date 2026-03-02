import { useState } from 'react'
import { Call } from '@wailsio/runtime'
import type { DebugBundleParams, DebugBundleResult } from '../bindings'

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
    setProgress(runForDuration ? `Running with trace logs for ${durationMins} minute(s)…` : 'Creating debug bundle…')

    const params: DebugBundleParams = {
      anonymize,
      systemInfo,
      upload,
      uploadUrl: upload ? uploadUrl : '',
      runDurationMins: runForDuration ? durationMins : 0,
      enablePersistence: true,
    }

    try {
      console.log('[Debug] calling services.DebugService.CreateDebugBundle')
      const res = await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.DebugService.CreateDebugBundle', params) as DebugBundleResult
      console.log('[Debug] CreateDebugBundle result:', JSON.stringify(res))
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
      <h1 className="text-2xl font-bold mb-2">Debug</h1>
      <p className="text-nb-gray-400 text-sm mb-6">
        Create a debug bundle to help troubleshoot issues with NetBird.
      </p>

      <div className="bg-nb-gray-920 rounded-xl p-6 border border-nb-gray-900 space-y-5">
        <Toggle label="Anonymize sensitive information (IPs, domains…)" checked={anonymize} onChange={setAnonymize} />
        <Toggle label="Include system information (routes, interfaces…)" checked={systemInfo} onChange={setSystemInfo} />
        <Toggle label="Upload bundle automatically after creation" checked={upload} onChange={setUpload} />

        {upload && (
          <div>
            <label className="block text-sm text-nb-gray-400 mb-1.5">Upload URL</label>
            <input
              className="w-full px-3 py-2 bg-nb-gray-900 border border-nb-gray-800 rounded-lg text-sm focus:outline-none focus:border-netbird"
              value={uploadUrl}
              onChange={e => setUploadUrl(e.target.value)}
              disabled={running}
            />
          </div>
        )}

        <div className="border-t border-nb-gray-900 pt-4">
          <Toggle
            label="Run with trace logs before creating bundle"
            checked={runForDuration}
            onChange={setRunForDuration}
          />
          {runForDuration && (
            <div className="mt-3 flex items-center gap-2">
              <span className="text-sm text-nb-gray-400">for</span>
              <input
                type="number"
                min={1}
                max={60}
                value={durationMins}
                onChange={e => setDurationMins(Math.max(1, parseInt(e.target.value) || 1))}
                disabled={running}
                className="w-16 px-2 py-1 bg-nb-gray-900 border border-nb-gray-800 rounded text-sm text-center focus:outline-none focus:border-netbird"
              />
              <span className="text-sm text-nb-gray-400">{durationMins === 1 ? 'minute' : 'minutes'}</span>
            </div>
          )}
          {runForDuration && (
            <p className="text-xs text-nb-gray-500 mt-2">
              Note: NetBird will be brought up and down during collection.
            </p>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-4 p-3 bg-red-900/50 border border-red-700 rounded-lg text-red-300 text-sm">
          {error}
        </div>
      )}

      {progress && (
        <div className="mt-4 p-3 bg-nb-gray-920 border border-nb-gray-900 rounded-lg text-sm">
          <span className={running ? 'animate-pulse text-yellow-300' : 'text-green-400'}>{progress}</span>
        </div>
      )}

      {result && (
        <div className="mt-4 bg-nb-gray-920 rounded-xl p-5 border border-nb-gray-900 text-sm space-y-2">
          {result.uploadedKey ? (
            <>
              <p className="text-green-400 font-medium">Bundle uploaded successfully!</p>
              <div className="flex items-center gap-2">
                <span className="text-nb-gray-400">Upload key:</span>
                <code className="bg-nb-gray-900 px-2 py-0.5 rounded text-xs font-mono">{result.uploadedKey}</code>
              </div>
            </>
          ) : result.uploadFailureReason ? (
            <p className="text-yellow-400">Upload failed: {result.uploadFailureReason}</p>
          ) : null}
          <div className="flex items-center gap-2">
            <span className="text-nb-gray-400">Local path:</span>
            <code className="bg-nb-gray-900 px-2 py-0.5 rounded text-xs font-mono break-all">{result.localPath}</code>
          </div>
        </div>
      )}

      <div className="mt-4">
        <button
          onClick={handleCreate}
          disabled={running}
          className="px-6 py-2.5 bg-netbird hover:bg-netbird-500 disabled:opacity-50 rounded-lg font-medium transition-colors"
        >
          {running ? 'Running…' : 'Create Debug Bundle'}
        </button>
      </div>
    </div>
  )
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer">
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className="toggle-track"
      >
        <span className="toggle-thumb" />
      </button>
      <span className="text-sm">{label}</span>
    </label>
  )
}
