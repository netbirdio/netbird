import { useState, useEffect } from 'react'
import { Call } from '@wailsio/runtime'
import type { ProfileInfo } from '../bindings'

export default function Profiles() {
  const [profiles, setProfiles] = useState<ProfileInfo[]>([])
  const [newName, setNewName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<{ action: string; profile: string } | null>(null)

  async function refresh() {
    try {
      console.log('[Profiles] calling services.ProfileService.ListProfiles')
      const data = await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ProfileService.ListProfiles') as ProfileInfo[]
      console.log('[Profiles] ListProfiles returned', data?.length ?? 0, 'profiles')
      setProfiles(data ?? [])
    } catch (e) {
      console.error('[Profiles] ListProfiles error:', e)
      setError(String(e))
    }
  }

  useEffect(() => { refresh() }, [])

  function showInfo(msg: string) {
    setInfo(msg)
    setTimeout(() => setInfo(null), 3000)
  }

  async function handleConfirm() {
    if (!confirm) return
    setLoading(true)
    setError(null)
    try {
      if (confirm.action === 'switch') await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ProfileService.SwitchProfile', confirm.profile)
      else if (confirm.action === 'remove') await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ProfileService.RemoveProfile', confirm.profile)
      else if (confirm.action === 'logout') await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ProfileService.Logout', confirm.profile)
      showInfo(`${confirm.action === 'switch' ? 'Switched to' : confirm.action === 'remove' ? 'Removed' : 'Deregistered from'} profile '${confirm.profile}'`)
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
      setConfirm(null)
    }
  }

  async function handleAdd() {
    if (!newName.trim()) return
    setLoading(true)
    setError(null)
    try {
      await Call.ByName('github.com/netbirdio/netbird/client/uiwails/services.ProfileService.AddProfile', newName.trim())
      showInfo(`Profile '${newName.trim()}' created`)
      setNewName('')
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Profiles</h1>

      {error && (
        <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded-lg text-red-300 text-sm">
          {error}
        </div>
      )}
      {info && (
        <div className="mb-4 p-3 bg-green-900/50 border border-green-700 rounded-lg text-green-300 text-sm">
          {info}
        </div>
      )}

      {/* Confirm dialog */}
      {confirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-nb-gray-920 rounded-xl p-6 max-w-sm w-full mx-4 border border-nb-gray-900">
            <h2 className="text-lg font-semibold mb-2 capitalize">
              {confirm.action === 'switch' ? 'Switch Profile' : confirm.action === 'remove' ? 'Remove Profile' : 'Deregister Profile'}
            </h2>
            <p className="text-nb-gray-300 text-sm mb-5">
              {confirm.action === 'switch' && `Switch to profile '${confirm.profile}'?`}
              {confirm.action === 'remove' && `Delete profile '${confirm.profile}'? This cannot be undone.`}
              {confirm.action === 'logout' && `Deregister from '${confirm.profile}'?`}
            </p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirm(null)} className="px-4 py-2 text-sm bg-nb-gray-900 hover:bg-nb-gray-800 rounded-lg">
                Cancel
              </button>
              <button onClick={handleConfirm} disabled={loading} className="px-4 py-2 text-sm bg-netbird hover:bg-netbird-500 disabled:opacity-50 rounded-lg">
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Profile list */}
      <div className="bg-nb-gray-920 rounded-xl border border-nb-gray-900 overflow-hidden mb-6">
        {profiles.length === 0 ? (
          <div className="p-4 text-nb-gray-400 text-sm">No profiles found.</div>
        ) : (
          profiles.map(p => (
            <div key={p.name} className="flex items-center gap-3 px-4 py-3 border-b border-nb-gray-900 last:border-0">
              <span className="text-green-400 w-5 text-center">
                {p.isActive ? '✓' : ''}
              </span>
              <span className="flex-1 font-medium">{p.name}</span>
              {p.isActive && <span className="text-xs text-netbird px-2 py-0.5 bg-netbird-950/40 rounded-full">Active</span>}
              <div className="flex gap-2">
                {!p.isActive && (
                  <button
                    onClick={() => setConfirm({ action: 'switch', profile: p.name })}
                    className="px-3 py-1 text-xs bg-netbird-600 hover:bg-netbird-500 rounded transition-colors"
                  >
                    Select
                  </button>
                )}
                <button
                  onClick={() => setConfirm({ action: 'logout', profile: p.name })}
                  className="px-3 py-1 text-xs bg-nb-gray-900 hover:bg-nb-gray-800 rounded transition-colors"
                >
                  Deregister
                </button>
                <button
                  onClick={() => setConfirm({ action: 'remove', profile: p.name })}
                  className="px-3 py-1 text-xs bg-red-900 hover:bg-red-800 rounded transition-colors"
                >
                  Remove
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Add new profile */}
      <div className="flex gap-3">
        <input
          className="flex-1 px-3 py-2 bg-nb-gray-920 border border-nb-gray-800 rounded-lg text-sm focus:outline-none focus:border-netbird"
          placeholder="New profile name"
          value={newName}
          onChange={e => setNewName(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />
        <button
          onClick={handleAdd}
          disabled={!newName.trim() || loading}
          className="px-4 py-2 text-sm bg-netbird hover:bg-netbird-500 disabled:opacity-50 rounded-lg transition-colors"
        >
          Add Profile
        </button>
      </div>
    </div>
  )
}
