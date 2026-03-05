import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import type { ProfileInfo } from '../bindings'
import Card from '../components/ui/Card'
import CardRow from '../components/ui/CardRow'
import Button from '../components/ui/Button'
import Input from '../components/ui/Input'
import Modal from '../components/ui/Modal'

export default function Profiles() {
  const [profiles, setProfiles] = useState<ProfileInfo[]>([])
  const [newName, setNewName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<{ action: string; profile: string } | null>(null)

  async function refresh() {
    try {
      const data = await invoke<ProfileInfo[]>('list_profiles')
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
      if (confirm.action === 'switch') await invoke('switch_profile', { profileName: confirm.profile })
      else if (confirm.action === 'remove') await invoke('remove_profile', { profileName: confirm.profile })
      else if (confirm.action === 'logout') await invoke('logout', { profileName: confirm.profile })
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
      await invoke('add_profile', { profileName: newName.trim() })
      showInfo(`Profile '${newName.trim()}' created`)
      setNewName('')
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  function confirmTitle(): string {
    if (!confirm) return ''
    if (confirm.action === 'switch') return 'Switch Profile'
    if (confirm.action === 'remove') return 'Remove Profile'
    return 'Deregister Profile'
  }

  function confirmMessage(): string {
    if (!confirm) return ''
    if (confirm.action === 'switch') return `Switch to profile '${confirm.profile}'?`
    if (confirm.action === 'remove') return `Delete profile '${confirm.profile}'? This cannot be undone.`
    return `Deregister from '${confirm.profile}'?`
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-xl font-semibold mb-6" style={{ color: 'var(--color-text-primary)' }}>Profiles</h1>

      {error && (
        <div
          className="mb-4 p-3 rounded-[var(--radius-control)] text-[13px]"
          style={{ backgroundColor: 'var(--color-status-red-bg)', color: 'var(--color-status-red)' }}
        >
          {error}
        </div>
      )}
      {info && (
        <div
          className="mb-4 p-3 rounded-[var(--radius-control)] text-[13px]"
          style={{ backgroundColor: 'var(--color-status-green-bg)', color: 'var(--color-status-green)' }}
        >
          {info}
        </div>
      )}

      {confirm && (
        <Modal
          title={confirmTitle()}
          message={confirmMessage()}
          destructive={confirm.action === 'remove'}
          loading={loading}
          onConfirm={handleConfirm}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* Profile list */}
      <Card label="PROFILES" className="mb-6">
        {profiles.length === 0 ? (
          <div className="p-4 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>No profiles found.</div>
        ) : (
          profiles.map(p => (
            <CardRow key={p.name} label={p.name}>
              <div className="flex items-center gap-2">
                {p.isActive && (
                  <span
                    className="text-[11px] px-2 py-0.5 rounded-full font-medium"
                    style={{
                      backgroundColor: 'var(--color-status-green-bg)',
                      color: 'var(--color-status-green)',
                    }}
                  >
                    Active
                  </span>
                )}
                {!p.isActive && (
                  <Button variant="primary" size="sm" onClick={() => setConfirm({ action: 'switch', profile: p.name })}>
                    Select
                  </Button>
                )}
                <Button variant="secondary" size="sm" onClick={() => setConfirm({ action: 'logout', profile: p.name })}>
                  Deregister
                </Button>
                <Button variant="destructive" size="sm" onClick={() => setConfirm({ action: 'remove', profile: p.name })}>
                  Remove
                </Button>
              </div>
            </CardRow>
          ))
        )}
      </Card>

      {/* Add new profile */}
      <Card label="ADD PROFILE">
        <div className="flex items-center gap-3 px-4 py-3">
          <Input
            className="flex-1"
            placeholder="New profile name"
            value={newName}
            onChange={e => setNewName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAdd()}
          />
          <Button onClick={handleAdd} disabled={!newName.trim() || loading} size="sm">
            Add
          </Button>
        </div>
      </Card>
    </div>
  )
}
