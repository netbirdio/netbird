import { HashRouter, Routes, Route, useNavigate } from 'react-router-dom'
import { useEffect } from 'react'
import { Events } from '@wailsio/runtime'
import Status from './pages/Status'
import Settings from './pages/Settings'
import Networks from './pages/Networks'
import Profiles from './pages/Profiles'
import Peers from './pages/Peers'
import Debug from './pages/Debug'
import Update from './pages/Update'
import NavBar from './components/NavBar'

/**
 * Navigator listens for the "navigate" event emitted by the Go backend
 * and programmatically navigates the React router.
 */
function Navigator() {
  const navigate = useNavigate()

  useEffect(() => {
    const unsub = Events.On('navigate', (event: { data: string[] }) => {
      const path = event.data[0]
      if (path) navigate(path)
    })
    return () => {
      if (typeof unsub === 'function') unsub()
    }
  }, [navigate])

  return null
}

export default function App() {
  return (
    <HashRouter>
      <Navigator />
      <div
        className="min-h-screen flex"
        style={{
          backgroundColor: 'var(--color-bg-primary)',
          color: 'var(--color-text-primary)',
        }}
      >
        <NavBar />
        <main className="flex-1 px-10 py-8 overflow-y-auto h-screen">
          <Routes>
            <Route path="/" element={<Status />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/peers" element={<Peers />} />
            <Route path="/networks" element={<Networks />} />
            <Route path="/profiles" element={<Profiles />} />
            <Route path="/debug" element={<Debug />} />
            <Route path="/update" element={<Update />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  )
}
