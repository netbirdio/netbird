import { NavLink } from 'react-router-dom'
import NetBirdLogo from './NetBirdLogo'

const navItems = [
  { to: '/', label: 'Status', icon: StatusIcon },
  { to: '/peers', label: 'Peers', icon: PeersIcon },
  { to: '/networks', label: 'Networks', icon: NetworksIcon },
  { to: '/profiles', label: 'Profiles', icon: ProfilesIcon },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
  { to: '/debug', label: 'Debug', icon: DebugIcon },
  { to: '/update', label: 'Update', icon: UpdateIcon },
]

export default function NavBar() {
  return (
    <nav className="w-[15rem] min-w-[15rem] bg-nb-gray-950 border-r border-nb-gray-900 flex flex-col h-screen">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-nb-gray-900">
        <NetBirdLogo full />
      </div>

      {/* Nav items */}
      <div className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-[.87rem] font-normal transition-colors ${
                isActive
                  ? 'bg-nb-gray-900 text-white'
                  : 'text-nb-gray-400 hover:text-white hover:bg-nb-gray-900/50'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <item.icon active={isActive} />
                <span>{item.label}</span>
              </>
            )}
          </NavLink>
        ))}
      </div>

      {/* Version footer */}
      <div className="px-5 py-3 border-t border-nb-gray-900 text-xs text-nb-gray-500">
        NetBird Client
      </div>
    </nav>
  )
}

function StatusIcon({ active }: { active: boolean }) {
  return (
    <svg className={`w-4 h-4 shrink-0 ${active ? 'text-netbird' : 'text-nb-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </svg>
  )
}

function PeersIcon({ active }: { active: boolean }) {
  return (
    <svg className={`w-4 h-4 shrink-0 ${active ? 'text-netbird' : 'text-nb-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  )
}

function NetworksIcon({ active }: { active: boolean }) {
  return (
    <svg className={`w-4 h-4 shrink-0 ${active ? 'text-netbird' : 'text-nb-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="5" r="2" />
      <circle cx="5" cy="19" r="2" />
      <circle cx="19" cy="19" r="2" />
      <line x1="12" y1="7" x2="5" y2="17" />
      <line x1="12" y1="7" x2="19" y2="17" />
    </svg>
  )
}

function ProfilesIcon({ active }: { active: boolean }) {
  return (
    <svg className={`w-4 h-4 shrink-0 ${active ? 'text-netbird' : 'text-nb-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  )
}

function SettingsIcon({ active }: { active: boolean }) {
  return (
    <svg className={`w-4 h-4 shrink-0 ${active ? 'text-netbird' : 'text-nb-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}

function DebugIcon({ active }: { active: boolean }) {
  return (
    <svg className={`w-4 h-4 shrink-0 ${active ? 'text-netbird' : 'text-nb-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m8 2 1.88 1.88" />
      <path d="M14.12 3.88 16 2" />
      <path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1" />
      <path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6" />
      <path d="M12 20v-9" />
      <path d="M6.53 9C4.6 8.8 3 7.1 3 5" />
      <path d="M6 13H2" />
      <path d="M3 21c0-2.1 1.7-3.9 3.8-4" />
      <path d="M20.97 5c0 2.1-1.6 3.8-3.5 4" />
      <path d="M22 13h-4" />
      <path d="M17.2 17c2.1.1 3.8 1.9 3.8 4" />
    </svg>
  )
}

function UpdateIcon({ active }: { active: boolean }) {
  return (
    <svg className={`w-4 h-4 shrink-0 ${active ? 'text-netbird' : 'text-nb-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
      <path d="M3 3v5h5" />
      <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
      <path d="M16 16h5v5" />
    </svg>
  )
}
