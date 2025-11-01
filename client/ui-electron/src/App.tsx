import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Wifi,
  WifiOff,
  Settings,
  Network,
  User,
  Bug,
  LogOut,
  Home,
  Users,
} from 'lucide-react';
import { useStore } from './store/useStore';
import Overview from './pages/Overview';
import SettingsPage from './pages/Settings';
import NetworksPage from './pages/Networks';
import ProfilesPage from './pages/Profiles';
import DebugPage from './pages/Debug';
import Peers from './pages/Peers';

type Page = 'overview' | 'settings' | 'networks' | 'profiles' | 'debug' | 'peers';

function App() {
  const [currentPage, setCurrentPage] = useState<Page>('overview');
  const { status, connected, refreshStatus, refreshConfig, refreshProfiles } = useStore();

  useEffect(() => {
    // Initial data load
    refreshStatus();
    refreshConfig();
    refreshProfiles();

    // Listen for navigation from main process
    if (window.electronAPI) {
      window.electronAPI.onNavigate((path: string) => {
        if (path === '/settings') setCurrentPage('settings');
        else if (path === '/networks') setCurrentPage('networks');
        else if (path === '/debug') setCurrentPage('debug');
        else if (path === '/profiles') setCurrentPage('profiles');
        else setCurrentPage('overview');
      });
    }
  }, [refreshStatus, refreshConfig, refreshProfiles]);

  const navItems = [
    { id: 'overview', label: 'Overview', icon: Home },
    { id: 'peers', label: 'Peers', icon: Users },
    { id: 'networks', label: 'Networks', icon: Network },
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'profiles', label: 'Profiles', icon: User },
    { id: 'debug', label: 'Debug', icon: Bug },
  ];

  return (
    <div className="flex h-screen bg-dark-bg text-text-light overflow-hidden">
      {/* Sidebar */}
      <motion.div
        initial={{ x: -300 }}
        animate={{ x: 0 }}
        className="w-64 bg-dark-bg-card border-r border-icy-blue/20 flex flex-col"
      >
        {/* Logo & Status */}
        <div className="p-6 border-b border-icy-blue/20">
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center transition-all ${
              connected
                ? 'bg-icy-blue/10 border border-icy-blue/30 neon-pulse'
                : 'bg-dark-bg border border-icy-blue/10'
            }`}>
              {connected ? (
                <Wifi className="w-6 h-6 text-icy-blue" />
              ) : (
                <WifiOff className="w-6 h-6 text-text-muted" />
              )}
            </div>
            <div>
              <h1 className="text-xl font-bold text-text-light">NetBird</h1>
              <p className="text-xs text-text-muted">{status}</p>
            </div>
          </div>

          {/* Connection indicator */}
          <div className="flex items-center gap-2">
            <div
              className={`w-2 h-2 rounded-full transition-all ${
                connected ? 'bg-icy-blue shadow-icy-glow' : 'bg-text-muted'
              }`}
            />
            <span className={`text-sm ${
              connected ? 'text-icy-blue font-medium' : 'text-text-muted'
            }`}>
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;

            return (
              <motion.button
                key={item.id}
                whileHover={{ scale: 1.02, x: 4 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => setCurrentPage(item.id as Page)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                  isActive
                    ? 'bg-icy-blue/10 text-icy-blue border border-icy-blue/30 shadow-icy-glow'
                    : 'text-text-muted hover:text-text-light hover:bg-dark-bg hover:border-icy-blue/30 hover:shadow-icy-glow border border-transparent'
                }`}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
              </motion.button>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-icy-blue/20">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => useStore.getState().logout()}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-text-muted hover:text-text-light hover:bg-dark-bg hover:border-icy-blue/20 border border-transparent transition-all"
          >
            <LogOut className="w-5 h-5" />
            <span className="font-medium">Logout</span>
          </motion.button>
        </div>
      </motion.div>

      {/* Main content */}
      <div className="flex-1 overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.div
            key={currentPage}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
            className="h-full"
          >
            {currentPage === 'overview' && <Overview onNavigate={setCurrentPage} />}
            {currentPage === 'peers' && <Peers onNavigate={setCurrentPage} />}
            {currentPage === 'settings' && <SettingsPage />}
            {currentPage === 'networks' && <NetworksPage />}
            {currentPage === 'profiles' && <ProfilesPage />}
            {currentPage === 'debug' && <DebugPage />}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

export default App;
