import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import Lottie, { LottieRefCurrentProps } from 'lottie-react';
import {
  Settings, Network, Users, Bug, UserCircle,
  Home, Copy, Check, ChevronDown, Route
} from 'lucide-react';
import { useStore } from './store/useStore';
import Overview from './pages/Overview';
import SettingsPage from './pages/Settings';
import Networks from './pages/Networks';
import Profiles from './pages/Profiles';
import Peers from './pages/Peers';
import Debug from './pages/Debug';
import animationData from './assets/button-full.json';
import netbirdLogo from './assets/netbird-full.svg';

type Page = 'overview' | 'settings' | 'networks' | 'profiles' | 'debug' | 'peers';

export default function App() {
  const [currentPage, setCurrentPage] = useState<Page>('overview');
  const [copiedIp, setCopiedIp] = useState(false);
  const [copiedFqdn, setCopiedFqdn] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const expertMode = useStore((state) => state.expertMode);
  const lottieRef = useRef<LottieRefCurrentProps>(null);
  const profileDropdownRef = useRef<HTMLDivElement>(null);
  const connected = useStore((state) => state.connected);
  const profiles = useStore((state) => state.profiles);
  const activeProfile = useStore((state) => state.activeProfile);
  const switchProfile = useStore((state) => state.switchProfile);

  useEffect(() => {
    // Always start on overview page
    setCurrentPage('overview');

    // Initialize app
    useStore.getState().refreshStatus();
    useStore.getState().refreshConfig();
    useStore.getState().refreshExpertMode();
    useStore.getState().refreshPeers();
    useStore.getState().refreshLocalPeer();
    useStore.getState().refreshProfiles();

    // Set up periodic status refresh
    const interval = setInterval(() => {
      useStore.getState().refreshStatus();
      if (useStore.getState().connected) {
        useStore.getState().refreshPeers();
        useStore.getState().refreshLocalPeer();
      }
    }, 3000);

    // Listen for navigation messages from tray
    if (window.electronAPI?.onNavigateToPage) {
      window.electronAPI.onNavigateToPage((page: string) => {
        console.log('Navigation request from tray:', page);
        setCurrentPage(page as Page);
      });
    }

    return () => {
      clearInterval(interval);
    };
  }, []);

  // Handle animation based on connection state
  useEffect(() => {
    if (lottieRef.current) {
      if (connected) {
        // Play connect animation (frames 0-142)
        lottieRef.current.goToAndPlay(0, true);
        lottieRef.current.setSpeed(1.5);
      } else {
        // Play disconnect animation (frames 143-339) or stay at disconnected state
        if (lottieRef.current.currentFrame > 142) {
          // Already in disconnected state
          lottieRef.current.goToAndStop(339, true);
        } else {
          // Play disconnect animation
          lottieRef.current.goToAndPlay(143, true);
          lottieRef.current.setSpeed(1.5);
        }
      }
    }
  }, [connected]);

  // Handle click outside profile dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (profileDropdownRef.current && !profileDropdownRef.current.contains(event.target as Node)) {
        setProfileDropdownOpen(false);
      }
    };

    if (profileDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [profileDropdownOpen]);

  const navItems = [
    { id: 'overview' as Page, icon: Home, label: 'Overview' },
    { id: 'peers' as Page, icon: Users, label: 'Peers' },
    { id: 'networks' as Page, icon: Network, label: 'Networks' },
    { id: 'profiles' as Page, icon: UserCircle, label: 'Profiles' },
    { id: 'settings' as Page, icon: Settings, label: 'Settings' },
    { id: 'debug' as Page, icon: Bug, label: 'Debug' },
  ];

  const renderPage = () => {
    switch (currentPage) {
      case 'overview':
        return <Overview onNavigate={setCurrentPage} />;
      case 'settings':
        return <SettingsPage />;
      case 'networks':
        return <Networks />;
      case 'profiles':
        return <Profiles />;
      case 'peers':
        return <Peers />;
      case 'debug':
        return <Debug onBack={() => setCurrentPage('overview')} />;
      default:
        return <Overview onNavigate={setCurrentPage} />;
    }
  };

  const status = useStore((state) => state.status);
  const loading = useStore((state) => state.loading);
  const version = useStore((state) => state.version);
  const connect = useStore((state) => state.connect);
  const disconnect = useStore((state) => state.disconnect);

  const handleClick = () => {
    if (loading) return;
    if (connected) {
      disconnect();
    } else {
      connect();
    }
  };

  // Clean, user-friendly UI with connect button as centerpiece
  const peers = useStore((state) => state.peers);
  const connectedPeersCount = peers.filter(p => p.connStatus === 'Connected').length;
  const localPeer = useStore((state) => state.localPeer);

  const handleDebugClick = () => {
    setCurrentPage('debug');
  };

  const handlePeersClick = () => {
    setCurrentPage('peers');
  };

  const handleCopyIp = async () => {
    if (localPeer?.ip) {
      await navigator.clipboard.writeText(localPeer.ip);
      setCopiedIp(true);
      setTimeout(() => setCopiedIp(false), 2000);
    }
  };

  const handleCopyFqdn = async () => {
    if (localPeer?.fqdn) {
      await navigator.clipboard.writeText(localPeer.fqdn);
      setCopiedFqdn(true);
      setTimeout(() => setCopiedFqdn(false), 2000);
    }
  };

  // If debug page is active, render it
  if (currentPage === 'debug') {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-bg overflow-hidden">
        <Debug onBack={() => setCurrentPage('overview')} />
      </div>
    );
  }

  // If peers page is active, render it
  if (currentPage === 'peers') {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-bg overflow-hidden">
        <Peers onBack={() => setCurrentPage('overview')} />
      </div>
    );
  }

  // Bottom Navigation Bar Component
  const BottomNav = () => {
    if (!expertMode) return null;

    return (
      <div className="absolute bottom-0 left-0 right-0 h-16 nb-frosted border-t border-nb-orange/20 flex items-center justify-around px-4 backdrop-blur-md z-50">
        <button
          onClick={() => setCurrentPage('overview')}
          className={`flex flex-col items-center gap-1 px-4 py-2 rounded-lg transition-all ${
            currentPage === 'overview'
              ? 'text-nb-orange bg-nb-orange/10'
              : 'text-text-muted hover:text-nb-orange hover:bg-nb-orange/5'
          }`}
        >
          <Home className="w-5 h-5" />
          <span className="text-xs font-medium">Home</span>
        </button>

        <button
          onClick={() => setCurrentPage('networks')}
          className={`flex flex-col items-center gap-1 px-4 py-2 rounded-lg transition-all ${
            currentPage === 'networks'
              ? 'text-nb-orange bg-nb-orange/10'
              : 'text-text-muted hover:text-nb-orange hover:bg-nb-orange/5'
          }`}
        >
          <Network className="w-5 h-5" />
          <span className="text-xs font-medium">Networks</span>
        </button>

        <button
          onClick={() => setCurrentPage('settings')}
          className={`flex flex-col items-center gap-1 px-4 py-2 rounded-lg transition-all ${
            currentPage === 'settings'
              ? 'text-nb-orange bg-nb-orange/10'
              : 'text-text-muted hover:text-nb-orange hover:bg-nb-orange/5'
          }`}
        >
          <Settings className="w-5 h-5" />
          <span className="text-xs font-medium">Settings</span>
        </button>
      </div>
    );
  };

  // If profiles page is active, render it
  if (currentPage === 'profiles') {
    return (
      <div className="h-screen w-screen bg-gray-bg overflow-hidden relative flex flex-col">
        <div className="flex-1 overflow-auto pb-20">
          <Profiles onBack={() => setCurrentPage('overview')} />
        </div>
        <BottomNav />
      </div>
    );
  }

  // If settings page is active, render it
  if (currentPage === 'settings') {
    return (
      <div className="h-screen w-screen bg-gray-bg overflow-hidden relative flex flex-col">
        <div className="flex-1 overflow-auto pb-20">
          <SettingsPage onBack={() => setCurrentPage('overview')} />
        </div>
        <BottomNav />
      </div>
    );
  }

  // If networks page is active, render it
  if (currentPage === 'networks') {
    return (
      <div className="h-screen w-screen bg-gray-bg overflow-hidden relative flex flex-col">
        <div className="flex-1 overflow-auto pb-20">
          <Networks onBack={() => setCurrentPage('overview')} />
        </div>
        <BottomNav />
      </div>
    );
  }

  // Otherwise render main overview UI
  return (
    <div className="h-screen w-screen bg-gray-bg overflow-hidden relative flex flex-col">
      {/* Main Content - Scrollable */}
      <div className="flex-1 overflow-auto pb-20">
        {/* Main Content Container */}
        <div className="p-4 w-full min-h-full flex flex-col">
        {/* Main scrollable content */}
        <div className="flex-1 space-y-6">
        {/* NetBird Logo */}
        <div className="flex justify-center">
          <img
            src={netbirdLogo}
            alt="NetBird"
            className="h-12 w-auto opacity-90"
          />
        </div>

        {/* Connection Status Badge */}
        <div className="flex justify-center">
          <motion.div
            animate={{
              scale: connected ? [1, 1.05, 1] : 1,
            }}
            transition={{ duration: 2, repeat: connected ? Infinity : 0 }}
            className={`px-6 py-2 rounded-full text-lg font-bold transition-all ${
              connected
                ? 'bg-nb-orange/20 text-nb-orange nb-border-strong orange-pulse'
                : loading
                ? 'bg-nb-orange/10 text-nb-orange border border-nb-orange/30'
                : 'bg-gray-bg-card text-text-muted border border-nb-orange/20'
            }`}
          >
            {status}
          </motion.div>
        </div>

        {/* Main Lottie Animation Button - Centerpiece */}
        <div className="flex justify-center py-4">
          <button
            onClick={handleClick}
            disabled={loading}
            className={`relative transition-all duration-300 ${
              loading ? 'opacity-80 cursor-wait' : 'hover:scale-105 active:scale-95 cursor-pointer'
            }`}
            style={{ width: '240px', height: '240px' }}
            title={connected ? 'Click to disconnect' : 'Click to connect'}
          >
            <Lottie
              lottieRef={lottieRef}
              animationData={animationData}
              loop={false}
              autoplay={false}
              style={{
                width: '100%',
                height: '100%',
                filter: 'brightness(0) saturate(100%) invert(57%) sepia(98%) saturate(2548%) hue-rotate(345deg) brightness(101%) contrast(94%)',
              }}
              rendererSettings={{
                preserveAspectRatio: 'xMidYMid meet',
                clearCanvas: false,
              }}
            />
          </button>
        </div>

        {/* Profile Dropdown - Expert Mode Only */}
        {expertMode && activeProfile && (
          <div ref={profileDropdownRef} className="relative flex justify-center mb-4">
            <button
              onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
              className="flex items-center gap-2 px-4 py-2 nb-frosted rounded-lg hover:bg-nb-orange/10 transition-all"
            >
              <UserCircle className="w-4 h-4 text-nb-orange" />
              <span className="text-sm font-medium text-text-light">
                {activeProfile.name}
                {activeProfile.email && (
                  <span className="text-text-muted ml-1">({activeProfile.email})</span>
                )}
              </span>
              <ChevronDown className={`w-4 h-4 text-text-muted transition-transform ${profileDropdownOpen ? 'rotate-180' : ''}`} />
            </button>

            {/* Dropdown Menu */}
            {profileDropdownOpen && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="absolute top-full mt-2 w-64 nb-card rounded-lg shadow-lg z-50 overflow-hidden flex flex-col"
              >
                <div className="overflow-y-auto max-h-40">
                {profiles.map((profile) => (
                  <button
                    key={profile.id}
                    onClick={() => {
                      switchProfile(profile.id);
                      setProfileDropdownOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-nb-orange/10 transition-colors ${
                      profile.active ? 'bg-nb-orange/5' : ''
                    }`}
                  >
                    <UserCircle className={`w-4 h-4 ${profile.active ? 'text-nb-orange' : 'text-text-muted'}`} />
                    <div className="flex-1 text-left">
                      <div className={`text-sm font-medium ${profile.active ? 'text-nb-orange' : 'text-text-light'}`}>
                        {profile.name}
                      </div>
                      {profile.email && (
                        <div className="text-xs text-text-muted">({profile.email})</div>
                      )}
                    </div>
                    {profile.active && (
                      <Check className="w-4 h-4 text-nb-orange" />
                    )}
                  </button>
                ))}
                </div>

                {/* Divider */}
                <div className="border-t border-nb-orange/20" />

                {/* Manage Profiles Button */}
                <button
                  onClick={() => {
                    setCurrentPage('profiles');
                    setProfileDropdownOpen(false);
                  }}
                  className="w-full flex items-center gap-3 px-4 py-3 hover:bg-nb-orange/10 transition-colors"
                >
                  <Settings className="w-4 h-4 text-text-muted" />
                  <div className="flex-1 text-left">
                    <div className="text-sm font-medium text-text-light">
                      Manage Profiles
                    </div>
                  </div>
                </button>
              </motion.div>
            )}
          </div>
        )}

        {/* Connection Info - Only when connected */}
        {connected && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-3 border-t border-nb-orange/20 pt-4"
          >
            {/* Local Peer Info */}
            {localPeer && (
              <div className="p-3 nb-frosted rounded-lg">
                <div className="text-center">
                  <div className="text-xs text-text-muted uppercase mb-1">Your NetBird IP</div>
                  <div className="flex items-center justify-center gap-2">
                    <div className="text-lg font-semibold text-nb-orange">{localPeer.ip}</div>
                    <button
                      onClick={handleCopyIp}
                      className="p-1 hover:bg-nb-orange/10 rounded transition-colors"
                      title="Copy IP"
                    >
                      {copiedIp ? (
                        <Check className="w-4 h-4 text-green-500" />
                      ) : (
                        <Copy className="w-4 h-4 text-text-muted hover:text-nb-orange" />
                      )}
                    </button>
                  </div>
                  {localPeer.fqdn && (
                    <div className="flex items-center justify-center gap-2 mt-1">
                      <div className="text-xs text-text-muted">{localPeer.fqdn}</div>
                      <button
                        onClick={handleCopyFqdn}
                        className="p-1 hover:bg-nb-orange/10 rounded transition-colors"
                        title="Copy FQDN"
                      >
                        {copiedFqdn ? (
                          <Check className="w-3 h-3 text-green-500" />
                        ) : (
                          <Copy className="w-3 h-3 text-text-muted hover:text-nb-orange" />
                        )}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Connected Peers Counter */}
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={handlePeersClick}
              className="w-full flex items-center justify-center gap-3 p-3 nb-frosted rounded-lg hover:bg-nb-orange/10 transition-all cursor-pointer"
            >
              <Users className="w-5 h-5 text-nb-orange" />
              <span className="text-lg font-semibold">
                <span className="text-nb-orange">{connectedPeersCount}</span>
                <span className="text-text-muted"> / {peers.length}</span>
                <span className="text-sm text-text-muted ml-2">peers</span>
              </span>
            </motion.button>
          </motion.div>
        )}

        {/* Helpful hint when disconnected */}
        {!connected && !loading && (
          <div className="text-center text-sm text-text-muted">
            Click the button to establish secure connection
          </div>
        )}
        </div>

        {/* Version Info - Bottom, subtle - Fixed at bottom */}
        <div className="flex items-center justify-center gap-3 pt-2 mt-4 border-t border-nb-orange/10">
          <div className="text-center text-xs text-text-muted/60">
            NetBird v{version}
          </div>
          <button
            onClick={handleDebugClick}
            className="p-1 hover:bg-nb-orange/10 rounded transition-colors"
            title="Debug Tools"
          >
            <Bug className="w-3 h-3 text-text-muted/40 hover:text-nb-orange/60" />
          </button>
        </div>
        </div>
      </div>

      <BottomNav />

      {/* DISABLED UI - Keeping code for future use */}
      {false && (
        <>
          {/* Sidebar */}
          <motion.div
            initial={{ x: -300 }}
            animate={{ x: 0 }}
            className="w-64 nb-sidebar flex flex-col"
          >
            {/* Navigation */}
            <nav className="flex-1 p-4 space-y-2">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = currentPage === item.id;

                return (
                  <motion.button
                    key={item.id}
                    whileHover={{ x: 4 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => setCurrentPage(item.id)}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all nb-nav-item ${
                      isActive
                        ? 'nb-nav-active'
                        : 'text-text-muted hover:text-text-light border-l-3 border-transparent'
                    }`}
                  >
                    <Icon className={`w-5 h-5 ${isActive ? 'text-nb-orange' : ''}`} />
                    <span className="font-medium">{item.label}</span>
                  </motion.button>
                );
              })}
            </nav>

            {/* Footer */}
            <div className="p-4 border-t border-nb-orange/20">
              <div className="text-xs text-text-muted text-center">
                NetBird Client v1.0.0
              </div>
              {expertMode && (
                <div className="mt-2 px-2 py-1 bg-nb-orange/20 border border-nb-orange/40 rounded text-xs text-nb-orange text-center font-semibold">
                  EXPERT MODE
                </div>
              )}
            </div>
          </motion.div>

          {/* Main Content */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <motion.div
              key={currentPage}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
              className="flex-1 overflow-auto"
            >
              {renderPage()}
            </motion.div>
          </div>
        </>
      )}
    </div>
  );
}
