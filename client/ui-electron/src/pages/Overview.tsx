import { useEffect } from 'react';
import { motion } from 'framer-motion';
import { Wifi, WifiOff, Power, User, Shield, Zap, Globe, Activity, Users } from 'lucide-react';
import { useStore } from '../store/useStore';
import LottieButton from '../components/LottieButton';

type Page = 'overview' | 'settings' | 'networks' | 'profiles' | 'debug' | 'peers';

interface OverviewProps {
  onNavigate: (page: Page) => void;
}

export default function Overview({ onNavigate }: OverviewProps) {
  const { status, connected, loading, error, connect, disconnect, activeProfile, config, peers, refreshPeers } = useStore();

  const connectedPeers = peers.filter(peer => peer.connStatus === 'Connected').length;

  // Auto-refresh peers data every 5 seconds when connected
  useEffect(() => {
    if (connected && status === 'Connected') {
      // Initial refresh
      refreshPeers().catch(err => console.error('Failed to refresh peers:', err));

      // Set up interval for continuous refresh
      const interval = setInterval(() => {
        if (connected && status === 'Connected') {
          refreshPeers().catch(err => console.error('Failed to refresh peers:', err));
        }
      }, 5000);

      return () => clearInterval(interval);
    }
  }, [connected, status, refreshPeers]);

  const handleToggleConnection = async () => {
    if (connected) {
      await disconnect();
    } else {
      await connect();
    }
  };

  const features = [
    {
      icon: Shield,
      label: 'Allow SSH',
      enabled: config?.serverSSHAllowed,
      description: 'SSH server access',
    },
    {
      icon: Zap,
      label: 'Auto Connect',
      enabled: config?.autoConnect,
      description: 'Connect on startup',
    },
    {
      icon: Globe,
      label: 'Rosenpass',
      enabled: config?.rosenpassEnabled,
      description: 'Quantum resistance',
    },
    {
      icon: Activity,
      label: 'Lazy Connection',
      enabled: config?.lazyConnectionEnabled,
      description: 'On-demand peers',
    },
  ];

  return (
    <div className="h-full overflow-auto p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Connection Status Card */}
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="glass rounded-glass p-8 shadow-glass"
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-3xl font-bold text-text-light mb-2 text-neon">Connection Status</h2>
              <p className="text-text-muted">Manage your NetBird VPN connection</p>
            </div>
            <motion.div
              animate={{
                scale: connected ? [1, 1.05, 1] : 1,
              }}
              transition={{ duration: 2, repeat: connected ? Infinity : 0 }}
              className={`p-4 rounded-full ${
                connected ? 'bg-dark-bg-card neon-border-strong neon-pulse' : 'bg-dark-bg-card border border-icy-blue/20'
              }`}
            >
              {connected ? (
                <Wifi className="w-12 h-12 text-icy-blue drop-shadow-[0_0_10px_rgba(163,215,229,0.8)]" />
              ) : (
                <WifiOff className="w-12 h-12 text-text-muted" />
              )}
            </motion.div>
          </div>

          {/* Status display and Peers Counter */}
          <div className="flex items-center justify-between gap-4 mb-6 flex-wrap">
            <div
              className={`px-6 py-3 rounded-lg font-semibold text-lg transition-all ${
                connected
                  ? 'bg-icy-blue/10 text-icy-blue neon-border shimmer'
                  : 'bg-dark-bg-card text-text-muted border border-icy-blue/20'
              }`}
            >
              {status}
            </div>

            {/* Connected Peers Counter - Only show when connected */}
            {connected && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => onNavigate('peers')}
                className="flex items-center gap-2 px-4 py-3 frosted rounded-lg neon-border cursor-pointer hover:neon-border-strong transition-all"
              >
                <Users className="w-5 h-5 text-icy-blue drop-shadow-[0_0_8px_rgba(163,215,229,0.6)]" />
                <span className="text-lg font-semibold text-text-light">
                  <span className="text-icy-blue text-neon">{connectedPeers}</span>
                  <span className="text-text-muted"> / {peers.length}</span>
                </span>
                <span className="text-xs text-text-muted">peers</span>
              </motion.div>
            )}
          </div>

          {/* Error message */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-4"
            >
              <p className="text-red-400 font-medium">⚠️ {error}</p>
            </motion.div>
          )}

          {/* Lottie Connection Button */}
          <div className="flex flex-col items-center gap-4">
            <LottieButton
              status={status}
              connected={connected}
              loading={loading}
              onClick={handleToggleConnection}
            />
            {/* Status text below button */}
            <div className="text-center">
              <p className="text-text-light font-semibold text-xl">
                {loading
                  ? connected
                    ? 'Disconnecting...'
                    : 'Connecting...'
                  : status === 'NeedsLogin'
                  ? 'Login Required'
                  : connected
                  ? 'Connected'
                  : 'Disconnected'}
              </p>
            </div>
          </div>
        </motion.div>

        {/* Profile Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass rounded-glass p-6 shadow-glass"
        >
          <h3 className="text-xl font-bold text-text-light mb-4">Active Profile</h3>

          {activeProfile ? (
            <motion.div
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              onClick={() => onNavigate('profiles')}
              className="flex items-center gap-4 p-4 frosted rounded-lg neon-border cursor-pointer hover:neon-border-strong transition-all"
            >
              <div className="p-3 bg-dark-bg-card rounded-lg border border-icy-blue/20">
                <User className="w-6 h-6 text-icy-blue drop-shadow-[0_0_8px_rgba(163,215,229,0.6)]" />
              </div>
              <div className="flex-1">
                <div className="font-semibold text-text-light">{activeProfile.name}</div>
                {activeProfile.email && (
                  <div className="text-sm text-text-muted">{activeProfile.email}</div>
                )}
              </div>
              <div className="text-xs text-text-muted font-medium px-3 py-1 bg-dark-bg-card rounded">
                Click to manage
              </div>
            </motion.div>
          ) : (
            <motion.div
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              onClick={() => onNavigate('profiles')}
              className="text-center py-8 text-text-muted cursor-pointer hover:bg-dark-bg-card/30 rounded-lg transition-all"
            >
              <User className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No active profile</p>
              <p className="text-sm mt-1">Click to configure a profile</p>
            </motion.div>
          )}
        </motion.div>

        {/* Features Grid */}
        <div className="grid grid-cols-2 gap-4">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <motion.div
                key={feature.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 + index * 0.1 }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => onNavigate('settings')}
                className={`frosted rounded-md p-6 transition-all cursor-pointer ${
                  feature.enabled
                    ? 'neon-border'
                    : 'border border-icy-blue/10 hover:border-icy-blue/20'
                }`}
              >
                <div className="flex items-start gap-4">
                  <div
                    className={`p-3 rounded-lg transition-all ${
                      feature.enabled
                        ? 'bg-icy-blue/10 text-icy-blue border border-icy-blue/30'
                        : 'bg-dark-bg-card text-text-muted border border-icy-blue/10'
                    }`}
                  >
                    <Icon className={`w-6 h-6 ${feature.enabled ? 'drop-shadow-[0_0_8px_rgba(163,215,229,0.6)]' : ''}`} />
                  </div>
                  <div className="flex-1">
                    <h3 className={`font-semibold mb-1 ${
                      feature.enabled ? 'text-icy-blue' : 'text-text-light'
                    }`}>{feature.label}</h3>
                    <p className="text-sm text-text-muted">{feature.description}</p>
                    <div
                      className={`mt-2 inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium transition-all ${
                        feature.enabled
                          ? 'bg-icy-blue/10 text-icy-blue border border-icy-blue/30'
                          : 'bg-dark-bg-card text-text-muted border border-icy-blue/20'
                      }`}
                    >
                      <div className={`w-1.5 h-1.5 rounded-full transition-all ${
                        feature.enabled ? 'bg-icy-blue icy-glow-animate' : 'bg-text-muted'
                      }`} />
                      {feature.enabled ? 'Active' : 'Inactive'}
                    </div>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
