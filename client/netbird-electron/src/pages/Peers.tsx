import { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Users, Wifi, WifiOff, Shield, Activity, RefreshCw, Filter, Network, Copy, Check, ArrowLeft } from 'lucide-react';
import { useStore } from '../store/useStore';

interface PeersProps {
  onBack?: () => void;
}

type ConnectionFilter = 'all' | 'connected' | 'disconnected' | 'relayed';

export default function Peers({ onBack }: PeersProps) {
  const { peers, refreshPeers, connected } = useStore();
  const [search, setSearch] = useState('');
  const [connectionFilter, setConnectionFilter] = useState<ConnectionFilter>('all');
  const [refreshing, setRefreshing] = useState(false);
  const [copiedItems, setCopiedItems] = useState<Record<string, boolean>>({});

  useEffect(() => {
    refreshPeers();
    // Refresh peers every 5 seconds when connected
    const interval = setInterval(() => {
      if (connected) {
        refreshPeers();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [connected, refreshPeers]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await refreshPeers();
    setTimeout(() => setRefreshing(false), 500);
  };

  const handleCopy = async (text: string, itemId: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedItems(prev => ({ ...prev, [itemId]: true }));
      setTimeout(() => {
        setCopiedItems(prev => ({ ...prev, [itemId]: false }));
      }, 2000);
    } catch (err) {
      console.error('Failed to copy text:', err);
    }
  };

  // Filter and search peers
  const filteredPeers = useMemo(() => {
    const filtered = peers.filter(peer => {
      // Connection filter
      if (connectionFilter === 'connected' && peer.connStatus !== 'Connected') return false;
      if (connectionFilter === 'disconnected' && peer.connStatus === 'Connected') return false;
      if (connectionFilter === 'relayed' && !peer.relayed) return false;

      // Search filter
      if (search) {
        const searchLower = search.toLowerCase();
        return (
          peer.fqdn.toLowerCase().includes(searchLower) ||
          peer.ip.toLowerCase().includes(searchLower) ||
          peer.pubKey.toLowerCase().includes(searchLower)
        );
      }

      return true;
    });

    // Sort by IP address to maintain stable list order
    return filtered.sort((a, b) => {
      // Convert IP addresses to comparable format
      const ipToNumber = (ip: string) => {
        const parts = ip.split('.').map(Number);
        return (parts[0] || 0) * 16777216 + (parts[1] || 0) * 65536 + (parts[2] || 0) * 256 + (parts[3] || 0);
      };
      return ipToNumber(a.ip) - ipToNumber(b.ip);
    });
  }, [peers, search, connectionFilter]);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatLatency = (ms: number) => {
    if (ms === 0) return 'N/A';
    return `${ms.toFixed(0)}ms`;
  };

  const getConnectionColor = (status: string) => {
    switch (status) {
      case 'Connected':
        return 'text-nb-orange';
      case 'Connecting':
        return 'text-yellow-400';
      default:
        return 'text-text-muted';
    }
  };

  const getConnectionIcon = (status: string) => {
    return status === 'Connected' ? Wifi : WifiOff;
  };

  return (
    <div className="h-full overflow-auto p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Back Button */}
        {onBack && (
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={onBack}
            className="flex items-center gap-2 px-4 py-2 nb-frosted rounded-lg nb-border hover:nb-border-strong transition-all"
          >
            <ArrowLeft className="w-4 h-4 text-nb-orange" />
            <span className="text-text-light font-medium">Back</span>
          </motion.button>
        )}

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between"
        >
          <div className="flex items-center gap-4">
            <div className="p-3 bg-nb-orange/20 rounded-lg nb-border">
              <Users className="w-8 h-8 text-nb-orange drop-shadow-[0_0_10px_rgba(163,215,229,0.8)]" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-text-light text-orange-glow">Peers</h1>
              <p className="text-text-muted">
                {filteredPeers.length} of {peers.length} peer{peers.length !== 1 ? 's' : ''}
              </p>
            </div>
          </div>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={handleRefresh}
            disabled={refreshing}
            className="p-3 bg-nb-orange/20 text-nb-orange rounded-lg hover:bg-nb-orange/30 nb-border hover:nb-border-strong transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-5 h-5 ${refreshing ? 'animate-spin' : ''}`} />
          </motion.button>
        </motion.div>

        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="nb-card rounded-nb-card p-4 shadow-nb-card"
        >
          <div className="flex flex-col gap-3">
            {/* Connection Filter - First Row */}
            <div className="flex flex-wrap gap-2">
              {(['all', 'connected', 'disconnected', 'relayed'] as ConnectionFilter[]).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setConnectionFilter(filter)}
                  className={`px-3 py-2 rounded-lg font-medium text-sm transition-all ${
                    connectionFilter === filter
                      ? 'bg-nb-orange/30 text-nb-orange border border-nb-orange/30'
                      : 'bg-gray-bg-card text-text-muted hover:bg-nb-orange/10 border border-transparent'
                  }`}
                >
                  {filter.charAt(0).toUpperCase() + filter.slice(1)}
                </button>
              ))}
            </div>

            {/* Search - Second Row */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-text-muted w-4 h-4" />
              <input
                type="text"
                placeholder="Search by FQDN, IP, or public key..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 text-sm bg-gray-bg-card border border-nb-orange/20 rounded-lg text-text-light placeholder-text-muted focus:outline-none focus:border-nb-orange/50 transition-all"
              />
            </div>
          </div>
        </motion.div>

        {/* Peer List */}
        <AnimatePresence mode="popLayout">
          {filteredPeers.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="nb-card rounded-nb-card p-12 text-center shadow-nb-card"
            >
              <Users className="w-16 h-16 mx-auto mb-4 text-text-muted opacity-50" />
              <h3 className="text-xl font-semibold text-text-light mb-2">No peers found</h3>
              <p className="text-text-muted">
                {!connected
                  ? 'Connect to NetBird to see your peers'
                  : search || connectionFilter !== 'all'
                  ? 'Try adjusting your search or filters'
                  : 'No peers are currently available'}
              </p>
            </motion.div>
          ) : (
            <div className="space-y-4">
              {filteredPeers.map((peer, index) => {
                const Icon = getConnectionIcon(peer.connStatus);
                return (
                  <motion.div
                    key={peer.pubKey}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ delay: index * 0.05 }}
                    className="nb-card rounded-nb-card p-6 hover:bg-nb-orange/5 transition-all shadow-nb-card"
                  >
                    <div className="flex items-start gap-4">
                      {/* Status Icon */}
                      <div
                        className={`p-3 rounded-lg ${
                          peer.connStatus === 'Connected'
                            ? 'bg-nb-orange/30 text-nb-orange'
                            : 'bg-text-muted/20 text-text-muted'
                        }`}
                      >
                        <Icon className="w-6 h-6" />
                      </div>

                      {/* Peer Info */}
                      <div className="flex-1 space-y-3">
                        {/* Main Info */}
                        <div className="flex flex-col gap-2">
                          {/* Peer Name and IP */}
                          <div className="min-w-0 overflow-hidden">
                            <div className="flex items-center gap-2 min-w-0">
                              <h3 className="text-xl font-semibold text-text-light truncate flex-1 min-w-0">
                                {peer.fqdn || peer.ip || 'Unknown Peer'}
                              </h3>
                              {peer.fqdn && (
                                <button
                                  onClick={() => handleCopy(peer.fqdn, `fqdn-${peer.pubKey}`)}
                                  className="p-1 hover:bg-nb-orange/20 rounded transition-all flex-shrink-0"
                                  title="Copy FQDN"
                                >
                                  {copiedItems[`fqdn-${peer.pubKey}`] ? (
                                    <Check className="w-4 h-4 text-green-400" />
                                  ) : (
                                    <Copy className="w-4 h-4 text-text-muted hover:text-nb-orange" />
                                  )}
                                </button>
                              )}
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <p className="text-sm text-text-muted">{peer.ip}</p>
                              <button
                                onClick={() => handleCopy(peer.ip, `ip-${peer.pubKey}`)}
                                className="p-1 hover:bg-nb-orange/20 rounded transition-all flex-shrink-0"
                                title="Copy IP"
                              >
                                {copiedItems[`ip-${peer.pubKey}`] ? (
                                  <Check className="w-3 h-3 text-green-400" />
                                ) : (
                                  <Copy className="w-3 h-3 text-text-muted hover:text-nb-orange" />
                                )}
                              </button>
                            </div>
                          </div>

                          {/* Status Badges */}
                          <div className="flex items-center gap-2 flex-wrap">
                            {peer.rosenpassEnabled && (
                              <span className="px-2 py-1 bg-nb-orange/20 text-nb-orange text-xs font-medium rounded border border-nb-orange/30 whitespace-nowrap">
                                <Shield className="w-3 h-3 inline mr-1" />
                                Quantum-Safe
                              </span>
                            )}
                            <span
                              className={`px-3 py-1 rounded text-sm font-medium whitespace-nowrap ${
                                peer.connStatus === 'Connected'
                                  ? 'bg-nb-orange/20 text-nb-orange border border-nb-orange/30'
                                  : 'bg-text-muted/20 text-text-muted border border-text-muted/20'
                              }`}
                            >
                              {peer.connStatus}
                            </span>
                          </div>
                        </div>

                        {/* Connection Details Grid */}
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                          {/* Connection Type */}
                          <div className="space-y-1">
                            <p className="text-xs text-text-muted uppercase">Connection</p>
                            <p className="text-sm font-medium text-text-light">
                              {peer.relayed ? (
                                <span className="text-yellow-400">
                                  <Network className="w-4 h-4 inline mr-1" />
                                  Relayed
                                </span>
                              ) : peer.connStatus === 'Connected' ? (
                                <span className="text-nb-orange">Direct P2P</span>
                              ) : (
                                <span className="text-text-muted">-</span>
                              )}
                            </p>
                          </div>

                          {/* Latency */}
                          <div className="space-y-1">
                            <p className="text-xs text-text-muted uppercase">Latency</p>
                            <p className="text-sm font-medium text-text-light">
                              <Activity className="w-4 h-4 inline mr-1 text-nb-orange" />
                              {formatLatency(peer.latency)}
                            </p>
                          </div>

                          {/* Data Transferred */}
                          <div className="space-y-1">
                            <p className="text-xs text-text-muted uppercase">Received</p>
                            <p className="text-sm font-medium text-text-light">
                              {formatBytes(peer.bytesRx)}
                            </p>
                          </div>

                          <div className="space-y-1">
                            <p className="text-xs text-text-muted uppercase">Sent</p>
                            <p className="text-sm font-medium text-text-light">
                              {formatBytes(peer.bytesTx)}
                            </p>
                          </div>
                        </div>

                        {/* ICE Candidates */}
                        {peer.connStatus === 'Connected' && (
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2 border-t border-nb-orange/10">
                            <div className="space-y-1">
                              <p className="text-xs text-text-muted uppercase">Local Endpoint</p>
                              <p className="text-xs font-mono text-text-light break-all">
                                {peer.localIceCandidateType && `${peer.localIceCandidateType}: `}
                                {peer.localIceCandidateEndpoint || 'N/A'}
                              </p>
                            </div>
                            <div className="space-y-1">
                              <p className="text-xs text-text-muted uppercase">Remote Endpoint</p>
                              <p className="text-xs font-mono text-text-light break-all">
                                {peer.remoteIceCandidateType && `${peer.remoteIceCandidateType}: `}
                                {peer.remoteIceCandidateEndpoint || 'N/A'}
                              </p>
                            </div>
                          </div>
                        )}

                        {/* Networks */}
                        {peer.networks && peer.networks.length > 0 && (
                          <div className="space-y-1 pt-2">
                            <p className="text-xs text-text-muted uppercase">Networks</p>
                            <div className="flex flex-wrap gap-2">
                              {peer.networks.map((network) => (
                                <span
                                  key={network}
                                  className="px-2 py-1 bg-gray-bg-card text-text-light text-xs rounded border border-nb-orange/20"
                                >
                                  {network}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Public Key - Collapsed by default */}
                        <details className="pt-2">
                          <summary className="text-xs text-text-muted uppercase cursor-pointer hover:text-nb-orange transition-colors">
                            Public Key
                          </summary>
                          <p className="text-xs font-mono text-text-light break-all mt-2 p-2 bg-gray-bg-card rounded border border-nb-orange/10">
                            {peer.pubKey}
                          </p>
                        </details>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
