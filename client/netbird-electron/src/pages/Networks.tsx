import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { RefreshCw, Globe, CheckCircle2, Circle } from 'lucide-react';
import { useStore } from '../store/useStore';

export default function NetworksPage() {
  const { networks, networkFilter, setNetworkFilter, refreshNetworks, toggleNetwork } = useStore();
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    refreshNetworks();
  }, [refreshNetworks]);

  const handleRefresh = async () => {
    setLoading(true);
    await refreshNetworks();
    setLoading(false);
  };

  const handleToggleNetwork = async (networkId: string) => {
    try {
      await toggleNetwork(networkId);
    } catch (error) {
      console.error('Toggle network error:', error);
    }
  };

  const filteredNetworks = networks.filter((network) => {
    if (networkFilter === 'all') return true;
    // Add filtering logic for overlapping and exit-nodes when available
    return true;
  });

  return (
    <div className="h-full overflow-auto p-8">
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between mb-8"
        >
          <div>
            <h1 className="text-3xl font-bold text-text-light text-orange-glow mb-2">Networks</h1>
            <p className="text-text-muted">Manage network routes and exit nodes</p>
          </div>
          <motion.button
            whileHover={{ scale: 1.05, rotate: loading ? 360 : 0 }}
            whileTap={{ scale: 0.95 }}
            onClick={handleRefresh}
            disabled={loading}
            className="p-3 bg-nb-orange/20 text-nb-orange rounded-lg hover:bg-nb-orange/30 nb-border hover:nb-border-strong transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
          </motion.button>
        </motion.div>

        {/* Filter tabs */}
        <div className="flex gap-2">
          {['all', 'overlapping', 'exit-nodes'].map((filter) => (
            <motion.button
              key={filter}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => setNetworkFilter(filter as any)}
              className={`px-6 py-2 rounded-lg font-medium transition-all ${
                networkFilter === filter
                  ? 'bg-nb-orange/30 text-nb-orange border border-nb-orange/30'
                  : 'bg-gray-bg-card text-text-muted hover:text-text-light'
              }`}
            >
              {filter === 'all' ? 'All Networks' : filter === 'overlapping' ? 'Overlapping' : 'Exit Nodes'}
            </motion.button>
          ))}
        </div>

        {/* Networks list */}
        <div className="space-y-3">
          {filteredNetworks.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="nb-card rounded-nb-card p-12 text-center shadow-nb-card"
            >
              <Globe className="w-16 h-16 text-text-muted mx-auto mb-4" />
              <h3 className="text-xl font-bold text-text-light mb-2">No Networks Found</h3>
              <p className="text-text-muted">There are no networks available at the moment</p>
            </motion.div>
          ) : (
            filteredNetworks.map((network, index) => (
              <motion.div
                key={network.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className="nb-card rounded-nb-card p-6 cursor-pointer transition-all hover:bg-nb-orange/5"
                onClick={() => handleToggleNetwork(network.id)}
              >
                <div className="flex items-start gap-4">
                  <div
                    className={`p-3 rounded-lg ${
                      network.selected
                        ? 'bg-nb-orange/20 text-nb-orange'
                        : 'bg-text-muted/20 text-text-muted'
                    }`}
                  >
                    {network.selected ? (
                      <CheckCircle2 className="w-6 h-6" />
                    ) : (
                      <Circle className="w-6 h-6" />
                    )}
                  </div>

                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-lg font-bold text-text-light">{network.id}</h3>
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-medium ${
                          network.selected
                            ? 'bg-nb-orange/20 text-nb-orange'
                            : 'bg-text-muted/20 text-text-muted'
                        }`}
                      >
                        {network.selected ? 'Active' : 'Inactive'}
                      </span>
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm">
                        <span className="text-text-muted">Range:</span>
                        <span className="text-text-light font-mono">{network.networkRange}</span>
                      </div>

                      {network.domains && network.domains.length > 0 && (
                        <div className="flex items-start gap-2 text-sm">
                          <span className="text-text-muted">Domains:</span>
                          <div className="flex flex-wrap gap-2">
                            {network.domains.map((domain) => (
                              <span
                                key={domain}
                                className="px-2 py-1 bg-gray-bg-card rounded text-text-light font-mono text-xs border border-nb-orange/10"
                              >
                                {domain}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {network.resolvedIPs && network.resolvedIPs.length > 0 && (
                        <div className="flex items-start gap-2 text-sm">
                          <span className="text-text-muted">IPs:</span>
                          <div className="flex flex-wrap gap-2">
                            {network.resolvedIPs.map((ip) => (
                              <span
                                key={ip}
                                className="px-2 py-1 bg-gray-bg-card rounded text-text-light font-mono text-xs border border-nb-orange/10"
                              >
                                {ip}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </motion.div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
