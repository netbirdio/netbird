import { useState } from 'react';
import { motion } from 'framer-motion';
import { Bug, Package, AlertCircle, CheckCircle2, Copy, Check } from 'lucide-react';

export default function DebugPage() {
  const [creating, setCreating] = useState(false);
  const [anonymize, setAnonymize] = useState(true);
  const [bundlePath, setBundlePath] = useState('');
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const handleCreateBundle = async () => {
    try {
      setCreating(true);
      setError('');
      setBundlePath('');
      setCopied(false);

      // TODO: Implement debug bundle creation via IPC
      // const path = await window.electronAPI.daemon.createDebugBundle(anonymize);
      // setBundlePath(path);

      // Simulated for now
      await new Promise((resolve) => setTimeout(resolve, 2000));
      setBundlePath('/tmp/netbird-debug-bundle-20241030.zip');
    } catch (err) {
      setError('Failed to create debug bundle');
      console.error('Debug bundle error:', err);
    } finally {
      setCreating(false);
    }
  };

  const handleCopyPath = async () => {
    try {
      await navigator.clipboard.writeText(bundlePath);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy path:', err);
    }
  };

  return (
    <div className="h-full overflow-auto p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-text-light text-neon mb-2">Debug Bundle</h1>
          <p className="text-text-muted">Create diagnostic bundle for troubleshooting</p>
        </motion.div>

        {/* Info Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass rounded-glass p-6 shadow-glass"
        >
          <div className="flex items-start gap-4 mb-6">
            <div className="p-3 bg-icy-blue/20 rounded-lg">
              <AlertCircle className="w-6 h-6 text-icy-blue" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-text-light mb-2">What's included?</h3>
              <ul className="space-y-2 text-sm text-text-muted">
                <li>• System information</li>
                <li>• NetBird configuration</li>
                <li>• Network interfaces</li>
                <li>• Routing tables</li>
                <li>• Daemon logs</li>
              </ul>
            </div>
          </div>

          {/* Anonymize option */}
          <div
            className="flex items-start gap-3 p-4 rounded-lg hover:bg-icy-blue/5 transition-all cursor-pointer border border-transparent hover:border-icy-blue/20"
            onClick={() => setAnonymize(!anonymize)}
          >
            <div
              className={`relative w-12 h-6 rounded-full p-1 transition-all ${
                anonymize ? 'bg-icy-blue shadow-icy-glow' : 'bg-text-muted/30'
              }`}
            >
              <motion.div
                animate={{ x: anonymize ? 24 : 0 }}
                transition={{ type: "spring", stiffness: 500, damping: 30 }}
                className="w-4 h-4 bg-white rounded-full shadow-lg"
              />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-text-light">Anonymize sensitive data</h3>
              <p className="text-sm text-text-muted mt-1">
                Replace IP addresses, emails, and other identifying information
              </p>
            </div>
          </div>
        </motion.div>

        {/* Create Button */}
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={handleCreateBundle}
          disabled={creating}
          className="w-full py-4 bg-icy-blue/30 text-icy-blue hover:bg-icy-blue/40 rounded-lg font-bold flex items-center justify-center gap-2 neon-border hover:neon-border-strong transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Package className="w-5 h-5" />
          {creating ? 'Creating Bundle...' : 'Create Debug Bundle'}
        </motion.button>

        {/* Success message */}
        {bundlePath && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="glass rounded-glass p-6  border-2 border-icy-blue/30 shadow-glass"
          >
            <div className="flex items-start gap-4">
              <div className="p-3 bg-icy-blue/20 rounded-lg">
                <CheckCircle2 className="w-6 h-6 text-icy-blue" />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-bold text-text-light mb-2">Bundle Created!</h3>
                <p className="text-sm text-text-muted mb-3">
                  Your debug bundle has been created successfully
                </p>
                <div className="p-3 bg-dark-bg-card rounded-lg border border-icy-blue/10">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <p className="text-xs text-text-muted">File location:</p>
                    <button
                      onClick={handleCopyPath}
                      className="p-1 hover:bg-icy-blue/20 rounded transition-all"
                      title="Copy path"
                    >
                      {copied ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4 text-text-muted hover:text-icy-blue" />
                      )}
                    </button>
                  </div>
                  <p className="text-sm text-icy-blue font-mono break-all">{bundlePath}</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Error message */}
        {error && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="glass rounded-glass p-6  border-2 border-red-500/30 shadow-glass"
          >
            <div className="flex items-start gap-4">
              <div className="p-3 bg-red-500/20 rounded-lg">
                <AlertCircle className="w-6 h-6 text-red-500" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-text-light mb-2">Error</h3>
                <p className="text-sm text-text-muted">{error}</p>
              </div>
            </div>
          </motion.div>
        )}

        {/* Additional Info */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass rounded-glass p-6 shadow-glass"
        >
          <div className="flex items-start gap-4">
            <div className="p-3 bg-text-muted/20 rounded-lg">
              <Bug className="w-6 h-6 text-text-muted" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-text-light mb-2">Need Help?</h3>
              <p className="text-sm text-text-muted mb-3">
                If you're experiencing issues, create a debug bundle and share it with the NetBird
                support team.
              </p>
              <a
                href="https://github.com/netbirdio/netbird/issues"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-icy-blue hover:underline"
              >
                Report an issue on GitHub →
              </a>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
