import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Save, Shield, Zap, Globe, Activity, Lock, Monitor } from 'lucide-react';
import { useStore } from '../store/useStore';

export default function SettingsPage() {
  const { config, refreshConfig, updateConfig } = useStore();
  const [formData, setFormData] = useState({
    managementUrl: '',
    preSharedKey: '',
    interfaceName: '',
    wireguardPort: 51820,
    mtu: 1280,
    serverSSHAllowed: false,
    autoConnect: false,
    rosenpassEnabled: false,
    rosenpassPermissive: false,
    lazyConnectionEnabled: false,
    blockInbound: false,
    networkMonitor: false,
    disableDns: false,
    disableClientRoutes: false,
    disableServerRoutes: false,
    blockLanAccess: false,
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (config) {
      setFormData(config);
    }
  }, [config]);

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      setSaved(false);
      await updateConfig(formData);
      await refreshConfig();
      setSaved(true);
      // Auto-clear success message after 3 seconds
      setTimeout(() => setSaved(false), 3000);
    } catch (error: any) {
      console.error('Save error:', error);
      setError(error?.message || 'Failed to save settings');
      // Auto-clear error after 5 seconds
      setTimeout(() => setError(null), 5000);
    } finally {
      setSaving(false);
    }
  };

  const toggleSettings = [
    {
      key: 'serverSSHAllowed',
      icon: Shield,
      label: 'Allow SSH',
      description: 'Enable SSH server role for remote access',
    },
    {
      key: 'autoConnect',
      icon: Zap,
      label: 'Auto Connect',
      description: 'Automatically connect when the service starts',
    },
    {
      key: 'rosenpassEnabled',
      icon: Globe,
      label: 'Enable Rosenpass',
      description: 'Add post-quantum encryption layer',
    },
    {
      key: 'rosenpassPermissive',
      icon: Globe,
      label: 'Rosenpass Permissive Mode',
      description: 'Allow fallback if Rosenpass fails',
    },
    {
      key: 'lazyConnectionEnabled',
      icon: Activity,
      label: 'Enable Lazy Connections',
      description: 'Defer peer initialization until needed (experimental)',
    },
    {
      key: 'blockInbound',
      icon: Lock,
      label: 'Block Inbound Connections',
      description: 'Prevent inbound connections via firewall',
    },
    {
      key: 'networkMonitor',
      icon: Monitor,
      label: 'Network Monitor',
      description: 'Restart connection on network changes',
    },
    {
      key: 'blockLanAccess',
      icon: Lock,
      label: 'Block LAN Access',
      description: 'Disable access to local network',
    },
  ];

  return (
    <div className="h-full overflow-auto p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-text-light text-orange-glow mb-2">Settings</h1>
          <p className="text-text-muted">Configure your NetBird connection</p>
        </motion.div>

        {/* Connection Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="nb-card rounded-nb-card p-6 shadow-nb-card"
        >
          <h2 className="text-xl font-bold text-text-light mb-6">Connection</h2>
          <div className="space-y-4">
            <InputField
              label="Management URL"
              value={formData.managementUrl}
              onChange={(value) => setFormData({ ...formData, managementUrl: value })}
              placeholder="https://api.netbird.io"
            />
            <InputField
              label="Pre-shared Key"
              value={formData.preSharedKey}
              onChange={(value) => setFormData({ ...formData, preSharedKey: value })}
              placeholder="Optional WireGuard PSK"
              type="password"
            />
            <InputField
              label="Interface Name"
              value={formData.interfaceName}
              onChange={(value) => setFormData({ ...formData, interfaceName: value })}
              placeholder="wt0"
            />
            <div className="grid grid-cols-2 gap-4">
              <InputField
                label="WireGuard Port"
                value={formData.wireguardPort.toString()}
                onChange={(value) =>
                  setFormData({ ...formData, wireguardPort: parseInt(value) || 51820 })
                }
                type="number"
              />
              <InputField
                label="MTU"
                value={formData.mtu.toString()}
                onChange={(value) => setFormData({ ...formData, mtu: parseInt(value) || 1280 })}
                type="number"
              />
            </div>
          </div>
        </motion.div>

        {/* Feature Toggles */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="nb-card rounded-nb-card p-6 shadow-nb-card"
        >
          <h2 className="text-xl font-bold text-text-light mb-6">Features</h2>
          <div className="space-y-3">
            {toggleSettings.map((setting, index) => {
              const Icon = setting.icon;
              const isEnabled = formData[setting.key as keyof typeof formData] as boolean;

              return (
                <motion.div
                  key={setting.key}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="flex items-start gap-4 p-4 rounded-lg hover:bg-nb-orange/5 transition-all cursor-pointer border border-transparent hover:border-nb-orange/20"
                  onClick={() => setFormData({ ...formData, [setting.key]: !isEnabled })}
                >
                  <div
                    className={`p-3 rounded-lg transition-all ${
                      isEnabled ? 'bg-nb-orange/20 text-nb-orange border border-nb-orange/30' : 'bg-text-muted/20 text-text-muted border border-transparent'
                    }`}
                  >
                    <Icon className={`w-5 h-5 ${isEnabled ? 'drop-shadow-[0_0_8px_rgba(163,215,229,0.6)]' : ''}`} />
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-text-light">{setting.label}</h3>
                    <p className="text-sm text-text-muted mt-1">{setting.description}</p>
                  </div>
                  <div
                    className={`relative w-12 h-6 rounded-full p-1 transition-all ${
                      isEnabled ? 'bg-nb-orange shadow-icy-glow' : 'bg-text-muted/30'
                    }`}
                  >
                    <motion.div
                      animate={{ x: isEnabled ? 24 : 0 }}
                      transition={{ type: "spring", stiffness: 500, damping: 30 }}
                      className="w-4 h-4 bg-white rounded-full shadow-lg"
                    />
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>

        {/* Advanced Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="nb-card rounded-nb-card p-6 shadow-nb-card"
        >
          <h2 className="text-xl font-bold text-text-light mb-6">Advanced</h2>
          <div className="space-y-3">
            <CheckboxField
              label="Disable DNS Management"
              checked={formData.disableDns}
              onChange={(checked) => setFormData({ ...formData, disableDns: checked })}
              description="Keep system DNS unchanged"
            />
            <CheckboxField
              label="Disable Client Routes"
              checked={formData.disableClientRoutes}
              onChange={(checked) => setFormData({ ...formData, disableClientRoutes: checked })}
              description="Don't route traffic to peers"
            />
            <CheckboxField
              label="Disable Server Routes"
              checked={formData.disableServerRoutes}
              onChange={(checked) => setFormData({ ...formData, disableServerRoutes: checked })}
              description="Don't act as a router for peers"
            />
          </div>
        </motion.div>

        {/* Feedback Messages */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-red-500/10 border border-red-500/30 rounded-lg p-4"
          >
            <p className="text-red-400 font-medium">⚠️ {error}</p>
          </motion.div>
        )}

        {saved && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-green-500/10 border border-green-500/30 rounded-lg p-4"
          >
            <p className="text-green-400 font-medium">✓ Settings saved successfully!</p>
          </motion.div>
        )}

        {/* Save Button */}
        <motion.button
          whileHover={{ scale: saving ? 1 : 1.02 }}
          whileTap={{ scale: saving ? 1 : 0.98 }}
          onClick={handleSave}
          disabled={saving}
          className="w-full py-4 bg-nb-orange/30 text-nb-orange hover:bg-nb-orange/40 rounded-lg font-bold flex items-center justify-center gap-2 nb-border hover:nb-border-strong transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? (
            <>
              <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Saving...
            </>
          ) : (
            <>
              <Save className="w-5 h-5" />
              Save Settings
            </>
          )}
        </motion.button>
      </div>
    </div>
  );
}

function InputField({
  label,
  value,
  onChange,
  placeholder,
  type = 'text',
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <div>
      <label className="block text-sm font-medium text-text-muted mb-2">{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-4 py-3 bg-gray-bg-card border border-nb-orange/20 rounded-lg text-text-light placeholder-text-muted focus:border-nb-orange focus:outline-none focus:ring-2 focus:ring-nb-orange/20 transition-all"
      />
    </div>
  );
}

function CheckboxField({
  label,
  checked,
  onChange,
  description,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  description: string;
}) {
  return (
    <div
      className="flex items-start gap-3 p-4 rounded-lg hover:bg-nb-orange/5 transition-all cursor-pointer"
      onClick={() => onChange(!checked)}
    >
      <div
        className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all ${
          checked ? 'bg-nb-orange border-nb-orange' : 'border-text-muted/30'
        }`}
      >
        {checked && (
          <svg className="w-3 h-3 text-dark-bg" fill="currentColor" viewBox="0 0 12 12">
            <path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="2" fill="none" />
          </svg>
        )}
      </div>
      <div className="flex-1">
        <h3 className="font-medium text-text-light">{label}</h3>
        <p className="text-sm text-text-muted mt-1">{description}</p>
      </div>
    </div>
  );
}
