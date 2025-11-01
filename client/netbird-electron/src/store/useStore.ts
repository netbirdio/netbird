import { create } from 'zustand';

interface Config {
  managementUrl: string;
  preSharedKey: string;
  interfaceName: string;
  wireguardPort: number;
  mtu: number;
  serverSSHAllowed: boolean;
  autoConnect: boolean;
  rosenpassEnabled: boolean;
  rosenpassPermissive: boolean;
  lazyConnectionEnabled: boolean;
  blockInbound: boolean;
  networkMonitor: boolean;
  disableDns: boolean;
  disableClientRoutes: boolean;
  disableServerRoutes: boolean;
  blockLanAccess: boolean;
}

interface Network {
  id: string;
  networkRange: string;
  domains: string[];
  resolvedIPs: string[];
  selected: boolean;
}

interface Profile {
  id: string;
  name: string;
  email?: string;
  active: boolean;
}

interface Peer {
  ip: string;
  pubKey: string;
  connStatus: string;
  connStatusUpdate: string;
  relayed: boolean;
  localIceCandidateType: string;
  remoteIceCandidateType: string;
  fqdn: string;
  localIceCandidateEndpoint: string;
  remoteIceCandidateEndpoint: string;
  lastWireguardHandshake: string;
  bytesRx: number;
  bytesTx: number;
  rosenpassEnabled: boolean;
  networks: string[];
  latency: number;
  relayAddress: string;
}

interface AppState {
  status: string;
  connected: boolean;
  loading: boolean;
  error: string | null;
  version: string;
  config: Config | null;
  networks: Network[];
  networkFilter: 'all' | 'overlapping' | 'exit-nodes';
  profiles: Profile[];
  activeProfile: Profile | null;
  peers: Peer[];
  localPeer: any | null;
  expertMode: boolean;

  setStatus: (status: string, connected: boolean, version?: string) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setConfig: (config: Config) => void;
  setNetworks: (networks: Network[]) => void;
  setNetworkFilter: (filter: 'all' | 'overlapping' | 'exit-nodes') => void;
  setProfiles: (profiles: Profile[]) => void;
  setActiveProfile: (profile: Profile | null) => void;
  setPeers: (peers: Peer[]) => void;
  setLocalPeer: (localPeer: any) => void;
  setExpertMode: (expertMode: boolean) => void;

  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  logout: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  refreshConfig: () => Promise<void>;
  updateConfig: (config: Config) => Promise<void>;
  refreshNetworks: () => Promise<void>;
  toggleNetwork: (networkId: string) => Promise<void>;
  refreshProfiles: () => Promise<void>;
  switchProfile: (profileId: string) => Promise<void>;
  deleteProfile: (profileId: string) => Promise<void>;
  addProfile: (name: string) => Promise<void>;
  removeProfile: (profileId: string) => Promise<void>;
  refreshPeers: () => Promise<void>;
  refreshExpertMode: () => Promise<void>;
}

export const useStore = create<AppState>((set, get) => ({
  status: 'Disconnected',
  connected: false,
  loading: false,
  error: null,
  version: '0.0.0',
  config: null,
  networks: [],
  networkFilter: 'all',
  profiles: [],
  activeProfile: null,
  peers: [],
  localPeer: null,
  expertMode: false,

  setStatus: (status, connected, version) => set({ status, connected, ...(version && { version }) }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setConfig: (config) => set({ config }),
  setNetworks: (networks) => set({ networks }),
  setNetworkFilter: (filter) => set({ networkFilter: filter }),
  setProfiles: (profiles) => set({ profiles }),
  setActiveProfile: (profile) => set({ activeProfile: profile }),
  setPeers: (peers) => set({ peers }),
  setLocalPeer: (localPeer) => set({ localPeer }),
  setExpertMode: (expertMode) => set({ expertMode }),

  connect: async () => {
    try {
      set({ loading: true, error: null });
      await window.electronAPI.connect();
      // Wait a moment for daemon to update, then fetch actual status
      await new Promise(resolve => setTimeout(resolve, 500));
      await get().refreshStatus();
    } catch (error: any) {
      set({ error: error?.message || 'Failed to connect' });
      setTimeout(() => set({ error: null }), 5000);
    } finally {
      set({ loading: false });
    }
  },

  disconnect: async () => {
    try {
      set({ loading: true, error: null });
      await window.electronAPI.disconnect();
      // Wait a moment for daemon to update, then fetch actual status
      await new Promise(resolve => setTimeout(resolve, 500));
      await get().refreshStatus();
    } catch (error: any) {
      set({ error: error?.message || 'Failed to disconnect' });
      setTimeout(() => set({ error: null }), 5000);
    } finally {
      set({ loading: false });
    }
  },

  logout: async () => {
    try {
      set({ loading: true, error: null });
      await window.electronAPI.logout();
      set({ status: 'Logged Out', connected: false, activeProfile: null });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      set({ loading: false });
    }
  },

  refreshStatus: async () => {
    try {
      const status = await window.electronAPI.getStatus();
      set({
        status: status.status,
        connected: status.status === 'Connected',
        version: status.version || '0.0.0',
      });
    } catch (error) {
      console.error('Status refresh error:', error);
    }
  },

  refreshConfig: async () => {
    try {
      const config = await window.electronAPI.getConfig();
      set({ config });
    } catch (error) {
      console.error('Config refresh error:', error);
    }
  },

  updateConfig: async (config: Config) => {
    try {
      await window.electronAPI.updateConfig(config);
      set({ config });
    } catch (error: any) {
      console.error('Config update error:', error);
      throw error;
    }
  },

  refreshNetworks: async () => {
    try {
      const networks = await window.electronAPI.getNetworks();
      set({ networks });
    } catch (error) {
      console.error('Networks refresh error:', error);
    }
  },

  toggleNetwork: async (networkId: string) => {
    try {
      await window.electronAPI.toggleNetwork(networkId);
      const networks = get().networks.map(net =>
        net.id === networkId ? { ...net, selected: !net.selected } : net
      );
      set({ networks });
    } catch (error) {
      console.error('Toggle network error:', error);
    }
  },

  refreshProfiles: async () => {
    try {
      const profiles = await window.electronAPI.getProfiles();
      const active = profiles.find(p => p.active);
      set({ profiles, activeProfile: active || null });
    } catch (error) {
      console.error('Profiles refresh error:', error);
    }
  },

  switchProfile: async (profileId: string) => {
    try {
      await window.electronAPI.switchProfile(profileId);
      const profile = get().profiles.find(p => p.id === profileId);
      if (profile) {
        set({ activeProfile: profile });
      }
    } catch (error) {
      console.error('Switch profile error:', error);
    }
  },

  deleteProfile: async (profileId: string) => {
    try {
      await window.electronAPI.deleteProfile(profileId);
      const profiles = get().profiles.filter(p => p.id !== profileId);
      set({ profiles });
    } catch (error) {
      console.error('Delete profile error:', error);
    }
  },

  addProfile: async (name: string) => {
    try {
      await window.electronAPI.addProfile(name);
      await get().refreshProfiles();
    } catch (error) {
      console.error('Add profile error:', error);
    }
  },

  removeProfile: async (profileId: string) => {
    try {
      await window.electronAPI.removeProfile(profileId);
      const profiles = get().profiles.filter(p => p.id !== profileId);
      set({ profiles });
    } catch (error) {
      console.error('Remove profile error:', error);
    }
  },

  refreshPeers: async () => {
    try {
      const peers = await window.electronAPI.getPeers();
      set({ peers });
    } catch (error) {
      console.error('Peers refresh error:', error);
    }
  },

  refreshLocalPeer: async () => {
    try {
      const localPeer = await window.electronAPI.getLocalPeer();
      set({ localPeer });
    } catch (error) {
      console.error('Local peer refresh error:', error);
    }
  },

  refreshExpertMode: async () => {
    try {
      const expertMode = await window.electronAPI.getExpertMode();
      set({ expertMode });
    } catch (error) {
      console.error('Expert mode refresh error:', error);
    }
  },
}));
