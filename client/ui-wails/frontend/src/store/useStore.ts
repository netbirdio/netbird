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
  // Connection state
  status: string;
  connected: boolean;
  loading: boolean;
  error: string | null;

  // Configuration
  config: Config | null;

  // Networks
  networks: Network[];
  networkFilter: 'all' | 'overlapping' | 'exit-nodes';

  // Profiles
  profiles: Profile[];
  activeProfile: Profile | null;

  // Peers
  peers: Peer[];
  localPeer: any | null;

  // Actions
  setStatus: (status: string, connected: boolean) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setConfig: (config: Config) => void;
  setNetworks: (networks: Network[]) => void;
  setNetworkFilter: (filter: 'all' | 'overlapping' | 'exit-nodes') => void;
  setProfiles: (profiles: Profile[]) => void;
  setActiveProfile: (profile: Profile | null) => void;
  setPeers: (peers: Peer[]) => void;
  setLocalPeer: (localPeer: any) => void;

  // Daemon operations
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  logout: () => Promise<void>;

  // Data refresh operations
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
}

export const useStore = create<AppState>((set, get) => ({
  // Initial state
  status: 'Disconnected',
  connected: false,
  loading: false,
  error: null,
  config: null,
  networks: [],
  networkFilter: 'all',
  profiles: [],
  activeProfile: null,
  peers: [],
  localPeer: null,

  // State setters
  setStatus: (status, connected) => set({ status, connected }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setConfig: (config) => set({ config }),
  setNetworks: (networks) => set({ networks }),
  setNetworkFilter: (filter) => set({ networkFilter: filter }),
  setProfiles: (profiles) => set({ profiles }),
  setActiveProfile: (profile) => set({ activeProfile: profile }),
  setPeers: (peers) => set({ peers }),
  setLocalPeer: (localPeer) => set({ localPeer }),

  // Daemon operations (placeholder implementations)
  connect: async () => {
    try {
      set({ loading: true, error: null });
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate API call
      set({ status: 'Connected', connected: true });
    } catch (error: any) {
      console.error('Connect error:', error);
      set({ error: error?.message || 'Failed to connect' });
      setTimeout(() => set({ error: null }), 5000);
    } finally {
      set({ loading: false });
    }
  },

  disconnect: async () => {
    try {
      set({ loading: true, error: null });
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
      set({ status: 'Disconnected', connected: false });
    } catch (error: any) {
      console.error('Disconnect error:', error);
      set({ error: error?.message || 'Failed to disconnect' });
      setTimeout(() => set({ error: null }), 5000);
    } finally {
      set({ loading: false });
    }
  },

  logout: async () => {
    try {
      set({ loading: true, error: null });
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
      set({ status: 'Logged Out', connected: false, activeProfile: null });
    } catch (error: any) {
      console.error('Logout error:', error);
    } finally {
      set({ loading: false });
    }
  },

  // Data refresh operations (placeholder implementations with mock data)
  refreshStatus: async () => {
    try {
      // TODO: Call Wails Go backend method
      const mockStatus = {
        status: 'Disconnected',
        daemon: 'Connected',
      };
      set({
        status: mockStatus.status,
        connected: mockStatus.status === 'Connected',
      });
    } catch (error) {
      console.error('Status refresh error:', error);
    }
  },

  refreshConfig: async () => {
    try {
      // TODO: Call Wails Go backend method
      const mockConfig: Config = {
        managementUrl: 'https://api.netbird.io:443',
        preSharedKey: '',
        interfaceName: 'wt0',
        wireguardPort: 51820,
        mtu: 1280,
        serverSSHAllowed: false,
        autoConnect: false,
        rosenpassEnabled: false,
        rosenpassPermissive: false,
        lazyConnectionEnabled: false,
        blockInbound: false,
        networkMonitor: true,
        disableDns: false,
        disableClientRoutes: false,
        disableServerRoutes: false,
        blockLanAccess: false,
      };
      set({ config: mockConfig });
    } catch (error) {
      console.error('Config refresh error:', error);
    }
  },

  updateConfig: async (config: Config) => {
    try {
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
      set({ config });
    } catch (error: any) {
      console.error('Config update error:', error);
      throw error;
    }
  },

  refreshNetworks: async () => {
    try {
      // TODO: Call Wails Go backend method
      const mockNetworks: Network[] = [];
      set({ networks: mockNetworks });
    } catch (error) {
      console.error('Networks refresh error:', error);
    }
  },

  toggleNetwork: async (networkId: string) => {
    try {
      // TODO: Call Wails Go backend method
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
      // TODO: Call Wails Go backend method
      const mockProfiles: Profile[] = [];
      set({ profiles: mockProfiles });
    } catch (error) {
      console.error('Profiles refresh error:', error);
    }
  },

  switchProfile: async (profileId: string) => {
    try {
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
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
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
      const profiles = get().profiles.filter(p => p.id !== profileId);
      set({ profiles });
    } catch (error) {
      console.error('Delete profile error:', error);
    }
  },

  addProfile: async (name: string) => {
    try {
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
      await get().refreshProfiles();
    } catch (error) {
      console.error('Add profile error:', error);
    }
  },

  removeProfile: async (profileId: string) => {
    try {
      // TODO: Call Wails Go backend method
      await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
      const profiles = get().profiles.filter(p => p.id !== profileId);
      set({ profiles });
    } catch (error) {
      console.error('Remove profile error:', error);
    }
  },

  refreshPeers: async () => {
    try {
      // TODO: Call Wails Go backend method
      const mockPeers: Peer[] = [];
      set({ peers: mockPeers });
    } catch (error) {
      console.error('Peers refresh error:', error);
    }
  },
}));
