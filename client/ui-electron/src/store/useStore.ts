import { create } from 'zustand';

interface Config {
  managementUrl: string;
  preSharedKey: string;
  interfaceName: string;
  interfacePort: number;
  mtu: number;
  allowSSH: boolean;
  autoConnect: boolean;
  rosenpass: boolean;
  lazyConnection: boolean;
  blockInbound: boolean;
  networkMonitor: boolean;
  disableDNS: boolean;
  disableClientRoutes: boolean;
  disableServerRoutes: boolean;
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
  refreshStatus: () => Promise<void>;
  refreshConfig: () => Promise<void>;
  updateConfig: (config: Partial<Config>) => Promise<void>;
  refreshNetworks: () => Promise<void>;
  toggleNetwork: (networkId: string) => Promise<void>;
  refreshProfiles: () => Promise<void>;
  switchProfile: (profileId: string) => Promise<void>;
  addProfile: (profileName: string) => Promise<void>;
  removeProfile: (profileId: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshPeers: () => Promise<void>;
}

export const useStore = create<AppState>((set, get) => ({
  // Initial state
  status: 'Unknown',
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
  setNetworkFilter: (networkFilter) => set({ networkFilter }),
  setProfiles: (profiles) => set({ profiles }),
  setActiveProfile: (activeProfile) => set({ activeProfile }),
  setPeers: (peers) => set({ peers }),
  setLocalPeer: (localPeer) => set({ localPeer }),

  // Daemon operations
  connect: async () => {
    try {
      set({ loading: true, error: null });

      // First, try to call login to get the SSO URL
      const loginResponse = await window.electronAPI.daemon.login();

      if (loginResponse.needsSSOLogin && loginResponse.verificationURIComplete) {
        // Open browser for SSO login
        console.log('Opening browser for SSO login:', loginResponse.verificationURIComplete);
        await window.electronAPI.shell.openExternal(loginResponse.verificationURIComplete);

        // Wait for the user to complete login in browser
        if (loginResponse.userCode) {
          console.log('Waiting for SSO login completion...');
          const ssoResult = await window.electronAPI.daemon.waitSSOLogin(loginResponse.userCode);
          console.log('SSO login completed for:', ssoResult.email);
        }
      }

      // Now call up to actually connect
      await window.electronAPI.daemon.up();
      await get().refreshStatus();
    } catch (error: any) {
      console.error('Connect error:', error);
      const errorMessage = error?.message || 'Failed to connect';
      set({ error: errorMessage });
      // Auto-clear error after 5 seconds
      setTimeout(() => set({ error: null }), 5000);
    } finally {
      set({ loading: false });
    }
  },

  disconnect: async () => {
    try {
      set({ loading: true, error: null });
      await window.electronAPI.daemon.down();
      await get().refreshStatus();
    } catch (error: any) {
      console.error('Disconnect error:', error);
      const errorMessage = error?.message || 'Failed to disconnect';
      set({ error: errorMessage });
      // Auto-clear error after 5 seconds
      setTimeout(() => set({ error: null }), 5000);
    } finally {
      set({ loading: false });
    }
  },

  refreshStatus: async () => {
    try {
      const status = await window.electronAPI.daemon.getStatus();
      const connected = status === 'Connected';
      set({ status, connected, loading: false });
    } catch (error) {
      console.error('Refresh status error:', error);
      set({ status: 'Error', connected: false, loading: false });
    }
  },

  refreshConfig: async () => {
    try {
      const config = await window.electronAPI.daemon.getConfig();
      set({ config });
    } catch (error) {
      console.error('Refresh config error:', error);
    }
  },

  updateConfig: async (configUpdate) => {
    try {
      const currentConfig = get().config;
      if (!currentConfig) return;

      const newConfig = { ...currentConfig, ...configUpdate };
      await window.electronAPI.daemon.updateConfig(newConfig);
      set({ config: newConfig });
    } catch (error) {
      console.error('Update config error:', error);
      throw error;
    }
  },

  refreshNetworks: async () => {
    try {
      const networks = await window.electronAPI.daemon.listNetworks();
      set({ networks });
    } catch (error) {
      console.error('Refresh networks error:', error);
    }
  },

  toggleNetwork: async (networkId) => {
    try {
      const network = get().networks.find((n) => n.id === networkId);
      if (!network) return;

      if (network.selected) {
        await window.electronAPI.daemon.deselectNetworks([networkId]);
      } else {
        await window.electronAPI.daemon.selectNetworks([networkId]);
      }

      await get().refreshNetworks();
    } catch (error) {
      console.error('Toggle network error:', error);
      throw error;
    }
  },

  refreshProfiles: async () => {
    try {
      // Get profiles list from daemon (includes active flag)
      const profiles = await window.electronAPI.daemon.listProfiles();

      console.log('Profiles from daemon:', JSON.stringify(profiles, null, 2));

      // Find the active profile from the list
      const activeProfile = profiles.find((p: any) => p.active) || null;

      console.log('Active profile:', activeProfile);

      set({ profiles, activeProfile });
    } catch (error) {
      console.error('Refresh profiles error:', error);
      // Set empty state on error
      set({ profiles: [], activeProfile: null });
    }
  },

  switchProfile: async (profileId) => {
    try {
      console.log('Store: Calling daemon.switchProfile with profileId:', profileId);
      await window.electronAPI.daemon.switchProfile(profileId);
      console.log('Store: daemon.switchProfile completed, refreshing profiles');
      await get().refreshProfiles();
      console.log('Store: Profiles refreshed, refreshing status');
      await get().refreshStatus();
      console.log('Store: Status refreshed, switch complete');
    } catch (error) {
      console.error('Switch profile error:', error);
      throw error;
    }
  },

  addProfile: async (profileName) => {
    try {
      await window.electronAPI.daemon.addProfile(profileName);
      await get().refreshProfiles();
    } catch (error) {
      console.error('Add profile error:', error);
      throw error;
    }
  },

  removeProfile: async (profileId) => {
    try {
      await window.electronAPI.daemon.removeProfile(profileId);
      await get().refreshProfiles();
    } catch (error) {
      console.error('Remove profile error:', error);
      throw error;
    }
  },

  logout: async () => {
    try {
      await window.electronAPI.daemon.logout();
      await get().refreshStatus();
      await get().refreshProfiles();
    } catch (error) {
      console.error('Logout error:', error);
      throw error;
    }
  },

  refreshPeers: async () => {
    try {
      console.log('refreshPeers: Calling getFullStatus...');
      const fullStatus = await window.electronAPI.daemon.getFullStatus();
      console.log('refreshPeers: Got fullStatus:', fullStatus);
      if (fullStatus && fullStatus.peers) {
        console.log('refreshPeers: Found', fullStatus.peers.length, 'peers');
        const mappedPeers = fullStatus.peers.map((peer: any) => ({
          ip: peer.IP || '',
          pubKey: peer.pubKey || '',
          connStatus: peer.connStatus || '',
          connStatusUpdate: peer.connStatusUpdate || '',
          relayed: peer.relayed || false,
          localIceCandidateType: peer.localIceCandidateType || '',
          remoteIceCandidateType: peer.remoteIceCandidateType || '',
          fqdn: peer.fqdn || '',
          localIceCandidateEndpoint: peer.localIceCandidateEndpoint || '',
          remoteIceCandidateEndpoint: peer.remoteIceCandidateEndpoint || '',
          lastWireguardHandshake: peer.lastWireguardHandshake || '',
          bytesRx: parseInt(peer.bytesRx) || 0,
          bytesTx: parseInt(peer.bytesTx) || 0,
          rosenpassEnabled: peer.rosenpassEnabled || false,
          networks: peer.networks || [],
          latency: peer.latency ? (parseInt(peer.latency.seconds) * 1000 + peer.latency.nanos / 1000000) : 0,
          relayAddress: peer.relayAddress || '',
        }));
        console.log('refreshPeers: Mapped peers:', mappedPeers);
        set({ peers: mappedPeers, localPeer: fullStatus.localPeerState });
      } else {
        console.log('refreshPeers: No peers in fullStatus');
        set({ peers: [], localPeer: null });
      }
    } catch (error) {
      console.error('Refresh peers error:', error);
      set({ peers: [], localPeer: null });
    }
  },
}));

// Set up status update listener
if (typeof window !== 'undefined' && window.electronAPI) {
  window.electronAPI.onStatusUpdate((data) => {
    useStore.getState().setStatus(data.status, data.connected);
  });
}
