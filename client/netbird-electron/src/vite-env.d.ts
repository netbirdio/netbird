/// <reference types="vite/client" />

interface ElectronAPI {
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  logout: () => Promise<void>;
  getStatus: () => Promise<{ status: string; daemon: string }>;
  getConfig: () => Promise<any>;
  updateConfig: (config: any) => Promise<void>;
  getNetworks: () => Promise<any[]>;
  toggleNetwork: (networkId: string) => Promise<void>;
  getProfiles: () => Promise<any[]>;
  switchProfile: (profileId: string) => Promise<void>;
  deleteProfile: (profileId: string) => Promise<void>;
  addProfile: (name: string) => Promise<void>;
  removeProfile: (profileId: string) => Promise<void>;
  getPeers: () => Promise<any[]>;
  getExpertMode: () => Promise<boolean>;
}

interface Window {
  electronAPI: ElectronAPI;
}
