import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Daemon communication
  daemon: {
    getStatus: () => ipcRenderer.invoke('daemon:status'),
    getFullStatus: () => ipcRenderer.invoke('daemon:getFullStatus'),
    up: () => ipcRenderer.invoke('daemon:up'),
    down: () => ipcRenderer.invoke('daemon:down'),
    getConfig: () => ipcRenderer.invoke('daemon:getConfig'),
    updateConfig: (config: any) => ipcRenderer.invoke('daemon:updateConfig', config),
    listNetworks: () => ipcRenderer.invoke('daemon:listNetworks'),
    selectNetworks: (networkIds: string[]) =>
      ipcRenderer.invoke('daemon:selectNetworks', networkIds),
    deselectNetworks: (networkIds: string[]) =>
      ipcRenderer.invoke('daemon:deselectNetworks', networkIds),
    listProfiles: () => ipcRenderer.invoke('daemon:listProfiles'),
    getActiveProfile: () => ipcRenderer.invoke('daemon:getActiveProfile'),
    switchProfile: (profileId: string) =>
      ipcRenderer.invoke('daemon:switchProfile', profileId),
    addProfile: (profileName: string) =>
      ipcRenderer.invoke('daemon:addProfile', profileName),
    removeProfile: (profileId: string) =>
      ipcRenderer.invoke('daemon:removeProfile', profileId),
    logout: () => ipcRenderer.invoke('daemon:logout'),
    login: (setupKey?: string) => ipcRenderer.invoke('daemon:login', setupKey),
    waitSSOLogin: (userCode: string) => ipcRenderer.invoke('daemon:waitSSOLogin', userCode),
  },

  // Shell operations
  shell: {
    openExternal: (url: string) => ipcRenderer.invoke('shell:openExternal', url),
  },

  // Filesystem operations
  fs: {
    getActiveProfile: () => ipcRenderer.invoke('fs:getActiveProfile'),
  },

  // Event listeners
  onStatusUpdate: (callback: (data: any) => void) => {
    ipcRenderer.on('status-update', (_, data) => callback(data));
  },
  onNavigate: (callback: (path: string) => void) => {
    ipcRenderer.on('navigate', (_, path) => callback(path));
  },
});

// Type definitions for TypeScript
declare global {
  interface Window {
    electronAPI: {
      daemon: {
        getStatus: () => Promise<string>;
        getFullStatus: () => Promise<any>;
        up: () => Promise<void>;
        down: () => Promise<void>;
        getConfig: () => Promise<any>;
        updateConfig: (config: any) => Promise<void>;
        listNetworks: () => Promise<any[]>;
        selectNetworks: (networkIds: string[]) => Promise<void>;
        deselectNetworks: (networkIds: string[]) => Promise<void>;
        listProfiles: () => Promise<any[]>;
        getActiveProfile: () => Promise<any>;
        switchProfile: (profileId: string) => Promise<void>;
        addProfile: (profileName: string) => Promise<void>;
        removeProfile: (profileId: string) => Promise<void>;
        logout: () => Promise<void>;
        login: (setupKey?: string) => Promise<{
          needsSSOLogin: boolean;
          userCode?: string;
          verificationURI?: string;
          verificationURIComplete?: string;
        }>;
        waitSSOLogin: (userCode: string) => Promise<{ email: string }>;
      };
      shell: {
        openExternal: (url: string) => Promise<boolean>;
      };
      fs: {
        getActiveProfile: () => Promise<any>;
      };
      onStatusUpdate: (callback: (data: any) => void) => void;
      onNavigate: (callback: (path: string) => void) => void;
    };
  }
}
