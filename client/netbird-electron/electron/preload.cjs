const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  connect: () => ipcRenderer.invoke('netbird:connect'),
  disconnect: () => ipcRenderer.invoke('netbird:disconnect'),
  logout: () => ipcRenderer.invoke('netbird:logout'),
  getStatus: () => ipcRenderer.invoke('netbird:status'),
  getConfig: () => ipcRenderer.invoke('netbird:get-config'),
  updateConfig: (config) => ipcRenderer.invoke('netbird:update-config', config),
  getNetworks: () => ipcRenderer.invoke('netbird:get-networks'),
  toggleNetwork: (networkId) => ipcRenderer.invoke('netbird:toggle-network', networkId),
  getProfiles: () => ipcRenderer.invoke('netbird:get-profiles'),
  switchProfile: (profileId) => ipcRenderer.invoke('netbird:switch-profile', profileId),
  deleteProfile: (profileId) => ipcRenderer.invoke('netbird:delete-profile', profileId),
  addProfile: (name) => ipcRenderer.invoke('netbird:add-profile', name),
  removeProfile: (profileId) => ipcRenderer.invoke('netbird:remove-profile', profileId),
  getPeers: () => ipcRenderer.invoke('netbird:get-peers'),
  getLocalPeer: () => ipcRenderer.invoke('netbird:get-local-peer'),
  getExpertMode: () => ipcRenderer.invoke('netbird:get-expert-mode'),
  onNavigateToPage: (callback) => ipcRenderer.on('navigate-to-page', (event, page) => callback(page)),
});
