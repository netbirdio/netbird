const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path = require('path');
const os = require('os');
const { app } = require('electron');

class DaemonClient {
  constructor(address) {
    this.address = address;
    // Path to proto file - use resourcesPath for packaged app, or relative path for dev
    const isPackaged = app && app.isPackaged;
    this.protoPath = isPackaged
      ? path.join(process.resourcesPath, 'proto/daemon.proto')
      : path.join(__dirname, '../../proto/daemon.proto');
    this.client = null;
    this.initializeClient();
  }

  initializeClient() {
    try {
      const packageDefinition = protoLoader.loadSync(this.protoPath, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
      });

      const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
      const DaemonService = protoDescriptor.daemon.DaemonService;

      // Create client with Unix socket or TCP
      const credentials = grpc.credentials.createInsecure();
      this.client = new DaemonService(this.address, credentials);

      console.log(`gRPC client initialized with address: ${this.address}`);
    } catch (error) {
      console.error('Failed to initialize gRPC client:', error);
    }
  }

  promisifyCall(method, request = {}) {
    return new Promise((resolve, reject) => {
      if (!this.client) {
        reject(new Error('gRPC client not initialized'));
        return;
      }

      try {
        this.client[method](request, (error, response) => {
          if (error) {
            const enhancedError = {
              ...error,
              method,
              message: error.message || 'Unknown gRPC error',
              code: error.code,
            };
            reject(enhancedError);
          } else {
            resolve(response);
          }
        });
      } catch (error) {
        console.error(`gRPC call ${method} failed synchronously:`, error);
        reject({
          method,
          message: error.message,
          code: error.code || 'UNKNOWN',
          originalError: error,
        });
      }
    });
  }

  async getStatus() {
    try {
      const response = await this.promisifyCall('Status', {});
      return {
        status: response.status || 'Unknown',
        version: response.daemonVersion || '0.0.0'
      };
    } catch (error) {
      console.error('getStatus error:', error);
      return {
        status: 'Error',
        version: '0.0.0'
      };
    }
  }

  async login() {
    try {
      const response = await this.promisifyCall('Login', {});
      return {
        needsSSOLogin: response.needsSSOLogin || false,
        userCode: response.userCode || '',
        verificationURI: response.verificationURI || '',
        verificationURIComplete: response.verificationURIComplete || ''
      };
    } catch (error) {
      console.error('login error:', error);
      throw error;
    }
  }

  async waitSSOLogin(userCode) {
    try {
      const hostname = os.hostname();
      const response = await this.promisifyCall('WaitSSOLogin', {
        userCode,
        hostname
      });
      return {
        email: response.email || ''
      };
    } catch (error) {
      console.error('waitSSOLogin error:', error);
      throw error;
    }
  }

  async up() {
    await this.promisifyCall('Up', {});
  }

  async down() {
    await this.promisifyCall('Down', {});
  }

  async getConfig() {
    try {
      const username = os.userInfo().username;

      // Get active profile name
      const profiles = await this.listProfiles();
      const activeProfile = profiles.find(p => p.active);
      const profileName = activeProfile?.name || 'default';

      const response = await this.promisifyCall('GetConfig', { username, profileName });
      return {
        managementUrl: response.managementUrl || '',
        preSharedKey: response.preSharedKey || '',
        interfaceName: response.interfaceName || '',
        wireguardPort: response.wireguardPort || 51820,
        mtu: response.mtu || 1280,
        serverSSHAllowed: response.serverSSHAllowed || false,
        autoConnect: !response.disableAutoConnect, // Invert the daemon's disableAutoConnect
        rosenpassEnabled: response.rosenpassEnabled || false,
        rosenpassPermissive: response.rosenpassPermissive || false,
        lazyConnectionEnabled: response.lazyConnectionEnabled || false,
        blockInbound: response.blockInbound || false,
        networkMonitor: response.networkMonitor || false,
        disableDns: response.disable_dns || false,
        disableClientRoutes: response.disable_client_routes || false,
        disableServerRoutes: response.disable_server_routes || false,
        blockLanAccess: response.block_lan_access || false,
      };
    } catch (error) {
      console.error('getConfig error:', error);
      // Return default config on error
      return {
        managementUrl: '',
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
    }
  }

  async updateConfig(config) {
    try {
      const username = os.userInfo().username;

      // Get active profile name
      const profiles = await this.listProfiles();
      const activeProfile = profiles.find(p => p.active);
      const profileName = activeProfile?.name || 'default';

      // Build the SetConfigRequest with proper field names matching proto
      const request = {
        username,
        profileName,
      };

      // Map config fields to proto field names (snake_case for gRPC)
      if (config.managementUrl !== undefined) request.managementUrl = config.managementUrl;
      if (config.interfaceName !== undefined) request.interfaceName = config.interfaceName;
      if (config.wireguardPort !== undefined) request.wireguardPort = config.wireguardPort;
      if (config.preSharedKey !== undefined) request.optionalPreSharedKey = config.preSharedKey;
      if (config.mtu !== undefined) request.mtu = config.mtu;
      if (config.serverSSHAllowed !== undefined) request.serverSSHAllowed = config.serverSSHAllowed;
      if (config.autoConnect !== undefined) request.disableAutoConnect = !config.autoConnect; // Invert for daemon
      if (config.rosenpassEnabled !== undefined) request.rosenpassEnabled = config.rosenpassEnabled;
      if (config.rosenpassPermissive !== undefined) request.rosenpassPermissive = config.rosenpassPermissive;
      if (config.lazyConnectionEnabled !== undefined) request.lazyConnectionEnabled = config.lazyConnectionEnabled;
      if (config.blockInbound !== undefined) request.block_inbound = config.blockInbound;
      if (config.networkMonitor !== undefined) request.networkMonitor = config.networkMonitor;
      if (config.disableDns !== undefined) request.disable_dns = config.disableDns;
      if (config.disableClientRoutes !== undefined) request.disable_client_routes = config.disableClientRoutes;
      if (config.disableServerRoutes !== undefined) request.disable_server_routes = config.disableServerRoutes;
      if (config.blockLanAccess !== undefined) request.block_lan_access = config.blockLanAccess;

      await this.promisifyCall('SetConfig', request);
    } catch (error) {
      console.error('updateConfig error:', error);
      throw error;
    }
  }

  async listProfiles() {
    try {
      const username = os.userInfo().username;
      const response = await this.promisifyCall('ListProfiles', { username });

      console.log('Raw gRPC response profiles:', JSON.stringify(response.profiles, null, 2));

      const mapped = (response.profiles || []).map((profile) => ({
        id: profile.id || profile.name, // Use name as id if id is not provided
        name: profile.name,
        email: profile.email,
        active: profile.is_active || false, // gRPC uses snake_case: is_active
      }));

      console.log('Mapped profiles:', JSON.stringify(mapped, null, 2));

      return mapped;
    } catch (error) {
      console.error('listProfiles error:', error);
      // Return empty array on error instead of throwing
      if (error.code === 'EPIPE' || error.code === 'ECONNREFUSED') {
        console.warn('gRPC connection lost, returning empty profiles list');
      }
      return [];
    }
  }

  async switchProfile(profileName) {
    try {
      console.log('gRPC client: switchProfile called with profileName:', profileName);
      const username = os.userInfo().username;
      const result = await this.promisifyCall('SwitchProfile', { profileName, username });
      console.log('gRPC client: switchProfile result:', result);
      return result;
    } catch (error) {
      console.error('switchProfile error:', error);
      throw error;
    }
  }

  async addProfile(profileName) {
    try {
      const username = os.userInfo().username;
      await this.promisifyCall('AddProfile', { username, profileName });
    } catch (error) {
      console.error('addProfile error:', error);
      throw error;
    }
  }

  async removeProfile(profileName) {
    try {
      const username = os.userInfo().username;
      await this.promisifyCall('RemoveProfile', { username, profileName });
    } catch (error) {
      console.error('removeProfile error:', error);
      throw error;
    }
  }

  async logout() {
    try {
      await this.promisifyCall('Logout', {});
    } catch (error) {
      console.error('logout error:', error);
      throw error;
    }
  }

  async createDebugBundle(anonymize = true) {
    try {
      const response = await this.promisifyCall('DebugBundle', {
        anonymize,
        systemInfo: true,
        status: '',
        logFileCount: 5
      });
      return response.path || '';
    } catch (error) {
      console.error('createDebugBundle error:', error);
      throw error;
    }
  }

  async getPeers() {
    try {
      console.log('[getPeers] Calling Status RPC with getFullPeerStatus: true');
      const response = await this.promisifyCall('Status', {
        getFullPeerStatus: true,
        shouldRunProbes: false,
      });

      console.log('[getPeers] Status response:', JSON.stringify({
        status: response.status,
        hasFullStatus: !!response.fullStatus,
        peersCount: response.fullStatus?.peers?.length || 0
      }));

      // Extract peers from fullStatus
      const peers = response.fullStatus?.peers || [];
      console.log(`[getPeers] Found ${peers.length} peers`);

      // Map the peers to the format expected by the UI
      const mapped = peers.map(peer => ({
        ip: peer.IP || '',
        pubKey: peer.pubKey || '',
        connStatus: peer.connStatus || 'Disconnected',
        connStatusUpdate: peer.connStatusUpdate ? new Date(peer.connStatusUpdate.seconds * 1000).toISOString() : '',
        relayed: peer.relayed || false,
        localIceCandidateType: peer.localIceCandidateType || '',
        remoteIceCandidateType: peer.remoteIceCandidateType || '',
        fqdn: peer.fqdn || '',
        localIceCandidateEndpoint: peer.localIceCandidateEndpoint || '',
        remoteIceCandidateEndpoint: peer.remoteIceCandidateEndpoint || '',
        lastWireguardHandshake: peer.lastWireguardHandshake ? new Date(peer.lastWireguardHandshake.seconds * 1000).toISOString() : '',
        bytesRx: peer.bytesRx || 0,
        bytesTx: peer.bytesTx || 0,
        rosenpassEnabled: peer.rosenpassEnabled || false,
        networks: peer.networks || [],
        latency: peer.latency ? (peer.latency.seconds * 1000 + peer.latency.nanos / 1000000) : 0,
        relayAddress: peer.relayAddress || '',
      }));

      console.log('[getPeers] Returning mapped peers:', JSON.stringify(mapped.map(p => ({ ip: p.ip, fqdn: p.fqdn, connStatus: p.connStatus }))));
      return mapped;
    } catch (error) {
      console.error('getPeers error:', error);
      return [];
    }
  }

  async getLocalPeer() {
    try {
      const response = await this.promisifyCall('Status', {
        getFullPeerStatus: true,
        shouldRunProbes: false,
      });

      const localPeer = response.fullStatus?.localPeerState;
      if (!localPeer) {
        console.log('[getLocalPeer] No local peer state found');
        return null;
      }

      const mapped = {
        ip: localPeer.IP || '',
        pubKey: localPeer.pubKey || '',
        fqdn: localPeer.fqdn || '',
        kernelInterface: localPeer.kernelInterface || false,
        rosenpassEnabled: localPeer.rosenpassEnabled || false,
        rosenpassPermissive: localPeer.rosenpassPermissive || false,
        networks: localPeer.networks || [],
      };

      console.log('[getLocalPeer] Local peer:', JSON.stringify({ ip: mapped.ip, fqdn: mapped.fqdn }));
      return mapped;
    } catch (error) {
      console.error('getLocalPeer error:', error);
      return null;
    }
  }
}

module.exports = { DaemonClient };
