import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';

export interface Config {
  managementUrl?: string;
  preSharedKey?: string;
  interfaceName?: string;
  wireguardPort?: number;
  mtu?: number;
  serverSSHAllowed?: boolean;
  autoConnect?: boolean;
  rosenpassEnabled?: boolean;
  rosenpassPermissive?: boolean;
  lazyConnectionEnabled?: boolean;
  blockInbound?: boolean;
  networkMonitor?: boolean;
  disableDns?: boolean;
  disableClientRoutes?: boolean;
  disableServerRoutes?: boolean;
  blockLanAccess?: boolean;
}

export interface Network {
  id: string;
  networkRange: string;
  domains: string[];
  resolvedIPs: string[];
  selected: boolean;
}

export interface Profile {
  id: string;
  name: string;
  email?: string;
  active: boolean;
}

export class DaemonClient {
  private client: any;
  private protoPath: string;

  constructor(private address: string) {
    // Path to proto file: dist/electron/grpc/client.js -> ../../proto/daemon.proto
    this.protoPath = path.join(__dirname, '../../proto/daemon.proto');
    this.initializeClient();
  }

  private initializeClient() {
    const packageDefinition = protoLoader.loadSync(this.protoPath, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });

    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
    const DaemonService = protoDescriptor.daemon.DaemonService;

    // Create client with Unix socket or TCP
    const credentials = grpc.credentials.createInsecure();
    this.client = new DaemonService(this.address, credentials);
  }

  promisifyCall(method: string, request: any = {}): Promise<any> {
    return new Promise((resolve, reject) => {
      try {
        this.client[method](request, (error: any, response: any) => {
          if (error) {
            // Add more context to the error
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
      } catch (error: any) {
        // Catch synchronous errors (like EPIPE on write)
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

  async getStatus(): Promise<string> {
    try {
      const response = await this.promisifyCall('Status', {});
      return response.status || 'Unknown';
    } catch (error) {
      console.error('getStatus error:', error);
      return 'Error';
    }
  }

  async getFullStatus(): Promise<any> {
    try {
      const response = await this.promisifyCall('Status', {
        getFullPeerStatus: true,
        shouldRunProbes: false
      });
      console.log('getFullStatus response:', JSON.stringify(response.fullStatus, null, 2));
      return response.fullStatus || null;
    } catch (error) {
      console.error('getFullStatus error:', error);
      return null;
    }
  }

  async up(): Promise<void> {
    await this.promisifyCall('Up', {});
  }

  async down(): Promise<void> {
    await this.promisifyCall('Down', {});
  }

  async getConfig(): Promise<Config> {
    const username = require('os').userInfo().username;

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
  }

  async updateConfig(config: Partial<Config>): Promise<void> {
    const username = require('os').userInfo().username;

    // Get active profile name
    const profiles = await this.listProfiles();
    const activeProfile = profiles.find(p => p.active);
    const profileName = activeProfile?.name || 'default';

    // Build the SetConfigRequest with proper field names matching proto
    const request: any = {
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
  }

  async listNetworks(): Promise<Network[]> {
    const response = await this.promisifyCall('ListNetworks', {});
    return (response.networks || []).map((network: any) => ({
      id: network.id,
      networkRange: network.networkRange,
      domains: network.domains || [],
      resolvedIPs: network.resolvedIPs || [],
      selected: network.selected || false,
    }));
  }

  async selectNetworks(networkIds: string[]): Promise<void> {
    await this.promisifyCall('SelectNetworks', { networkIds });
  }

  async deselectNetworks(networkIds: string[]): Promise<void> {
    await this.promisifyCall('DeselectNetworks', { networkIds });
  }

  async listProfiles(): Promise<Profile[]> {
    try {
      // Get OS username for profiles API
      const username = require('os').userInfo().username;
      const response = await this.promisifyCall('ListProfiles', { username });

      console.log('Raw gRPC response profiles:', JSON.stringify(response.profiles, null, 2));

      const mapped = (response.profiles || []).map((profile: any) => ({
        id: profile.id || profile.name, // Use name as id if id is not provided
        name: profile.name,
        email: profile.email,
        active: profile.is_active || false, // gRPC uses snake_case: is_active
      }));

      console.log('Mapped profiles:', JSON.stringify(mapped, null, 2));

      return mapped;
    } catch (error: any) {
      console.error('listProfiles error:', error);
      // Return empty array on error instead of throwing
      if (error.code === 'EPIPE' || error.code === 'ECONNREFUSED') {
        console.warn('gRPC connection lost, returning empty profiles list');
      }
      return [];
    }
  }

  async getActiveProfile(): Promise<Profile | null> {
    try {
      const response = await this.promisifyCall('GetActiveProfile', {});
      if (response.profile) {
        return {
          id: response.profile.id,
          name: response.profile.name,
          email: response.profile.email,
          active: true,
        };
      }
      return null;
    } catch (error) {
      console.error('getActiveProfile error:', error);
      return null;
    }
  }

  async switchProfile(profileId: string): Promise<void> {
    console.log('gRPC client: switchProfile called with profileId:', profileId);
    // The proto expects profileName, not profileId
    const username = require('os').userInfo().username;
    const result = await this.promisifyCall('SwitchProfile', { profileName: profileId, username });
    console.log('gRPC client: switchProfile result:', result);
    return result;
  }

  async addProfile(profileName: string): Promise<void> {
    const username = require('os').userInfo().username;
    await this.promisifyCall('AddProfile', { username, profileName });
  }

  async removeProfile(profileName: string): Promise<void> {
    const username = require('os').userInfo().username;
    await this.promisifyCall('RemoveProfile', { username, profileName });
  }

  async logout(): Promise<void> {
    await this.promisifyCall('Logout', {});
  }

  async login(setupKey?: string): Promise<{
    needsSSOLogin: boolean;
    userCode?: string;
    verificationURI?: string;
    verificationURIComplete?: string;
  }> {
    const request = setupKey ? { setupKey } : {};
    const response = await this.promisifyCall('Login', request);
    return {
      needsSSOLogin: response.needsSSOLogin || false,
      userCode: response.userCode,
      verificationURI: response.verificationURI,
      verificationURIComplete: response.verificationURIComplete,
    };
  }

  async waitSSOLogin(userCode: string): Promise<{ email: string }> {
    const hostname = require('os').hostname();
    const response = await this.promisifyCall('WaitSSOLogin', { userCode, hostname });
    return {
      email: response.email || '',
    };
  }

  async createDebugBundle(anonymize: boolean): Promise<string> {
    const response = await this.promisifyCall('DebugBundle', { anonymize });
    return response.path || '';
  }
}
