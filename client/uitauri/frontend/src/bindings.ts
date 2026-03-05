/**
 * Type definitions for Tauri command responses.
 * These mirror the Rust serde-serialized DTOs.
 */

// ---- Connection service ----

export interface StatusInfo {
  status: string
  ip: string
  publicKey: string
  fqdn: string
  connectedPeers: number
}

// ---- Settings service ----

export interface ConfigInfo {
  managementUrl: string
  adminUrl: string
  preSharedKey: string
  interfaceName: string
  wireguardPort: number
  disableAutoConnect: boolean
  serverSshAllowed: boolean
  rosenpassEnabled: boolean
  rosenpassPermissive: boolean
  lazyConnectionEnabled: boolean
  blockInbound: boolean
  disableNotifications: boolean
}

// ---- Network service ----

export interface NetworkInfo {
  id: string
  range: string
  domains: string[]
  selected: boolean
  resolvedIPs: Record<string, string[]>
}

// ---- Profile service ----

export interface ProfileInfo {
  name: string
  isActive: boolean
}

export interface ActiveProfileInfo {
  profileName: string
  username: string
  email: string
}

// ---- Debug service ----

export interface DebugBundleParams {
  anonymize: boolean
  systemInfo: boolean
  upload: boolean
  uploadUrl: string
  runDurationMins: number
  enablePersistence: boolean
}

export interface DebugBundleResult {
  localPath: string
  uploadedKey: string
  uploadFailureReason: string
}

// ---- Peers service ----

export interface PeerInfo {
  ip: string
  pubKey: string
  fqdn: string
  connStatus: string
  connStatusUpdate: string
  relayed: boolean
  relayAddress: string
  latencyMs: number
  bytesRx: number
  bytesTx: number
  rosenpassEnabled: boolean
  networks: string[]
  lastHandshake: string
  localIceType: string
  remoteIceType: string
  localEndpoint: string
  remoteEndpoint: string
}

// ---- Update service ----

export interface InstallerResult {
  success: boolean
  errorMsg: string
}
