/**
 * Type definitions for the auto-generated Wails v3 service bindings.
 * Run `wails3 generate bindings` to regenerate the actual TypeScript bindings
 * from the Go service methods. These types mirror the Go structs.
 *
 * The actual binding files will be generated into frontend/bindings/ by the
 * Wails CLI. This file serves as a centralized re-export and type reference.
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

/**
 * Wails v3 service call helper.
 * After running `wails3 generate bindings`, use the generated functions directly.
 * This helper wraps window.__wails.call for manual use during development.
 */
export async function call<T>(service: string, method: string, ...args: unknown[]): Promise<T> {
  // This will be replaced by generated bindings after `wails3 generate bindings`
  // For now, call via the Wails runtime bridge
  const w = window as typeof window & {
    go?: {
      [svc: string]: {
        [method: string]: (...args: unknown[]) => Promise<T>
      }
    }
  }
  const svc = w.go?.[service]
  if (!svc) throw new Error(`Service ${service} not found. Run wails3 generate bindings.`)
  const fn = svc[method]
  if (!fn) throw new Error(`Method ${service}.${method} not found.`)
  return fn(...args)
}
