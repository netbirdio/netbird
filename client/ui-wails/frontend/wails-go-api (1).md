# Wails Go API surface for the React frontend

All bindings live under `frontend/bindings/github.com/netbirdio/netbird/client/ui-wails/services/`. Import them as:

```ts
import { Connection, Peers, Networks, Settings, Profiles, Debug, Update, Forwarding } from "./bindings/github.com/netbirdio/netbird/client/ui-wails/services";
import * as $models from "./bindings/github.com/netbirdio/netbird/client/ui-wails/services/models";
```

Every method returns `$CancellablePromise<T>` (Wails3 wrapper around a Promise — call `.cancel()` to abort the underlying gRPC stream / call).

## Push events

Subscribe with the Wails event API: `import { Events } from "@wailsio/runtime"`.

| Event name | Payload type | Fires on |
|---|---|---|
| `netbird:status` | `Status` | Daemon connection-state change (Connected / Connecting / Disconnected / Idle), peer-list change, address change, management/signal flip. **Replaces polling**. |
| `netbird:event` | `SystemEvent` | One push per daemon-emitted event (DNS/network/auth/connectivity/system). Drives toasts and the event log. |
| `netbird:update:available` | `UpdateAvailable` | Daemon detected a new version. Show the update menu/banner. |
| `netbird:update:progress` | `UpdateProgress` | `action:"show"` → open the update progress page; `action:"hide"` → close. |

Calling `Peers.Watch()` once at boot starts both backend stream loops; both self-restart with backoff on errors.

## Connection lifecycle — `Connection`

```ts
Connection.Up(p: UpParams): Promise<void>
Connection.Down(): Promise<void>
Connection.Login(p: LoginParams): Promise<LoginResult>
Connection.WaitSSOLogin(p: WaitSSOParams): Promise<string>  // returns email/userInfo
Connection.Logout(p: LogoutParams): Promise<void>
```

- **Up flow**: call `Login` first; if `LoginResult.needsSsoLogin === true` open `verificationUriComplete` in the browser, then call `WaitSSOLogin` with `{ userCode: LoginResult.userCode, hostname: ... }`. Once that resolves call `Up`.
- **Down flow**: just `Down()`. The daemon transitions to `Idle`.

```ts
class LoginParams { profileName, username, managementUrl, setupKey, preSharedKey, hostname, hint: string }
class LoginResult { needsSsoLogin: boolean; userCode, verificationUri, verificationUriComplete: string }
class WaitSSOParams { userCode, hostname: string }
class UpParams { profileName, username: string }
class LogoutParams { profileName, username: string }
```

## Status / peer list — `Peers`

```ts
Peers.Get(): Promise<Status>     // one-shot snapshot
Peers.Watch(): Promise<void>     // call once at boot to enable push events
```

```ts
class Status {
  status: string                // "Idle" | "Connecting" | "Connected" | "SessionExpired" (see below)
  daemonVersion: string
  management: PeerLink
  signal: PeerLink
  local: LocalPeer
  peers: PeerStatus[]
  events: SystemEvent[]
}

class PeerLink {
  url: string
  connected: boolean
}

class LocalPeer {
  ip, pubKey, fqdn: string
  networks: string[]
}

class PeerStatus {
  ip, pubKey, fqdn: string
  connStatus: string                              // "Connected" | "Connecting" | "Idle"
  connStatusUpdateUnix: number                    // unix seconds
  relayed: boolean
  localIceCandidateType, remoteIceCandidateType: string
  localIceCandidateEndpoint, remoteIceCandidateEndpoint: string
  bytesRx, bytesTx: number
  latencyMs: number
  relayAddress: string                            // populated when relayed
  lastHandshakeUnix: number
  rosenpassEnabled: boolean
  networks: string[]
}

class SystemEvent {
  id: string
  severity: string     // "info" | "warning" | "error" | "critical"
  category: string     // "network" | "dns" | "authentication" | "connectivity" | "system"
  message: string      // technical / log message
  userMessage: string  // human-friendly message — render this
  timestamp: number    // unix seconds
  metadata: Record<string, string>
}
```

### Connection-state values

The `Status.status` field uses these literal strings (from the daemon):

| Value | Meaning |
|---|---|
| `"Idle"` | Disconnected — Up not invoked, or Down completed |
| `"Connecting"` | Up in progress |
| `"Connected"` | Tunnel up |
| `"SessionExpired"` | SSO token expired — needs Login again |

(The Fyne UI also reads a synthetic `"Error"` label for some failed states; check `events` for details.)

### ICE candidate type values

`localIceCandidateType` / `remoteIceCandidateType` are pion/ICE strings: `"host"`, `"srflx"`, `"prflx"`, `"relay"`, or `""` while connecting.

## Networks — `Networks`

```ts
Networks.List(): Promise<Network[]>
Networks.Select(p: SelectNetworksParams): Promise<void>
Networks.Deselect(p: SelectNetworksParams): Promise<void>
```

```ts
class Network {
  id, range: string                             // range is a CIDR
  selected: boolean
  domains: string[]                             // empty unless this is a domain network
  resolvedIps: Record<string, string[]>         // domain -> IPs
}

class SelectNetworksParams {
  networkIds: string[]
  append: boolean   // false = replace selection, true = merge with existing
  all: boolean      // true = ignore networkIds and target every network (Select-All / Deselect-All)
}
```

The Fyne UI's All / Overlapping / Exit-node tabs are filters over the same `List()` result:
- **Exit-node**: `range === "0.0.0.0/0" || range === "::/0"`
- **Overlapping**: client-side detection of CIDR overlap among `range` values
- **All**: everything

## Forwarding / exposed services — `Forwarding`

```ts
Forwarding.List(): Promise<ForwardingRule[]>
```

```ts
class ForwardingRule {
  protocol: string                  // "tcp" | "udp"
  destinationPort: PortInfo
  translatedAddress, translatedHostname: string
  translatedPort: PortInfo
}

class PortInfo {                    // exactly one field is populated
  port?: number
  range?: PortRange
}

class PortRange { start, end: number }
```

## Profiles — `Profiles`

```ts
Profiles.List(username: string): Promise<Profile[]>
Profiles.GetActive(): Promise<ActiveProfile>
Profiles.Switch(p: ProfileRef): Promise<void>
Profiles.Add(p: ProfileRef): Promise<void>
Profiles.Remove(p: ProfileRef): Promise<void>
Profiles.Username(): Promise<string>           // current OS username
```

```ts
class Profile { name: string; isActive: boolean }
class ProfileRef { profileName, username: string }
class ActiveProfile { profileName, username: string }
```

## Settings / config — `Settings`

```ts
Settings.GetConfig(p: ConfigParams): Promise<Config>
Settings.SetConfig(p: SetConfigParams): Promise<void>
Settings.GetFeatures(): Promise<Features>
```

```ts
class ConfigParams { profileName, username: string }   // identifies which profile's config

class Config {
  managementUrl, adminUrl, configFile, logFile, preSharedKey: string
  interfaceName: string; wireguardPort, mtu: number
  disableAutoConnect, serverSshAllowed: boolean
  rosenpassEnabled, rosenpassPermissive: boolean
  disableNotifications, lazyConnectionEnabled, blockInbound: boolean
  networkMonitor, disableClientRoutes, disableServerRoutes: boolean
  disableDns, blockLanAccess: boolean
  enableSshRoot, enableSshSftp: boolean
  enableSshLocalPortForwarding, enableSshRemotePortForwarding: boolean
  disableSshAuth: boolean
  sshJwtCacheTtl: number
}

class SetConfigParams {
  // identity (always required)
  profileName, username: string
  // any field below is optional — only the ones you set are pushed to the daemon
  managementUrl?, adminUrl?, ...
  // ... same shape as Config
}

class Features {
  // feature flags from the daemon — hide UI sections when these are true
  disableProfiles, disableUpdateSettings, disableNetworks: boolean
}
```

`SetConfig` is partial — supply only the fields you want to change, plus `profileName` + `username`. Booleans use Go pointer-presence under the hood; on the TS side undefined / missing means "leave as-is".

## Debug bundle / log level — `Debug`

```ts
Debug.GetLogLevel(): Promise<LogLevel>
Debug.SetLogLevel(lvl: LogLevel): Promise<void>
Debug.Bundle(p: DebugBundleParams): Promise<DebugBundleResult>
```

```ts
class LogLevel { level: string }   // "trace" | "debug" | "info" | "warning" | "error" | "panic"

class DebugBundleParams {
  anonymize: boolean
  systemInfo: boolean
  uploadUrl: string                   // empty string = no upload
  logFileCount: number                // 0 = default
}

class DebugBundleResult {
  path: string                        // local path of the generated bundle
  uploadedKey: string                 // populated when uploadUrl was set
  uploadFailureReason: string         // populated on upload error
}
```

## Update flow — `Update`

```ts
Update.Trigger(): Promise<UpdateResult>            // start the install
Update.GetInstallerResult(): Promise<UpdateResult> // poll the install outcome (long-running)
```

```ts
class UpdateResult { success: boolean; errorMsg: string }

class UpdateAvailable {           // payload of "netbird:update:available"
  version: string
  enforced: boolean               // true = management server requires it
}

class UpdateProgress {            // payload of "netbird:update:progress"
  action: string                  // "show" | "hide"
  version: string
}
```

Typical flow:
1. Listen for `"netbird:update:available"` → show the "Update X.Y.Z" affordance.
2. User clicks → call `Update.Trigger()`.
3. The page that shows the install progress polls `GetInstallerResult()` (15-min timeout). On `success: true` the daemon will exit; the app should `app.Quit()` (or restart). On `success: false` show `errorMsg`.

## Toast notifications

The tray sends OS notifications via `application/services/notifications` automatically for `netbird:event` events that have `userMessage`. The frontend doesn't need to do anything for that; the data is also delivered via `netbird:event` if you want to render an in-window log.
