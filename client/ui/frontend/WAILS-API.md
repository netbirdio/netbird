# Wails Go API reference (frontend)

Reference for every binding method and model shape exposed to the frontend. Generated from `client/ui/services/*.go` via `wails3 generate bindings -clean=true -ts` — regenerate after any Go-side change. Authoritative source is always `bindings/github.com/netbirdio/netbird/client/ui/services/*.ts`.

Every method returns `$CancellablePromise<T>` (a Wails3 wrapper around `Promise`). Call `.cancel()` to abort the underlying gRPC call; in practice we just `await` and let it run.

## Imports

```ts
// Services
import {
  Connection, Peers, ProfileSwitcher, Profiles,
  Settings, Networks, Forwarding, Debug, Update, WindowManager,
  I18n, Preferences,
} from "@bindings/services";

// Models (types-only)
import type {
  Status, PeerStatus, PeerLink, LocalPeer, SystemEvent,
  Profile, ProfileRef, ActiveProfile,
  Config, ConfigParams, SetConfigParams, Features,
  Network, SelectNetworksParams,
  ForwardingRule, PortInfo, PortRange,
  LoginParams, LoginResult, LogoutParams, WaitSSOParams, UpParams,
  DebugBundleParams, DebugBundleResult, LogLevel,
  UpdateResult, UpdateAvailable, UpdateProgress,
} from "@bindings/services/models.js";

// i18n / preferences models live in sibling packages, not services/models
import { LanguageCode, type Language } from "@bindings/i18n/models.js";
import type { UIPreferences } from "@bindings/preferences/models.js";
```

## Push events

Subscribe with `Events.On(name, handler)` from `@wailsio/runtime`. Handlers receive `{ data: <payload> }`.

| Event | Payload | Fires on |
|---|---|---|
| `netbird:status` | `Status` | Daemon SubscribeStatus snapshot — connection-state change, peer-list change, address change, mgmt/signal flip. Synthetic `StatusDaemonUnavailable` is emitted when the gRPC socket is unreachable, and a synthetic `Connecting` is emitted at the start of an active profile switch. |
| `netbird:event` | `SystemEvent` | One push per daemon SubscribeEvents item (DNS / network / authentication / connectivity / system). Used by the tray for OS toasts; the TS side reads events through `Status.events` instead. |
| `netbird:update:available` | `UpdateAvailable` | Daemon detected a new version (fan-out of the `new_version_available` metadata key). |
| `netbird:preferences:changed` | `{ language: string }` | Fires after every successful `Preferences.SetLanguage` (including the caller's own window). `src/lib/i18n.ts` subscribes and calls `i18next.changeLanguage`. |
| `netbird:update:progress` | `UpdateProgress` | Daemon enforced-update install progress (`action: "show"` etc.). |
| `browser-login:cancel` | (none) | Either the user closed the `BrowserLogin` window (Go-emitted) or the page's Cancel button (frontend-emitted). |
| `trigger-login` | (none) | Reserved by the tray for asking the frontend to start an SSO flow. `layouts/ConnectionStatusSwitch.tsx` subscribes and runs `startLogin()`; no Go-side emitter today. |

The two stream loops behind `netbird:status` and `netbird:event` start automatically — `main.go` calls `peers.Watch(context.Background())` at boot. `Peers.Watch` is still exported but the frontend doesn't need to invoke it.

## `Connection`

```ts
Connection.Login(p: LoginParams): Promise<LoginResult>
Connection.WaitSSOLogin(p: WaitSSOParams): Promise<string>   // returns email
Connection.Up(p: UpParams): Promise<void>                    // async on the daemon
Connection.Down(): Promise<void>
Connection.Logout(p: LogoutParams): Promise<void>
Connection.OpenURL(url: string): Promise<void>               // honors $BROWSER
```

`Login` Down-resets the daemon first to dislodge a stale `WaitSSOLogin` (so a previously abandoned SSO flow doesn't fail the next attempt). `Up` always uses async mode — status flows back through `netbird:status`. **Do not call `Up` on an `Idle` / `NeedsLogin` daemon** — the daemon's internal 50s `waitForUp` will block and return `DeadlineExceeded`.

Full SSO sequence: `Login` → if `result.needsSsoLogin`, open `result.verificationUriComplete` via `OpenURL` + `WindowManager.OpenBrowserLogin(uri)` → `WaitSSOLogin({ userCode })` → `Up({})`. The canonical implementation is `startLogin()` in `layouts/ConnectionStatusSwitch.tsx`.

## `Peers`

```ts
Peers.Get(): Promise<Status>            // one-shot snapshot
Peers.Watch(): Promise<void>            // already invoked from main.go
Peers.BeginProfileSwitch(): Promise<void>
Peers.CancelProfileSwitch(): Promise<void>
```

`BeginProfileSwitch` and `CancelProfileSwitch` are normally driven by `ProfileSwitcher` / the tray, not the frontend.

## `ProfileSwitcher`

```ts
ProfileSwitcher.SwitchActive(p: ProfileRef): Promise<void>
```

The single entry point both tray and frontend should use for profile flips. Applies the reconnect policy below, mirrors the switch into the user-side `profilemanager` (so the CLI's `netbird up` reads a consistent active profile), and drives the optimistic-Connecting paint via `Peers.BeginProfileSwitch`.

Reconnect policy (driven by `prevStatus` captured at entry):

| Previous status | Action | Optimistic UI | Suppressed events until new flow |
|---|---|---|---|
| Connected | Switch + Down + Up | Connecting (synthetic) | Connected, Idle |
| Connecting | Switch + Down + Up | Connecting (unchanged) | Connected, Idle |
| NeedsLogin / LoginFailed / SessionExpired | Switch + Down | (no change) | — |
| Idle | Switch only | (no change) | — |

## `Profiles`

```ts
Profiles.Username(): Promise<string>            // current OS username
Profiles.List(username: string): Promise<Profile[]>
Profiles.GetActive(): Promise<ActiveProfile>
Profiles.Switch(p: ProfileRef): Promise<void>   // raw daemon RPC; prefer ProfileSwitcher.SwitchActive
Profiles.Add(p: ProfileRef): Promise<void>
Profiles.Remove(p: ProfileRef): Promise<void>
```

`Profile.email` is populated by the **UI process** reading the per-profile state file (`~/Library/Application Support/netbird/<name>.state.json` on macOS), not by the daemon — the daemon runs as root and can't read user-owned files.

## `Settings`

```ts
Settings.GetConfig(p: ConfigParams): Promise<Config>
Settings.SetConfig(p: SetConfigParams): Promise<void>     // partial update
Settings.GetFeatures(): Promise<Features>                 // operator-disabled UI sections
```

`SetConfig` is a partial update: only fields you set are pushed to the daemon. `profileName` + `username` are always required; the typed fields in `SetConfigParams` are optional (`field?: T | null`). `managementUrl` and `adminUrl` are always-string for historical reasons.

**PSK mask quirk:** `GetConfig` returns existing pre-shared keys as `"**********"`. If you send the mask back, `wgtypes.ParseKey` fails on the next connect. `SettingsContext.save` drops the field when it equals `"**********"`. See `modules/settings/SettingsContext.tsx`.

`SetConfigParams` carries one field that `Config` does not: `disableFirewall`. There's no current GET path for it.

## `Networks`

```ts
Networks.List(): Promise<Network[]>
Networks.Select(p: SelectNetworksParams): Promise<void>
Networks.Deselect(p: SelectNetworksParams): Promise<void>
```

`SelectNetworksParams.append=true` merges into the existing selection; `false` replaces. `all=true` ignores `networkIds` and targets every network (Select-All / Deselect-All).

Exit-node filter: `range === "0.0.0.0/0" || range === "::/0"`. Domain network: `domains.length > 0`. CIDR overlap check is client-side.

## `Forwarding`

```ts
Forwarding.List(): Promise<ForwardingRule[]>
```

`PortInfo` is a daemon-side oneof — exactly one of `port?: number` or `range?: PortRange` is populated. `protocol` is the lowercase daemon string (`"tcp"` / `"udp"`).

## `Debug`

```ts
Debug.GetLogLevel(): Promise<LogLevel>
Debug.SetLogLevel(lvl: LogLevel): Promise<void>
Debug.Bundle(p: DebugBundleParams): Promise<DebugBundleResult>
Debug.RevealFile(path: string): Promise<void>          // OS file-manager focus
```

**Log level case sensitivity bug:** `proto.LogLevel_value` is keyed on uppercase enum names (`"TRACE"`, `"DEBUG"`, `"INFO"`, `"WARN"`, `"ERROR"`, `"PANIC"`, `"FATAL"`, `"UNKNOWN"`). `Debug.SetLogLevel` calls `proto.LogLevel_value[lvl.Level]` and falls back to `INFO` on miss. `useDebugBundle` currently passes `"trace"` (lowercase), which silently maps to `INFO` — the trace-capture flow doesn't actually raise the log level today. To raise to trace, pass `{ level: "TRACE" }`. Fix on the cleanup list.

`Debug.Bundle` uploads when `uploadUrl != ""`. Result fields: `path` (local copy), `uploadedKey` (set on success), `uploadFailureReason` (set on upload failure — the local copy is still saved).

## `Update`

```ts
Update.Trigger(): Promise<UpdateResult>             // start the install
Update.GetInstallerResult(): Promise<UpdateResult>  // poll the outcome (long-running)
Update.Quit(): Promise<void>                        // 100ms later, app.Quit()
```

Typical enforced-update flow on the `/update` route: call `Trigger` once, then poll `GetInstallerResult` every 2s with a 15-minute total timeout. On `success: true` call `Quit`. On `success: false` show `errorMsg`. If the gRPC poll itself starts failing for `DAEMON_DOWN_GRACE_MS` (5s), treat that as success and quit too — the installer commonly takes the daemon offline mid-upgrade. See `pages/Update.tsx` for the canonical implementation.

## `WindowManager`

```ts
WindowManager.OpenSettings(): Promise<void>
WindowManager.OpenBrowserLogin(uri: string): Promise<void>   // uri appended as ?uri=…
WindowManager.CloseBrowserLogin(): Promise<void>
WindowManager.OpenError(title: string, message: string): Promise<void>  // custom branded error window; both query-escaped as ?title=…&message=…
WindowManager.CloseError(): Promise<void>
```

Prefer `errorDialog({Title, Message})` from `lib/dialogs.ts` over calling `OpenError` directly — it's the app's single error surface (the old native MessageBox wrapper now routes here). Both strings must be pre-localised.

Both auxiliary windows are created on first open and destroyed on close (mutex-guarded singleton). The BrowserLogin window's red-X close fires the `browser-login:cancel` event so `startLogin()` can tear down the pending daemon `WaitSSOLogin`.

## `I18n`

```ts
I18n.Languages(): Promise<Language[]>                       // from _index.json
I18n.Bundle(code: LanguageCode): Promise<Record<string,string>>  // full key→text map
```

Source of truth is `client/ui/i18n/locales/` (shared with the Go tray). The frontend's i18next bootstrap doesn't need `I18n.Bundle` at runtime (bundles are statically imported by Vite via the glob in `src/lib/i18n.ts`), but the language picker reads `I18n.Languages()` so the list matches `_index.json` without duplicating it in TS.

## `Preferences`

```ts
Preferences.Get(): Promise<UIPreferences>                   // { language: string }
Preferences.SetLanguage(code: LanguageCode): Promise<void>  // rejects on unknown code
```

`SetLanguage` validates against the loaded `i18n.Bundle`, persists to `os.UserConfigDir()/netbird/ui-preferences.json`, and emits `netbird:preferences:changed`. The frontend's `src/lib/i18n.ts` listens to that event and calls `i18next.changeLanguage` so a flip in any window paints in all of them. Missing preferences file → defaults to `en`, written on first read.

## Daemon `Status.status` values

Mirror `internal.Status*` in `client/internal/state.go` plus the synthetic UI label:

| Value | Meaning |
|---|---|
| `"Idle"` | Tunnel down (Up never invoked or Down completed) |
| `"Connecting"` | Up in progress |
| `"Connected"` | Tunnel up |
| `"NeedsLogin"` | Fresh install or token cleared; needs Login → SSO → Up |
| `"LoginFailed"` | Previous Login attempt errored |
| `"SessionExpired"` | SSO token expired; needs re-Login |
| `"DaemonUnavailable"` | **Synthetic** — UI side, emitted when the daemon gRPC socket is unreachable. Not a real daemon enum. |

The tray also reads a tray-only synthetic `"Error"` for icon purposes; the frontend doesn't see that.

## Model field reference

`Status`:
```ts
{ status, daemonVersion: string;
  management: PeerLink; signal: PeerLink;
  local: LocalPeer;
  peers: PeerStatus[];
  events: SystemEvent[]; }
```

`PeerLink`: `{ url: string; connected: boolean; error?: string }`.

`LocalPeer`: `{ ip, pubKey, fqdn: string; networks: string[] }`.

`PeerStatus`:
```ts
{ ip, pubKey, fqdn, connStatus: string;
  connStatusUpdateUnix: number;
  relayed: boolean;
  localIceCandidateType, remoteIceCandidateType: string;     // pion: "host"|"srflx"|"prflx"|"relay"|""
  localIceCandidateEndpoint, remoteIceCandidateEndpoint: string;
  bytesRx, bytesTx, latencyMs, lastHandshakeUnix: number;
  relayAddress: string;                                       // set when relayed=true
  rosenpassEnabled: boolean;
  networks: string[]; }
```

`SystemEvent`:
```ts
{ id: string;
  severity: string;       // "info"|"warning"|"error"|"critical" (lowercased proto enum, "SystemEvent_" prefix stripped)
  category: string;       // "network"|"dns"|"authentication"|"connectivity"|"system" (same casing rules)
  message: string;        // technical / log line
  userMessage: string;    // human-friendly — render this
  timestamp: number;      // unix seconds
  metadata: Record<string, string>; }   // keys: "new_version_available", "enforced", "id", "network", "version", "progress_window", …
```

`Profile`: `{ name: string; isActive: boolean; email: string }`.

`Config` (read-only mirror, all required):
```ts
{ managementUrl, adminUrl, configFile, logFile, preSharedKey, interfaceName: string;
  wireguardPort, mtu, sshJwtCacheTtl: number;
  disableAutoConnect, serverSshAllowed,
  rosenpassEnabled, rosenpassPermissive,
  disableNotifications, lazyConnectionEnabled, blockInbound,
  networkMonitor, disableClientRoutes, disableServerRoutes,
  disableDns, disableIpv6, blockLanAccess,
  enableSshRoot, enableSshSftp,
  enableSshLocalPortForwarding, enableSshRemotePortForwarding,
  disableSshAuth: boolean; }
```

`SetConfigParams` has all `Config` fields as `field?: T | null` (partial update), plus the write-only `disableFirewall?: boolean | null`, plus `profileName` / `username` / `managementUrl` / `adminUrl` as required strings.

`Features`: `{ disableProfiles, disableUpdateSettings, disableNetworks: boolean }`.

`Network`: `{ id, range: string; selected: boolean; domains: string[]; resolvedIps: Record<string, string[]> }`.

`ForwardingRule`: `{ protocol: string; destinationPort: PortInfo; translatedAddress, translatedHostname: string; translatedPort: PortInfo }`.

`PortInfo`: `{ port?: number | null; range?: PortRange | null }` (exactly one populated).

`PortRange`: `{ start, end: number }` (inclusive).

`LoginParams`: `{ profileName, username, managementUrl, setupKey, preSharedKey, hostname, hint: string }`.

`LoginResult`: `{ needsSsoLogin: boolean; userCode, verificationUri, verificationUriComplete: string }`.

`WaitSSOParams`: `{ userCode, hostname: string }`. Resolves to the user's email.

`UpParams` / `LogoutParams` / `ProfileRef` / `ConfigParams` / `ActiveProfile`: all `{ profileName, username: string }` (different names but same shape — kept distinct by Wails for clarity).

`DebugBundleParams`: `{ anonymize, systemInfo: boolean; uploadUrl: string; logFileCount: number }`.

`DebugBundleResult`: `{ path, uploadedKey, uploadFailureReason: string }`.

`LogLevel`: `{ level: string }` — **uppercase** proto enum name (`"TRACE"`, `"DEBUG"`, `"INFO"`, `"WARN"`, `"ERROR"`, `"PANIC"`, `"FATAL"`).

`UpdateResult`: `{ success: boolean; errorMsg: string }`.

`UpdateAvailable`: `{ version: string; enforced: boolean }`.

`UpdateProgress`: `{ action: string; version: string }`.
