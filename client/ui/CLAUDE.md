# NetBird Wails UI — Working Notes

This is the Wails v3 desktop UI for NetBird. Go services live in `services/`; the React/TS frontend lives in `frontend/`; bindings between them are generated under `frontend/bindings/`.

> **Keep these notes current.** When working in this directory with Claude, update this file (and `frontend/CLAUDE.md` for frontend-only changes) whenever you add a service, change an event name, shift a convention, rename a key directory, or land any other change that future-you would want to know about before reading the code. The goal is that a cold-start agent can orient itself from these notes without re-deriving the codebase.

## Layout

### Go (top-level package `main`)
- `main.go` — app entry. Builds the shared gRPC `Conn`, constructs services, registers them with Wails, creates the main webview window, then starts (in order) the Linux SNI watcher → tray → `peers.Watch` → `app.Run`. CLI flags: `--daemon-addr`, `--log-file` (repeatable; first user-provided value drops the seeded `console` default), `--log-level` (`trace|debug|info|warn|error`, default `info`).
- `tray.go` — `Tray` struct + menu. Subscribes to `EventStatus`, `EventSystem`, `EventUpdateAvailable`, `EventUpdateProgress`. Owns per-status icon/dot, Profiles submenu, Connect/Disconnect swap, About → Update, session-expired toast.
- `tray_linux.go` — `init()` sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` to avoid the blank-white window on VMs / minimal WMs.
- `tray_watcher_linux.go`, `xembed_host_linux.go`, `xembed_tray_linux.{c,h}` — in-process SNI watcher + XEmbed bridge for minimal WMs. See `LINUX-TRAY.md`.
- `signal_unix.go` / `signal_windows.go` — `listenForShowSignal`. Unix uses SIGUSR1; Windows uses a named event `Global\NetBirdQuickActionsTriggerEvent`. Mirrors the legacy Fyne UI's external-trigger contract so the installer / CLI keep working.
- `grpc.go` — lazy, mutex-protected gRPC `Conn` shared by every service. `DaemonAddr()`: `unix:///var/run/netbird.sock` on Linux/macOS, `tcp://127.0.0.1:41731` on Windows.
- `icons.go` — `//go:embed` tray/window PNGs. macOS uses template variants (`*-macos.png`); Linux ships light + dark PNGs; Windows reuses the light PNG (multi-frame `.ico` never redrew on Wails3's `NIM_MODIFY`).

### Wails services (`services/*.go`)
Each service is registered via `app.RegisterService(application.NewService(svc))`. Every method becomes a TS function in `frontend/bindings/.../services/`. Frontend-facing details (TS signatures, push events, models) are in `frontend/WAILS-API.md`. After editing any `services/*.go` or the proto, regenerate with `wails3 generate bindings -clean=true -ts` (or `pnpm bindings` from `frontend/`). `frontend/bindings/**` is gitignored.

For frontend-side conventions (routing, providers, contexts) see `frontend/CLAUDE.md`.

## Services rundown

All services live in `services/` and assume a build tag `!android && !ios && !freebsd && !js`. Each takes a shared `DaemonConn` (`conn.go`) and is registered in `main.go`.

| Service | File | Responsibility |
|---|---|---|
| `Connection` | `connection.go` | `Login` / `WaitSSOLogin` / `Up` / `Down` / `Logout` / `OpenURL`. `Up` is always async (`Async: true`); status flows back through `Peers`. `Login` Down-resets the daemon first to dislodge a stale WaitSSOLogin. `OpenURL` honors `$BROWSER`. |
| `Settings` | `settings.go` | `GetConfig` / `SetConfig` (partial update — pointer fields are sent, nil fields preserved) / `GetFeatures` (operator-disabled UI surfaces). |
| `Profiles` | `profile.go` | `Username` / `List` / `GetActive` / `Switch` / `Add` / `Remove`. `List` populates `Email` from the **user-side** state file (`profilemanager.NewProfileManager().GetProfileState`) — the daemon runs as root and can't read it. |
| `ProfileSwitcher` | `profileswitcher.go` | `SwitchActive` — the single entry point both tray and frontend should use for profile flips. Applies the reconnect policy (see "Profile switching" below), mirrors the daemon switch into the user-side `profilemanager`, drives optimistic feedback via `Peers.BeginProfileSwitch`. |
| `Peers` | `peers.go` | Daemon status snapshot + two long-running streams (`SubscribeStatus` → `EventStatus`, `SubscribeEvents` → `EventSystem`). Emits synthetic `StatusDaemonUnavailable` when the socket is unreachable. Owns the profile-switch suppression filter (`BeginProfileSwitch` / `CancelProfileSwitch` / `shouldSuppress`). Fan-outs update metadata into dedicated `EventUpdateAvailable` / `EventUpdateProgress` events. |
| `Networks` | `network.go` | `List` / `Select` / `Deselect` of routed networks. |
| `Forwarding` | `forwarding.go` | `List` exposed/forwarded services from the daemon's reverse-proxy table. |
| `Debug` | `debug.go` | `Bundle` (debug bundle creation + optional upload) / `Get|SetLogLevel` / `RevealFile` (cross-platform "show in file manager"). |
| `Update` | `update.go` | `Trigger` (enforced installer) / `GetInstallerResult` / `Quit` (used by the `/update` page after a successful install). |
| `WindowManager` | `windowmanager.go` | `OpenSettings` / `OpenBrowserLogin(uri)` / `CloseBrowserLogin`. Auxiliary windows are created on first open and **destroyed** on close (Wails-recommended singleton pattern; prevents the macOS dock-reopen from resurrecting hidden windows). |
| `I18n` | `i18n.go` | Thin facade over `i18n.Bundle`. `Languages()` returns the shipped locales (`_index.json`); `Bundle(code)` returns the full key→text map for one language so the React layer can drive its own translation library. |
| `Preferences` | `preferences.go` | Thin facade over `preferences.Store`. `Get()` returns `{language}`; `SetLanguage(code)` validates against `i18n.Bundle.HasLanguage`, persists, and broadcasts `netbird:preferences:changed`. |

`DaemonConn` is defined in `services/conn.go`; `ptrStr` (string-to-*string helper for proto pointer fields) lives there too.

## Daemon proto
- Proto source: `../proto/daemon.proto`. Generated Go in `../proto/*.pb.go`.
- Regen: `cd ../proto && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative daemon.proto`
- Pinned versions (see `daemon.pb.go` header): `protoc v7.34.1`, `protoc-gen-go v1.36.6`. CI's `proto-version-check` workflow fails on mismatch.
- After proto regen, also regen Wails bindings so the TS layer picks up new fields.

## Events bus

`main.go` registers five typed events for the frontend: `netbird:status` (`Status`), `netbird:event` (`SystemEvent`), `netbird:profile:changed` (`ProfileRef`), `netbird:update:available` (`UpdateAvailable`), `netbird:update:progress` (`UpdateProgress`). `netbird:profile:changed` fires from `ProfileSwitcher.SwitchActive` after a successful daemon-side switch — both the React `ProfileContext` and the tray subscribe so a flip driven from one surface paints in the others (the daemon itself does not emit a profile event). Plus three plain-string events:

- `EventTriggerLogin = "trigger-login"` — tray asking the frontend's `startLogin()` to begin an SSO flow.
- `EventBrowserLoginCancel = "browser-login:cancel"` — the `BrowserLogin` window's Cancel button or red-X close. `startLogin()` listens and tears down the daemon's pending `WaitSSOLogin`.
- `preferences.EventPreferencesChanged = "netbird:preferences:changed"` — emitted after every successful `SetLanguage` (payload `{language}`). Both the tray menu rebuild and the React `i18next.changeLanguage` subscribe so a flip from any window paints everywhere.

Daemon connection status strings (`services/peers.go`) mirror `internal.Status*` in `client/internal/state.go`: `Connected`, `Connecting`, `Idle`, `NeedsLogin`, `LoginFailed`, `SessionExpired`, plus the synthetic `DaemonUnavailable` emitted by `Peers` when the socket is unreachable.

## Profile switching

`services/profileswitcher.go` is the single source of truth for the reconnect policy. Both the tray (`tray.go switchProfile`) and the frontend's `screens/Profiles.tsx` call `ProfileSwitcher.SwitchActive`; identical inputs give identical state transitions.

Reconnect policy (driven by `prevStatus` from `Peers.Get`):

| Previous status | Action | Optimistic UI | Suppressed events until new flow begins |
|---|---|---|---|
| Connected | Switch + Down + Up | Connecting (synthetic) | Connected, Idle |
| Connecting | Switch + Down + Up | Connecting (unchanged) | Connected, Idle |
| NeedsLogin / LoginFailed / SessionExpired | Switch + Down | (no change) | — |
| Idle | Switch only | (no change) | — |

Only Connected/Connecting trigger `Peers.BeginProfileSwitch`. That:
1. Sets a 30s `switchInProgress` guard.
2. Emits a synthetic `Status{Status: StatusConnecting}` so both tray and React paint immediately.
3. Tells `statusStreamLoop` to drop the daemon's stale Connected updates (peer count drops as the engine tears down) and the transient Idle in between Down and the new Up.

`shouldSuppress` releases the guard as soon as a status that signals the new flow began arrives:
- **Suppressed**: Connected, Idle
- **Pass through and clear**: Connecting / NeedsLogin / LoginFailed / SessionExpired / DaemonUnavailable
- **Timeout fallback**: 30s elapsed → clear flag, emit normally.

`Peers.CancelProfileSwitch` aborts the suppression — called by `tray.go handleDisconnect` so the user's "Disconnect while Connecting" click paints through immediately.

Also: `ProfileSwitcher.SwitchActive` mirrors the daemon switch into the user-side `profilemanager` (`~/Library/Application Support/netbird/active_profile`). The CLI's `netbird up` reads this file and sends the resolved profile name back; if it diverges from the daemon's `/var/lib/netbird/active_profile.json`, the daemon silently flips back. Mirror failures don't abort the switch — surfaced as a warning.

## Auxiliary windows (`WindowManager`)

The main window is created up front in `main.go`. Auxiliary windows are created on demand by `services.WindowManager`:

- **Settings** (`/#/settings`) — opened from the header gear icon (`layouts/Header.tsx → WindowManager.OpenSettings`). Frameless-look (translucent macOS backdrop, hidden inset title bar), fixed 900×640, no resize, no minimise/maximise.
- **BrowserLogin** (`/#/browser-login?uri=…`) — opened by the connection toggle's SSO flow (`layouts/ConnectionStatusSwitch.tsx`). 460×440, fixed size. The close button (red X) fires `EventBrowserLoginCancel` so the JS-side `startLogin()` can tear down the daemon's pending `WaitSSOLogin`. `WindowManager.CloseBrowserLogin` closes it programmatically when the flow completes.

Both windows are **destroyed** on close (mutex-guarded singleton; `closing` hook nils the field). Destroying rather than hiding is deliberate — Wails' macOS dock-reopen handler resurrects hidden windows, which we don't want for auxiliaries.

The main window is **hidden** on close (the `WindowClosing` hook calls `e.Cancel(); window.Hide()`). The user reaches "really quit" through the tray → Quit menu entry.

## Localisation (i18n)

The locale tree under `frontend/src/i18n/locales/` is the single source of truth for both Go (tray, OS notifications) and React (every user-facing string). Layout: `_index.json` lists shipped languages (`code` / `displayName` / `englishName`); `<code>/common.json` per language. `en/common.json` must exist (the `Bundle` loader hard-fails without it); languages listed in `_index.json` without a bundle are skipped with a warning. Placeholders are single-braced (`"Install version {version}"`) — Go substitutes via `Bundle.Translate(lang, key, "name", value, ...)`; React uses i18next with `interpolation: { prefix: "{", suffix: "}" }`.

Adding a language: drop a `<code>/common.json`, append a row to `_index.json`, add the static import in `frontend/src/i18n/index.ts`, rebuild. Embed lives in `client/ui/main.go`'s `embed.FS`.

Package layout:
- `client/ui/i18n/` — pure `LanguageCode` / `Language` / `Bundle` loader. No Wails / no daemon. Reads the tree from an `fs.FS` passed in by `main.go`.
- `client/ui/preferences/` — `Store` persists `UIPreferences{language}` to `os.UserConfigDir()/netbird/ui-preferences.json` (per-OS-user, shared across daemon profiles). Validates against an injected `LanguageValidator` (`*i18n.Bundle`). No file → in-memory default `en`, persisted on first `SetLanguage`. Broadcasts via in-process pub/sub + optional Wails event emitter.
- `services/i18n.go` + `services/preferences.go` — Wails facades. Preferences emits `netbird:preferences:changed` (payload `{language}`) on every `SetLanguage`.

Key conventions: `tray.*` / `notify.*` (Go-side), `common.* / connect.* / nav.* / profile.* / settings.* / update.* / browserLogin.* / sessionExpired.* / peers.*` (frontend). Keep keys stable — renames cascade everywhere.

## Linux tray support

The in-process `StatusNotifierWatcher` + XEmbed host that lets the tray work on minimal WMs is detailed in `LINUX-TRAY.md` (sibling). Touch that doc when modifying `tray_watcher_linux.go` / `xembed_host_linux.go` / `xembed_tray_linux.{c,h}`.

## Wails Dialogs (frontend, `@wailsio/runtime`)

API surface — `Dialogs.Info` / `Warning` / `Error` / `Question` / `OpenFile` / `SaveFile`, options shape, per-OS behaviour, and the Go-side frameless-window pattern — lives in `WAILS-DIALOGS.md` (sibling). The conventions for **when** to use a native dialog vs inline UI are in the "Conventions" section below.

## Conventions in this codebase

### Errors → native dialogs

User-actionable operation failures (config save, profile switch, debug bundle, update, etc.) surface via `Dialogs.Error` with an action-named title — "Save Settings Failed", "Switch Profile Failed", not "Error" / "Something went wrong". The dialog itself already says "Error" visually.

Confirmations use `Dialogs.Warning` with explicit `Buttons`. The promise resolves with the **button Label string**, not an index — pin the label into a variable before comparing (especially with i18n, where labels translate). Full API in `WAILS-DIALOGS.md`.

**Skip native dialogs** for: inline form validation (`Input.tsx`, URL-format checks — too heavy for keystroke feedback); transient link errors on the dashboard (flap in/out with daemon — use an inline indicator); "partial success" notes inside an otherwise-OK flow (e.g. "bundle saved but upload failed" stays inline); dedicated screens like `/update` may show an additional inline header alongside the dialog so the screen isn't blank after dismissal.

### OS notifications

The tray uses Wails' built-in `notifications` service. One `notifications.NotificationService` is created in `main.go` and passed into `TrayServices.Notifier`. Notification IDs are prefixed for coalescing: `netbird-update-<version>`, `netbird-event-<id>`, `netbird-tray-error`, `netbird-session-expired`. Notifications are gated by the user's "Notifications" toggle (cached in `Tray.notificationsEnabled`, seeded from `Settings.GetConfig` at boot). `Severity == "critical"` events bypass the gate, mirroring the legacy Fyne `event.Manager`.

### Profile switching invariants

`ProfileSwitcher.SwitchActive` is the only switch path on the TS side — `ProfileContext.switchProfile` and `screens/Profiles.tsx` both call it. The Go side captures `prevStatus`, drives the optimistic-Connecting paint via `Peers.BeginProfileSwitch`, mirrors into the user-side `profilemanager`, and conditionally fires Down/Up per the reconnect-policy table above.

**Never call `Connection.Up` on an Idle/NeedsLogin daemon** — the daemon's internal 50s `waitForUp` blocks until `DeadlineExceeded`. `Connection.Up` from the frontend is reserved for the explicit Connect button (`ConnectionStatusSwitch.connect`) and the post-SSO resume inside `startLogin`; the gating for profile-switch reconnects lives Go-side in `ProfileSwitcher.SwitchActive`.

## Build / dev tasks

`task dev` (Wails dev, live reload), `task build` (prod build for the current OS, dispatches to `build/{darwin,linux,windows}/Taskfile.yml`), `task build:server` / `run:server` / `build:docker` / `run:docker` (server-mode variants in `build/Taskfile.yml`). **No** `task generate:bindings` alias — run `wails3 generate bindings -clean=true -ts` directly from this directory. CLI flags + log-target semantics are documented in the `main.go` bullet under "Layout".

## Useful references
- `WAILS-DIALOGS.md` (sibling) — full `@wailsio/runtime` `Dialogs` API + per-OS behaviour + frameless-window pattern.
- `LINUX-TRAY.md` (sibling) — StatusNotifierWatcher + XEmbed host details.
- `frontend/WAILS-API.md` — frontend-facing binding signatures and model shapes.
- Wails v3 dialog docs: https://v3.wails.io/features/dialogs/message/ and https://v3.wails.io/features/dialogs/custom/ (may 403 from some clients).
- Wails v3 multiple-windows guidance: https://v3.wails.io/learn/multiple-windows/
- Authoritative TS signatures: `frontend/node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails examples: https://github.com/wailsapp/wails/tree/master/v3/examples/dialogs
