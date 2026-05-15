# NetBird Wails UI — Working Notes

This is the Wails v3 desktop UI for NetBird. Go services live in `services/`; the React/TS frontend lives in `frontend/`; bindings between them are generated under `frontend/bindings/`.

## Layout

### Go (top-level package `main`)
- `main.go` — app entry. Builds the gRPC `Conn`, constructs services, registers them with Wails, creates the main webview window, starts the in-process Linux SNI watcher, then the tray, then `peers.Watch`, then `app.Run`. Also wires `--daemon-addr`, `--log-file` (repeatable, defaults to `console`), `--log-level` flags.
- `tray.go` — `Tray` struct and its menu. Subscribes to `EventStatus`, `EventSystem`, `EventUpdateAvailable`, `EventUpdateProgress`. Owns the per-status icon/dot, the Profiles submenu, the Connect/Disconnect swap, the About → Update flow, session-expired toast.
- `tray_linux.go` — `init()` that sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` to avoid the blank-white window on VMs / minimal WMs.
- `tray_watcher_linux.go`, `xembed_host_linux.go`, `xembed_tray_linux.{c,h}` — in-process `org.kde.StatusNotifierWatcher` and XEmbed bridge so the tray works on minimal WMs (Fluxbox, OpenBox, i3, dwm, vanilla GNOME without AppIndicator). See "Linux tray support" below.
- `tray_watcher_other.go` — no-op stub on non-Linux builds.
- `signal_unix.go` / `signal_windows.go` — `listenForShowSignal`. On Unix, SIGUSR1 brings the window forward. On Windows, a named event `Global\NetBirdQuickActionsTriggerEvent` does the same. Mirrors the legacy Fyne UI's external-trigger contract so the installer / CLI keep working.
- `grpc.go` — `Conn` is a lazy, mutex-protected gRPC channel to the daemon. One `Conn` is shared by every service. `DaemonAddr()` returns `unix:///var/run/netbird.sock` on Linux/macOS and `tcp://127.0.0.1:41731` on Windows.
- `icons.go` — `//go:embed` the tray/window PNGs from `assets/`. macOS uses template variants (`*-macos.png`); Linux ships light + dark PNGs; Windows reuses the light PNG (multi-frame `.ico` never redrew on Wails3's `NIM_MODIFY`).
- `desktop/desktop.go` — tiny helper returning `GetUIUserAgent()` (`netbird-desktop-ui/<version>`) for the gRPC dialer.

### Wails services (`services/*.go`)
Each service is registered via `app.RegisterService(application.NewService(svc))`. Every method becomes a TS function in `frontend/bindings/.../services/`. See "Services rundown" below.

### Frontend (`frontend/src/`)
- `app.tsx` — top-level routes. Hash router with `/quick`, `/browser-login`, `/update`, `/session-expired`, `/settings` (own layout), and a root `AppLayout` that hosts `Main` and a `*` catch-all.
- `layouts/AppLayout.tsx` — composition shell. Wraps `Header + Outlet` in `AppearanceProvider → ProfileProvider → DebugBundleProvider → ClientVersionProvider`.
- `layouts/SettingsLayout.tsx` — used when the settings window opens (route `/settings`).
- `modules/*/Context.tsx` — context providers (`appearance`, `auto-update`, `debug-bundle`, `profile`).
- `pages/` — full-screen, single-purpose pages opened in popups or via top-level routes (`BrowserLogin`, `SessionExpired`, `Update`, `Debug`).
- `screens/` — content shown inside `AppLayout` (`Status`, `Peers`, `Networks`, `Profiles`, `Settings`, `Update`, `QuickActions`, `Debug`).

### Generated bindings
- `frontend/bindings/**` — generated, do not edit by hand. Regenerate via `wails3 generate bindings -clean=true -ts` from this directory after editing any `services/*.go`.

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

`DaemonConn` is defined in `services/conn.go`; `ptrStr` (string-to-*string helper for proto pointer fields) lives there too.

## Daemon proto
- Proto source: `../proto/daemon.proto`. Generated Go in `../proto/*.pb.go`.
- Regen: `cd ../proto && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative daemon.proto`
- Pinned versions (see `daemon.pb.go` header): `protoc v7.34.1`, `protoc-gen-go v1.36.6`. CI's `proto-version-check` workflow fails on mismatch.
- After proto regen, also regen Wails bindings so the TS layer picks up new fields.

## Events bus

`main.go` registers four event types so the frontend can subscribe with typed payloads:

```go
application.RegisterEvent[services.Status](services.EventStatus)              // "netbird:status"
application.RegisterEvent[services.SystemEvent](services.EventSystem)         // "netbird:event"
application.RegisterEvent[services.UpdateAvailable](services.EventUpdateAvailable)   // "netbird:update:available"
application.RegisterEvent[services.UpdateProgress](services.EventUpdateProgress)     // "netbird:update:progress"
```

Two additional plain-string events flow between Go and JS without a typed payload:

- `EventTriggerLogin = "trigger-login"` — emitted by the tray (or other Go-side triggers) to ask the frontend's `startLogin()` orchestrator to begin an SSO flow.
- `EventBrowserLoginCancel = "browser-login:cancel"` — emitted by the `BrowserLogin` window when the user clicks Cancel or closes the window (red X). `startLogin()` listens and tears down the pending daemon SSO wait.

Daemon connection status strings (`services/peers.go`) — mirror `internal.Status*` in `client/internal/state.go`:

```go
StatusConnected, StatusConnecting, StatusIdle,
StatusNeedsLogin, StatusLoginFailed, StatusSessionExpired,
StatusDaemonUnavailable  // synthetic, emitted by Peers when the socket is unreachable
```

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

## Linux tray support (StatusNotifierWatcher + XEmbed)

Minimal WMs (Fluxbox, OpenBox, i3, dwm, vanilla GNOME without the AppIndicator extension) don't ship a `StatusNotifierWatcher`, so tray icons using libayatana-appindicator / freedesktop StatusNotifier silently fail. `main.go` calls `startStatusNotifierWatcher()` *before* `NewTray` so the Wails systray's `RegisterStatusNotifierItem` call hits the in-process watcher we control.

- `tray_watcher_linux.go` — owns `org.kde.StatusNotifierWatcher` on the session bus if no other process has it. Safe to call unconditionally.
- `xembed_host_linux.go` + `xembed_tray_linux.{c,h}` — when an XEmbed tray (`_NET_SYSTEM_TRAY_S0`) is available, also start an in-process XEmbed host that bridges the SNI icon into the XEmbed tray. Reads `IconPixmap` over D-Bus, draws via cairo+X11, polls for clicks, fetches `com.canonical.dbusmenu.GetLayout` for the popup menu, fires `com.canonical.dbusmenu.Event` on click.

Build is gated on `linux && !386`; the 386 build (no cgo) and non-Linux builds use the `tray_watcher_other.go` no-op.

## Wails Dialogs (frontend, `@wailsio/runtime`)

The frontend dialog API lives in `@wailsio/runtime` as `Dialogs`. Authoritative signatures are in
`frontend/node_modules/@wailsio/runtime/types/dialogs.d.ts`.

### Message dialogs

```ts
import { Dialogs } from "@wailsio/runtime";

await Dialogs.Info({ Title, Message, Buttons?, Detached? });
await Dialogs.Warning({ Title, Message, Buttons?, Detached? });
await Dialogs.Error({ Title, Message, Buttons?, Detached? });
await Dialogs.Question({ Title, Message, Buttons?, Detached? });
```

All four return `Promise<string>` resolving to the **Label** of the button the user clicked. With no `Buttons` provided you get a single OK button — the promise just resolves when the user dismisses.

`MessageDialogOptions` fields:
- `Title?: string` — window title (short).
- `Message?: string` — the body text.
- `Buttons?: Button[]` — custom buttons. Each `Button` is `{ Label?, IsCancel?, IsDefault? }`. `IsCancel` is what Esc/⌘. triggers; `IsDefault` is what Enter triggers.
- `Detached?: boolean` — when `true`, the dialog isn't tied to the parent window (no sheet behavior on macOS).

### File dialogs

`Dialogs.OpenFile(options)` and `Dialogs.SaveFile(options)` — see `dialogs.d.ts` for the full `OpenFileDialogOptions` / `SaveFileDialogOptions` field set (filters, ButtonText, multi-select, hidden files, alias resolution, directory mode, etc).

### Per-OS behavior

| Platform | Behavior |
|---|---|
| **macOS** | Sheet-style when attached to a parent window. Up to ~4 custom buttons render naturally. Keyboard: Enter = default, ⌘. or Esc = cancel. Follows system theme. Accessibility is built-in. |
| **Windows** | Modal `TaskDialog`-style. Standard button labels are nudged toward OS conventions. Keyboard: Enter = default, Esc = cancel. Follows system theme. |
| **Linux** | GTK dialogs — appearance varies by desktop environment (GNOME/KDE). Follows desktop theme. Standard keyboard nav. |

Behavioural notes that affect us:
- The promise resolves with the **button label string**, not an index. Compare against the literal `Label` you passed (e.g. `if (result !== "Delete") return;`).
- `Buttons[]` on Linux/Windows uses the labels you supply, but the OS layout/styling is fixed.
- `Dialogs.Error` plays the platform error sound and uses the platform error icon. Don't use it for confirmations — use `Dialogs.Warning` or `Dialogs.Question`.
- Don't fire dialogs in a tight loop or from every keystroke — they interrupt focus and (on macOS) animate in/out. Debounce or guard with a `busy` flag.

### Frameless / custom-window dialogs (Go side)

When the native dialog API isn't enough — rich content, embedded webview, multi-screen flow — open a regular Wails window. This is done on the **Go side** via `app.Window.NewWithOptions(application.WebviewWindowOptions{...})`. Useful options:
- `Parent` — attach to a parent so OS treats it as a child.
- `AlwaysOnTop: true` — float above the parent.
- `Frameless: true` — no titlebar/chrome.
- `Resizable: false` (also `DisableResize: true` in v3) — fixed-size dialog feel.
- `Hidden: true` initially, then `dialog.Show()` + `dialog.SetFocus()`.

We **do** use this pattern, but pragmatically: `WindowManager.OpenSettings` and `OpenBrowserLogin` are regular small webview windows (not modal sheets) with no resize, hidden minimise/maximise buttons, and a translucent macOS title bar. They're not classic "OS modal dialogs"; they're just lightweight ancillary windows that look the part. Modal behaviour (`parent.SetEnabled(false)`) is intentionally not used — the user can still click back to the main window.

In-app modals (`NewProfileDialog`, delete-profile confirmation, etc.) are Radix `Dialog` primitives inside the main webview. Reach for a custom OS window only when content must escape the main window (BrowserLogin is the canonical example — its lifecycle is tied to the SSO wait) or when the window needs its own taskbar entry / dock icon.

## Conventions in this codebase

### Errors → native dialogs

We surface user-actionable errors via `Dialogs.Error` rather than red inline text. This started with the profile selector and applies broadly to operation failures (config save, profile switch, debug bundle, update, etc.).

Pattern:
```ts
try {
    await SomeSvc.Operation(...);
} catch (e) {
    await Dialogs.Error({
        Title: "Operation Failed",  // short, action-named
        Message: e instanceof Error ? e.message : String(e),
    });
}
```

Title rules:
- Action-named, short: "Switch Profile Failed", "Save Settings Failed", "Debug Bundle Failed".
- Not "Error" / "Something went wrong" — the dialog already says that visually.

When **not** to use a native dialog:
- **Form validation** (`Input.tsx`, URL-format checks, etc.) — inline next to the field. Native dialogs are too heavy for keystroke-driven feedback.
- **Status/result chrome on a dedicated screen** — e.g. the `/update` and `/login` pages can show a brief "Update failed" header *in addition to* the dialog, so the screen isn't blank after dismissal.
- **Transient link errors on the dashboard** (e.g. `link.error` on a management/signal card) — these flap in/out as the daemon recovers; an inline indicator is more appropriate than a dialog.
- **Result notifications inside a success flow** — e.g. "bundle saved but upload failed" can stay inline since the operation otherwise succeeded.

### Confirmations
Use `Dialogs.Warning` with explicit `Buttons`:
```ts
const r = await Dialogs.Warning({
    Title: "Delete Profile",
    Message: `Are you sure you want to delete "${name}"?`,
    Buttons: [
        { Label: "Cancel", IsCancel: true },
        { Label: "Delete", IsDefault: true },
    ],
});
if (r !== "Delete") return;
```
Compare against the **Label string** returned, not an index.

### OS notifications

The tray uses Wails' built-in `notifications` service (`github.com/wailsapp/wails/v3/pkg/services/notifications`). One `notifications.NotificationService` is created in `main.go` and passed into `TrayServices.Notifier`. Notification IDs are prefixed for coalescing (`netbird-update-<version>`, `netbird-event-<id>`, `netbird-tray-error`, `netbird-session-expired`).

OS notifications are gated by the user's "Notifications" toggle (cached in `Tray.notificationsEnabled`, seeded from `Settings.GetConfig` at boot). `Severity == "critical"` events bypass the gate, mirroring the legacy Fyne event.Manager.

### Bindings & types
Always import generated bindings from `@bindings/services` and types from `@bindings/services/models.js`. The path alias is set up in `tsconfig.json` / `vite.config.ts`.

After editing any `services/*.go` (or the underlying proto), regenerate:
```
wails3 generate bindings -clean=true -ts
```

### Profile context

`modules/profile/ProfileContext.tsx` is the React-side source of truth for `username`, `activeProfile`, and the `profiles` list. It exposes `switchProfile`, `addProfile`, `removeProfile`, `logoutProfile`, and `refresh`.

Two important nuances:

1. **Two switch paths exist.** `screens/Profiles.tsx` calls `ProfileSwitcher.SwitchActive` (the Go-side single-source-of-truth path that also drives the optimistic-Connecting paint and the Peers suppression filter). `ProfileContext.switchProfile`, used elsewhere, still implements the reconnect policy in TS: it calls `Profiles.Switch` and, only if the daemon was actively online, follows up with `Connection.Down` + `Connection.Up`. The TS path skips `Peers.BeginProfileSwitch` so it won't paint optimistic Connecting through the tray. Prefer `ProfileSwitcher.SwitchActive` for new call sites.

2. **Don't call `Connection.Up` on an Idle/NeedsLogin daemon.** The daemon's internal 50s `waitForUp` will block until `DeadlineExceeded`. Both switch paths gate `Up` on a previously-online status (Connected/Connecting). Callers should not bring the connection up themselves outside this flow — `Connection.Up` is reserved for the explicit Connect button and the post-switch resume.

## Build / dev tasks
- `task dev` — Wails dev mode (live reload).
- `task build` — production build for the current OS (`Taskfile.yml` dispatches to `build/{darwin,linux,windows}/Taskfile.yml`).
- `task build:server` / `task run:server` / `task build:docker` / `task run:docker` — server-mode (HTTP, no GUI) variants. See `build/Taskfile.yml`.
- `task generate:bindings` does **not** exist as a top-level alias — run `wails3 generate bindings -clean=true -ts` directly from this directory.

CLI flags (parsed in `main.go`):
- `--daemon-addr <addr>` — gRPC address, default per `DaemonAddr()` (Unix socket on Linux/macOS, `tcp://127.0.0.1:41731` on Windows).
- `--log-file <target>` — repeatable. Each value is `console`, `syslog`, or a file path. First user-provided value drops the seeded `console` default.
- `--log-level <level>` — `trace|debug|info|warn|error` (default `info`).

## Useful references
- Wails v3 dialog docs: https://v3.wails.io/features/dialogs/message/ and https://v3.wails.io/features/dialogs/custom/ (may 403 from some clients).
- Wails v3 multiple-windows guidance: https://v3.wails.io/learn/multiple-windows/
- Authoritative TS signatures: `frontend/node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails examples: https://github.com/wailsapp/wails/tree/master/v3/examples/dialogs
